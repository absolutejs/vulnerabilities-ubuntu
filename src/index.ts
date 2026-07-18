import type {
  FeedAdapter,
  VulnerabilityAdvisory,
} from "@absolutejs/vulnerabilities";
import {
  OSV_API_URL,
  createOsvAdapter,
  normalizeOsvAdvisory,
  type OsvFetch,
} from "@absolutejs/vulnerabilities-osv";

export const UBUNTU_OSV_URL = "https://security-metadata.canonical.com/osv/";
export const UBUNTU_OSV_REPOSITORY =
  "https://github.com/canonical/ubuntu-security-notices";

export type UbuntuComponent = {
  ecosystem: `Ubuntu:${string}`;
  name: string;
  version: string;
};

const requireText = (value: string, label: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) throw new Error(`${label} is required`);
  return normalized;
};

export const canonicalUbuntuOsvUrl = (id: string) => {
  const normalized = requireText(id, "Ubuntu advisory id");
  const encoded = encodeURIComponent(normalized);
  const cve = /^UBUNTU-CVE-(\d{4})-/.exec(normalized);
  if (cve?.[1])
    return `https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/cve/${cve[1]}/${encoded}.json`;
  if (/^USN-/.test(normalized))
    return `https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/usn/${encoded}.json`;
  if (/^LSN-/.test(normalized))
    return `https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/lsn/${encoded}.json`;
  return `${OSV_API_URL}/vulns/${encoded}`;
};

export const normalizeUbuntuOsvAdvisory = (input: unknown, fetchedAt: string) =>
  normalizeOsvAdvisory(input, {
    fetchedAt,
    sourceName: "ubuntu",
    sourceUrl: canonicalUbuntuOsvUrl,
  });

export const createUbuntuAdapter = (options: {
  components: readonly UbuntuComponent[];
  fetch?: OsvFetch;
}): FeedAdapter<VulnerabilityAdvisory> => {
  if (options.components.length === 0)
    throw new Error("At least one Ubuntu component is required");
  const components = options.components.map((component) => {
    const ecosystem = requireText(component.ecosystem, "Ubuntu ecosystem");
    if (!ecosystem.startsWith("Ubuntu:"))
      throw new Error("Ubuntu ecosystem must start with Ubuntu:");
    return {
      ecosystem,
      name: requireText(component.name, "Ubuntu package name"),
      version: requireText(component.version, "Ubuntu package version"),
    };
  });
  const osv = createOsvAdapter({
    ...(options.fetch ? { fetch: options.fetch } : {}),
    queries: components.map(({ ecosystem, name, version }) => ({
      package: { ecosystem, name },
      version,
    })),
  });
  return {
    descriptor: {
      id: "ubuntu",
      name: "Canonical Ubuntu OSV",
      url: UBUNTU_OSV_URL,
    },
    fetch: async (request) => {
      const result = await osv.fetch(request);
      if (result.status === "not_modified") return result;
      return {
        ...result,
        records: result.records.map((record) => ({
          ...record,
          value: {
            ...record.value,
            source: {
              ...record.value.source,
              name: "ubuntu",
              url: canonicalUbuntuOsvUrl(record.id),
            },
          },
        })),
      };
    },
  };
};
