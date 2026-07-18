import { describe, expect, test } from "bun:test";
import {
  canonicalUbuntuOsvUrl,
  createUbuntuAdapter,
  normalizeUbuntuOsvAdvisory,
} from "../src";
import type { OsvFetch } from "@absolutejs/vulnerabilities-osv";

const fetchedAt = "2026-07-18T19:00:00Z";
const advisory = {
  affected: [
    {
      package: {
        ecosystem: "Ubuntu:24.04:LTS",
        name: "nginx",
        purl: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5?arch=source&distro=noble",
      },
      ranges: [
        {
          events: [{ introduced: "0" }, { fixed: "1.24.0-2ubuntu7.5" }],
          type: "ECOSYSTEM",
        },
      ],
      versions: ["1.24.0-2ubuntu7.4"],
    },
  ],
  aliases: [],
  id: "UBUNTU-CVE-2026-0001",
  modified: "2026-07-18T18:30:00Z",
  severity: [{ score: "medium", type: "Ubuntu" }],
  upstream: ["CVE-2026-0001"],
};

describe("Ubuntu OSV", () => {
  test("maps official record URLs for CVEs, USNs, and LSNs", () => {
    expect(canonicalUbuntuOsvUrl("UBUNTU-CVE-2026-0001")).toContain(
      "/osv/cve/2026/UBUNTU-CVE-2026-0001.json",
    );
    expect(canonicalUbuntuOsvUrl("USN-9999-1")).toContain(
      "/osv/usn/USN-9999-1.json",
    );
    expect(canonicalUbuntuOsvUrl("LSN-9999-1")).toContain(
      "/osv/lsn/LSN-9999-1.json",
    );
  });

  test("preserves distro versions, upstream CVEs, and vendor severity", () => {
    const result = normalizeUbuntuOsvAdvisory(advisory, fetchedAt);
    expect(result.aliases).toEqual(["UBUNTU-CVE-2026-0001", "CVE-2026-0001"]);
    expect(result.affected?.[0]?.ranges[0]?.events[1]?.fixed).toBe(
      "1.24.0-2ubuntu7.5",
    );
    expect(result.severity[0]?.value).toBe("medium");
    expect(result.source.name).toBe("ubuntu");
  });

  test("queries exact Ubuntu ecosystems and versions", async () => {
    let queryBody = "";
    const fetcher: OsvFetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/querybatch")) {
        queryBody = String(init?.body);
        return Response.json({
          results: [{ vulns: [{ id: advisory.id }] }],
        });
      }
      return Response.json(advisory);
    };
    const adapter = createUbuntuAdapter({
      components: [
        {
          ecosystem: "Ubuntu:24.04:LTS",
          name: "nginx",
          version: "1.24.0-2ubuntu7.4",
        },
      ],
      fetch: fetcher,
    });
    const result = await adapter.fetch({ cursor: null });

    expect(queryBody).toContain('"ecosystem":"Ubuntu:24.04:LTS"');
    expect(queryBody).toContain('"version":"1.24.0-2ubuntu7.4"');
    expect(result.status).toBe("updated");
    if (result.status !== "updated") throw new Error("Expected update");
    expect(result.records[0]?.value.source.url).toBe(
      canonicalUbuntuOsvUrl(advisory.id),
    );
  });

  test("rejects empty component sets", () => {
    expect(() => createUbuntuAdapter({ components: [] })).toThrow(
      "At least one Ubuntu component",
    );
  });
});
