import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams"],
    intents: [
      "query official Ubuntu vulnerability data",
      "correlate Ubuntu package versions with Canonical advisories",
      "preserve Ubuntu vendor security status",
    ],
    keywords: ["Ubuntu", "Canonical", "CVE", "USN", "OSV"],
    protocols: ["Ubuntu OSV", "OSV API v1"],
  },
  identity: {
    accent: "#e95420",
    category: "operations",
    description:
      "Canonical Ubuntu OSV ingestion with distribution-version fidelity and official record provenance.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-ubuntu",
    name: "@absolutejs/vulnerabilities-ubuntu",
    tagline: "Evaluate Ubuntu packages against Canonical's own intelligence.",
  },
  settings: Type.Object({}),
  wiring: [],
});
