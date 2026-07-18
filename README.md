# @absolutejs/vulnerabilities-ubuntu

Canonical Ubuntu OSV intelligence for `@absolutejs/vulnerabilities`. The
adapter queries exact Ubuntu ecosystems, source package names, and full Debian
package versions through the official central OSV API. It preserves Canonical
vendor severity, upstream CVE aliases, distro revisions, affected ranges, and
links each normalized record back to Canonical's official OSV repository.

```ts
import { createUbuntuAdapter } from "@absolutejs/vulnerabilities-ubuntu";

const adapter = createUbuntuAdapter({
  components: [
    {
      ecosystem: "Ubuntu:24.04:LTS",
      name: "nginx",
      version: "1.24.0-2ubuntu7.5",
    },
  ],
});
```

The ecosystem and full distribution version are never reduced to generic
SemVer. That prevents upstream-only comparisons from incorrectly flagging
Canonical security backports as vulnerable.
