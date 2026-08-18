## Sanaan Fayaz Wani

**I break AI agent frameworks.**

Security Engineer at Amazon. I hunt unauthenticated remote code execution in the infrastructure that runs large language models: agent frameworks, inference servers, workflow orchestrators, and the serialization formats they trust.

<!-- COUNTERS:START -->
`9 published advisories` &nbsp;·&nbsp; `7 CVEs assigned` &nbsp;·&nbsp; `6 projects` &nbsp;·&nbsp; `highest published: CVSS 8.8`
<!-- COUNTERS:END -->

### Published advisories

<!-- ADVISORIES:START -->
| Advisory | Project | CVSS | Class |
|:---|:---|:---|:---|
| [CVE-2026-57516](https://github.com/advisories/GHSA-hhrp-gw25-jr43) | `ray` | 8.8 High | Code injection (CWE-94) |
| [CVE-2026-45675](https://github.com/advisories/GHSA-h3ww-q6xx-w7x3) | `open-webui` | 8.1 High | Privilege escalation (CWE-269) |
| [CVE-2026-59714](https://github.com/advisories/GHSA-x2ff-v5v8-m75m) | `open-webui` | 7.1 High | Missing authorization (CWE-862) |
| [CVE-2026-53577](https://github.com/kestra-io/kestra/security/advisories/GHSA-r6v3-xxwj-9h42) | `kestra` | 6.5 Medium | Incorrect authorization (CWE-863) |
| [CVE-2026-63342](https://github.com/hatchet-dev/hatchet/security/advisories/GHSA-g26x-m427-f48f) | `hatchet` | 6.3 Medium | Incorrect authorization (CWE-863) |
| [GHSA-59h8-w5q6-mfmp](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-59h8-w5q6-mfmp) | `trigger.dev` | 5.3 Medium | Missing authentication (CWE-306) |
| [CVE-2026-73301](https://github.com/advisories/GHSA-4qcj-m5wp-jmf4) | `@budibase/server` | 4.3 Medium | Missing authorization (CWE-862) |
| [CVE-2026-59715](https://github.com/advisories/GHSA-gmfw-g93r-vg53) | `open-webui` | 3.1 Low | Missing authentication (CWE-306) |
| [GHSA-pqxw-g93w-hj9x](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-pqxw-g93w-hj9x) | `trigger.dev` | High | Improper isolation (CWE-653) |
<!-- ADVISORIES:END -->

Regenerated daily from the [GitHub Advisory Database](https://github.com/advisories?query=credit%3Asfwani) and from repository level advisories that were published but never forwarded to it. 127 reports filed across 45 open source projects since April 2026; the table above is the published and credited subset, since coordinated disclosure runs on the maintainer's clock and most of the rest are still in it.

Full writeups with root cause, reproduction, and fix diffs: [**sfwani/advisories**](https://github.com/sfwani/advisories)

### What I look for

**Unauthenticated reachability.** An auth-gated code execution sink is a bug. The same sink reachable before auth is a 10.0. Most of my highest severity findings are reachability failures rather than novel sinks: missing authentication (CWE-306) and missing authorization (CWE-862) in front of machinery that was never meant to be public.

**Sandboxes that are not sandboxes.** Agent frameworks ship "safe" Python evaluators built on AST allowlists. Format string dunder traversal, decorator abuse, and incomplete node denylists walk out of most of them.

**Deserialization on exposed ports.** `pickle`, `cloudpickle`, `joblib`, and `torch.load(weights_only=False)` behind an inference or actor pool port that quietly binds `0.0.0.0` (CWE-502).

**Server side request forgery into control planes.** My highest volume class (CWE-918): metadata endpoints, internal schedulers, and cluster APIs one redirect away from a user supplied URL.

### Applied

**DEF CON 34, 2026.** Built autonomous agents for AI Village HalCTF, the OWASP Secure Development CTF, and Adversary Wars: model exploitation, live patching of running vulnerable services, and flag capture with no human in the loop.

**USF CyberHerd.** Blue Team Captain. Collegiate defense competition: incident response and infrastructure hardening under contest conditions.

### Elsewhere

[LinkedIn](https://www.linkedin.com/in/sfwani) &nbsp;·&nbsp; [Advisory writeups](https://github.com/sfwani/advisories)
