<div align="center">

# Sanaan Fayaz Wani

### I break AI agent frameworks.

Security Engineer at Amazon, working in IAM security on bringing agentic AI into identity
and access management. Outside that, I hunt unauthenticated remote code execution in the
infrastructure that runs large language models: agent frameworks, inference servers,
workflow orchestrators, and the serialization formats they trust.

<!-- COUNTERS:START -->
`7 CVEs assigned` &nbsp;·&nbsp; `12 published advisories` &nbsp;·&nbsp; `167 filed across 59 projects`
<!-- COUNTERS:END -->

</div>

## Published advisories

<!-- ADVISORIES:START -->
| Advisory | Project | CVSS | Class |
|:---|:---|:---|:---|
| [CVE-2026-57516](https://sfwani.github.io/advisories/cve-2026-57516/) | `ray` | ![8.8 High](https://img.shields.io/badge/8.8-High-cf222e?style=flat-square) | Code injection (CWE-94) |
| [CVE-2026-45675](https://sfwani.github.io/advisories/cve-2026-45675/) | `open-webui` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Privilege escalation (CWE-269) |
| [GHSA-pqxw-g93w-hj9x](https://sfwani.github.io/advisories/ghsa-pqxw-g93w-hj9x/) | `trigger.dev` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Improper isolation (CWE-653) |
| [GHSA-jc26-22qp-cgqj](https://sfwani.github.io/advisories/ghsa-jc26-22qp-cgqj/) | `trigger.dev` | ![7.9 High](https://img.shields.io/badge/7.9-High-cf222e?style=flat-square) | Missing authentication (CWE-306) |
| [GHSA-3c52-v5v2-3r56](https://sfwani.github.io/advisories/ghsa-3c52-v5v2-3r56/) | `budibase` | ![7.7 High](https://img.shields.io/badge/7.7-High-cf222e?style=flat-square) | Server side request forgery (CWE-918) |
| [CVE-2026-59714](https://sfwani.github.io/advisories/cve-2026-59714/) | `open-webui` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Missing authorization (CWE-862) |
| [GHSA-8p4j-2mm9-rh78](https://sfwani.github.io/advisories/ghsa-8p4j-2mm9-rh78/) | `Tracecat` | ![6.5 Medium](https://img.shields.io/badge/6.5-Medium-d4a72c?style=flat-square) | Server side request forgery (CWE-918) |
| [CVE-2026-53577](https://sfwani.github.io/advisories/cve-2026-53577/) | `kestra` | ![6.5 Medium](https://img.shields.io/badge/6.5-Medium-d4a72c?style=flat-square) | Incorrect authorization (CWE-863) |
| [CVE-2026-63342](https://sfwani.github.io/advisories/cve-2026-63342/) | `hatchet` | ![6.3 Medium](https://img.shields.io/badge/6.3-Medium-d4a72c?style=flat-square) | Incorrect authorization (CWE-863) |
| [GHSA-59h8-w5q6-mfmp](https://sfwani.github.io/advisories/ghsa-59h8-w5q6-mfmp/) | `trigger.dev` | ![5.3 Medium](https://img.shields.io/badge/5.3-Medium-d4a72c?style=flat-square) | Missing authentication (CWE-306) |
| [CVE-2026-73301](https://sfwani.github.io/advisories/cve-2026-73301/) | `@budibase/server` | ![4.3 Medium](https://img.shields.io/badge/4.3-Medium-d4a72c?style=flat-square) | Missing authorization (CWE-862) |
| [CVE-2026-59715](https://sfwani.github.io/advisories/cve-2026-59715/) | `open-webui` | ![3.1 Low](https://img.shields.io/badge/3.1-Low-2da44e?style=flat-square) | Missing authentication (CWE-306) |
<!-- ADVISORIES:END -->

Each advisory above links to a full writeup: root cause, the vulnerable code, reproduction
steps and the fix. Mirrored at **[sfwani/advisories](https://github.com/sfwani/advisories)**.

<sub>Table regenerates daily from published advisories credited to me. Verify independently:
[GitHub Advisory Database](https://github.com/advisories?query=credit%3Asfwani).</sub>

## What I look for

<table>
<tr><td width="50%" valign="top">

**Unauthenticated reachability**

An auth gated code execution sink is a bug. The same sink reachable before auth is a 10.0.
My highest severity findings are reachability failures rather than novel sinks: CWE-306 and
CWE-862 standing in front of machinery that was never meant to be public.

</td><td width="50%" valign="top">

**Sandboxes that are not sandboxes**

Agent frameworks ship "safe" Python evaluators built on AST allowlists. Format string dunder
traversal, decorator abuse, and incomplete node denylists walk straight out of most of them.

</td></tr>
<tr><td width="50%" valign="top">

**Deserialization on exposed ports**

`pickle`, `cloudpickle`, `joblib`, and `torch.load(weights_only=False)` sitting behind an
inference or actor pool port that quietly binds `0.0.0.0` (CWE-502).

</td><td width="50%" valign="top">

**Request forgery into control planes**

My highest volume class (CWE-918): metadata endpoints, internal schedulers, and cluster APIs
one redirect away from a user supplied URL.

</td></tr>
</table>

## Disclosure

Reports go to maintainers privately, through GitHub Security Advisories or the project's
stated security channel, never a public issue tracker. Advisories carry a 90 day
disclosure window. Nothing is named, hinted at, or mirrored publicly until the maintainer
publishes.

## Competitions

| Placement | Event |
|:---|:---|
| **1st** | AI Village CTF, DEF CON 34 |
| **2nd** | Adversary Wars CTF, Adversary Village, DEF CON 34 |
| **1st** | Adversary Wars CTF, Adversary Village, DEF CON 33 |
| **1st** | SHPE National CTF |
| **1st** | Hackabull CTF |
| **1st** | Central Florida Tech Grove CTF |
| **1st** | Social Engineering Competition, The CARE Lab at Temple University |
| **3rd** | SecureTheFuture Research Award, Palo Alto Networks |
| **3rd** | NCAE CyberGames, South East Regionals |

<div align="center">
<br>

[**Website**](https://sfwani.github.io) &nbsp;·&nbsp; [**Experience**](https://sfwani.github.io/experience/) &nbsp;·&nbsp; [**Advisories**](https://sfwani.github.io/advisories/) &nbsp;·&nbsp; [**LinkedIn**](https://www.linkedin.com/in/sfwani)

</div>
