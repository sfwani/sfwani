#!/usr/bin/env python3
"""Regenerate the advisory table on the profile README.

Source of truth is the public GitHub Advisory Database. The REST /advisories
endpoint has no credit filter, so the credited set is read from the advisories
search page and each ID is then resolved through the API for structured fields.
"""

import os
import re
import sys
import time
import urllib.parse

import requests

USER = os.environ.get("ADVISORY_CREDIT_USER", "sfwani")
README = os.environ.get("README_PATH", "README.md")
API = "https://api.github.com"
UA = "sfwani-profile-updater"

# These two come from private research notes rather than the API, so they are
# maintained by hand. Everything else on the page is derived from public data.
REPORTS_FILED = 127
PROJECTS_AUDITED = 45

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {"critical": "8b1a1a", "high": "cf222e", "medium": "d4a72c", "low": "2da44e"}

# Short, readable labels for the CWEs that actually show up in this work.
CWE_LABELS = {
    "CWE-22": "Path traversal",
    "CWE-78": "Command injection",
    "CWE-79": "Cross site scripting",
    "CWE-94": "Code injection",
    "CWE-200": "Information disclosure",
    "CWE-269": "Privilege escalation",
    "CWE-284": "Access control",
    "CWE-287": "Authentication bypass",
    "CWE-306": "Missing authentication",
    "CWE-352": "Cross site request forgery",
    "CWE-362": "Race condition",
    "CWE-434": "Unrestricted upload",
    "CWE-502": "Unsafe deserialization",
    "CWE-639": "Insecure direct object reference",
    "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization",
    "CWE-653": "Improper isolation",
    "CWE-918": "Server side request forgery",
    "CWE-1333": "Regex denial of service",
}


def session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def credited_ghsa_ids(s):
    """Scrape the advisory search page for every GHSA credited to USER."""
    found, page = [], 1
    while page <= 10:
        url = "https://github.com/advisories"
        r = s.get(url, params={"query": f"credit:{USER}", "page": page}, timeout=30)
        r.raise_for_status()
        ids = re.findall(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", r.text)
        fresh = [i for i in dict.fromkeys(ids) if i not in found]
        if not fresh:
            break
        found.extend(fresh)
        page += 1
        time.sleep(1)
    return found


def extra_repo_advisories():
    """Repository level advisories that are published and credited but never
    forwarded to the global database, so the credit search cannot see them.

    Format: one "owner/repo GHSA-id" per line, blank lines and # comments ignored.
    """
    path = os.environ.get("EXTRA_ADVISORIES", "advisories.txt")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 2:
            out.append((parts[0], parts[1]))
    return out


def resolve_repo_level(s, repo, ghsa_id):
    """Only returns an advisory that is published and where USER credit is accepted."""
    r = s.get(f"{API}/repos/{repo}/security-advisories/{ghsa_id}", timeout=30)
    if r.status_code != 200:
        print(f"skip {ghsa_id}: HTTP {r.status_code}", file=sys.stderr)
        return None
    a = r.json()
    if a.get("state") != "published" or a.get("withdrawn_at"):
        print(f"skip {ghsa_id}: state={a.get('state')}", file=sys.stderr)
        return None
    accepted = any(
        (c.get("user") or {}).get("login") == USER and c.get("state") == "accepted"
        for c in a.get("credits_detailed") or []
    )
    if not accepted:
        print(f"skip {ghsa_id}: credit not accepted", file=sys.stderr)
        return None
    packages = sorted({v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")})
    cwes = [c["cwe_id"] for c in a.get("cwes") or []]
    score = (a.get("cvss") or {}).get("score")
    return {
        "ghsa_id": a["ghsa_id"],
        "cve_id": a.get("cve_id"),
        "score": score if isinstance(score, (int, float)) else None,
        "severity": (a.get("severity") or "").capitalize(),
        "package": packages[0] if packages else repo.split("/")[-1],
        "cwe": cwes[0] if cwes else None,
        "url": a.get("html_url") or f"https://github.com/{repo}/security/advisories/{ghsa_id}",
    }


def resolve(s, ghsa_id):
    r = s.get(f"{API}/advisories/{ghsa_id}", timeout=30)
    if r.status_code != 200:
        print(f"skip {ghsa_id}: HTTP {r.status_code}", file=sys.stderr)
        return None
    a = r.json()
    if a.get("withdrawn_at"):
        return None
    packages = sorted({v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")})
    cwes = [c["cwe_id"] for c in a.get("cwes") or []]
    score = (a.get("cvss") or {}).get("score")
    return {
        "ghsa_id": a["ghsa_id"],
        "cve_id": a.get("cve_id"),
        "score": score if isinstance(score, (int, float)) else None,
        "severity": (a.get("severity") or "").capitalize(),
        "package": packages[0] if packages else "n/a",
        "cwe": cwes[0] if cwes else None,
        "url": a.get("html_url") or f"https://github.com/advisories/{a['ghsa_id']}",
    }


def short_package(name):
    """Trim ecosystem qualifiers so the table stays readable.

    Scoped npm names such as @budibase/server keep their scope, since the scope
    is the project. Go module paths and Maven coordinates lose their prefix.
    """
    if name.startswith("@"):
        return name
    for sep in ("/", ":"):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    return name


def rating_badge(score, severity):
    """Colour the severity so the table can be read at a glance."""
    color = SEVERITY_COLOR.get(severity.lower(), "6e7781")
    if score is None:
        # A maintainer who published without a score should not get the loudest
        # cell in the table, so this stays a plain single colour badge.
        text = urllib.parse.quote(severity, safe="")
        return f"![{severity}](https://img.shields.io/badge/{text}-{color}?style=flat-square)"
    left = urllib.parse.quote(f"{score:.1f}", safe="")
    right = urllib.parse.quote(severity, safe="")
    return f"![{score:.1f} {severity}](https://img.shields.io/badge/{left}-{right}-{color}?style=flat-square)"


def label(cwe):
    if not cwe:
        return "Other"
    return CWE_LABELS.get(cwe, cwe)


def render_table(rows):
    out = [
        "| Advisory | Project | CVSS | Class |",
        "|:---|:---|:---|:---|",
    ]
    for r in rows:
        name = r["cve_id"] or r["ghsa_id"]
        cls = label(r["cwe"])
        if r["cwe"] and cls != r["cwe"]:
            cls = f"{cls} ({r['cwe']})"
        rating = rating_badge(r["score"], r["severity"])
        out.append(f"| [{name}]({r['url']}) | `{short_package(r['package'])}` | {rating} | {cls} |")
    return "\n".join(out)


def render_counters(rows):
    n = len(rows)
    cves = len({r["cve_id"] for r in rows if r["cve_id"]})
    top = max((r["score"] for r in rows if r["score"] is not None), default=0.0)
    word = "advisory" if n == 1 else "advisories"
    return (
        f"`{cves} CVEs assigned` &nbsp;·&nbsp; `{n} published {word}` "
        f"&nbsp;·&nbsp; `{REPORTS_FILED} reports across {PROJECTS_AUDITED} projects` "
        f"&nbsp;·&nbsp; `highest CVSS {top:.1f}`"
    )


def splice(text, marker, body):
    start, end = f"<!-- {marker}:START -->", f"<!-- {marker}:END -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
    if not pattern.search(text):
        raise SystemExit(f"marker {marker} not found in {README}")
    return pattern.sub(f"{start}\n{body}\n{end}", text)


def main():
    s = session()
    ids = credited_ghsa_ids(s)
    print(f"credited advisories found: {len(ids)}", file=sys.stderr)
    rows = [r for r in (resolve(s, i) for i in ids) if r]
    seen = {r["ghsa_id"] for r in rows}
    for repo, ghsa_id in extra_repo_advisories():
        if ghsa_id in seen:
            continue
        extra = resolve_repo_level(s, repo, ghsa_id)
        if extra:
            rows.append(extra)
            seen.add(ghsa_id)
    if not rows:
        raise SystemExit("no advisories resolved, refusing to write an empty table")
    rows.sort(key=lambda r: (
        SEVERITY_RANK.get(r["severity"].lower(), 9),
        -(r["score"] if r["score"] is not None else 0.0),
        r["package"],
    ))

    original = open(README, encoding="utf-8").read()
    updated = splice(original, "ADVISORIES", render_table(rows))
    updated = splice(updated, "COUNTERS", render_counters(rows))

    if updated == original:
        print("no change", file=sys.stderr)
        return
    open(README, "w", encoding="utf-8").write(updated)
    print(f"updated {README} with {len(rows)} advisories", file=sys.stderr)


if __name__ == "__main__":
    main()
