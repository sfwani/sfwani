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
SITE = "https://sfwani.github.io"
UA = "sfwani-profile-updater"

# These two come from private research notes rather than the API, so they are
# maintained by hand. Everything else on the page is derived from public data.
REPORTS_FILED = 167
PROJECTS_AUDITED = 59

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {"critical": "8b1a1a", "high": "cf222e", "medium": "d4a72c", "low": "2da44e"}

# Kept byte for byte in step with sfwani.github.io/scripts/update_advisories.py.
# GHSA-pqxw-g93w-hj9x was published High with no CVSS score and no vector, in
# v3 or v4, so nothing upstream can supply one and it was the only row in the
# table without a number. This vector is derived by hand from the advisory's
# own text and computes to 8.1. It is marked wherever it is shown, because the
# claim these surfaces make is that their numbers resolve to a public advisory
# and this one does not.
SELF_ASSESSED = {
    "GHSA-pqxw-g93w-hj9x": {
        "score": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
}


def cvss_of(a):
    """Return (score, vector, self_assessed) for one advisory payload."""
    cvss = a.get("cvss") or {}
    score, vector = cvss.get("score"), cvss.get("vector_string")
    if not vector:
        v3 = (a.get("cvss_severities") or {}).get("cvss_v3") or {}
        score, vector = score if score is not None else v3.get("score"), v3.get("vector_string")
    if isinstance(score, (int, float)) and vector:
        return float(score), vector, False
    sa = SELF_ASSESSED.get(a.get("ghsa_id"))
    if sa:
        return sa["score"], sa["vector"], True
    return (float(score) if isinstance(score, (int, float)) else None), vector, False

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
    score, vector, self_assessed = cvss_of(a)
    return {
        "ghsa_id": a["ghsa_id"],
        "cve_id": a.get("cve_id"),
        "score": score,
        "vector": vector,
        "self_assessed": self_assessed,
        "severity": (a.get("severity") or "").capitalize(),
        "package": packages[0] if packages else repo.split("/")[-1],
        "cwe": cwes[0] if cwes else None,
        "url": f"{SITE}/advisories/{(a.get('cve_id') or a['ghsa_id']).lower()}/",
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
    score, vector, self_assessed = cvss_of(a)
    return {
        "ghsa_id": a["ghsa_id"],
        "cve_id": a.get("cve_id"),
        "score": score,
        "vector": vector,
        "self_assessed": self_assessed,
        "severity": (a.get("severity") or "").capitalize(),
        "package": packages[0] if packages else "n/a",
        "cwe": cwes[0] if cwes else None,
        "url": f"{SITE}/advisories/{(a.get('cve_id') or a['ghsa_id']).lower()}/",
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


def rating_badge(r):
    """Colour the severity so the table can be read at a glance."""
    score, severity = r["score"], r["severity"]
    color = SEVERITY_COLOR.get(severity.lower(), "6e7781")
    if score is None:
        # A maintainer who published without a score should not get the loudest
        # cell in the table, so this stays a plain single colour badge.
        text = urllib.parse.quote(severity, safe="")
        return f"![{severity}](https://img.shields.io/badge/{text}-{color}?style=flat-square)"
    alt = f"{score:.1f} {severity}"
    left = urllib.parse.quote(f"{score:.1f}", safe="")
    right = urllib.parse.quote(severity, safe="")
    return f"![{alt}](https://img.shields.io/badge/{left}-{right}-{color}?style=flat-square)"


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
        rating = rating_badge(r)
        out.append(f"| [{name}]({r['url']}) | `{short_package(r['package'])}` | {rating} | {cls} |")
    return "\n".join(out)


def render_counters(rows):
    n = len(rows)
    cves = len({r["cve_id"] for r in rows if r["cve_id"]})
    word = "advisory" if n == 1 else "advisories"
    return (
        f"`{cves} CVEs assigned` &nbsp;·&nbsp; `{n} published {word}` "
        f"&nbsp;·&nbsp; `{REPORTS_FILED} filed across {PROJECTS_AUDITED} projects`"
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
