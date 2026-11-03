#!/usr/bin/env python3
"""Read-only GitHub status check for GHSA-channel reports we've submitted.

For every analysis.private.json entry with report_status in
{submitted, triaged} and a GHSA-style report_channel (owner/repo parsed from
the URL embedded in report_channel, or report_id already set), queries
`gh api` for the advisory's current state and any discussion comments.

Never posts, comments, or writes anything back to GitHub or to
analysis.private.json -- read-only reconnaissance only. Email-channel and
other non-GitHub reports are skipped (no API visibility into those).
"""
import json
import re
import subprocess
import sys

ANALYSIS = "data/analysis.private.json"
REPO_RE = re.compile(r"(?:github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/security|#\d)")
GHSA_ID_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")


def gh_api(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def find_ghsa_id(owner, repo):
    """Return (ghsa_id, None) if exactly one self-authored advisory exists in
    this repo, else (None, [candidates]) -- never guess among several."""
    advisories = gh_api(f"repos/{owner}/{repo}/security-advisories")
    if not advisories:
        return None, []
    mine = [adv for adv in advisories if (adv.get("author") or {}).get("login") == "baeseungwon1010"]
    if len(mine) == 1:
        return mine[0]["ghsa_id"], None
    return None, mine


def main():
    with open(ANALYSIS) as f:
        data = json.load(f)

    targets = []
    for key, v in data.items():
        if v.get("report_status") not in ("submitted", "triaged"):
            continue
        channel = v.get("report_channel") or ""
        if "ghsa" not in channel.lower() and not (v.get("report_id") or "").startswith("GHSA"):
            continue
        targets.append((key, v))

    if not targets:
        print("No submitted/triaged GHSA-channel reports found.")
        return

    for key, v in targets:
        channel = v.get("report_channel") or ""
        ghsa_id = v.get("report_id")
        gm = GHSA_ID_RE.search(ghsa_id or "") or GHSA_ID_RE.search(channel)
        if gm:
            ghsa_id = gm.group(0)
        m = REPO_RE.search(channel)
        owner_repo = f"{m.group(1)}/{m.group(2)}" if m else None

        print(f"=== {key} ===")
        print(f"  title: {v.get('title')}")
        print(f"  report_channel: {channel}")

        if not owner_repo:
            print("  [skip] could not extract owner/repo from report_channel (not a GitHub GHSA channel)")
            continue

        owner, repo = owner_repo.split("/")
        if not ghsa_id:
            ghsa_id, candidates = find_ghsa_id(owner, repo)
            if not ghsa_id:
                if candidates:
                    print(f"  [ambiguous] {len(candidates)} self-authored advisories in {owner_repo}, store report_id explicitly to disambiguate:")
                    for c in candidates:
                        print(f"    - {c['ghsa_id']}: {c.get('summary')}")
                else:
                    print(f"  [warn] no self-authored advisories found for {owner_repo}")
                continue

        adv = gh_api(f"repos/{owner}/{repo}/security-advisories/{ghsa_id}")
        if not adv:
            print(f"  [warn] could not fetch advisory {ghsa_id}")
            continue

        print(f"  ghsa_id: {ghsa_id}")
        print(f"  state: {adv.get('state')}  (updated_at: {adv.get('updated_at')})")

        comments = gh_api(f"repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments")
        n = len(comments) if comments else 0
        print(f"  comments: {n}")
        if comments:
            for c in comments:
                author = c.get("user", {}).get("login", "?")
                body = (c.get("body") or "").strip().replace("\n", " ")
                if len(body) > 200:
                    body = body[:200] + "..."
                print(f"    - [{c.get('created_at')}] {author}: {body}")
        print()


if __name__ == "__main__":
    main()
