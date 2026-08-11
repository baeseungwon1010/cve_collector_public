"""GitHub Security Advisories (GraphQL) 클라이언트.

두 가지 용도가 있다 — CVE 보강(fetch_ghsa_for_cve)과 후보 발견(fetch_advisories_since).
"""
import re
from typing import Optional

import requests

GRAPHQL_URL = "https://api.github.com/graphql"

QUERY = """
query($cve: String!) {
  securityAdvisories(first: 1, identifier: {type: CVE, value: $cve}) {
    nodes {
      summary
      severity
      permalink
      references { url }
    }
  }
}
"""


def fetch_ghsa_for_cve(cve_id: str, token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    try:
        resp = requests.post(
            GRAPHQL_URL,
            json={"query": QUERY, "variables": {"cve": cve_id}},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        nodes = resp.json().get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        return nodes[0] if nodes else None
    except (requests.RequestException, KeyError, ValueError):
        return None


# ── 발견 소스로서의 GHSA ─────────────────────────────────────────────────────
#
# 위 fetch_ghsa_for_cve 는 이미 찾은 CVE 에 보강 정보를 붙이는 용도다. 아래는 GHSA
# 자체를 후보 발견 소스로 쓰기 위한 것으로, 목적이 다르다.
#
# 왜 후보 풀이 아니라 분석 큐로만 보내는가:
#   GHSA 참조에는 PoC 가 없다 (실측: 최근 100건 중 Exploit-DB 0%, PacketStorm 0%,
#   CVE명을 담은 저장소 링크 0건). 패치 커밋은 81% 가 있다. 즉 GHSA 는 "재현 가능한가"
#   에는 답하지 못하고 "패치를 뜯어볼 수 있는가"에만 답한다. 후보 풀에 넣으면 PoC 증거는
#   하나도 못 주면서 GitHub 검색 부하만 늘린다.
#
# updatedSince 를 쓰는 이유:
#   GHSA 가 먼저 나오고 나중에 CVE 가 붙는 경우, 그 어드바이저리의 updatedAt 이 갱신되어
#   다음 증분 조회에 다시 잡힌다. 별도 재조회(reconciliation) 없이 CVE 별칭이 병합된다.

LIST_QUERY = """
query($since: DateTime!, $after: String) {
  securityAdvisories(first: 100, updatedSince: $since,
                     orderBy: {field: UPDATED_AT, direction: ASC}, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId summary publishedAt updatedAt withdrawnAt severity permalink
      cvss { score }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 1) { nodes { package { ecosystem name } } }
    }
  }
}
"""

_COMMIT_RE = re.compile(r"https://github\.com/[^/\s]+/[^/\s]+/commit/([0-9a-f]{7,40})", re.I)
_PULL_RE = re.compile(r"https://github\.com/[^/\s]+/[^/\s]+/pull/\d+", re.I)


def _patch_ref(urls: list[str]) -> Optional[str]:
    """참조 중 패치로 볼 수 있는 것 하나. 커밋을 PR 보다 우선한다."""
    for u in urls:
        if _COMMIT_RE.search(u):
            return u
    for u in urls:
        if _PULL_RE.search(u):
            return u
    return None


def _parse_advisory(node: dict) -> dict:
    ids = {i["type"]: i["value"] for i in node.get("identifiers", [])}
    urls = [r["url"] for r in node.get("references", [])]
    pkgs = node.get("vulnerabilities", {}).get("nodes", [])
    pkg = pkgs[0]["package"] if pkgs else {}
    cvss = (node.get("cvss") or {}).get("score") or None
    return {
        # CVE 가 있으면 그것을 정규 키로 쓴다 — NVD 로 들어온 것과 자동으로 합쳐진다
        "key": ids.get("CVE") or node["ghsaId"],
        "ghsa_id": node["ghsaId"],
        "cve_id": ids.get("CVE"),
        "summary": node.get("summary") or "",
        "severity": node.get("severity"),
        "cvss_score": cvss,
        "package": f"{pkg.get('ecosystem','?')}:{pkg.get('name','?')}" if pkg else None,
        "patch_ref": _patch_ref(urls),
        "permalink": node.get("permalink"),
        "updated_at": node.get("updatedAt"),
        "withdrawn": bool(node.get("withdrawnAt")),
    }


def fetch_advisories_since(since_iso: str, token: str, limit: int = 50) -> tuple[list[dict], Optional[str]]:
    """updatedSince 이후 갱신된 어드바이저리를 파싱해 반환한다.

    반환: (어드바이저리 목록, 마지막으로 본 updatedAt) — 뒤엣것을 다음 실행의 커서로 쓴다.
    limit 에 도달하면 거기서 멈추고, 남은 것은 커서가 그대로라 다음 실행에 이어서 받는다.
    """
    out: list[dict] = []
    cursor = None
    last_updated = None
    while len(out) < limit:
        try:
            resp = requests.post(
                GRAPHQL_URL,
                json={"query": LIST_QUERY, "variables": {"since": since_iso, "after": cursor}},
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError):
            break
        if "errors" in payload:
            break
        conn = payload.get("data", {}).get("securityAdvisories") or {}
        for node in conn.get("nodes", []):
            adv = _parse_advisory(node)
            last_updated = adv["updated_at"]
            if adv["withdrawn"]:
                continue
            out.append(adv)
            if len(out) >= limit:
                break
        if not conn.get("pageInfo", {}).get("hasNextPage"):
            break
        cursor = conn["pageInfo"]["endCursor"]
    return out, last_updated
