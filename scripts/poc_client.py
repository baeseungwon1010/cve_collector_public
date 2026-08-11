"""GitHub 저장소 검색으로 CVE의 공개 PoC 존재 여부를 확인한다.

GitHub REST Search API는 코어 API와 별도로 30회/분(인증시) 제한이 있어
호출 사이 지연을 반드시 지켜야 한다 (rate_limit_delay).
"""
import re
import time
from typing import Optional

import requests

SEARCH_URL = "https://api.github.com/search/repositories"


def _normalize(text: str) -> str:
    """비교용 정규화: 영숫자만 남기고 소문자화.

    저장소마다 CVE 표기가 제각각이라(CVE-2026-1234 / cve_2026_1234 / CVE20261234)
    구분자를 지운 뒤 비교해야 정상 PoC를 놓치지 않는다.
    """
    return re.sub(r"[^a-z0-9]", "", text.lower())


def mentions_cve(cve_id: str, *texts: str) -> bool:
    """주어진 텍스트들이 이 CVE를 **정확히** 언급하는지 검사한다.

    GitHub 검색은 정확 일치가 아니라서 CVE-2026-3141 로 검색하면
    CVE-2026-31413 저장소가 걸린다. 시퀀스 번호가 짧은 CVE가 긴 CVE에
    잡아먹히므로, 뒤에 숫자가 이어지면 다른 CVE로 보고 배제한다.
    """
    needle = _normalize(cve_id)
    if not needle:
        return False
    pattern = re.escape(needle) + r"(?!\d)"
    return any(re.search(pattern, _normalize(t or "")) for t in texts)


def search_poc_repos(cve_id: str, token: Optional[str], max_results: int = 3) -> Optional[list[dict]]:
    """cve_id를 이름/설명에 포함하는 저장소를 스타 수 순으로 최대 max_results개 반환.

    반환 항목: {"url", "full_name", "stars", "description", "created_at", "pushed_at"}
    `created_at`은 저장소가 실제로 만들어진 시각이라 "PoC가 세상에 나온 시점"의 근사치로 쓴다
    (우리가 크롤링으로 확인한 시각과는 무관).

    **반환값 구분**: `[]` 는 "검색은 됐고 결과가 없음", `None` 은 "검색 자체가 실패"
    (rate limit, 네트워크 오류 등). 둘을 섞으면 일시적 장애를 'PoC 없음'으로 오판해
    후보를 헛되이 소진하거나 감사에서 거짓 경보를 낸다.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(
            SEARCH_URL,
            params={
                "q": f"{cve_id} in:name,description",
                "sort": "stars",
                "order": "desc",
                "per_page": max_results,
            },
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return None          # rate limit / 서버 오류 — '결과 없음'과 구분
        items = resp.json().get("items", [])
        return [
            {
                "url": it["html_url"],
                "full_name": it["full_name"],
                "stars": it.get("stargazers_count", 0),
                "description": it.get("description") or "",
                "created_at": it.get("created_at"),
                "pushed_at": it.get("pushed_at"),
            }
            for it in items
            if mentions_cve(cve_id, it["full_name"], it.get("description") or "")
        ]
    except requests.RequestException:
        return None              # 네트워크 오류 — '결과 없음'과 구분


def earliest_poc_date(repos: list[dict]) -> Optional[str]:
    """PoC 저장소들 중 가장 먼저 만들어진 것의 생성일(YYYY-MM-DD). 없으면 None.

    "PoC가 실제로 세상에 나온 시점"의 근사치. 우리가 크롤링으로 확인한 날짜와는 무관하다.
    """
    dates = [r["created_at"][:10] for r in repos if r.get("created_at")]
    return min(dates) if dates else None


def rate_limit_delay(token: Optional[str]) -> float:
    """Search API 호출 사이 대기 시간(초). 인증시 30회/분, 미인증시 10회/분 기준에 여유를 둠."""
    return 2.2 if token else 6.5


# ── 외부 PoC 인덱스 (1순위 조회 경로) ────────────────────────────────────────
#
# GitHub Search API 30회/분이 이 프로젝트의 유일한 병목이라, 후보 1,400건을 하나씩
# 검색하면 그것만으로 50분이 넘는다. nomi-sec/PoC-in-GitHub 은 같은 매핑을
# CVE 별 JSON 으로 공개하고 있어(CC0-1.0, 퍼블릭 도메인 헌정) 트리 조회 1회로
# "PoC 가 존재하는 CVE" 전체 집합을 받을 수 있다. 그러면 대부분의 후보는 네트워크
# 호출 없이 '없음' 판정이 나고, 적중한 것만 상세를 받으면 된다 (실측 51분 -> 5초).
#
# 실측 일치율 98% (우리가 직접 검색으로 승격한 40건 중 39건이 인덱스에도 존재).
# 다만 저쪽이 멈추거나 놓치는 경우가 있으므로 **실패하면 기존 검색으로 되돌아간다**.
# 의존은 최적화일 뿐 단일 실패점이 되어서는 안 된다.

POC_INDEX_REPO = "nomi-sec/PoC-in-GitHub"
POC_INDEX_TREE = f"https://api.github.com/repos/{POC_INDEX_REPO}/git/trees/master?recursive=1"
POC_INDEX_RAW = f"https://raw.githubusercontent.com/{POC_INDEX_REPO}/master/{{year}}/{{cve}}.json"


def fetch_poc_index(token: Optional[str]) -> Optional[set]:
    """PoC 가 존재하는 CVE ID 집합을 한 번에 받는다. 실패하면 None (호출부가 폴백)."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(POC_INDEX_TREE, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        payload = resp.json()
        if payload.get("truncated"):
            return None          # 잘렸으면 신뢰할 수 없다 — 폴백
        return {
            node["path"].rsplit("/", 1)[-1][:-5]
            for node in payload.get("tree", [])
            if node["path"].endswith(".json")
        }
    except (requests.RequestException, ValueError, KeyError):
        return None


def lookup_poc_repos(cve_id: str, max_results: int = 3) -> Optional[list[dict]]:
    """인덱스에서 해당 CVE 의 PoC 저장소 목록을 받아 우리 스키마로 변환한다.

    인덱스 데이터에도 mentions_cve() 경계 검사를 그대로 적용한다 — 비용이 없고,
    남의 매칭 기준을 검증 없이 신뢰하지 않기 위해서다.
    """
    year = cve_id.split("-")[1] if cve_id.startswith("CVE-") else None
    if not year:
        return None
    try:
        resp = requests.get(POC_INDEX_RAW.format(year=year, cve=cve_id), timeout=15)
        if resp.status_code == 404:
            return []            # 인덱스에 없음 = PoC 없음
        if resp.status_code != 200:
            return None
        items = resp.json()
    except (requests.RequestException, ValueError):
        return None

    repos = [
        {
            "url": it.get("html_url"),
            "full_name": it.get("full_name"),
            "stars": it.get("stargazers_count", 0),
            "description": it.get("description") or "",
            "created_at": it.get("created_at"),
            "pushed_at": it.get("pushed_at"),
        }
        for it in items
        if it.get("full_name")
        and mentions_cve(cve_id, it.get("full_name"), it.get("description") or "")
    ]
    repos.sort(key=lambda r: r["stars"], reverse=True)
    return repos[:max_results]


# ── 역방향 스윕 (신규 PoC 실시간 포착) ───────────────────────────────────────
#
# 지금까지는 후보마다 "이 CVE 에 PoC 가 있나?" 를 물었다(O(후보 수) = 하루 1,400 쿼리).
# 질문을 뒤집으면 "최근 새로 생긴 CVE 이름 저장소가 뭔가?" 가 되고, 이건 하루 수십 건뿐이라
# 쿼리 1~2 회로 끝난다. PoC 저장소는 하루 수십 개 생기는데 후보는 수천 개라, 적은 쪽을
# 세는 것이 맞다.
#
# 외부 인덱스(nomi-sec)는 6시간 주기로 갱신되므로 최대 6시간 지연이 있다. 이 스윕이
# 그 구간을 메운다. 반대로 스윕은 과거를 못 본다 — GitHub 검색이 1,000건까지만 페이징돼서
# 누적분 조회가 불가능하다. 그래서 둘을 함께 쓴다: 과거는 인덱스, 신규는 스윕.
#
# 한계: 저장소 **이름**에 CVE 가 있는 것만 잡힌다. 설명에만 적은 것은 정방향 검색
# (in:name,description) 이라야 잡히므로, 스윕은 보강이지 대체가 아니다.

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def sweep_recent_poc_repos(token: Optional[str], since_date: str,
                           max_pages: int = 3) -> Optional[dict]:
    """since_date 이후 생성된 CVE 이름 저장소를 훑어 {CVE ID: [repo, ...]} 로 반환.

    실패하면 None (호출부가 무시하고 다른 경로로 진행). since_date 는 YYYY-MM-DD.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    out: dict[str, list[dict]] = {}
    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(
                SEARCH_URL,
                params={"q": f"CVE in:name created:>{since_date}",
                        "per_page": 100, "page": page},
                headers=headers, timeout=20,
            )
            if resp.status_code != 200:
                return out or None
            items = resp.json().get("items", [])
        except (requests.RequestException, ValueError):
            return out or None

        for it in items:
            name = it.get("full_name") or ""
            desc = it.get("description") or ""
            repo = {
                "url": it.get("html_url"),
                "full_name": name,
                "stars": it.get("stargazers_count", 0),
                "description": desc,
                "created_at": it.get("created_at"),
                "pushed_at": it.get("pushed_at"),
            }
            for cve_id in {m.upper() for m in _CVE_RE.findall(name)}:
                # 경계 검사를 그대로 적용한다 — CVE-2026-3141 검색이 CVE-2026-31413 을
                # 물어오던 사고가 있었고, 여기서도 같은 혼동이 가능하다.
                if mentions_cve(cve_id, name, desc):
                    out.setdefault(cve_id, []).append(repo)

        if len(items) < 100:
            break
        time.sleep(rate_limit_delay(token))

    for repos in out.values():
        repos.sort(key=lambda r: r["stars"], reverse=True)
    return out
