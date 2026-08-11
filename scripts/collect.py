#!/usr/bin/env python3
"""CVE PoC 수집 메인 스크립트.

CVSS>=min-cvss 로 신규 발행된 CVE를 후보 풀(data/.pool.json)에 넣고, 발행일과
무관하게 PoC가 확인될 때까지 스케줄대로 재검사한다. 신규 발행분과 별도로, 과거에
이미 발행된 고심각도 CVE도 하루 backfill-batch-size건씩(CRITICAL→HIGH→MEDIUM 순)
풀에 채워 넣는다 — 그래야 프로젝트 시작 이전에 나온 CVE도 검토 대상이 된다.

PoC 탐지는 두 단계:

  1. NVD lastModified 벌크 조회로 Exploit 레퍼런스 태그가 새로 붙었는지 값싸게 확인
  2. 위에서 못 잡았고 재검사 시점이 된 후보만 GitHub 저장소 검색으로 재확인

PoC가 확인되면 CISA KEV/GHSA 보강 정보를 붙여 data/<year>/<CVE-ID>.md 로 저장하고
풀에서 뺀다. 아카이브 전체에서 CVSS>=high-severity-min-cvss 인 것만 모은 목록을
data/high-severity.md 에 항상 최신 상태로 재생성한다 (발행일/PoC 확인일 무관, 누적).
"""
import argparse
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone

import analysis as analysis_store
import ghsa_client
import kev_client
import manifest as manifest_store
import nvd_client
import pool as pool_store
import render
import state
from ghsa_client import fetch_ghsa_for_cve
from poc_client import (earliest_poc_date, fetch_poc_index, lookup_poc_repos,
                        rate_limit_delay, search_poc_repos, sweep_recent_poc_repos)

PUB_OVERLAP_HOURS = 2
LASTMOD_OVERLAP_HOURS = 2
LASTMOD_DEFAULT_WINDOW_HOURS = 6
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
STUDY_DIR = os.path.join(DATA_DIR, "study")

BACKFILL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]  # 이 순서대로 다 훑고 나면 완료
BACKFILL_PAGE_SIZE = 200
BACKFILL_MAX_PAGES_PER_RUN = 20  # 안전장치: 후보가 희소한 구간에서 무한정 페이지를 넘기지 않도록


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def compute_pub_window(state_data: dict, days_override: int | None) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    if days_override is not None:
        return end - timedelta(days=days_override), end
    last_end = state_data.get("last_pub_end")
    if last_end is None:
        return end - timedelta(days=2), end
    return datetime.fromisoformat(last_end) - timedelta(hours=PUB_OVERLAP_HOURS), end


def compute_lastmod_window(state_data: dict) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    last_end = state_data.get("last_lastmod_end")
    if last_end is None:
        return end - timedelta(hours=LASTMOD_DEFAULT_WINDOW_HOURS), end
    return datetime.fromisoformat(last_end) - timedelta(hours=LASTMOD_OVERLAP_HOURS), end


def ingest_historical_backfill(
    pool: dict, manifest: dict, state_data: dict, api_key: str | None, min_cvss: float, batch_size: int
) -> tuple[list[str], str]:
    """발행일 무관하게 과거 CVE를 CVSS 높은 순(CRITICAL→HIGH→MEDIUM 버킷 순)으로 훑어

    하루 batch_size건씩 후보 풀에 추가한다. NVD가 정확한 CVSS 정렬을 제공하진 않지만
    심각도 버킷 자체가 대략적인 CVSS 내림차순이라 이 정도로도 충분하다. 버킷 내에서는
    커서(startIndex)를 상태 파일에 저장해 이어서 순회한다.
    """
    today = date.today()
    sev_idx = state_data.get("backfill_severity_index", 0)
    cursor = state_data.get("backfill_start_index", 0)
    delay = 0.7 if api_key else 6.5

    added: list[str] = []
    pages_fetched = 0
    while len(added) < batch_size and sev_idx < len(BACKFILL_SEVERITIES) and pages_fetched < BACKFILL_MAX_PAGES_PER_RUN:
        severity = BACKFILL_SEVERITIES[sev_idx]
        items, total = nvd_client.fetch_page({"cvssV3Severity": severity}, cursor, BACKFILL_PAGE_SIZE, api_key)
        pages_fetched += 1
        if pages_fetched > 1:
            time.sleep(delay)

        if not items:
            sev_idx += 1
            cursor = 0
            continue

        cursor += len(items)
        for cve in items:
            if len(added) >= batch_size:
                break
            if cve["cvss_score"] is None or cve["cvss_score"] < min_cvss:
                continue
            if cve["id"] in manifest or cve["id"] in pool:
                continue
            pool_store.add_candidate(pool, cve, today)
            added.append(cve["id"])

        if cursor >= total:
            sev_idx += 1
            cursor = 0

    state_data["backfill_severity_index"] = sev_idx
    state_data["backfill_start_index"] = cursor
    status = BACKFILL_SEVERITIES[sev_idx] if sev_idx < len(BACKFILL_SEVERITIES) else "완료(전체 순회 끝)"
    return added, status


def write_cve_file(cve: dict, markdown: str) -> None:
    year = cve["id"].split("-")[1]
    year_dir = os.path.join(DATA_DIR, year)
    os.makedirs(year_dir, exist_ok=True)
    with open(os.path.join(year_dir, f"{cve['id']}.md"), "w", encoding="utf-8") as f:
        f.write(markdown)


def rebuild_indices(manifest: dict) -> None:
    by_year: dict[str, list[dict]] = {}
    for cve_id, entry in manifest.items():
        year = cve_id.split("-")[1]
        by_year.setdefault(year, []).append({**entry, "id": cve_id})

    for year, entries in by_year.items():
        entries.sort(key=lambda e: e.get("poc_confirmed_date") or "", reverse=True)
        year_dir = os.path.join(DATA_DIR, year)
        os.makedirs(year_dir, exist_ok=True)
        with open(os.path.join(year_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(render.render_year_index(year, entries))

    all_entries = [{**entry, "id": cve_id} for cve_id, entry in manifest.items()]
    all_entries.sort(key=lambda e: e.get("poc_confirmed_date") or "", reverse=True)
    latest = all_entries[:20]

    root_readme = os.path.join(os.path.dirname(__file__), "..", "README.md")
    years_sorted = sorted(by_year.keys(), reverse=True)
    with open(root_readme, "w", encoding="utf-8") as f:
        f.write(render.render_root_readme(latest, years_sorted))


def find_poc(cve_id: str, poc_index: set | None, gh_token: str | None) -> tuple[list | None, bool]:
    """이 CVE 의 PoC 저장소를 찾는다. 반환: (repos, 검색API를 썼는지)

    1순위는 외부 인덱스다 — 트리 조회 1회로 전체 집합을 이미 받아뒀으므로, 집합에
    없으면 네트워크 호출 없이 '없음'이 확정된다. 이게 실행 시간을 50분대에서
    초 단위로 줄이는 핵심이다.
    2순위는 기존 GitHub 검색. 인덱스를 못 받았거나 인덱스 상세 조회가 실패했을 때만
    쓰므로, 외부 의존이 끊겨도 파이프라인은 그대로 돈다.
    """
    if poc_index is not None:
        if cve_id not in poc_index:
            return [], False                  # 인덱스에 없음 = PoC 없음 (호출 0회)
        repos = lookup_poc_repos(cve_id)
        if repos is not None:
            return repos, False
    return search_poc_repos(cve_id, gh_token), True


def ingest_ghsa_candidates(state_data: dict, gh_token: str | None,
                           min_cvss: float, batch_size: int) -> tuple[int, int]:
    """GHSA 를 분석 큐(data/analysis.json)의 공급원으로 쓴다.

    **후보 풀에는 넣지 않는다.** GHSA 참조에는 PoC 가 없어서(실측: Exploit-DB 0%,
    PoC 저장소 링크 0건) 후보 풀에 넣어봐야 PoC 증거는 못 주면서 GitHub 검색 부하만
    늘린다. 대신 패치 커밋은 81% 가 있어(NVD 는 13%) 패치 분석 트랙의 공급원으로는
    NVD 보다 훨씬 낫다.

    패치 참조가 없는 어드바이저리는 건너뛴다 — 뜯어볼 패치가 없으면 우회 분석 자체가
    성립하지 않고, 실제로 그런 항목이 검토 큐의 32% 를 차지해 시간만 쓴 이력이 있다.
    CVSS 가 없는 건은 min_cvss 로 거를 수 없지만 패치가 있으면 분석은 가능하므로 통과시킨다.
    """
    if not gh_token:
        print("[collect] GHSA ingest skipped (GITHUB_TOKEN 없음)", file=sys.stderr)
        return 0, 0

    since = state_data.get("last_ghsa_updated")
    if since is None:
        since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    advisories, last_updated = ghsa_client.fetch_advisories_since(since, gh_token, batch_size)
    analysis = analysis_store.load()
    added = 0
    for adv in advisories:
        if not adv["patch_ref"]:
            continue
        score = adv["cvss_score"]
        if score is not None and score < min_cvss:
            continue
        if adv["key"] in analysis:      # 이미 있으면 손대지 않는다 (사람이 적은 값 보존)
            continue
        entry = dict(analysis_store.DEFAULT_ENTRY)
        entry.update({
            "patch_commit": adv["patch_ref"],
            "title": adv["summary"][:200] or None,
            "package": adv["package"],
        })
        analysis[adv["key"]] = entry
        added += 1

    if last_updated:
        state_data["last_ghsa_updated"] = last_updated
    analysis_store.save(analysis)
    return added, len(advisories)


def sync_analysis(manifest: dict) -> tuple[int, dict]:
    """아카이브에 새로 들어온 CVE의 분석 항목을 만들고, 현황 인덱스를 재생성한다.

    기존 항목은 절대 덮어쓰지 않는다 — 사람이 손으로 적는 파일이라 수집기는 빈 항목만
    추가한다. 값을 고칠 때는 data/analysis.json 을 직접 편집할 것.
    """
    analysis = analysis_store.load()
    added = analysis_store.ensure_entries(analysis, manifest.keys())
    analysis_store.save(analysis)

    # 아카이브에 없는 CVE도 분석 이력은 남긴다 (PoC 미확인이라 승격은 안 됐지만
    # 패치를 뜯어본 기록이 있는 경우). 아카이브 수록분만 파일 링크를 건다.
    entries = []
    for cve_id, entry in analysis.items():
        meta = manifest.get(cve_id) or {}
        # CVE 형식이 아닌 키도 허용한다 — CVE 가 발급되지 않은 자체 발견 건(GHSA 로만
        # 존재하는 것 등)도 추적해야 하므로. 그런 키는 연도를 뽑을 수 없다.
        parts = cve_id.split("-")
        year = parts[1] if cve_id.startswith("CVE-") and len(parts) > 2 else None
        entries.append({
            **entry,
            "id": cve_id,
            "year": year,
            "in_archive": cve_id in manifest and year is not None,
            "cvss_score": meta.get("cvss_score"),
            "cvss_severity": meta.get("cvss_severity"),
        })
    # 미검토 먼저, 그다음 CVSS 높은 순 — 손볼 것이 위로 오게
    entries.sort(key=lambda e: (bool(e.get("reviewed")), -(e.get("cvss_score") or 0)))

    with open(os.path.join(DATA_DIR, "analysis.md"), "w", encoding="utf-8") as f:
        f.write(render.render_analysis_index(
            entries, analysis_store.counts(analysis), analysis_store.reported(analysis)))

    # 출구 A 용 색인. analysis.md 가 "우회를 찾았나" 라면 이쪽은 "원리가 무엇인가" 다.
    with open(os.path.join(DATA_DIR, "mechanisms.md"), "w", encoding="utf-8") as f:
        f.write(render.render_mechanism_index(entries))

    return added, analysis


def audit_archive(manifest: dict, gh_token: str | None, nvd_api_key: str | None) -> tuple[list, list, dict]:
    """아카이브 각 항목의 PoC 근거를 현재 소스 기준으로 다시 확인한다 (쓰기 없음).

    GitHub 검색은 정확 일치가 아니라서 짧은 시퀀스 번호의 CVE가 긴 CVE에 잡아먹힌다
    (CVE-2026-3141 → CVE-2026-31413). 실제로 아카이브의 23%가 이렇게 오염된 적이
    있어서, 사람이 눈으로 발견하기 전에 잡아내려고 둔 검사다.

    반환: (문제 항목, 확인 불가 항목, {cve_id: 유효 repos})
    """
    bad, unknown, evidence = [], [], {}
    for cve_id in sorted(manifest):
        entry = manifest[cve_id]
        source = entry.get("poc_source")

        if source == "github_search":
            repos = search_poc_repos(cve_id, gh_token)
            time.sleep(rate_limit_delay(gh_token))
            if repos is None:
                unknown.append((cve_id, "GitHub 검색 실패"))
                continue
            if not repos:
                bad.append((cve_id, "유효한 PoC 저장소 없음 (오매칭으로 승격된 것으로 보임)"))
                continue
            evidence[cve_id] = repos

        elif source == "nvd_exploit_tag":
            try:
                full = nvd_client.fetch_by_id(cve_id, nvd_api_key)
            except Exception as exc:
                unknown.append((cve_id, f"NVD 조회 실패: {type(exc).__name__}"))
                continue
            time.sleep(1 if nvd_api_key else 6.5)
            if full is None:
                unknown.append((cve_id, "NVD에 없음"))
            elif not full.get("has_exploit_tag"):
                bad.append((cve_id, "NVD Exploit 태그가 더 이상 없음"))

        else:
            unknown.append((cve_id, f"알 수 없는 poc_source: {source!r}"))

    return bad, unknown, evidence


def rerender_archive(manifest: dict, evidence: dict, kev_map: dict,
                     gh_token: str | None, nvd_api_key: str | None) -> tuple[int, list]:
    """아카이브 파일을 현재 소스/렌더 포맷으로 다시 만든다.

    CVE 파일은 승격 시점에 한 번 쓰이고 그 뒤로는 갱신되지 않는다. 렌더 포맷이나
    필드가 바뀌면 기존 파일만 옛 상태로 남으므로, 그때 이걸로 일괄 재생성한다.
    evidence(감사에서 얻은 유효 repos)가 있으면 PoC 목록·공개일도 함께 바로잡는다.
    """
    done, changed = 0, []
    for cve_id in sorted(manifest):
        entry = manifest[cve_id]
        try:
            full = nvd_client.fetch_by_id(cve_id, nvd_api_key)
        except Exception as exc:
            print(f"  {cve_id}: NVD 조회 실패 ({type(exc).__name__}), 건너뜀", file=sys.stderr)
            continue
        time.sleep(1 if nvd_api_key else 6.5)
        if full is None:
            continue

        repos = evidence.get(cve_id, [])
        if entry.get("poc_source") == "github_search" and repos:
            new_published = earliest_poc_date(repos)
            exploit_refs = []
        else:
            new_published = entry.get("poc_published_date")
            exploit_refs = [r["url"] for r in full["references"] if "Exploit" in r["tags"]]

        poc_info = {
            "source": entry.get("poc_source"),
            "repos": repos,
            "nvd_exploit_refs": exploit_refs,
            "confirmed_date": entry.get("poc_confirmed_date"),
            "published_date": new_published,
        }
        markdown = render.render_cve_markdown(
            full, kev_map.get(cve_id), fetch_ghsa_for_cve(cve_id, gh_token), poc_info)
        write_cve_file(full, markdown)

        if entry.get("poc_published_date") != new_published:
            changed.append((cve_id, entry.get("poc_published_date"), new_published))
        entry["poc_published_date"] = new_published
        entry["cvss_score"] = full["cvss_score"]
        entry["cvss_severity"] = full["cvss_severity"]
        entry["published"] = full["published"]
        done += 1
    return done, changed


def write_high_severity_index(manifest: dict, min_cvss: float) -> int:
    entries = [
        {**entry, "id": cve_id, "year": cve_id.split("-")[1]}
        for cve_id, entry in manifest.items()
        if entry.get("cvss_score") and entry["cvss_score"] >= min_cvss
    ]
    entries.sort(key=lambda e: e["cvss_score"], reverse=True)

    path = os.path.join(DATA_DIR, "high-severity.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render.render_high_severity_index(entries))

    return len(entries)


def scan_full_db_for_study(
    today: date,
    need: int,
    delivered: set,
    pool: dict,
    manifest: dict,
    kev_map: dict,
    state_data: dict,
    nvd_api_key: str | None,
    gh_token: str | None,
    poc_index: set | None,
    min_cvss: float,
    scan_limit: int,
) -> list[dict]:
    """NVD 전체 DB를 CVSS 내림차순으로 훑으며 PoC 있는 것만 need건 골라 아카이브로 승격한다.

    발행일과 무관하게 "가장 심각한 것부터" 순서대로 소진하는 별도 트랙. 스캔 위치는
    state_data의 study_severity_index/study_scan_index에 커서로 저장해 매번 이어서 진행하며,
    PoC 없는 것은 커서가 지나가므로 다시 검사하지 않는다(중복 방지).

    CVSS 최상위권이라도 공개 PoC가 없는 경우가 많아 실측 적중률이 ~12% 수준이라,
    need건을 채우려면 보통 수십 건을 검사하게 된다. scan_limit으로 상한을 둔다.
    """
    sev_idx = state_data.get("study_severity_index", 0)
    cursor = state_data.get("study_scan_index", 0)

    selected: list[dict] = []
    checks = 0
    index_cache: dict[str, list[dict]] = {}

    while len(selected) < need and sev_idx < len(BACKFILL_SEVERITIES) and checks < scan_limit:
        severity = BACKFILL_SEVERITIES[sev_idx]
        if severity not in index_cache:
            print(f"[collect] building CVSS-sorted index for {severity} bucket...", file=sys.stderr)
            index_cache[severity] = nvd_client.fetch_severity_index(severity, nvd_api_key)
            print(f"[collect] {severity}: {len(index_cache[severity])} CVEs", file=sys.stderr)
        index = index_cache[severity]

        if cursor >= len(index):
            sev_idx += 1
            cursor = 0
            continue

        entry = index[cursor]
        cursor += 1
        cve_id = entry["id"]

        if entry["cvss_score"] < min_cvss or cve_id in delivered:
            continue

        # 이미 아카이브에 있으면 PoC는 확인된 상태이므로 GitHub 검색 없이 바로 채택
        if cve_id in manifest:
            selected.append({
                **manifest[cve_id],
                "id": cve_id,
                "year": cve_id.split("-")[1],
            })
            continue

        repos, used_search = find_poc(cve_id, poc_index, gh_token)
        checks += 1
        if used_search:
            time.sleep(rate_limit_delay(gh_token))
        if repos is None:
            cursor -= 1          # 검색 실패 — 커서를 되돌려 다음 실행에 다시 본다
            continue
        if not repos:
            continue

        full_cve = nvd_client.fetch_by_id(cve_id, nvd_api_key)
        if full_cve is None:
            continue

        poc_info = {
            "source": "github_search",
            "repos": repos,
            "nvd_exploit_refs": [],
            "confirmed_date": today.isoformat(),
            "published_date": earliest_poc_date(repos),
        }
        kev_entry = kev_map.get(cve_id)
        markdown = render.render_cve_markdown(
            full_cve, kev_entry, fetch_ghsa_for_cve(cve_id, gh_token), poc_info
        )
        write_cve_file(full_cve, markdown)
        manifest[cve_id] = {
            "published": full_cve["published"],
            "cvss_score": full_cve["cvss_score"],
            "cvss_severity": full_cve["cvss_severity"],
            "kev": kev_entry is not None,
            "poc_confirmed_date": poc_info["confirmed_date"],
            "poc_published_date": poc_info.get("published_date"),
            "poc_source": poc_info["source"],
        }
        pool_store.remove(pool, cve_id)
        selected.append({**manifest[cve_id], "id": cve_id, "year": cve_id.split("-")[1]})

    state_data["study_severity_index"] = sev_idx
    state_data["study_scan_index"] = cursor
    print(
        f"[collect] full-DB study scan: {len(selected)} found in {checks} PoC checks "
        f"(cursor: {BACKFILL_SEVERITIES[sev_idx] if sev_idx < len(BACKFILL_SEVERITIES) else 'DONE'}#{cursor})",
        file=sys.stderr,
    )
    return selected


def write_daily_study_batch(
    today: date,
    promotions: list[tuple[dict, dict]],
    pool: dict,
    manifest: dict,
    kev_map: dict,
    state_data: dict,
    nvd_api_key: str | None,
    gh_token: str | None,
    poc_index: set | None,
    min_cvss: float,
    batch_size: int,
    scan_limit: int,
) -> int:
    """오늘 5건(기본)을 뽑아 data/study/<CVE-ID>.md 로 저장한다 (날짜별 파일 아님).

    1순위: 오늘 새로 승격된 것 중 CVSS>=min_cvss
    2순위: 기존 아카이브(manifest)에서 아직 안 뽑힌 것 중 CVSS 높은 순
    3순위: 그래도 모자라면 NVD 전체 DB를 CVSS 내림차순으로 훑어 PoC 있는 것을 찾아 채움
           (이게 실질적으로 매일 5건을 보장하는 소스 — 1·2순위는 초기에 거의 비어 있음)
    한 번 뽑힌 CVE는 state_data["study_delivered"]에 기록해 다시 안 뽑히게 한다.
    """
    delivered = set(state_data.get("study_delivered", []))

    fresh = sorted(
        (
            (cve, poc_info)
            for cve, poc_info in promotions
            if cve["cvss_score"] and cve["cvss_score"] >= min_cvss and cve["id"] not in delivered
        ),
        key=lambda pair: pair[0]["cvss_score"],
        reverse=True,
    )
    selected = [
        {
            "id": cve["id"],
            "year": cve["id"].split("-")[1],
            "cvss_score": cve["cvss_score"],
            "cvss_severity": cve["cvss_severity"],
            "published": cve["published"],
            "poc_confirmed_date": today.isoformat(),
            "poc_published_date": poc_info.get("published_date"),
        }
        for cve, poc_info in fresh[:batch_size]
    ]

    if len(selected) < batch_size:
        need = batch_size - len(selected)
        selected_ids = {e["id"] for e in selected}
        backlog = sorted(
            (
                {**entry, "id": cve_id, "year": cve_id.split("-")[1]}
                for cve_id, entry in manifest.items()
                if entry.get("cvss_score")
                and entry["cvss_score"] >= min_cvss
                and cve_id not in delivered
                and cve_id not in selected_ids
            ),
            key=lambda e: e["cvss_score"],
            reverse=True,
        )
        selected.extend(backlog[:need])

    if len(selected) < batch_size:
      try:
        scanned = scan_full_db_for_study(
            today,
            batch_size - len(selected),
            delivered | {e["id"] for e in selected},
            pool,
            manifest,
            kev_map,
            state_data,
            nvd_api_key,
            gh_token,
            poc_index,
            min_cvss,
            scan_limit,
        )
        selected.extend(scanned)
      except Exception as exc:
        # 전체 DB 스캔은 NVD 의존이라 장애 시 실패할 수 있다. 이번 회차 배분만
        # 모자라게 끝내고, 커서는 scan_full_db_for_study 안에서 전진하지 않는다.
        print(f"[collect] study full-DB scan FAILED ({type(exc).__name__}: {exc})", file=sys.stderr)

    delivered.update(e["id"] for e in selected)
    state_data["study_delivered"] = sorted(delivered)

    os.makedirs(STUDY_DIR, exist_ok=True)
    for entry in selected:
        with open(os.path.join(STUDY_DIR, f"{entry['id']}.md"), "w", encoding="utf-8") as f:
            f.write(render.render_study_entry(entry))

    all_delivered = sorted(
        (
            {**manifest[cve_id], "id": cve_id, "year": cve_id.split("-")[1]}
            for cve_id in delivered
            if cve_id in manifest
        ),
        key=lambda e: e.get("poc_confirmed_date") or "",
        reverse=True,
    )
    with open(os.path.join(STUDY_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(render.render_study_index(all_delivered))

    return len(selected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=None, help="상태 파일 무시하고 최근 N일치 신규 CVE 강제 유입")
    parser.add_argument("--min-cvss", type=float, default=render.MIN_CVSS)
    parser.add_argument("--high-severity-min-cvss", type=float, default=render.HIGH_SEVERITY_MIN_CVSS)
    parser.add_argument("--study-batch-size", type=int, default=render.STUDY_BATCH_SIZE)
    parser.add_argument("--backfill-batch-size", type=int, default=5, help="하루에 후보 풀로 유입할 과거 CVE 건수 (CVSS 높은 순)")
    parser.add_argument("--sweep-days", type=int, default=3,
                        help="역방향 스윕이 훑을 신규 저장소 생성일 범위(일). 실행 주기보다 넉넉히")
    parser.add_argument("--ghsa-batch-size", type=int, default=50,
                        help="한 실행당 GHSA 에서 분석 큐로 유입할 어드바이저리 상한")
    parser.add_argument("--study-scan-limit", type=int, default=300, help="공부용 5건을 채우려고 전체 DB를 훑을 때의 PoC 검사 횟수 상한")
    parser.add_argument("--max-github-checks", type=int, default=1800, help="한 실행당 GitHub 검색 호출 상한 (rate limit 안전장치)")
    parser.add_argument("--verify", action="store_true",
                        help="아카이브 PoC 근거를 재확인만 하고 종료 (쓰기 없음). 문제 발견 시 종료코드 1")
    parser.add_argument("--rerender", action="store_true",
                        help="아카이브 파일을 현재 소스/포맷으로 다시 생성. --verify와 함께 쓰면 오매칭 정리 후 재생성")
    args = parser.parse_args()

    nvd_api_key = os.environ.get("NVD_API_KEY")
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if args.verify or args.rerender:
        manifest = manifest_store.load()
        print(f"[verify] 아카이브 {len(manifest)}건 검사 중...", file=sys.stderr)
        bad, unknown, evidence = audit_archive(manifest, gh_token, nvd_api_key)

        for cve_id, why in bad:
            print(f"  [문제] {cve_id}: {why}", file=sys.stderr)
        for cve_id, why in unknown:
            print(f"  [확인불가] {cve_id}: {why}", file=sys.stderr)
        print(f"[verify] 정상 {len(manifest)-len(bad)-len(unknown)} / 문제 {len(bad)} / 확인불가 {len(unknown)}",
              file=sys.stderr)

        if args.rerender:
            kev_map = kev_client.fetch_kev()
            done, changed = rerender_archive(manifest, evidence, kev_map, gh_token, nvd_api_key)
            for cve_id, old, new in changed:
                print(f"  [정정] {cve_id}: PoC 공개일 {old} -> {new}", file=sys.stderr)
            manifest_store.save(manifest)
            rebuild_indices(manifest)
            write_high_severity_index(manifest, args.high_severity_min_cvss)
            sync_analysis(manifest)
            print(f"[rerender] {done}건 재생성, 날짜 정정 {len(changed)}건", file=sys.stderr)

        # 확인불가는 일시적 장애일 수 있으므로 실패로 치지 않는다
        sys.exit(1 if bad else 0)

    today = date.today()
    state_data = state.load()
    pool = pool_store.load()
    manifest = manifest_store.load()

    # 각 단계는 독립적으로 실패할 수 있다. NVD 가 잠깐 죽으면(2026-08-08 실제 발생)
    # 한 단계 예외로 일일 실행 전체가 날아가므로, 단계별로 격리하고 **실패한 단계의
    # 커서는 전진시키지 않는다** — 전진시키면 그 구간을 영영 건너뛴다.
    failed_stages: list[str] = []

    # 1) 신규 후보 유입 (발행일 기준, CVSS>=min-cvss)
    pub_start, pub_end = compute_pub_window(state_data, args.days)
    print(f"[collect] pub window: {_iso(pub_start)} ~ {_iso(pub_end)}", file=sys.stderr)
    added = 0
    try:
        new_cves = nvd_client.fetch_by_published(_iso(pub_start), _iso(pub_end), api_key=nvd_api_key)
        for cve in new_cves:
            if cve["cvss_score"] is None or cve["cvss_score"] < args.min_cvss:
                continue
            if cve["id"] in manifest or cve["id"] in pool:
                continue
            pool_store.add_candidate(pool, cve, today)
            added += 1
        state_data["last_pub_end"] = _iso(pub_end)   # 성공했을 때만 전진
        print(f"[collect] +{added} new candidates (pool size: {len(pool)})", file=sys.stderr)
    except Exception as exc:
        failed_stages.append("ingest")
        print(f"[collect] ingest FAILED ({type(exc).__name__}: {exc}); 창 유지, 다음 실행에 재시도",
              file=sys.stderr)

    # 1b) 과거 고심각도 CVE도 하루 N건씩 CVSS 높은 순으로 풀에 유입 (발행일 무관 백필)
    try:
        backfilled, backfill_status = ingest_historical_backfill(
            pool, manifest, state_data, nvd_api_key, args.min_cvss, args.backfill_batch_size
        )
        print(f"[collect] +{len(backfilled)} historical candidates (severity cursor: {backfill_status})", file=sys.stderr)
    except Exception as exc:
        failed_stages.append("backfill")
        print(f"[collect] backfill FAILED ({type(exc).__name__}: {exc})", file=sys.stderr)

    # 2) lastModified 벌크 조회로 Exploit 태그 새로 붙은 후보 값싸게 탐지
    lm_start, lm_end = compute_lastmod_window(state_data)
    print(f"[collect] lastmod window: {_iso(lm_start)} ~ {_iso(lm_end)}", file=sys.stderr)
    modified = []
    try:
        modified = nvd_client.fetch_by_last_modified(_iso(lm_start), _iso(lm_end), api_key=nvd_api_key)
        state_data["last_lastmod_end"] = _iso(lm_end)    # 성공했을 때만 전진
    except Exception as exc:
        failed_stages.append("lastmod-scan")
        print(f"[collect] lastmod scan FAILED ({type(exc).__name__}: {exc}); 창 유지", file=sys.stderr)

    promotions: list[tuple[dict, dict]] = []
    resolved_ids: set[str] = set()
    for cve in modified:
        if cve["id"] in pool and cve["has_exploit_tag"]:
            exploit_refs = [r["url"] for r in cve["references"] if "Exploit" in r["tags"]]
            poc_info = {
                "source": "nvd_exploit_tag",
                "repos": [],
                "nvd_exploit_refs": exploit_refs,
                "confirmed_date": today.isoformat(),
                "published_date": None,  # NVD 레퍼런스는 게시 시각 정보가 없음
            }
            promotions.append((cve, poc_info))
            resolved_ids.add(cve["id"])
            pool_store.remove(pool, cve["id"])
    print(f"[collect] {len(resolved_ids)} resolved via NVD Exploit tag", file=sys.stderr)

    # 2b) 역방향 스윕 — 최근 새로 생긴 CVE 이름 저장소를 훑어 풀과 대조한다.
    # 후보마다 묻는 대신 신규 저장소 쪽을 세는 것이라 쿼리 1~2 회로 끝나고, 외부
    # 인덱스의 최대 6시간 지연을 메운다. 재검사 시점과 무관하게 즉시 승격시킨다.
    sweep_since = (datetime.now(timezone.utc) - timedelta(days=args.sweep_days)).strftime("%Y-%m-%d")
    sweep = sweep_recent_poc_repos(gh_token, sweep_since)
    swept = 0
    if sweep is None:
        print("[collect] 역방향 스윕 실패 — 건너뜀", file=sys.stderr)
    else:
        for cve_id, repos in sweep.items():
            if cve_id in manifest or cve_id not in pool or cve_id in resolved_ids:
                continue
            poc_info = {
                "source": "github_search",
                "repos": repos[:3],
                "nvd_exploit_refs": [],
                "confirmed_date": today.isoformat(),
                "published_date": earliest_poc_date(repos),
            }
            promotions.append((pool[cve_id]["cve"], poc_info))
            resolved_ids.add(cve_id)
            pool_store.remove(pool, cve_id)
            swept += 1
        print(f"[collect] 역방향 스윕: 신규 저장소에서 CVE {len(sweep)}개 발견, "
              f"풀과 대조해 {swept}건 즉시 승격", file=sys.stderr)

    # 3) 나머지 재검사 대상은 GitHub 저장소 검색
    poc_index = fetch_poc_index(gh_token)
    if poc_index is None:
        print("[collect] PoC 인덱스 조회 실패 — GitHub 검색으로 폴백", file=sys.stderr)
    else:
        print(f"[collect] PoC 인덱스 {len(poc_index):,}개 CVE 확보 (검색 API 절약)", file=sys.stderr)

    due = [cid for cid in pool_store.due_today(pool, today) if cid not in resolved_ids]
    checked = 0
    searched = 0
    github_resolved = 0
    dropped = 0
    search_failed = 0
    for cve_id in due:
        if checked >= args.max_github_checks:
            print(f"[collect] hit --max-github-checks={args.max_github_checks}, remaining stay due for next run", file=sys.stderr)
            break
        cve = pool[cve_id]["cve"]
        repos, used_search = find_poc(cve_id, poc_index, gh_token)
        checked += 1
        if used_search:
            searched += 1
            time.sleep(rate_limit_delay(gh_token))   # 검색 API 만 페이싱이 필요

        if repos is None:
            # 검색 자체가 실패(rate limit/네트워크). 'PoC 없음'이 아니므로 체크포인트를
            # 소진시키지 않고 다음 실행에서 같은 시점으로 다시 시도한다.
            search_failed += 1
            continue

        if repos:
            poc_info = {
                "source": "github_search",
                "repos": repos,
                "nvd_exploit_refs": [],
                "confirmed_date": today.isoformat(),
                "published_date": earliest_poc_date(repos),
            }
            promotions.append((cve, poc_info))
            github_resolved += 1
            pool_store.remove(pool, cve_id)
        else:
            if not pool_store.advance_or_drop(pool, cve_id):
                dropped += 1

    print(
        f"[collect] checked {checked}/{len(due)} due candidates via GitHub search "
        f"({github_resolved} resolved, {dropped} gave up, {search_failed} search errors, "
        f"{searched} via search API)",
        file=sys.stderr,
    )

    # 4) 승격된 CVE 렌더링/저장
    kev_map = kev_client.fetch_kev()
    for cve, poc_info in promotions:
        kev_entry = kev_map.get(cve["id"])
        ghsa_entry = fetch_ghsa_for_cve(cve["id"], gh_token)
        markdown = render.render_cve_markdown(cve, kev_entry, ghsa_entry, poc_info)
        write_cve_file(cve, markdown)
        manifest[cve["id"]] = {
            "published": cve["published"],
            "cvss_score": cve["cvss_score"],
            "cvss_severity": cve["cvss_severity"],
            "kev": kev_entry is not None,
            "poc_confirmed_date": poc_info["confirmed_date"],
            "poc_published_date": poc_info.get("published_date"),
            "poc_source": poc_info["source"],
        }

    # 5) 공부용 배분 — 3순위 전체 DB 스캔이 새 CVE를 아카이브로 승격시킬 수 있으므로
    #    manifest 저장/인덱스 재생성보다 먼저 돌린다.
    study_count = write_daily_study_batch(
        today,
        promotions,
        pool,
        manifest,
        kev_map,
        state_data,
        nvd_api_key,
        gh_token,
        poc_index,
        args.high_severity_min_cvss,
        args.study_batch_size,
        args.study_scan_limit,
    )

    manifest_store.save(manifest)
    rebuild_indices(manifest)
    high_severity_count = write_high_severity_index(manifest, args.high_severity_min_cvss)
    ghsa_added, ghsa_seen = ingest_ghsa_candidates(
        state_data, gh_token, args.min_cvss, args.ghsa_batch_size)
    print(f"[collect] GHSA: {ghsa_seen} advisories seen, +{ghsa_added} to analysis queue",
          file=sys.stderr)
    analysis_added, analysis = sync_analysis(manifest)
    pending = analysis_store.counts(analysis)["pending"]

    pool_store.save(pool)
    state.save(state_data)

    print(
        f"[collect] promoted {len(promotions)} CVEs today; pool size now {len(pool)}; "
        f"archive total {len(manifest)}; high-severity list {high_severity_count}; "
        f"study batch today {study_count}; analysis stubs +{analysis_added} ({pending} pending review)",
        file=sys.stderr,
    )

    # 일부 단계가 실패해도 나머지 결과는 저장·커밋되게 두되, 워크플로에는 알린다.
    if failed_stages:
        print(f"[collect] 실패한 단계: {', '.join(failed_stages)} (커서 유지, 다음 실행에 재시도)",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
