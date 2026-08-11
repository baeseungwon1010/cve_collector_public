"""수집된 CVE 데이터를 우리 형식의 Markdown으로 렌더링한다."""
from datetime import datetime, timezone

MAX_REFERENCES = 8
MIN_CVSS = 6.0
HIGH_SEVERITY_MIN_CVSS = 8.0
STUDY_BATCH_SIZE = 5


def _fmt_date(iso: str | None) -> str:
    if not iso:
        return "-"
    return iso.split("T")[0]


def _severity_emoji(severity: str | None) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get((severity or "").upper(), "⚪")


def render_cve_markdown(cve: dict, kev: dict | None, ghsa: dict | None, poc: dict) -> str:
    """poc: {"source", "repos", "nvd_exploit_refs", "confirmed_date"(우리가 확인한 날),
    "published_date"(PoC 저장소가 실제로 만들어진 날 — 표시용은 이쪽)}"""
    cve_id = cve["id"]
    score = cve["cvss_score"]
    severity = cve["cvss_severity"] or "UNKNOWN"
    vector = cve["cvss_vector"] or "-"
    version = cve["cvss_version"] or "-"

    lines = [f"# {cve_id}", ""]

    lines.append("| 항목 | 내용 |")
    lines.append("|---|---|")
    lines.append(f"| CVSS 점수 | {_severity_emoji(severity)} **{score}** ({severity}) |")
    lines.append(f"| CVSS 벡터 | `{vector}` (v{version}) |")
    lines.append(f"| 발행일 | {_fmt_date(cve['published'])} |")
    lines.append(f"| PoC 공개일 | {poc.get('published_date') or '-'} |")

    if kev:
        ransomware = kev.get("knownRansomwareCampaignUse", "Unknown")
        lines.append(
            f"| CISA KEV | ✅ 실제 악용 확인됨 (등재일: {kev.get('dateAdded', '-')}, "
            f"랜섬웨어 연계: {ransomware}) |"
        )
    else:
        lines.append("| CISA KEV | — 등재되지 않음 |")

    if cve["cwe_ids"]:
        lines.append(f"| CWE | {', '.join(cve['cwe_ids'])} |")

    if cve["products"]:
        shown = cve["products"][:10]
        more = f" 외 {len(cve['products']) - 10}건" if len(cve["products"]) > 10 else ""
        lines.append(f"| 영향받는 제품 | {', '.join(shown)}{more} |")

    lines.append("")
    lines.append("## 설명")
    lines.append("")
    lines.append(cve["description"] or "(설명 없음)")

    lines.append("")
    lines.append("## PoC")
    lines.append("")
    repos = poc.get("repos") or []
    exploit_refs = poc.get("nvd_exploit_refs") or []
    if repos:
        for r in repos:
            created = f" (생성 {r['created_at'][:10]})" if r.get("created_at") else ""
            desc = f" — {r['description']}" if r.get("description") else ""
            lines.append(f"- [{r['full_name']}]({r['url']}) ⭐{r['stars']}{created}{desc}")
    if exploit_refs:
        for url in exploit_refs:
            lines.append(f"- (NVD Exploit 레퍼런스) {url}")
    if not repos and not exploit_refs:
        lines.append("(상세 링크 없음)")

    if ghsa:
        lines.append("")
        lines.append("## GitHub Advisory")
        lines.append("")
        if ghsa.get("summary"):
            lines.append(ghsa["summary"])
        if ghsa.get("permalink"):
            lines.append("")
            lines.append(f"- [GHSA 상세]({ghsa['permalink']})")

    lines.append("")
    lines.append("## 참고 자료")
    lines.append("")
    lines.append(f"- [NVD 상세](https://nvd.nist.gov/vuln/detail/{cve_id})")
    for ref in cve["references"][:MAX_REFERENCES]:
        lines.append(f"- {ref['url']}")

    lines.append("")
    lines.append("---")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"*자동 수집됨 (NVD/CISA KEV/GitHub Advisories/GitHub Search) — 마지막 갱신: {now}*")
    lines.append("")

    return "\n".join(lines)


def render_year_index(year: str, entries: list[dict]) -> str:
    """entries: {id, published, cvss_score, cvss_severity, poc_published_date} 리스트, 수집 최신순."""
    lines = [f"# {year}년 CVE 목록", "", f"총 {len(entries)}건 (CVSS ≥ {MIN_CVSS}, PoC 확인됨)", ""]
    lines.append("| CVE | CVSS | 발행일 | PoC 공개일 |")
    lines.append("|---|---|---|---|")
    for e in entries:
        emoji = _severity_emoji(e["cvss_severity"])
        lines.append(
            f"| [{e['id']}]({e['id']}.md) | {emoji} {e['cvss_score']} | "
            f"{_fmt_date(e['published'])} | {e.get('poc_published_date') or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_root_readme(latest_entries: list[dict], years: list[str]) -> str:
    lines = [
        "# CVE 취약점 연구 파이프라인",
        "",
        "PoC가 실제로 확인된 CVE를 매일 자동 수집하고, 거기서 **두 갈래로 나갑니다**.",
        "",
        "```",
        "  수집(자동) ─ 선별(자동) ─┬─ CTF 문제 제작 소재    data/study/, data/high-severity.md",
        "                          └─ 패치 분석 → 우회 발굴 → 벤더 제보",
        "                                              data/analysis.json, reports/",
        "```",
        "",
        "둘 다 1급 목적입니다. 수집은 두 갈래 공통의 입력 단계이고, 실제로 지금까지 보낸",
        "제보 5건 중 3건이 이 아카이브에서 나왔습니다.",
        "",
        "- 데이터 소스: [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [GitHub Advisory Database](https://github.com/advisories), [GitHub 저장소 검색](https://github.com/search)",
        "- 수집 주기: 매일 1회, `0 3 * * *` UTC (GitHub Actions `.github/workflows/collect.yml`)",
        f"- 필터: CVSS ≥ {MIN_CVSS} 이면서 PoC 확인된 것만 저장 (발행일 무관 — 오래된 CVE도 오늘 PoC가 나오면 수집됨)",
        "- 형식: CVE별 Markdown 파일 (`data/<year>/<CVE-ID>.md`)",
        f"- 공부용 전체 목록: CVSS ≥ {HIGH_SEVERITY_MIN_CVSS} 인 전체 아카이브 항목을 `data/high-severity.md`에 항상 최신으로 유지",
        f"- 공부용 일일 배분: 하루 {STUDY_BATCH_SIZE}건씩 중복 없이 `data/study/<CVE-ID>.md`로 배분. 오늘 신규 승격분 → 기존 아카이브 → NVD 전체 DB를 CVSS 내림차순으로 훑어 PoC 있는 것 순으로 채움",
        "",
        "> 이 파일은 `scripts/collect.py` 실행 시 자동 생성/덮어쓰기됩니다. 직접 수정하지 마세요.",
        "",
        "## 동작 방식",
        "",
        "1. NVD에 신규 발행된 CVE(CVSS ≥ 6.0)를 후보 풀(`data/.pool.json`)에 추가",
        "1b. 과거에 이미 발행된 CVE도 CVSS 높은 순(CRITICAL→HIGH→MEDIUM 버킷 순)으로 하루 5건씩 풀에 추가 (발행일 무관 백필, 커서는 상태 파일에 저장)",
        "2. NVD lastModified 벌크 조회로 Exploit 레퍼런스 태그가 새로 붙은 후보를 값싸게 탐지",
        "3. 위에서 못 잡은 후보 중 재검사 시점(발행 후 3/7/14/30/60/90/180/365일)이 된 것을 GitHub 저장소 검색으로 재확인",
        "4. PoC가 확인되면 CISA KEV/GHSA 보강 정보를 붙여 `data/<year>/<CVE-ID>.md`로 저장하고 풀에서 제거",
        "5. 스케줄을 다 돌았는데도 PoC가 없으면 포기하고 풀에서 제거 (아카이브에는 남지 않음)",
        f"6. 전체 아카이브에서 CVSS ≥ {HIGH_SEVERITY_MIN_CVSS} 인 것만 골라 `data/high-severity.md`를 매번 재생성",
        "6b. GHSA 를 updatedSince 로 증분 조회해 **패치 커밋이 있는 것만** 분석 큐(`data/analysis.json`)에 유입 (후보 풀에는 넣지 않음 — GHSA 에는 PoC 정보가 없음)",
        f"7. 공부용 하루 {STUDY_BATCH_SIZE}건 배분 → `data/study/<CVE-ID>.md`. 1순위 오늘 신규 승격분, 2순위 기존 아카이브,",
        "   3순위 NVD 전체 DB를 CVSS 내림차순으로 훑으며 PoC 있는 것을 찾아 채움(발행일 무관, 커서로 이어서 진행)",
        "",
        "## 로컬 실행",
        "",
        "```bash",
        "pip install -r requirements.txt",
        "cd scripts",
        "python collect.py            # 증분 수집 (상태 파일 기준)",
        "python collect.py --days 3   # 최근 3일치 신규 CVE 강제 유입 (백필)",
        "python collect.py --verify   # 아카이브 PoC 근거 재확인만 (쓰기 없음, 문제 시 종료코드 1)",
        "python collect.py --verify --rerender  # 확인 후 현재 포맷으로 전량 재생성",
        "```",
        "",
        "환경변수:",
        "",
        "- `NVD_API_KEY` (선택): [무료 발급](https://nvd.nist.gov/developers/request-an-api-key). 없으면 rate limit이 낮아짐",
        "- `GITHUB_TOKEN` (권장): GitHub 저장소 검색/Advisory 조회용. 없으면 검색 API 제한이 10회/분으로 낮아져 실행시간이 크게 늘어남. Actions에서는 자동 주입됨",
        "",
        "## 연도별 목록",
        "",
    ]
    for y in years:
        lines.append(f"- [{y}년](data/{y}/README.md)")

    lines.append("")
    lines.append("## 최근 PoC 확인된 CVE")
    lines.append("")
    lines.append("| CVE | CVSS | KEV | 발행일 | PoC 공개일 |")
    lines.append("|---|---|---|---|---|")
    for e in latest_entries:
        emoji = _severity_emoji(e["cvss_severity"])
        kev_mark = "✅" if e.get("kev") else ""
        year = e["published"][:4] if e.get("published") else "unknown"
        lines.append(
            f"| [{e['id']}](data/{year}/{e['id']}.md) | {emoji} {e['cvss_score']} | {kev_mark} | "
            f"{_fmt_date(e['published'])} | {e.get('poc_published_date') or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_study_entry(entry: dict) -> str:
    """entry: {id, year, cvss_score, cvss_severity, published, poc_published_date}.

    날짜별 파일이 아니라 CVE 1건당 1파일 (data/study/<CVE-ID>.md), 아카이브의
    data/<year>/<CVE-ID>.md 와 같은 네이밍 규칙. manifest에서만 뽑으므로
    (=승격된 것만) PoC 확인은 이미 보장됨.
    """
    emoji = _severity_emoji(entry["cvss_severity"])
    lines = [
        f"# {entry['id']}",
        "",
        f"- CVSS: {emoji} **{entry['cvss_score']}** ({entry['cvss_severity']})",
        f"- 발행일: {_fmt_date(entry['published'])}",
        f"- PoC 공개일: {entry.get('poc_published_date') or '-'}",
        f"- 전체 정보: [{entry['id']}](../{entry['year']}/{entry['id']}.md)",
        "",
    ]
    return "\n".join(lines)


def render_study_index(entries: list[dict]) -> str:
    """entries: 지금까지 공부용으로 배분된 CVE 전체 (날짜 무관 누적), 수집 최신순."""
    lines = [
        "# 공부용 CVE 목록",
        "",
        f"CVSS ≥ {HIGH_SEVERITY_MIN_CVSS} & PoC 확인된 CVE를 하루 {STUDY_BATCH_SIZE}건씩, 중복 없이 배분한 누적 기록.",
        "",
        f"총 {len(entries)}건",
        "",
    ]
    lines.append("| CVE | CVSS | 발행일 | PoC 공개일 |")
    lines.append("|---|---|---|---|")
    for e in entries:
        emoji = _severity_emoji(e["cvss_severity"])
        lines.append(
            f"| [{e['id']}]({e['id']}.md) | {emoji} {e['cvss_score']} | "
            f"{_fmt_date(e['published'])} | {e.get('poc_published_date') or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_high_severity_index(entries: list[dict]) -> str:
    """entries: {id, year, cvss_score, cvss_severity, published, poc_published_date} 리스트.

    발행일/PoC 공개일과 무관하게 CVSS >= HIGH_SEVERITY_MIN_CVSS 인 아카이브 전체를
    점수 높은 순으로 모아 보여주는 공부용 목록. 매 실행마다 통째로 재생성된다.
    """
    lines = [
        "# 고심각도 CVE 전체 목록 (공부용)",
        "",
        f"아카이브 전체에서 CVSS ≥ {HIGH_SEVERITY_MIN_CVSS} 인 것만 모은 목록입니다. "
        "발행일/PoC 공개일과 무관하게 계속 누적됩니다. CVSS 점수 높은 순.",
        "",
        f"총 {len(entries)}건",
        "",
    ]
    lines.append("| CVE | CVSS | 발행일 | PoC 공개일 |")
    lines.append("|---|---|---|---|")
    for e in entries:
        emoji = _severity_emoji(e["cvss_severity"])
        lines.append(
            f"| [{e['id']}]({e['year']}/{e['id']}.md) | {emoji} {e['cvss_score']} | "
            f"{_fmt_date(e['published'])} | {e.get('poc_published_date') or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_analysis_index(entries: list[dict], stats: dict, reported: list[dict] | None = None) -> str:
    """entries: {id, year, cvss_score, cvss_severity, **analysis 필드} 리스트.

    분석 진행 현황 보기. data/analysis.json 이 원본이고 이 파일은 그걸 보여주기만
    한다(매 실행 재생성). 값을 고칠 때는 반드시 analysis.json 쪽을 고칠 것.
    """
    mark = {
        "unknown": "❔ 미판정",
        "none": "✅ 없음",
        "suspected": "⚠️ 의심",
        "confirmed": "🔴 확인됨",
        "unreachable": "🚫 도달불가",
        "undeterminable": "⛔ 판정불가",
    }
    lines = [
        "# CVE 분석 진행 현황",
        "",
        "각 CVE를 검토했는지, 패치 우회로 인한 취약점이 있는지 추적합니다.",
        "",
        "> `미판정`은 아직 안 봤거나 트리아지만 한 것, `판정불가`는 봤지만 패치를 볼 방법이",
        "> 없어 판정 자체가 불가능한 것입니다(사유는 각 항목 비고에 있습니다).",
        "**원본은 `data/analysis.json` 입니다. 이 파일은 매 실행 재생성되므로 여기 적지 마세요.**",
        "",
        f"- 전체 {stats['total']}건 / 검토 완료 {stats['reviewed']}건 / 미검토 {stats['pending']}건",
        f"- 우회: 확인됨 {stats['confirmed']}건, 의심 {stats['suspected']}건, "
        f"없음 {stats['none']}건, 도달불가 {stats['unreachable']}건, "
        f"판정불가 {stats['undeterminable']}건, 미판정 {stats['unknown']}건",
        f"- 제보: 발송 {stats['report_submitted']}건, 접수확인 {stats['report_triaged']}건, "
        f"수정완료 {stats['report_fixed']}건, 초안 {stats['report_drafted']}건",
        "",
    ]

    if reported:
        lines += [
            "## 제보 현황",
            "",
            "실제로 벤더에 보낸 건. 상태는 `data/analysis.json` 의 `report_*` 필드가 원본이다.",
            "",
            "| 대상 | 상태 | 채널 | 식별자 | 발송일 | 벤더 심각도 |",
            "|---|---|---|---|---|---|",
        ]
        smark = {"submitted": "📤 발송", "triaged": "🔍 접수확인",
                 "fixed": "✅ 수정완료", "rejected": "❌ 기각"}
        for e in reported:
            lines.append(
                f"| {e['id']} | {smark.get(e.get('report_status'), e.get('report_status'))} | "
                f"{e.get('report_channel') or '-'} | {e.get('report_id') or '-'} | "
                f"{e.get('report_date') or '-'} | {e.get('report_severity') or '-'} |"
            )
        lines.append("")

    def row(e, linked):
        reviewed = f"✔ {e['reviewed_date']}" if e.get("reviewed") else "—"
        if e.get("patch_complete") is True:
            patch = "완전"
        elif e.get("patch_complete") is False:
            patch = "불완전"
        else:
            patch = "—"
        note = e.get("bypass_note") or ""
        if e.get("already_known"):
            note = ("기존 CVE 커버 — " + note).strip(" —")
        # 아직 분석 전이면 bypass_note 가 비어 있다. 그때는 무엇에 대한 건인지가
        # 유일한 단서이므로 title/package 를 대신 보여준다 (GHSA 유입 건은 아카이브
        # 파일도 없어서 이게 없으면 식별자만 남는다).
        if not note:
            bits = [b for b in (e.get("package"), e.get("title")) if b]
            note = " — ".join(bits)
        note = note.replace("|", r"\|")[:110]   # 표 셀이 깨지지 않게 파이프 이스케이프
        bypass = mark.get(e.get("bypass"), e.get("bypass"))
        if linked:
            name = f"[{e['id']}]({e['year']}/{e['id']}.md)"
            cvss = f"{_severity_emoji(e.get('cvss_severity'))} {e.get('cvss_score')}"
            return f"| {name} | {cvss} | {reviewed} | {patch} | {bypass} | {note} |"
        return f"| {e['id']} | {reviewed} | {patch} | {bypass} | {note} |"

    archived = [e for e in entries if e.get("in_archive")]
    external = [e for e in entries if not e.get("in_archive")]

    lines += ["## 아카이브 수록분", "", "| CVE | CVSS | 검토 | 패치 | 우회 | 비고 |", "|---|---|---|---|---|---|"]
    lines += [row(e, True) for e in archived]

    if external:
        lines += [
            "",
            "## 아카이브 외 (조사만 한 것)",
            "",
            "PoC가 확인되지 않아 아카이브에는 없지만 분석 이력이 있는 CVE.",
            "",
            "| CVE | 검토 | 패치 | 우회 | 비고 |",
            "|---|---|---|---|---|",
        ]
        lines += [row(e, False) for e in external]

    lines.append("")
    return "\n".join(lines)


# 문제 유형 라벨. analysis.MECHANISM_CLASSES 와 키가 일치해야 한다.
MECHANISM_LABELS = {
    "path-traversal": "경로 탈출 · 심볼릭 링크",
    "injection": "주입 (명령/SQL/템플릿/인자)",
    "deserialization": "역직렬화 · 타입 혼동",
    "auth-bypass": "인증 · 인가 우회",
    "parser-differential": "파서 해석 차이",
    "resource-exhaustion": "자원 고갈 (ReDoS/폭탄)",
    "memory-safety": "메모리 안전성",
    "crypto-weakness": "암호 오용 · 약한 난수",
    "race-condition": "경쟁 조건 · TOCTOU",
    "info-disclosure": "정보 노출",
    "logic-flaw": "로직 · 상태 오류",
    "ssrf": "SSRF",
    "xss": "출력 인코딩 누락 (XSS)",
}


def render_mechanism_index(entries: list[dict]) -> str:
    """CTF 문제 제작용 소재 색인 (출구 A).

    analysis.json 의 mechanism/mechanism_class 를 유형별로 묶어 보여준다.
    analysis.md 가 "우회를 찾았나"(출구 B) 를 본다면 이 파일은 "이 버그의 원리가
    무엇인가" 를 본다. 매 실행 재생성되므로 여기 적지 말고 analysis.json 을 고칠 것.
    """
    with_mech = [e for e in entries if e.get("mechanism")]
    lines = [
        "# 취약점 원리 색인 (CTF 문제 제작용)",
        "",
        "각 CVE가 **왜 성립하는지**를 유형별로 묶은 목록입니다.",
        "문제를 만들 때 \"경로 탈출 하나 만들자\" 처럼 유형으로 찾으라고 만든 색인입니다.",
        "",
        "> 원본은 `data/analysis.json` 의 `mechanism` / `mechanism_class` 입니다.",
        "> **이 파일은 매 실행 재생성되므로 여기 적지 마세요.**",
        "",
        f"- 원리 기록됨 {len(with_mech)}건 / 전체 {len(entries)}건",
        "",
    ]

    # PoC 가 있는 건이 문제로 만들기 쉬우므로 유형 안에서 위로 올린다.
    by_class: dict[str, list[dict]] = {}
    for e in with_mech:
        by_class.setdefault(e.get("mechanism_class") or "logic-flaw", []).append(e)

    for cls in sorted(by_class, key=lambda c: -len(by_class[c])):
        rows = sorted(
            by_class[cls],
            key=lambda e: (not e.get("in_archive"), -(e.get("cvss_score") or 0)),
        )
        label = MECHANISM_LABELS.get(cls, cls)
        lines += [f"## {label}  ({len(rows)}건)", ""]
        for e in rows:
            score = e.get("cvss_score")
            head = f"### {e['id']}"
            if score:
                head += f"  {_severity_emoji(e.get('cvss_severity'))} {score}"
            if e.get("in_archive"):
                head += "  · 아카이브에 PoC 있음"
            lines += [head, ""]
            if e.get("title"):
                lines += [f"*{e['title']}*", ""]
            lines += [e["mechanism"], ""]
        lines.append("")

    no_mech = [e for e in entries if not e.get("mechanism")]
    if no_mech:
        lines += [
            f"## 원리 미기록 ({len(no_mech)}건)",
            "",
            "아직 `mechanism` 을 안 적은 항목입니다.",
            "",
            ", ".join(sorted(e["id"] for e in no_mech)),
            "",
        ]
    return "\n".join(lines) + "\n"
