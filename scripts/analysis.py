"""CVE별 분석 추적 (data/analysis.json).

manifest.json 은 수집기가 매 실행마다 다시 쓰는 기계 생성 색인이라, 사람이 손으로
적는 분석 결과를 거기 두면 덮어쓸 위험이 있다. 그래서 파일을 분리한다.

수집기는 이 파일에 **새 CVE의 빈 항목을 추가하기만** 하고, 이미 있는 항목은 절대
건드리지 않는다. 따라서 사람이 적어둔 값은 항상 보존된다.

필드 의미:
  reviewed        분석을 했는지 (사람이 true 로 바꾼다)
  reviewed_date   분석한 날 (YYYY-MM-DD)
  patch_commit    실제 수정 커밋 해시. NVD 참조 링크가 엉뚱한 커밋을 가리키는 경우가
                  있어(FreeRDP CVE-2026-64620 실측) 직접 찾은 것을 여기 적어둔다
  patch_complete  패치가 완전한가. true=완전, false=불완전, null=미판정
  bypass          우회 가능성. 아래 BYPASS_STATES 중 하나
  bypass_note     우회 관련 메모 (경로, 기각 사유 등 자유 서술)
  already_known   이미 다른 CVE/어드바이저리가 커버하는지. 신규라고 판단했다가
                  기존 CVE가 전 버전을 이미 커버하고 있던 사례가 있어 별도 필드로 둔다
  related_cve     자체 발견 건이 어느 CVE 의 우회/파생인지. 우리가 찾은 우회를 원 CVE
                  항목에 얹으면 그 CVE 의 분석 기록과 섞이므로 키를 따로 두고 여기서 잇는다
  title/package   무엇에 대한 건인지. GHSA 로 유입된 건은 아카이브에 CVE 파일이 없어
                  이 두 필드가 아니면 식별자만 남는다
  mechanism       **이 취약점이 왜 성립하는가**를 재현 가능한 수준으로 서술한다.
                  bypass_note 와 목적이 다르다 - bypass_note 는 "이 패치를 뚫을 수 있나"
                  (출구 B) 이고, mechanism 은 "이 버그의 원리가 무엇인가" (출구 A, CTF
                  문제 제작 소재) 다. 오래된 CVE 는 우회 여지가 거의 없어 bypass_note 가
                  비게 되는데, 문제 소재로는 오히려 더 좋으므로 이 필드가 그쪽을 담는다.
                  적을 것: 잘못된 가정 -> 그것을 깨는 입력 -> 그래서 무엇이 되는가.
  mechanism_class 위 원리의 분류 태그. MECHANISM_CLASSES 중 하나. 문제를 만들 때
                  "경로 탈출 문제 하나 만들자" 처럼 유형으로 찾기 위한 것이다

키는 CVE ID 가 아니어도 된다. CVE 미발급 자체 발견 건은 벤더가 준 식별자(GHSA-...)를,
그것도 없으면 서술형 키를 쓴다.
"""
import json
import os
import re

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# 사람이 편집하는 민감 원본(우회 연구·제보 상태). **비공개** — .gitignore 로 가린다.
ANALYSIS_PATH = os.path.join(_DATA_DIR, "analysis.private.json")
# 구버전 단일 파일. 있으면 private 로 1회 마이그레이션한다.
_LEGACY_PATH = os.path.join(_DATA_DIR, "analysis.json")
# 공개 저장소에 커밋해도 되는 투영본. 수집 관련 안전 필드만 담는다.
PUBLIC_PATH = os.path.join(_DATA_DIR, "analysis.public.json")

# 공개본에 내보내도 되는 필드(수집 속성만). bypass/bypass_note/report_*/patch_*/
# mechanism*/reviewed*/already_known/related_cve/title 은 전부 민감이라 제외한다.
PUBLIC_FIELDS = ("package",)
# 공개본은 실제 발급된 CVE 키만 포함한다 — 자체 발견 서술형 키(GHSA-…, CRAFT-…)는
# 그 존재 자체가 미공개 발견을 드러낼 수 있으므로 내보내지 않는다.
_REAL_CVE = re.compile(r"^CVE-\d{4}-\d+$")

# bypass 필드가 가질 수 있는 값
BYPASS_STATES = (
    "unknown",      # 아직 안 봤거나, 트리아지만 하고 심층 분석은 안 함
                    # (reviewed 가 True 면 후자다 - 이유를 bypass_note 에 적는다)
    "none",         # 봤고, 우회 경로 없음
    "suspected",    # 우회 가능해 보이나 미검증
    "confirmed",    # 우회 실증 완료
    "unreachable",  # 코드상 경로는 있으나 공격자 입력이 도달 못 함
    "undeterminable",  # 검토는 했으나 판정 자체가 불가능 - 패치를 볼 수 없다
                       # (폐쇄 소스, 수정 리비전 미특정, 수정이 존재하지 않음, CVE 철회 등).
                       # unknown 과 반드시 구분할 것: unknown 은 "아직 안 봄",
                       # 이건 "봤고, 더 볼 방법이 없음" 이다. 사유를 bypass_note 에 남긴다.
)

# 제보 진행 상태. bypass_note 자유 텍스트에 섞어두면 조회가 안 되고 실제로 여러 번
# 잘못 읽은 이력이 있어 별도 필드로 뺐다.
REPORT_STATES = (
    "not_reported",  # 제보 대상이지만 아직 안 보냄
    "drafted",       # 보고서는 썼고 발송 전
    "submitted",     # 보냄, 벤더 응답 대기
    "triaged",       # 벤더가 접수·검토 중임을 확인
    "fixed",         # 수정본 배포됨
    "rejected",      # 벤더가 취약점 아님으로 판단
    "n/a",           # 제보 대상 아님 (기존 CVE가 커버, 폐쇄형이라 분석 불가 등)
)

# mechanism_class 가 가질 수 있는 값. 문제 유형으로 소재를 찾기 위한 분류라
# CWE 처럼 촘촘하지 않고, "만들 문제의 모양" 기준으로 굵게 나눈다.
MECHANISM_CLASSES = (
    "path-traversal",     # 경로 탈출/심볼릭 링크/컨테인먼트
    "injection",          # 명령·SQL·템플릿·인자 주입
    "deserialization",    # 역직렬화/가젯 체인/타입 혼동
    "auth-bypass",        # 인증·인가 누락 및 우회
    "parser-differential",# 두 파서의 해석 차이 (URL/헤더/인코딩)
    "resource-exhaustion",# ReDoS/폭탄/무제한 할당
    "memory-safety",      # UAF/오버플로/경계 오류
    "crypto-weakness",    # 약한 난수·비교·프리미티브 오용
    "race-condition",     # TOCTOU/동시성
    "info-disclosure",    # 정보 노출 (위 어디에도 안 맞을 때)
    "logic-flaw",         # 상태 기계·순서·전제 오류
    "ssrf",               # 서버측 요청 위조
    "xss",                # 출력 인코딩 누락
)

DEFAULT_ENTRY = {
    "reviewed": False,
    "reviewed_date": None,
    "patch_commit": None,
    "patch_complete": None,
    "bypass": "unknown",
    "bypass_note": None,
    "already_known": None,
    "report_status": "not_reported",
    "report_channel": None,   # GHSA | email | hackerone | tidelift | ...
    "report_id": None,        # GHSA-xxxx-xxxx-xxxx 등 벤더가 부여한 식별자
    "report_date": None,      # 발송일 YYYY-MM-DD
    "report_severity": None,  # 벤더가 매긴 심각도 (우리가 주장한 값이 아님)
    "related_cve": None,      # 이 건이 어느 CVE 의 우회/파생인지 (자체 발견 건에서 씀)
    "title": None,            # 한 줄 설명. GHSA 유입 건은 아카이브 파일이 없어 이게 유일한 단서
    "package": None,          # 생태계:패키지명 (예: NPM:express)
    "mechanism": None,        # 원리 서술 (출구 A: CTF 문제 제작 소재)
    "mechanism_class": None,  # MECHANISM_CLASSES 중 하나
}


def load() -> dict[str, dict]:
    # private 가 우선. 없고 구버전 analysis.json 만 있으면 그걸 읽어(1회 마이그레이션은
    # 다음 save 에서 private 로 기록된다).
    path = ANALYSIS_PATH if os.path.exists(ANALYSIS_PATH) else _LEGACY_PATH
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _public_projection(analysis: dict[str, dict]) -> dict[str, dict]:
    """공개 저장소용 안전 투영본. 실제 CVE 키만, 수집 안전 필드만."""
    out = {}
    for key, entry in analysis.items():
        if not _REAL_CVE.match(key):
            continue  # 자체 발견 서술형 키는 공개본에서 제외
        safe = {f: entry.get(f) for f in PUBLIC_FIELDS if entry.get(f) is not None}
        if safe:
            out[key] = safe
    return out


def write_public(analysis: dict[str, dict]) -> None:
    """analysis.public.json (공개 커밋용) 재생성. save() 가 자동 호출한다."""
    with open(PUBLIC_PATH, "w", encoding="utf-8") as f:
        json.dump(_public_projection(analysis), f, indent=2, sort_keys=True,
                  ensure_ascii=False)
        f.write("\n")


def save(analysis: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(ANALYSIS_PATH), exist_ok=True)
    with open(ANALYSIS_PATH, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    # 민감 원본을 쓸 때마다 공개 투영본도 같이 갱신한다.
    write_public(analysis)


def ensure_entries(analysis: dict[str, dict], cve_ids) -> int:
    """아카이브에 있는 CVE 중 아직 항목이 없는 것만 기본값으로 추가한다.

    기존 항목은 값이 무엇이든 손대지 않는다(사람이 적은 내용 보존). 새 필드가
    나중에 추가된 경우에만 그 필드의 기본값을 채워 넣는다.
    반환값: 새로 추가한 CVE 수.
    """
    added = 0
    for cve_id in cve_ids:
        if cve_id not in analysis:
            analysis[cve_id] = dict(DEFAULT_ENTRY)
            added += 1

    # 새 필드가 추가됐을 때의 보충은 **전체 항목**에 대해 한다. 아카이브 밖 항목
    # (자체 발견 건 등)은 cve_ids 에 안 들어오므로, 여기서 따로 돌지 않으면
    # 그 항목들만 옛 스키마로 남는다.
    for entry in analysis.values():
        for key, default in DEFAULT_ENTRY.items():
            entry.setdefault(key, default)
    return added


def counts(analysis: dict[str, dict]) -> dict[str, int]:
    """진행 현황 집계 (인덱스 렌더링용)."""
    out = {"total": len(analysis), "reviewed": 0, "pending": 0}
    for state in BYPASS_STATES:
        out[state] = 0
    for state in REPORT_STATES:
        out[f"report_{state}"] = 0
    for entry in analysis.values():
        if entry.get("reviewed"):
            out["reviewed"] += 1
        else:
            out["pending"] += 1
        state = entry.get("bypass", "unknown")
        if state in out:
            out[state] += 1
        rkey = f"report_{entry.get('report_status', 'not_reported')}"
        if rkey in out:
            out[rkey] += 1
    return out


def reported(analysis: dict[str, dict]) -> list[dict]:
    """실제로 벤더에 보낸 건만 발송일 최신순으로. 제보 현황 표용."""
    rows = [
        {**e, "id": k}
        for k, e in analysis.items()
        if e.get("report_status") in ("submitted", "triaged", "fixed", "rejected")
    ]
    rows.sort(key=lambda e: e.get("report_date") or "", reverse=True)
    return rows
