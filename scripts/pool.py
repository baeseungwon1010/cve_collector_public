"""PoC 미확인 CVE 후보 풀 관리 (data/.pool.json).

CVSS>=min_cvss 로 발행된 CVE를 발행일과 무관하게 계속 보유하면서,
아래 스케줄대로 재검사하다가 PoC가 확인되면 풀에서 빼고 아카이브로 승격,
스케줄을 다 돌았는데도 못 찾으면 포기하고 버린다.
"""
import json
import os
from datetime import date, datetime, timedelta

POOL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", ".pool.json")

# 풀 유입일로부터 재검사까지 걸리는 일수 (누적 아님, 각 체크포인트 시점)
#
# 앞 일주일을 하루 간격으로 촘촘하게 두는 이유: 실측상 CVE 발행에서 PoC 공개까지가
# 대부분 0~4일에 몰려 있다. 이전 스케줄(3/7/14/30/...)은 그 구간에 구멍이 있어서
# 4일째 뜬 PoC 를 7일째에야 잡고, 15일째 뜬 것은 30일째에야 잡았다(실측 최대 17일 지연).
# 앞을 촘촘히 하면 최대 지연이 1일로 줄어든다.
#
# 뒤를 성기게 두는 이유: 오래된 후보는 적중률이 낮아 자주 볼 값이 적고, 체크포인트를
# 늘리면 일일 GitHub 검색 부하가 그대로 비례해 늘어난다(유입 x 단계 수 x 2.2초).
#
# 단계 수는 GitHub Actions 무료 한도(private 저장소 2,000분/월)가 실질 상한이다.
# 실측 유입 135건/일 기준: 8단계 77% / 11단계 100% / 14단계 122% / 16단계 137%.
# 병목인 GitHub Search API 30회/분은 외부 제약이라 못 올리므로, 부하를 더 줄여야 하면
# 단계를 깎기보다 풀 유입 기준(--min-cvss)을 올리는 쪽이 낫다 — 앞 일주일의 촘촘함이
# 이 스케줄의 목적이라 거기를 깎으면 목적 자체가 훼손된다.
CHECK_SCHEDULE_DAYS = [1, 2, 3, 4, 5, 6, 7, 14, 30, 90, 365]


def load() -> dict[str, dict]:
    if not os.path.exists(POOL_PATH):
        return {}
    with open(POOL_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save(pool: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(POOL_PATH), exist_ok=True)
    with open(POOL_PATH, "w", encoding="utf-8") as f:
        json.dump(pool, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def add_candidate(pool: dict[str, dict], cve: dict, today: date) -> None:
    if cve["id"] in pool:
        return
    added = today.isoformat()
    next_check = (today + timedelta(days=CHECK_SCHEDULE_DAYS[0])).isoformat()
    pool[cve["id"]] = {
        "cve": cve,
        "checks_done": 0,
        "added": added,
        "next_check": next_check,
    }


def due_today(pool: dict[str, dict], today: date) -> list[str]:
    return [
        cve_id
        for cve_id, entry in pool.items()
        if datetime.fromisoformat(entry["next_check"]).date() <= today
    ]


def advance_or_drop(pool: dict[str, dict], cve_id: str) -> bool:
    """다음 체크포인트로 넘기거나(True) 스케줄 소진시 풀에서 제거(False).

    체크포인트는 풀에 들어온 날(added) 기준 고정 오프셋이라, 실행이 하루쯤
    밀리거나 당겨져도 스케줄이 누적으로 어긋나지 않는다.
    """
    entry = pool[cve_id]
    entry["checks_done"] += 1
    if entry["checks_done"] >= len(CHECK_SCHEDULE_DAYS):
        del pool[cve_id]
        return False
    added = datetime.fromisoformat(entry["added"]).date()
    offset = CHECK_SCHEDULE_DAYS[entry["checks_done"]]
    entry["next_check"] = (added + timedelta(days=offset)).isoformat()
    return True


def remove(pool: dict[str, dict], cve_id: str) -> None:
    pool.pop(cve_id, None)
