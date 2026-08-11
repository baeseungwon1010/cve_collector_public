"""수집 파이프라인의 마지막 실행 시각 등을 기록/조회한다 (증분 수집용)."""
import json
import os

STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", ".state.json")


def load() -> dict:
    if not os.path.exists(STATE_PATH):
        return {}
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
