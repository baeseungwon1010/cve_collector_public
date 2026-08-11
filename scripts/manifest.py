"""전체 아카이브의 경량 색인 (data/manifest.json) — 인덱스 페이지 재생성에 사용."""
import json
import os

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "manifest.json")


def load() -> dict[str, dict]:
    if not os.path.exists(MANIFEST_PATH):
        return {}
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save(manifest: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
