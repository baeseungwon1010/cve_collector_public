"""NVD REST API 2.0 클라이언트: 기간 내 CVE를 조회하고 필요한 필드만 추출한다."""
import time
from typing import Optional

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


def _best_cvss(metrics: dict) -> tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    """returns (score, severity, vector, version) preferring v3.1 > v3.0 > v2."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity, vector, version
    return None, None, None, None


def _extract_products(configurations: list) -> list[str]:
    products = set()
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    products.add(f"{vendor}:{product}")
    return sorted(products)


def _parse_item(item: dict) -> dict:
    cve = item["cve"]
    descriptions = cve.get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    score, severity, vector, version = _best_cvss(cve.get("metrics", {}))

    cwe_ids = sorted({
        desc["value"]
        for weakness in cve.get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc["value"].startswith("CWE-")
    })

    references = [
        {"url": ref["url"], "tags": ref.get("tags") or []}
        for ref in cve.get("references", [])
    ]
    has_exploit_tag = any("Exploit" in ref["tags"] for ref in references)

    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": en_desc,
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cvss_version": version,
        "cwe_ids": cwe_ids,
        "products": _extract_products(cve.get("configurations", [])),
        "references": references,
        "has_exploit_tag": has_exploit_tag,
    }


MAX_RETRIES = 4


def _get_with_retry(params: dict, headers: dict, timeout: int = 30) -> dict:
    """NVD 조회 1회분. 일시적 실패는 지수 백오프로 재시도한다.

    NVD 는 부하가 걸리면 읽기 타임아웃이나 503 을 낸다. 재시도가 없으면 그 한 번에
    일일 실행 전체가 죽어버린다 (2026-08-08 실제로 그렇게 하루치를 통째로 날림).
    """
    last_exc = None
    for attempt in range(MAX_RETRIES):
        if attempt:
            time.sleep(min(60, 5 * 2 ** (attempt - 1)))   # 5s, 10s, 20s
        try:
            resp = requests.get(API_URL, params=params, headers=headers, timeout=timeout)
            if resp.status_code in (429, 503, 504):        # 일시적 — 재시도 대상
                last_exc = RuntimeError(f"NVD {resp.status_code}")
                continue
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
    raise last_exc


def _paginated_fetch(extra_params: dict, api_key: Optional[str]) -> list[dict]:
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5

    results: list[dict] = []
    start_index = 0
    while True:
        params = {**extra_params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        payload = _get_with_retry(params, headers)

        for item in payload.get("vulnerabilities", []):
            results.append(_parse_item(item))

        total = payload.get("totalResults", 0)
        start_index += PAGE_SIZE
        if start_index >= total:
            break
        time.sleep(delay)

    return results


def fetch_by_published(start_iso: str, end_iso: str, api_key: Optional[str] = None) -> list[dict]:
    """pubStartDate/pubEndDate 구간에 신규 발행된 CVE를 가져온다 (후보 풀 유입용)."""
    return _paginated_fetch({"pubStartDate": start_iso, "pubEndDate": end_iso}, api_key)


def fetch_by_last_modified(start_iso: str, end_iso: str, api_key: Optional[str] = None) -> list[dict]:
    """lastModStartDate/lastModEndDate 구간에 수정된 CVE를 가져온다.

    새로 Exploit 레퍼런스 태그가 붙은 CVE를 값싸게(벌크 1회 호출) 탐지하는 용도.
    """
    return _paginated_fetch({"lastModStartDate": start_iso, "lastModEndDate": end_iso}, api_key)


def fetch_severity_index(severity: str, api_key: Optional[str] = None) -> list[dict]:
    """해당 심각도 버킷 전체를 훑어 최소 필드만 담은 목록을 CVSS 내림차순으로 반환한다.

    NVD API 2.0은 CVSS 점수 정렬 파라미터를 제공하지 않으므로(심각도 필터만 있음)
    버킷을 통째로 받아 로컬에서 정렬한다. CRITICAL 버킷이 3만여 건이라 2000건씩
    16페이지 남짓이면 다 받아진다. 전체 CVE 객체를 들고 있으면 메모리가 커지므로
    id/점수/발행일만 남기고 버린다.
    """
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5

    out: list[dict] = []
    start_index = 0
    while True:
        params = {"cvssV3Severity": severity, "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        payload = _get_with_retry(params, headers, timeout=60)

        for item in payload.get("vulnerabilities", []):
            cve = item["cve"]
            score, sev, _, _ = _best_cvss(cve.get("metrics", {}))
            if score is None:
                continue
            out.append({
                "id": cve["id"],
                "cvss_score": score,
                "cvss_severity": sev,
                "published": cve.get("published"),
            })

        total = payload.get("totalResults", 0)
        start_index += PAGE_SIZE
        if start_index >= total:
            break
        time.sleep(delay)

    out.sort(key=lambda e: (-e["cvss_score"], e["id"]))
    return out


def fetch_by_id(cve_id: str, api_key: Optional[str] = None) -> Optional[dict]:
    """CVE ID 하나를 조회해 전체 파싱 데이터를 반환 (없으면 None)."""
    items, _ = fetch_page({"cveId": cve_id}, 0, 1, api_key)
    return items[0] if items else None


def fetch_page(
    extra_params: dict, start_index: int, page_size: int, api_key: Optional[str] = None
) -> tuple[list[dict], int]:
    """단일 페이지만 가져온다 (전체 순회 아님). 과거 CVE를 하루 N건씩 야금야금 훑는
    백필용 커서 순회에 쓴다. 반환: (이 페이지의 CVE 목록, 전체 결과 수)."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {**extra_params, "resultsPerPage": page_size, "startIndex": start_index}
    payload = _get_with_retry(params, headers)
    items = [_parse_item(item) for item in payload.get("vulnerabilities", [])]
    return items, payload.get("totalResults", 0)
