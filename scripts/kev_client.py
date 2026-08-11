"""CISA Known Exploited Vulnerabilities(KEV) 카탈로그 클라이언트."""
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> dict[str, dict]:
    """cveID -> KEV 항목 dict. 실패 시 빈 dict 반환 (필수 소스가 아니므로 전체 실패시키지 않음)."""
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return {v["cveID"]: v for v in vulns}
    except requests.RequestException:
        return {}
