# CVE 취약점 연구 파이프라인

PoC가 실제로 확인된 CVE를 매일 자동 수집하고, 거기서 **두 갈래로 나갑니다**.

```
  수집(자동) ─ 선별(자동) ─┬─ CTF 문제 제작 소재    data/study/, data/high-severity.md
                          └─ 패치 분석 → 우회 발굴 → 벤더 제보
                                              data/analysis.json, reports/
```

둘 다 1급 목적입니다. 수집은 두 갈래 공통의 입력 단계이고, 실제로 지금까지 보낸
제보 5건 중 3건이 이 아카이브에서 나왔습니다.

- 데이터 소스: [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [GitHub Advisory Database](https://github.com/advisories), [GitHub 저장소 검색](https://github.com/search)
- 수집 주기: 매일 1회, `0 3 * * *` UTC (GitHub Actions `.github/workflows/collect.yml`)
- 필터: CVSS ≥ 6.0 이면서 PoC 확인된 것만 저장 (발행일 무관 — 오래된 CVE도 오늘 PoC가 나오면 수집됨)
- 형식: CVE별 Markdown 파일 (`data/<year>/<CVE-ID>.md`)
- 공부용 전체 목록: CVSS ≥ 8.0 인 전체 아카이브 항목을 `data/high-severity.md`에 항상 최신으로 유지
- 공부용 일일 배분: 하루 5건씩 중복 없이 `data/study/<CVE-ID>.md`로 배분. 오늘 신규 승격분 → 기존 아카이브 → NVD 전체 DB를 CVSS 내림차순으로 훑어 PoC 있는 것 순으로 채움

> 이 파일은 `scripts/collect.py` 실행 시 자동 생성/덮어쓰기됩니다. 직접 수정하지 마세요.

## 동작 방식

1. NVD에 신규 발행된 CVE(CVSS ≥ 6.0)를 후보 풀(`data/.pool.json`)에 추가
1b. 과거에 이미 발행된 CVE도 CVSS 높은 순(CRITICAL→HIGH→MEDIUM 버킷 순)으로 하루 5건씩 풀에 추가 (발행일 무관 백필, 커서는 상태 파일에 저장)
2. NVD lastModified 벌크 조회로 Exploit 레퍼런스 태그가 새로 붙은 후보를 값싸게 탐지
3. 위에서 못 잡은 후보 중 재검사 시점(발행 후 3/7/14/30/60/90/180/365일)이 된 것을 GitHub 저장소 검색으로 재확인
4. PoC가 확인되면 CISA KEV/GHSA 보강 정보를 붙여 `data/<year>/<CVE-ID>.md`로 저장하고 풀에서 제거
5. 스케줄을 다 돌았는데도 PoC가 없으면 포기하고 풀에서 제거 (아카이브에는 남지 않음)
6. 전체 아카이브에서 CVSS ≥ 8.0 인 것만 골라 `data/high-severity.md`를 매번 재생성
6b. GHSA 를 updatedSince 로 증분 조회해 **패치 커밋이 있는 것만** 분석 큐(`data/analysis.json`)에 유입 (후보 풀에는 넣지 않음 — GHSA 에는 PoC 정보가 없음)
7. 공부용 하루 5건 배분 → `data/study/<CVE-ID>.md`. 1순위 오늘 신규 승격분, 2순위 기존 아카이브,
   3순위 NVD 전체 DB를 CVSS 내림차순으로 훑으며 PoC 있는 것을 찾아 채움(발행일 무관, 커서로 이어서 진행)

## 로컬 실행

```bash
pip install -r requirements.txt
cd scripts
python collect.py            # 증분 수집 (상태 파일 기준)
python collect.py --days 3   # 최근 3일치 신규 CVE 강제 유입 (백필)
python collect.py --verify   # 아카이브 PoC 근거 재확인만 (쓰기 없음, 문제 시 종료코드 1)
python collect.py --verify --rerender  # 확인 후 현재 포맷으로 전량 재생성
```

환경변수:

- `NVD_API_KEY` (선택): [무료 발급](https://nvd.nist.gov/developers/request-an-api-key). 없으면 rate limit이 낮아짐
- `GITHUB_TOKEN` (권장): GitHub 저장소 검색/Advisory 조회용. 없으면 검색 API 제한이 10회/분으로 낮아져 실행시간이 크게 늘어남. Actions에서는 자동 주입됨

## 연도별 목록

- [2026년](data/2026/README.md)
- [2025년](data/2025/README.md)
- [2024년](data/2024/README.md)
- [2023년](data/2023/README.md)
- [2022년](data/2022/README.md)
- [2021년](data/2021/README.md)
- [2020년](data/2020/README.md)
- [2019년](data/2019/README.md)
- [2018년](data/2018/README.md)
- [2017년](data/2017/README.md)
- [2016년](data/2016/README.md)
- [2015년](data/2015/README.md)

## 최근 PoC 확인된 CVE

| CVE | CVSS | KEV | 발행일 | PoC 공개일 |
|---|---|---|---|---|
| [CVE-2026-5006](data/2026/CVE-2026-5006.md) | 🟡 6.8 |  | 2026-08-24 | 2026-09-02 |
| [CVE-2026-62384](data/2026/CVE-2026-62384.md) | 🟠 7.5 |  | 2026-08-22 | - |
| [CVE-2026-71981](data/2026/CVE-2026-71981.md) | 🟠 8.8 |  | 2026-09-01 | 2026-09-02 |
| [CVE-2026-73296](data/2026/CVE-2026-73296.md) | 🔴 9.4 |  | 2026-08-12 | 2026-09-02 |
| [CVE-2026-75604](data/2026/CVE-2026-75604.md) | 🔴 9.0 |  | 2026-09-01 | 2026-08-25 |
| [CVE-2026-76221](data/2026/CVE-2026-76221.md) | 🟠 8.8 |  | 2026-08-19 | - |
| [CVE-2026-76222](data/2026/CVE-2026-76222.md) | 🟠 8.2 |  | 2026-08-19 | - |
| [CVE-2026-78675](data/2026/CVE-2026-78675.md) | 🟠 8.4 |  | 2026-08-25 | - |
| [CVE-2026-78676](data/2026/CVE-2026-78676.md) | 🔴 9.8 |  | 2026-08-25 | - |
| [CVE-2026-78677](data/2026/CVE-2026-78677.md) | 🟠 7.5 |  | 2026-08-25 | - |
| [CVE-2026-78678](data/2026/CVE-2026-78678.md) | 🟡 6.5 |  | 2026-08-25 | - |
| [CVE-2026-9055](data/2026/CVE-2026-9055.md) | 🔴 9.8 |  | 2026-09-02 | 2026-09-02 |
| [CVE-2026-9335](data/2026/CVE-2026-9335.md) | 🟡 6.5 |  | 2026-08-02 | 2026-09-02 |
| [CVE-2024-39700](data/2024/CVE-2024-39700.md) | 🔴 9.9 |  | 2024-07-16 | 2024-07-29 |
| [CVE-2024-39930](data/2024/CVE-2024-39930.md) | 🔴 9.9 |  | 2024-07-04 | 2025-06-29 |
| [CVE-2019-17658](data/2020/CVE-2019-17658.md) | 🔴 9.8 |  | 2020-03-12 | 2020-03-11 |
| [CVE-2022-45808](data/2023/CVE-2022-45808.md) | 🔴 9.9 |  | 2023-01-26 | 2023-08-18 |
| [CVE-2023-20048](data/2023/CVE-2023-20048.md) | 🔴 9.9 |  | 2023-11-01 | 2024-03-14 |
| [CVE-2023-40029](data/2023/CVE-2023-40029.md) | 🔴 9.9 |  | 2023-09-07 | 2025-01-25 |
| [CVE-2023-46404](data/2023/CVE-2023-46404.md) | 🔴 9.9 |  | 2023-11-03 | 2023-10-26 |
