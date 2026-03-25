# Large Repo Multi-Module 진단 절차

> **적용 조건**: 하나의 repo에 Fortify build_target이 복수이거나, API 인벤토리 endpoints 수가 많아 단일 스캔 시 timeout/context 초과가 우려되는 경우.

---

## 판정 기준 — 이 절차를 적용해야 하는 경우

| 조건 | 기준 | 대응 |
|---|---|---|
| 멀티 모듈 repo | Fortify build_target ≥ 2 | 필수 적용 |
| 대형 단일 repo | API inventory endpoints > 1,000 | 필수 적용 |
| 보통 크기 | endpoints ≤ 1,000, build_target = 1 | 일반 전체 스캔 (Phase 2.5 불필요) |

> ob-backend 경험: 4,176 endpoints → `scan_injection_enhanced.py` timeout 발생.
> `--modules <build_target>` 으로 분리하면 build_target 당 평균 800~1,000 endpoints → 정상 완료.

---

## 기본 원칙

```
┌─────────────────────────────────────────────────────────────────────┐
│  Multi-Module 진단 흐름                                              │
│                                                                     │
│  Phase 2a: 전체 repo 1회 스캔 (file_processing / data_protection)   │
│      ↓                                                              │
│  Phase 2b: build_target별 injection/xss 스캔 (--modules 사용)        │
│      ↓                          ↓                                   │
│  [build_target A]         [build_target B]  ...                     │
│   Phase 2.5 inscope        Phase 2.5 inscope                        │
│   Phase 3 LLM              Phase 3 LLM                              │
│   Phase 4 보고서/게시       Phase 4 보고서/게시                        │
│      ↓                          ↓                                   │
│  SCA: 전체 repo 1회 (build_target 공유 의존성 기준)                    │
└─────────────────────────────────────────────────────────────────────┘
```

- **공유 스캔 (전체 repo 1회)**: `scan_file_processing.py`, `scan_data_protection.py`, `scan_sca_gradle_tree.py`
- **분리 스캔 (build_target별)**: `scan_injection_enhanced.py --modules`, `scan_xss.py --modules`
- **전체 repo 원본 JSON 은 삭제하지 않음** — 증거 보존

---

## Step 0: Build-Target 목록 확인

```bash
# Gradle 멀티모듈 구조 확인
cat testbed/<repo>/settings.gradle | grep include

# API inventory 실행 후 module 필드 확인
python3 tools/scripts/scan_api.py testbed/<repo> -o state/<prefix>_api_inventory.json
python3 -c "
import json
from collections import Counter
d = json.load(open('state/<prefix>_api_inventory.json'))
mods = Counter(ep.get('module','') for ep in d.get('endpoints',[]))
print('총 endpoints:', sum(mods.values()))
for k,v in mods.most_common():
    print(f'  {v:4d}  {k}')
"
```

**Fortify build_target ↔ API inventory `module` 필드 매핑 확인**:
- Fortify `build_target`명 = Gradle submodule 디렉토리명 = `module` 필드값
- 불일치 시 `module` 필드값 기준으로 `--modules` 인수 결정

---

## Step 1: 공유 스캔 (전체 repo, 1회)

> scan_file_processing / data_protection / sca 는 build_target 구분 없이 전체 repo 대상 1회 실행.

```bash
PREFIX_REPO="state/<test_prefix>_<repo>"   # 예: state/t41_ob_backend

# 파일 처리 (전체 repo)
python3 tools/scripts/scan_file_processing.py testbed/<repo> \
    -a state/<prefix>_api_inventory.json \
    -o ${PREFIX_REPO}_task24.json

# 데이터 보호 (전체 repo)
nohup python3 tools/scripts/scan_data_protection.py testbed/<repo> \
    -o ${PREFIX_REPO}_task25.json > state/scan_dp.log 2>&1 &

# SCA (전체 repo)
python3 tools/scripts/scan_sca_gradle_tree.py testbed/<repo> \
    --project <repo_name> -o ${PREFIX_REPO}_sca.json
```

---

## Step 2: Build-Target별 분리 스캔

각 Fortify build_target마다 독립 prefix 사용:

```bash
# build_target 목록 예시: cms_resource, event_resource
BUILD_TARGETS=("cms_resource" "event_resource")

for BT in "${BUILD_TARGETS[@]}"; do
    PREFIX="state/<test_prefix>_${BT}"
    echo "=== Scanning: $BT ==="

    # Injection 스캔 (--modules 사용)
    nohup python3 tools/scripts/scan_injection_enhanced.py \
        testbed/<repo> \
        -a state/<test_prefix>_<repo>_api_inventory.json \
        --modules "$BT" \
        --source-root testbed/<repo> \
        -o ${PREFIX}_injection.json > state/scan_injection_${BT}.log 2>&1 &
    echo "injection PID: $!"

    # XSS 스캔 (--modules 사용)
    nohup python3 tools/scripts/scan_xss.py \
        testbed/<repo> \
        -a state/<test_prefix>_<repo>_api_inventory.json \
        --modules "$BT" \
        -o ${PREFIX}_xss.json > state/scan_xss_${BT}.log 2>&1 &
    echo "xss PID: $!"
done
```

> injection / xss 는 build_target별 개별 prefix(`state/<test_prefix>_<BT>_injection.json`)로 저장.

---

## Step 3: Build-Target별 Phase 2.5 — inscope JSON 생성

공유 스캔 결과(task24/task25)를 build_target별로 필터링.

```python
import json, copy

REPO_PREFIX = "state/<test_prefix>_<repo>"   # 공유 스캔 파일 prefix
BT          = "cms_resource"                  # 현재 build_target
BT_PREFIX   = f"state/<test_prefix>_{BT}"    # build_target 전용 prefix
SCOPE       = (BT,)                          # module 필드 키워드

def in_scope(path):
    return any(s in (path or '') for s in SCOPE)

# API 인벤토리 → build_target별 inscope
with open(f"{REPO_PREFIX}_api_inventory.json") as f: api = json.load(f)
api_f = copy.deepcopy(api)
orig = api.get("endpoints", [])
api_f["endpoints"] = [e for e in orig if in_scope(e.get("file","") + e.get("module",""))]
api_f["original_endpoint_count"] = len(orig)
with open(f"{BT_PREFIX}_api_inventory_inscope.json", "w") as f:
    json.dump(api_f, f, ensure_ascii=False, indent=2)

# Injection은 분리 스캔했으므로 전체가 inscope → 그대로 복사
import shutil
shutil.copy(f"{BT_PREFIX}_injection.json", f"{BT_PREFIX}_injection_inscope.json")
shutil.copy(f"{BT_PREFIX}_xss.json",       f"{BT_PREFIX}_xss_inscope.json")

# Data Protection → build_target별 필터링
with open(f"{REPO_PREFIX}_task25.json") as f: t25 = json.load(f)
t25_f = copy.deepcopy(t25)
t25_f["findings"] = [x for x in t25.get("findings",[]) if in_scope(x.get("file",""))]
with open(f"{BT_PREFIX}_task25_inscope.json", "w") as f:
    json.dump(t25_f, f, ensure_ascii=False, indent=2)

# File Processing → build_target별 필터링
with open(f"{REPO_PREFIX}_task24.json") as f: t24 = json.load(f)
t24_f = copy.deepcopy(t24)
t24_f["findings"] = [x for x in t24.get("findings",[]) if in_scope(x.get("file",""))]
with open(f"{BT_PREFIX}_task24_inscope.json", "w") as f:
    json.dump(t24_f, f, ensure_ascii=False, indent=2)
```

> 위 코드를 build_target별로 `BT` 변수만 바꿔 반복 실행.

---

## Step 4: Build-Target별 Phase 3 LLM 분석

각 build_target의 `_inscope.json`을 입력으로 LLM 수동 분석 수행.

```
입력: <test_prefix>_<BT>_injection_inscope.json  →  출력: <test_prefix>_<BT>_task22_llm.json
입력: <test_prefix>_<BT>_xss_inscope.json        →  출력: <test_prefix>_<BT>_task23_llm.json
입력: <test_prefix>_<BT>_task24_inscope.json     →  출력: <test_prefix>_<BT>_task24_llm.json
입력: <test_prefix>_<BT>_task25_inscope.json     →  출력: <test_prefix>_<BT>_task25_llm.json
```

SCA LLM 검토는 전체 repo 공유 결과 기준으로 1회만 수행:
```
입력: <test_prefix>_<repo>_sca.json  →  출력: <test_prefix>_<repo>_sca_llm.json
```

---

## Step 5: Build-Target별 Phase 4 — 보고서 생성 + Confluence 게시

### confluence_page_map.json 등록 패턴

```json
{
  "entries": [
    {
      "title": "테스트NN - <repo> 정적 진단 (2026-MM-DD)",
      "type": "container"
    },
    {
      "source": "state/<test_prefix>_<BT>_report.md",
      "title": "테스트NN - <repo> 보안진단 보고서 (<BT>)",
      "type": "main_report",
      "task_sources": {
        "api":             "state/<test_prefix>_<BT>_api_inventory_inscope.json",
        "injection":       "state/<test_prefix>_<BT>_injection_inscope.json",
        "xss":             "state/<test_prefix>_<BT>_xss_inscope.json",
        "file_handling":   "state/<test_prefix>_<BT>_task24_inscope.json",
        "data_protection": "state/<test_prefix>_<BT>_task25_inscope.json"
      }
    },
    {
      "source": "state/<test_prefix>_<BT>_injection_inscope.json",
      "supplemental_sources": ["state/<test_prefix>_<BT>_task22_llm.json"],
      "title": "테스트NN - 인젝션 취약점 진단 결과 (<BT>)",
      "type": "finding"
    },
    {
      "source": "state/<test_prefix>_<BT>_xss_inscope.json",
      "supplemental_sources": ["state/<test_prefix>_<BT>_task23_llm.json"],
      "title": "테스트NN - XSS 취약점 진단 결과 (<BT>)",
      "type": "finding"
    },
    {
      "source": "state/<test_prefix>_<BT>_task24_inscope.json",
      "supplemental_sources": ["state/<test_prefix>_<BT>_task24_llm.json"],
      "title": "테스트NN - 파일 처리 진단 결과 (<BT>)",
      "type": "finding"
    },
    {
      "source": "state/<test_prefix>_<BT>_task25_inscope.json",
      "supplemental_sources": ["state/<test_prefix>_<BT>_task25_llm.json"],
      "title": "테스트NN - 데이터 보호 진단 결과 (<BT>)",
      "type": "finding"
    },
    {
      "source": "state/<test_prefix>_<repo>_sca.json",
      "supplemental_sources": ["state/<test_prefix>_<repo>_sca_llm.json"],
      "title": "테스트NN - SCA (오픈소스 취약점) 진단 결과",
      "type": "sca"
    }
  ]
}
```

> - SCA는 build_target 공유이므로 컨테이너 페이지 하위에 **1개만** 게시
> - build_target별 보안진단 보고서는 각각 별도 페이지로 게시
> - Fortify SSC 검증(Phase 5)도 build_target별로 수행: `fetch_ssc.py --project <project>/<repo>/<BT>`

---

## Prefix 네이밍 컨벤션

| 항목 | 패턴 | 예시 |
|---|---|---|
| 전체 repo 공유 스캔 | `<test_prefix>_<repo>_` | `t41_ob_backend_` |
| build_target별 스캔 | `<test_prefix>_<BT>_` | `t41_cms_resource_` |
| API inventory | `<test_prefix>_<repo>_api_inventory.json` | 공유 (build_target 구분 없음) |
| SCA | `<test_prefix>_<repo>_sca.json` | 공유 |
| Task 11 | `<test_prefix>_<repo>_task11.json` | 공유 |
| Injection/XSS | `<test_prefix>_<BT>_injection.json` | build_target별 |
| Task22~25 LLM | `<test_prefix>_<BT>_task22_llm.json` | build_target별 |
| SSC findings | `<test_prefix>_<BT>_ssc_findings.json` | build_target별 |

---

## 미지원 언어 repo 처리

스캐너가 지원하지 않는 언어(PHP 등)는 자동 스캔을 생략하고 아래로 처리:
- Phase 2 자동 스캔 전량 skip
- `references/unsupported_lang_targets.md` 에 미지원 대상 목록 기록
- 향후 해당 언어 스캐너 구현 후 재진단

지원 언어 현황:
| 언어 | 지원 여부 | 비고 |
|---|---|---|
| Java | ✅ | 전체 지원 |
| Kotlin | ✅ | 전체 지원 |
| TypeScript/JavaScript | ✅ (부분) | XSS/DataProtection 중심, Injection 제한적 |
| PHP | ❌ | 미지원 — `unsupported_lang_targets.md` 참조 |

---

## 2월 정기진단 대상별 적용 계획

| Project/Repo | build_target | 적용 절차 | 비고 |
|---|---|---|---|
| OCB_BACK_END/ocb-cashbag-mall | cla-madame-point-admin, cla-madame-point-partner | Multi-Module | endpoints 수 확인 후 결정 |
| OCB-GAME/ocb-game-admin | 단일 | 일반 전체 스캔 | |
| OCB-GAME/ocb-game-batch | 단일 | 일반 전체 스캔 | |
| OCB-THP/ocb_fun_real | php_ocb_fun | **PHP 미지원** | skip + 메모 |
| OCB-THP/ocb_game_biz | php_ocbgame | **PHP 미지원** | skip + 메모 |
| OCB-THP/ocb_game_biz_admin | php_ocbgame | **PHP 미지원** | skip + 메모 |
| OCB-THP/ocb_game_biz_matgo | php_ocbgame_matgo | **PHP 미지원** | skip + 메모 |
| OCB-THP/ocb_game_biz_matgo_php_real | php_ocbgame_matgo | **PHP 미지원** | skip + 메모 |
| OCBWEBVIEW/ocb-community-api | 단일 | 일반 전체 스캔 | |
| OCBWEBVIEW/ocb-community-ssr | 단일 | 일반 전체 스캔 | |
| OCBWEBVIEW/ocb-ogeul-admin-frontend | 단일 | 일반 전체 스캔 (TS/React) | |
| OCBWEBVIEW/ocb-webview-admin-api | 단일 | 일반 전체 스캔 | |
| OKICK/okick-event-batch-server | 단일 | 일반 전체 스캔 | |
| OKICK/okick-event-server | 단일 | 일반 전체 스캔 | |
| OKICK/okick-front | 단일 | 일반 전체 스캔 (React) | |
| OKICK/okick-reward-batch-server | 단일 | 일반 전체 스캔 | |
| OKICK/okick-reward-front | 단일 | 일반 전체 스캔 (React) | |
| OKICK/okick-reward-server | 단일 | 일반 전체 스캔 | |
