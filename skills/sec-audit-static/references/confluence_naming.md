# Confluence 보고서 네이밍 규칙

> 정기진단 보고서는 테스트 번호 대신 **서비스명** 기반 이름을 사용한다.
> 모든 보고서는 `OCB 서비스군` (pageId=741064663) 하위에 생성한다.

---

## 페이지 계층 구조

```
OCB 서비스군  (pageId=741064663)
  └─ {서비스명}_ai자동진단_보고서          ← 컨테이너 (진단 세션 루트)
       ├─ {서비스명}_ai자동진단_진단결과요약  ← main_report (종합 보고서)
       ├─ {서비스명}_ai자동진단_API인벤토리  ← api_inventory
       ├─ {서비스명}_ai자동진단_인젝션취약점  ← finding (injection)
       ├─ {서비스명}_ai자동진단_XSS취약점    ← finding (xss)
       ├─ {서비스명}_ai자동진단_파일처리      ← finding (file_handling)
       ├─ {서비스명}_ai자동진단_데이터보호    ← finding (data_protection)
       ├─ {서비스명}_ai자동진단_SCA          ← sca
       └─ {서비스명}_ai자동진단_SSC검증      ← ssc (Phase 5, 정기진단 필수)
```

### Multi-Module repo (build_target별 분리 진단 시)

```
OCB 서비스군
  └─ {서비스명}_ai자동진단_보고서           ← 컨테이너
       ├─ {서비스명}({BT})_ai자동진단_진단결과요약   ← build_target별 main_report
       ├─ {서비스명}({BT})_ai자동진단_인젝션취약점
       ├─ {서비스명}({BT})_ai자동진단_XSS취약점
       ├─ {서비스명}({BT})_ai자동진단_파일처리
       ├─ {서비스명}({BT})_ai자동진단_데이터보호
       ├─ {서비스명}({BT})_ai자동진단_API인벤토리
       ├─ {서비스명}_ai자동진단_SCA           ← SCA는 repo 공유 → 1개만
       └─ {서비스명}_ai자동진단_SSC검증_{BT}  ← SSC는 build_target별
```

---

## 서비스명 매핑 테이블

### 1월 정기진단 (GWS/OB)

| Project | Repository | build_target | 서비스명 (Confluence 표시) |
|---|---|---|---|
| GWS | oki-admin-fe | — | `경유쇼핑(oki-admin-fe)` |
| GWS | oki-be | oki-admin-rest-api | `경유쇼핑(oki-admin-rest-api)` |
| GWS | oki-be | oki-batch | `경유쇼핑(oki-batch)` |
| GWS | oki-be | oki-gateway-rest | `경유쇼핑(oki-gateway-rest)` |
| GWS | oki-be | oki-point-rest-api | `경유쇼핑(oki-point-rest-api)` |
| GWS | oki-be | oki-promotion-consumer | `경유쇼핑(oki-promotion-consumer)` |
| GWS | oki-be | oki-pv-consumer | `경유쇼핑(oki-pv-consumer)` |
| GWS | oki-be | oki-pv-rest-api | `경유쇼핑(oki-pv-rest-api)` |
| GWS | oki-be | oki-user-rest-api | `경유쇼핑(oki-user-rest-api)` |
| GWS | oki-fe | — | `경유쇼핑(oki-fe)` |
| OB | cashbagmall | admin / front-service | `캐쉬백몰(cashbagmall)` |
| OB | front_resource | — | `OCB이벤트(front_resource)` |
| OB | ob-backend | cms_resource | `OCB이벤트(cms_resource)` |
| OB | ob-backend | event_resource | `OCB이벤트(event_resource)` |

> GWS/oki-be는 build_target 7개 → 컨테이너 1개(`경유쇼핑(oki-be)_ai자동진단_보고서`) + build_target별 하위 페이지

### 2월 정기진단 (OCB_BACK_END/OCB-GAME/OCB-THP/OCBWEBVIEW/OKICK)

| Project | Repository | build_target | 서비스명 (Confluence 표시) |
|---|---|---|---|
| OCB_BACK_END | ocb-cashbag-mall | cla-madame-point-admin | `쇼핑적립(cla-madame-point-admin)` |
| OCB_BACK_END | ocb-cashbag-mall | cla-madame-point-partner | `쇼핑적립(cla-madame-point-partner)` |
| OCB-GAME | ocb-game-admin | — | `OCB게임(ocb-game-admin)` |
| OCB-GAME | ocb-game-batch | — | `OCB게임(ocb-game-batch)` |
| OCB-THP | ocb_fun_real | — | `OCB운세(ocb_fun_real)` ⚠️ PHP 미지원 |
| OCB-THP | ocb_game_biz | — | `OCB캐쉬백게임(ocb_game_biz)` ⚠️ PHP 미지원 |
| OCB-THP | ocb_game_biz_admin | — | `OCB캐쉬백게임(ocb_game_biz_admin)` ⚠️ PHP 미지원 |
| OCB-THP | ocb_game_biz_matgo | — | `OCB캐쉬백게임(ocb_game_biz_matgo)` ⚠️ PHP 미지원 |
| OCB-THP | ocb_game_biz_matgo_php_real | — | `OCB캐쉬백게임(ocb_game_biz_matgo_php_real)` ⚠️ PHP 미지원 |
| OCBWEBVIEW | ocb-community-api | — | `OCB오글오글(ocb-community-api)` |
| OCBWEBVIEW | ocb-community-ssr | — | `OCB오글오글(ocb-community-ssr)` |
| OCBWEBVIEW | ocb-ogeul-admin-frontend | — | `OCB오글오글(ocb-ogeul-admin-frontend)` |
| OCBWEBVIEW | ocb-webview-admin-api | — | `OCB오글오글(ocb-webview-admin-api)` |
| OKICK | okick-event-batch-server | — | `오킥(okick-event-batch-server)` |
| OKICK | okick-event-server | — | `오킥(okick-event-server)` |
| OKICK | okick-front | — | `오킥(okick-front)` |
| OKICK | okick-reward-batch-server | — | `오킥(okick-reward-batch-server)` |
| OKICK | okick-reward-front | — | `오킥(okick-reward-front)` |
| OKICK | okick-reward-server | — | `오킥(okick-reward-server)` |

### 3월 정기진단 (OEP/OL/OTH/TALKS/OCBPASS)

| Project | Repository | 서비스명 (Confluence 표시) |
|---|---|---|
| OEP | event_resource | `OCB이벤트프로모션(event_resource)` |
| OEP | ob-promotion (ocb-resource-cms) | `OCB이벤트프로모션(ocb-resource-cms)` |
| OEP | ob-promotion (evt-resource-mobile) | `OCB이벤트프로모션(evt-resource-mobile)` |
| OL | locker-frontend-admin | `오락(locker-frontend-admin)` |
| OL | locker-push | `오락(locker-push)` |
| OL | locker-server (각 BT) | `오락(locker-server-{BT})` |
| OL | locker-vision | `오락(locker-vision)` |
| OL | locker-webview | `오락(locker-webview)` |
| OL | locker-webview-front | `오락(locker-webview-front)` |
| OTH | homeshopping | `OCB홈쇼핑적립(homeshopping)` |
| OTH | trend-ad | `OCB홈쇼핑적립(trend-ad)` |
| OTH | trend-cms | `OCB홈쇼핑적립(trend-cms)` |
| OTH | trendissue | `OCB홈쇼핑적립(trendissue)` |
| TALKS | oggletalk-admin-frontend | `오글톡(oggletalk-admin-frontend)` |
| TALKS | oggletalk-backend (각 BT) | `오글톡(oggletalk-{BT})` |
| TALKS | talkplanet-frontend (각 BT) | `오글톡(talkplanet-{BT})` |
| OCBPASS | ocbpass-11st | `OCBPASS(ocbpass-11st)` |
| OCBPASS | ocbpass-admin | `OCBPASS(ocbpass-admin)` |
| OCBPASS | ocbpass-app | `OCBPASS(ocbpass-app)` |
| OCBPASS | ocbpass-batch | `OCBPASS(ocbpass-batch)` |
| OCBPASS | ocbpass-inside | `OCBPASS(ocbpass-inside)` |
| OCBPASS | ocbpass-newpg | `OCBPASS(ocbpass-newpg)` |

---

## confluence_page_map.json 템플릿

### 단일 모듈 repo

```json
{
  "parent_id": "741064663",
  "entries": [
    {
      "title": "{서비스명}_ai자동진단_보고서",
      "type": "container"
    },
    {
      "source": "state/<prefix>_report.md",
      "title": "{서비스명}_ai자동진단_진단결과요약",
      "type": "main_report",
      "task_sources": {
        "api":             "state/<prefix>_api_inventory.json",
        "injection":       "state/<prefix>_injection.json",
        "xss":             "state/<prefix>_xss.json",
        "file_handling":   "state/<prefix>_task24_llm.json",
        "data_protection": "state/<prefix>_task25_llm.json"
      }
    },
    {
      "source": "state/<prefix>_api_inventory.json",
      "title": "{서비스명}_ai자동진단_API인벤토리",
      "type": "api_inventory"
    },
    {
      "source": "state/<prefix>_injection.json",
      "supplemental_sources": ["state/<prefix>_task22_llm.json"],
      "title": "{서비스명}_ai자동진단_인젝션취약점",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_xss.json",
      "supplemental_sources": ["state/<prefix>_task23_llm.json"],
      "title": "{서비스명}_ai자동진단_XSS취약점",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task24_llm.json",
      "title": "{서비스명}_ai자동진단_파일처리",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_task25_llm.json",
      "title": "{서비스명}_ai자동진단_데이터보호",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_sca.json",
      "supplemental_sources": ["state/<prefix>_sca_llm.json"],
      "title": "{서비스명}_ai자동진단_SCA",
      "type": "sca"
    },
    {
      "source": "state/<prefix>_ssc_report.md",
      "title": "{서비스명}_ai자동진단_SSC검증",
      "type": "ssc"
    }
  ]
}
```

### Multi-Module repo (build_target별)

```json
{
  "parent_id": "741064663",
  "entries": [
    {
      "title": "{서비스명(repo)}_ai자동진단_보고서",
      "type": "container"
    },
    {
      "source": "state/<prefix>_<BT>_report.md",
      "title": "{서비스명({BT})}_ai자동진단_진단결과요약",
      "type": "main_report",
      "task_sources": {
        "api":             "state/<prefix>_<BT>_api_inventory_inscope.json",
        "injection":       "state/<prefix>_<BT>_injection_inscope.json",
        "xss":             "state/<prefix>_<BT>_xss_inscope.json",
        "file_handling":   "state/<prefix>_<BT>_task24_inscope.json",
        "data_protection": "state/<prefix>_<BT>_task25_inscope.json"
      }
    },
    {
      "source": "state/<prefix>_<BT>_injection_inscope.json",
      "supplemental_sources": ["state/<prefix>_<BT>_task22_llm.json"],
      "title": "{서비스명({BT})}_ai자동진단_인젝션취약점",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_<BT>_xss_inscope.json",
      "supplemental_sources": ["state/<prefix>_<BT>_task23_llm.json"],
      "title": "{서비스명({BT})}_ai자동진단_XSS취약점",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_<BT>_task24_inscope.json",
      "supplemental_sources": ["state/<prefix>_<BT>_task24_llm.json"],
      "title": "{서비스명({BT})}_ai자동진단_파일처리",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_<BT>_task25_inscope.json",
      "supplemental_sources": ["state/<prefix>_<BT>_task25_llm.json"],
      "title": "{서비스명({BT})}_ai자동진단_데이터보호",
      "type": "finding"
    },
    {
      "source": "state/<prefix>_repo_sca.json",
      "supplemental_sources": ["state/<prefix>_repo_sca_llm.json"],
      "title": "{서비스명(repo)}_ai자동진단_SCA",
      "type": "sca"
    },
    {
      "source": "state/<prefix>_<BT>_ssc_report.md",
      "title": "{서비스명(repo)}_ai자동진단_SSC검증_{BT}",
      "type": "ssc"
    }
  ]
}
```

---

## PHP 미지원 서비스 — 대체 Confluence 페이지

PHP 대상은 자동 스캔 대신 아래 내용으로 안내 페이지만 생성:

```
제목: {서비스명}_ai자동진단_보고서
내용: "현재 AI 자동진단 도구는 Java/Kotlin을 지원합니다.
      PHP 기반 서비스({repo})는 자동 스캔 미지원으로 진단이 보류됩니다.
      PHP 스캐너 구현 후 재진단 예정입니다."
```
