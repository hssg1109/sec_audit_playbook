# TODO — AI-SEC-OPS Playbook

> 진단 자동화 프레임워크 개선 과제 목록입니다.

## 범례

| 상태 | 아이콘 | 설명 |
|------|--------|------|
| 대기 | ⬜ | 미착수 |
| 진행중 | 🔄 | 현재 작업 중 |
| 완료 | ✅ | 작업 완료 |
| 보류 | ⏸ | 외부 의존성/우선순위로 중단 |

| 우선순위 | 아이콘 |
|---------|--------|
| 높음 | 🔴 |
| 보통 | 🟡 |
| 낮음 | 🟢 |

| 복잡도 | 의미 |
|--------|------|
| S | 1~2일 이내 |
| M | 1주 이내 |
| L | 2~4주 |
| XL | 1개월 이상 / 설계 필요 |

---

## 과제 목록

| # | 항목 | 우선순위 | 복잡도 | 상태 | 관련 컴포넌트 | 시작일 | 완료일 | 참고/링크 |
|---|------|---------|--------|------|--------------|--------|--------|-----------|
| T-01 | 보고서 상단에 서비스 설명 및 자산 구조 명시<br>(URL, IP, Repo, 담당자) | 🔴 | M | ⬜ 대기 | `publish_confluence.py`<br>`generate_finding_report.py` | - | - | - |
| T-02 | 보안진단 완료 후 PoC/테스트 코드 자동 생성<br>(JUnit / Fuzz / ZAP 활용, 검증용) | 🔴 | XL | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/sec-audit-static/` | - | - | - |
| T-03 | 검증 절차 자동화<br>1차: AI 진단 → 보고서 자동 생성<br>2차: 인력 검토 → Confirm<br>오탐/과탐 체크 워크플로우 | 🔴 | L | ⬜ 대기 | 전체 파이프라인 | - | - | - |
| T-04 | Diff 기반 seed 설정 + RAG 형식 프롬프트 연동<br>(변경된 코드 diff를 RAG로 구성하여 진단 프롬프트에 추가) | 🟡 | L | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/` 프롬프트 | - | - | [참고: hoyeon](https://github.com/team-attention/hoyeon) |
| T-05 | Redis / 파일 DB (Elasticsearch 등) 대상 진단 지원 | 🟡 | L | ⬜ 대기 | `scan_injection_enhanced.py`<br>`skills/sec-audit-static/` | - | - | - |
| T-06 | 보고서 출력 개발자 친화적 개선<br>(실제 코드 수정 가이드 포함, 취약 라인 직접 링크) | 🟡 | M | ⬜ 대기 | `publish_confluence.py`<br>`generate_finding_report.py` | - | - | - |

---

## 완료 과제

| # | 항목 | 완료일 | 버전 | 비고 |
|---|------|--------|------|------|
| ✅ | Phase 24: Positional Index Taint Tracking 구현 | 2026-02-24 | v4.5.0 | HTTP param → SQL 계층간 taint 전파 |
| ✅ | DTO 랩핑 taint 전파 오류 수정 | 2026-02-24 | v4.5.1 | `ordering` via DTO → `[실제]` 정확 판정 |
| ✅ | Kotlin `${if(expr)}` 키워드 오탐 수정 | 2026-02-24 | v4.5.1 | `_KT_KEYWORDS` 모듈 상수화 |
| ✅ | `_extract_call_args` 선언부 오탐(FP) 수정 | 2026-02-24 | v4.5.2 | `.methodName(` 우선순위 적용 |
| ✅ | Confluence code macro kotlin → java 수정 | 2026-02-25 | v4.5.2 | Server/DC `InvalidValueException` 해결 |
| ✅ | Bitbucket push 증분 커밋 히스토리 보존 | 2026-02-25 | - | `BB_HISTORY_REF` 방식 도입 |
| ✅ | `.gitignore` 고객사 파일 누락 항목 보완 | 2026-02-25 | - | `보고서예시/`, Office 문서 등 |

---

## 추가 제안 항목 (미확정)

| # | 항목 | 우선순위 | 복잡도 | 비고 |
|---|------|---------|--------|------|
| A-01 | SARIF 포맷 출력 지원 (IDE 연동) | 🟡 | M | VS Code / IntelliJ Security 플러그인 연동 |
| A-02 | 진단 결과 Delta 비교 (이전 스캔 대비 변경점) | 🟡 | M | 신규/수정/해결된 취약점 추적 |
| A-03 | GitHub Actions CI 연동 (PR 시 자동 진단) | 🟢 | M | 개발 파이프라인 통합 |
| A-04 | 다국어 보고서 지원 (영문 보고서) | 🟢 | S | 해외 협업 시 필요 |
