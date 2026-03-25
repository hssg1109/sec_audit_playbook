# 미지원 언어 진단 대상 목록

> 현재 sec-audit-static 스캐너는 Java/Kotlin을 기본 지원하며, TypeScript/JavaScript는 부분 지원.
> 이 파일은 **지원 언어 스캐너가 없어 자동 진단이 불가한 대상**을 기록하고, 향후 스캐너 구현을 위한 요구사항을 명세합니다.

---

## PHP (미지원)

### 대상 repo 목록

| Project | Repository | build_target | 서비스명 | 진단 월 | 상태 |
|---|---|---|---|---|---|
| OCB-THP | ocb_fun_real | php_ocb_fun | OCB 운세, 스타일업 등 | 2026-02 | ⬜ 미진단 |
| OCB-THP | ocb_game_biz | php_ocbgame | OCB 캐쉬백게임 | 2026-02 | ⬜ 미진단 |
| OCB-THP | ocb_game_biz_admin | php_ocbgame | OCB 캐쉬백게임 (admin) | 2026-02 | ⬜ 미진단 |
| OCB-THP | ocb_game_biz_matgo | php_ocbgame_matgo | OCB 캐쉬백게임 (matgo) | 2026-02 | ⬜ 미진단 |
| OCB-THP | ocb_game_biz_matgo_php_real | php_ocbgame_matgo | OCB 캐쉬백게임 (matgo, real) | 2026-02 | ⬜ 미진단 |

> 주의: `ocb_game_biz_admin`(feature/20250924_php8_converting)과 `ocb_fun_real`(feature/20250909_php_converting)은 Fortify에서 master와 사실상 동일 판단 → 대상 제외 처리됨 (상기 목록에는 기록 유지).

### 현재 처리 방식

자동 스캔 전량 skip. Confluence에 "PHP 언어 미지원 — 추후 진단 예정" 페이지 생성 후 게시.

### 향후 PHP 스캐너 구현 요구사항

**구현 대상 스크립트**:

| 스크립트 | 역할 | 우선순위 |
|---|---|---|
| `scan_api_php.py` | PHP 라우터(Laravel/CodeIgniter/순수 PHP) API 엔드포인트 추출 | 🔴 |
| `scan_injection_php.py` | SQL Injection: PDO/MySQLi 쿼리 빌더 탐지, `$_GET/$_POST` taint | 🔴 |
| `scan_xss_php.py` | Reflected XSS: `echo $_GET[...]`, `htmlspecialchars` 미적용 패턴 | 🔴 |
| `scan_data_protection_php.py` | 하드코딩된 자격증명, 평문 세션/쿠키, `error_reporting` 노출 | 🟡 |
| `scan_file_processing_php.py` | `move_uploaded_file`, `include $_GET[...]` LFI 패턴 | 🟡 |

**PHP 주요 취약 패턴 참조**:

```php
// SQL Injection — 직접 쿼리 빌드
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($query);

// Reflected XSS — 미인코딩 출력
echo "<p>" . $_GET['name'] . "</p>";

// LFI — 동적 include
include($_GET['page'] . '.php');

// 하드코딩 자격증명
$db_password = 'admin1234';
define('DB_PASSWORD', 'secret');

// 명령 인젝션
system("ls " . $_GET['dir']);
```

**OCB-THP 프레임워크 분석 필요**:
- ocb_fun_real, ocb_game_biz 등: 레거시 PHP인지 Laravel/CodeIgniter 기반인지 fetch 후 확인
- PHP 버전 확인: PHP8 converting 브랜치 존재 → PHP 7→8 마이그레이션 중

---

## 지원 언어 현황

| 언어 / 프레임워크 | 지원 수준 | 주요 스캔 항목 |
|---|---|---|
| Java (Spring MVC / Spring Boot) | ✅ 완전 지원 | Injection / XSS / File / DataProtection / SCA |
| Kotlin (Spring Boot) | ✅ 완전 지원 | Injection / XSS / File / DataProtection / SCA |
| TypeScript (React / Next.js) | 🟡 부분 지원 | XSS(DOM/Reflected) / DataProtection / SCA(npm) |
| JavaScript (Node.js / React) | 🟡 부분 지원 | XSS / DataProtection / SCA(npm) |
| PHP | ❌ 미지원 | — |
| Python | ❌ 미지원 | — |
| Go | ❌ 미지원 | — |
