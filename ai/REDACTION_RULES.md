# 민감정보 마스킹 규칙 (Redaction Rules)

## 목적
AI에 전달하거나 보고서에 포함되는 데이터에서 민감정보를 자동/수동 마스킹하기 위한 규칙입니다.

## 필수 마스킹 대상

### 1. 네트워크 정보
- **IP 주소**: `192.168.1.100` → `[REDACTED_IP_1]`
- **내부 호스트명**: `db-prod-01.internal` → `[REDACTED_HOST_1]`
- **포트 정보**: 비표준 포트는 마스킹 대상

### 2. 인증 정보
- **비밀번호**: 모든 형태의 패스워드 → `[REDACTED_PASSWORD]`
- **API 키**: `sk-xxxx...` → `[REDACTED_API_KEY]`
- **토큰**: JWT, Bearer 토큰 → `[REDACTED_TOKEN]`
- **인증서**: 개인 키 내용 → `[REDACTED_CERT]`

### 3. 개인정보
- **이메일**: `user@company.com` → `[REDACTED_EMAIL]`
- **전화번호**: `010-xxxx-xxxx` → `[REDACTED_PHONE]`
- **주민등록번호**: → `[REDACTED_SSN]`

### 4. 비즈니스 정보
- **고객사명**: 실제 고객사명 → `[CLIENT_A]`, `[CLIENT_B]`
- **내부 프로젝트명**: → `[PROJECT_X]`

## 마스킹 방식
1. **자동 마스킹**: `tools/scripts/redact.py` 스크립트 사용
2. **수동 검토**: 자동 마스킹 후 반드시 수동 확인 1회 실시
3. **복원 금지**: 마스킹된 데이터의 원본은 별도 보안 저장소에만 보관

## 정규식 패턴
```
IPv4: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
Email: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
API Key: \b(sk|pk|api)[_-][A-Za-z0-9]{20,}\b
Korean Phone: \b01[016789]-?\d{3,4}-?\d{4}\b
```
