# Audit Overview

This playbook defines a parallelizable security audit workflow with strict task boundaries, explicit dependencies, and schema-validated outputs.

```mermaid
flowchart TB
  A[보안진단실 > 취약점진단<br/>Application 진단 업무]

  A --> B[정기/신규 진단]
  A --> C[이행 점검 진단]
  A --> D[기타]

  subgraph PROC[정기/신규 진단 절차]
    direction TB
    P0[보안 담당 매니저와 서비스 프리뷰 회의]
    P1[1) 자산정보 요청/수령]
    P2[진단 환경 구성(모바일 앱 설치/구동, 테스트 계정 로그인 등)]
    P3[2) 서버 진단(시스템 진단) 요청]
    P4[3) Fortify 및 라이브러리 진단 요청]
    P5[4) 소스코드 정적 진단(SQLi, XSS, 파일처리 등)]
    P6[5) 동적 모의해킹 진단(데이터보호, 인증 등)]
    P7[6) 라이브러리 취약점 확인(exploit 여부 등)]
    P8[7) 진단결과 매니저 리뷰 후 리포팅]
    P9[8) 진단결과 조치계획 요청/수신]
    P0 --> P1 --> P2 --> P3 --> P4 --> P5 --> P6 --> P7 --> P8 --> P9
  end

  B --> PROC
```
