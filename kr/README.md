# 로뎀가드(RotemGuard) - ARTEX 한국 특화 확장

> ARTEX의 모든 기능을 유지하면서 한국 보안 컨설팅에 필요한 기능을 추가합니다.

## 아키텍처 원칙

```
ARTEX (원본 Go 코드, 100% 유지)
  ├── agent/        ← Planner, Worker, MainAgent 그대로
  ├── server/       ← REST API, SSE, 인증 그대로
  ├── web/          ← Next.js 프론트엔드 그대로
  ├── db/           ← PostgreSQL 스키마 그대로
  └── ...           ← 모든 모듈 그대로
  
kr/ (한국 특화 확장, Python 사이드카)
  ├── frameworks.py      ← 주통기/NCT/ISMS-P 프레임워크 정의
  ├── categories.py      ← 진단 대상 10개 카테고리
  ├── knowledge/         ← 주통기 YAML + 수집 스크립트 + 판정 룰
  ├── inspectors/        ← SSH/WinRM 기반 인프라 취약점 수집
  ├── judgment/          ← 2단계 판정 (규칙→LLM)
  ├── sast/              ← 정적 소스코드 분석 (AI)
  ├── dast/              ← 동적 웹 취약점 스캔
  ├── report/            ← Excel/Markdown 보고서 (KHIDI 양식)
  ├── field/             ← 현장 맥북 경량 에이전트
  └── 001_schema.sql     ← 한국 특화 DB 확장 테이블
```

## 통합 방식

ARTEX는 Go 단일 바이너리로 실행됩니다.
한국 특화 기능(kr/)은 **Python 사이드카 서비스**로 실행되며,
ARTEX의 API를 통해 양방향 통신합니다.

```
┌──────────────────────┐     ┌──────────────────────┐
│  ARTEX (Go :8787)    │◄───►│  KR Sidecar (:8800)  │
│                      │     │                      │
│  - Planner/Worker    │     │  - 주통기 진단        │
│  - MainAgent Chat    │     │  - NCT 점검           │
│  - Asset/Finding DB  │     │  - SAST/DAST          │
│  - Traffic Proxy     │     │  - Excel 보고서       │
│  - Graph/Dashboard   │     │  - 판정 엔진          │
│  - LLM Pool          │     │  - Field Agent        │
│  - Guard/Intercept   │     │                      │
└──────────────────────┘     └──────────────────────┘
         ↕ PostgreSQL (공유)         ↕
```

## 한국 특화 기능 목록

### 컴플라이언스 프레임워크
| 프레임워크 | 법적 근거 | 항목 수 |
|---|---|---|
| 주통기 | 정보통신기반보호법 제9조 | 313개 |
| 국가핵심기술 보호 | 산업기술보호법 제11조 | 41개 |
| ISMS-P | 정보통신망법 제47조 | 102개 |

### 진단 기능
- **인프라 진단**: SSH/WinRM 원격 스크립트 실행 (read-only)
- **SAST**: 정규식 패턴 + AI 코드 리뷰 (Java/Python/JS/PHP)
- **DAST**: 크롤링 → 페이로드 주입 → AI 응답 분석
- **판정 엔진**: 규칙 기반 80% + LLM fallback 20%

### 보고서
- **Excel**: KHIDI 양식 (표지/점검대상/요약매트릭스/그래프/장비별시트)
- **모의해킹**: OWASP Top 10 매핑, PoC, SAST+DAST 통합
- **Markdown**: 주통기 + ISMS-P 통합 보고서

### 현장 운용
- **Field Agent**: 맥북프로 경량 수집 → 맥미니 동기화
- **오프라인 모드**: SQLite 버퍼 → USB 이관
