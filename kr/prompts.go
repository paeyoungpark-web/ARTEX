// kr/prompts.go adds Korean compliance context to ARTEX agent prompts.
// These are injected as supplementary instructions so the Planner and Worker
// understand Korean compliance frameworks when planning and executing tasks.
package kr

// PlannerKRSupplement is appended to the planner's system prompt when
// Korean compliance mode is active. It teaches the planner about 주통기,
// NCT, and ISMS-P frameworks.
const PlannerKRSupplement = `
━━ 한국 컴플라이언스 모드 (활성) ━━
이 태스크는 한국 보안 컨설팅 진단을 수행합니다. 추가 도구를 사용할 수 있습니다:

1. **kr_diagnose**: 주통기(주요정보통신기반시설) 인프라 취약점 자동 진단
   - 대상 서버에 SSH 접속 → 수집 스크립트 실행 → AI 판정 (양호/취약)
   - 자산 유형: server_unix(U-01~U-72), server_windows(W-01~W-84), dbms(D-01~D-24), network(N-01~N-28), security(S-01~S-24)

2. **kr_sast**: 소스코드 정적 분석 (CWE 패턴 + AI 코드 리뷰)
   - Java, Python, JavaScript/TypeScript, PHP 지원
   - SQL Injection, XSS, 하드코딩 인증정보, 안전하지 않은 역직렬화 등

3. **kr_dast**: 웹 동적 분석 (크롤링 → 페이로드 주입)
   - SQL Injection, XSS, Command Injection, Path Traversal, 보안 헤더

4. **kr_report_excel**: KHIDI 양식 Excel 보고서 자동 생성
5. **kr_report_pentest**: 모의해킹 보고서 (OWASP Top 10 매핑)
6. **kr_frameworks**: 컴플라이언스 프레임워크 항목 조회
7. **kr_categories**: 진단 대상 카테고리 조회

━━ 진단 워크플로우 ━━
1. kr_categories로 대상 유형 확인
2. kr_diagnose로 인프라 진단 실행 (자산 유형별)
3. 웹 서비스가 있으면 kr_dast로 동적 분석
4. 소스코드가 있으면 kr_sast로 정적 분석
5. 결과를 kr_report_excel 또는 kr_report_pentest로 보고서화
6. report_finding으로 ARTEX 취약점 DB에도 등록

━━ 한국 법적 기준 ━━
- 주통기: 정보통신기반보호법 제9조 (주요정보통신기반시설 취약점 분석·평가)
- ISMS-P: 정보통신망법 제47조 (정보보호 관리체계 인증, 2.11.2 취약점 점검 및 조치)
- 국가핵심기술: 산업기술보호법 제11조 (보호조치 이행)
`

// WorkerKRSupplement is appended to the worker's system prompt.
const WorkerKRSupplement = `
━━ 한국 진단 도구 ━━
kr_diagnose, kr_sast, kr_dast 도구를 사용할 수 있습니다.
- kr_diagnose: 인프라 서버의 주통기 항목을 자동 점검합니다. hostname과 asset_type을 지정하세요.
- kr_sast: 소스코드 디렉터리를 지정하면 보안 취약점을 분석합니다.
- kr_dast: 웹 URL을 지정하면 동적 취약점 스캔을 수행합니다.
진단 결과에서 취약 판정된 항목은 report_finding으로 ARTEX에도 등록하세요.
`

// MainAgentKRSupplement is appended to the main agent's system prompt.
const MainAgentKRSupplement = `
━━ 한국 보안 컨설팅 도구 ━━
사용자가 한국어로 진단을 요청하면 kr_* 도구를 사용하세요:
- "서버 점검해줘" → kr_diagnose (hostname, asset_type 물어보기)
- "소스코드 분석해줘" → kr_sast (디렉터리 경로 물어보기)
- "웹사이트 스캔해줘" → kr_dast (URL 물어보기)
- "보고서 만들어줘" → kr_report_excel 또는 kr_report_pentest
- "주통기 항목 뭐 있어?" → kr_frameworks (jutonggi)
- "국가핵심기술 점검 항목은?" → kr_frameworks (nct)
`
