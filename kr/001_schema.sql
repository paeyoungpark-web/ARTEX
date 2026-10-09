-- ============================================================
-- 로뎀가드(RotemGuard) 데이터베이스 스키마 v0.1
-- 이중 그래프: 자산 그래프 + 진단 그래프
-- ============================================================

-- === 확장 ===
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1. 프로젝트 (최상위 단위)
-- ============================================================
CREATE TABLE IF NOT EXISTS projects (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,                          -- "A사 ISMS-P 취약점 진단"
    client_name     TEXT NOT NULL,                          -- 고객사명
    description     TEXT DEFAULT '',
    check_standard  TEXT NOT NULL DEFAULT 'jutonggi',       -- jutonggi | ismsp | mixed
    status          TEXT NOT NULL DEFAULT 'draft',          -- draft | active | completed | archived
    start_date      DATE,
    end_date        DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- 2. 자산 그래프 (Asset Graph) - 프로젝트별 격리
-- ============================================================

-- 자산 그룹 (DMZ, 내부망, DB존 등)
CREATE TABLE IF NOT EXISTS asset_groups (
    id              SERIAL PRIMARY KEY,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,                          -- "DMZ 서버군"
    description     TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asset_groups_project ON asset_groups(project_id);

-- 개별 자산
CREATE TABLE IF NOT EXISTS assets (
    id              SERIAL PRIMARY KEY,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id        INT REFERENCES asset_groups(id) ON DELETE SET NULL,
    hostname        TEXT NOT NULL,
    ip_address      INET,
    asset_type      TEXT NOT NULL,                          -- server_unix | server_windows | network | security | dbms | web | pc | cloud
    os_family       TEXT DEFAULT '',                        -- rhel | centos | ubuntu | windows_2019 | ...
    os_version      TEXT DEFAULT '',
    service_info    JSONB DEFAULT '{}',                     -- {ssh_port: 22, db_type: "oracle", ...}
    credential_ref  TEXT DEFAULT '',                        -- Vault 참조 키
    isms_scope      TEXT[] DEFAULT '{}',                    -- ISMS-P 인증범위 태그 배열
    check_profile   TEXT DEFAULT '',                        -- jutonggi_unix | jutonggi_windows | ...
    properties      JSONB DEFAULT '{}',                     -- 추가 속성
    status          TEXT NOT NULL DEFAULT 'active',         -- active | unreachable | decommissioned
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, hostname, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);

-- ============================================================
-- 3. 진단 그래프 (Diagnosis Graph)
-- ============================================================

-- 점검 항목 마스터 (주통기/ISMS-P 항목 정의)
CREATE TABLE IF NOT EXISTS check_items (
    id              TEXT PRIMARY KEY,                       -- "U-01", "W-15", "ISMSP-2.5.1"
    standard        TEXT NOT NULL,                          -- jutonggi | ismsp
    category        TEXT NOT NULL,                          -- 계정관리 | 파일및디렉터리관리 | ...
    subcategory     TEXT DEFAULT '',
    title           TEXT NOT NULL,                          -- "root 계정 원격접속 제한"
    description     TEXT DEFAULT '',
    risk_level      TEXT DEFAULT 'medium',                  -- critical | high | medium | low | info
    target_types    TEXT[] NOT NULL DEFAULT '{}',           -- {server_unix} | {server_windows} | ...
    check_method    TEXT DEFAULT 'script',                  -- script | manual | hybrid
    script_ref      TEXT DEFAULT '',                        -- 스크립트 파일 경로
    pass_criteria   TEXT DEFAULT '',                        -- 양호 판정 조건 설명
    fail_criteria   TEXT DEFAULT '',                        -- 취약 판정 조건 설명
    remediation     TEXT DEFAULT '',                        -- 조치 방법
    ismsp_mapping   TEXT[] DEFAULT '{}',                    -- 매핑되는 ISMS-P 항목 ID
    rule_ref        TEXT DEFAULT '',                        -- 판정 룰 파일 경로
    metadata        JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_check_items_standard ON check_items(standard);
CREATE INDEX IF NOT EXISTS idx_check_items_target ON check_items USING GIN(target_types);

-- 진단 태스크 (Inspector에게 배정되는 실행 단위)
CREATE TABLE IF NOT EXISTS diagnosis_tasks (
    id              SERIAL PRIMARY KEY,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id        INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    check_item_ids  TEXT[] NOT NULL DEFAULT '{}',           -- 이 태스크에서 점검할 항목 ID 배열
    inspector_type  TEXT NOT NULL,                          -- unix_inspector | windows_inspector | db_inspector | net_inspector | web_inspector
    priority        INT NOT NULL DEFAULT 5,                 -- 1(최고) ~ 10(최저)
    status          TEXT NOT NULL DEFAULT 'queued',         -- queued | running | done | failed | timeout | cancelled
    assigned_at     TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT DEFAULT '',
    retry_count     INT NOT NULL DEFAULT 0,
    max_retries     INT NOT NULL DEFAULT 3,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dtasks_project ON diagnosis_tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_dtasks_status ON diagnosis_tasks(status);
CREATE INDEX IF NOT EXISTS idx_dtasks_asset ON diagnosis_tasks(asset_id);

-- 진단 결과 (개별 항목별 수집 결과 + 판정)
CREATE TABLE IF NOT EXISTS diagnosis_results (
    id              SERIAL PRIMARY KEY,
    task_id         INT NOT NULL REFERENCES diagnosis_tasks(id) ON DELETE CASCADE,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id        INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    check_item_id   TEXT NOT NULL REFERENCES check_items(id),
    
    -- 수집 결과
    raw_output      TEXT DEFAULT '',                        -- 스크립트 원본 출력
    parsed_data     JSONB DEFAULT '{}',                     -- 파싱된 구조화 데이터
    evidence_ref    TEXT DEFAULT '',                        -- S3/MinIO 증적 파일 경로
    
    -- 판정
    verdict         TEXT NOT NULL DEFAULT 'pending',        -- pass | fail | manual_review | error | not_applicable | pending
    verdict_method  TEXT DEFAULT '',                        -- rule | llm | manual
    confidence      REAL DEFAULT 0.0,                      -- 판정 신뢰도 (0.0~1.0)
    verdict_reason  TEXT DEFAULT '',                        -- 판정 근거 설명
    
    -- 조치
    remediation     TEXT DEFAULT '',                        -- 맞춤형 조치 권고
    
    -- 메타
    inspector_id    TEXT DEFAULT '',                        -- 실행한 Inspector ID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(task_id, check_item_id)
);
CREATE INDEX IF NOT EXISTS idx_dresults_project ON diagnosis_results(project_id);
CREATE INDEX IF NOT EXISTS idx_dresults_verdict ON diagnosis_results(verdict);
CREATE INDEX IF NOT EXISTS idx_dresults_asset_check ON diagnosis_results(asset_id, check_item_id);

-- 취약점 발견 (취약 판정된 항목의 상세 추적)
CREATE TABLE IF NOT EXISTS findings (
    id              SERIAL PRIMARY KEY,
    result_id       INT NOT NULL REFERENCES diagnosis_results(id) ON DELETE CASCADE,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id        INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    check_item_id   TEXT NOT NULL REFERENCES check_items(id),
    
    severity        TEXT NOT NULL DEFAULT 'medium',         -- critical | high | medium | low
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    evidence        TEXT DEFAULT '',                        -- 취약 증거
    remediation     TEXT DEFAULT '',                        -- 조치 권고
    
    status          TEXT NOT NULL DEFAULT 'open',           -- open | remediated | accepted_risk | deferred | false_positive
    exception_reason TEXT DEFAULT '',                       -- 예외 인정 사유
    
    -- 재진단 추적
    recheck_result_id INT REFERENCES diagnosis_results(id),
    rechecked_at    TIMESTAMPTZ,
    
    -- ISMS-P 매핑
    ismsp_items     TEXT[] DEFAULT '{}',                    -- 연관 ISMS-P 항목
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- ============================================================
-- 4. Anchor 테이블 (자산 ↔ 진단 그래프 연결)
-- ============================================================
CREATE TABLE IF NOT EXISTS diagnosis_anchors (
    id              SERIAL PRIMARY KEY,
    result_id       INT NOT NULL REFERENCES diagnosis_results(id) ON DELETE CASCADE,
    asset_id        INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    check_item_id   TEXT NOT NULL REFERENCES check_items(id),
    verdict         TEXT NOT NULL DEFAULT 'pending',        -- 최신 판정 미러
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(asset_id, check_item_id)                        -- 자산당 항목별 하나의 앵커
);
CREATE INDEX IF NOT EXISTS idx_anchors_asset ON diagnosis_anchors(asset_id);

-- ============================================================
-- 5. Planner 상태 (이벤트 드리븐 재계획)
-- ============================================================
CREATE TABLE IF NOT EXISTS planner_state (
    id              SERIAL PRIMARY KEY,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    todo_list       JSONB DEFAULT '[]',                     -- Planner의 지속적 TodoList
    last_trigger    TEXT DEFAULT '',                        -- task_done | task_failed | ...
    last_wake_at    TIMESTAMPTZ,
    round_count     INT NOT NULL DEFAULT 0,
    metadata        JSONB DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id)
);

-- 이벤트 로그 (감사 추적)
CREATE TABLE IF NOT EXISTS event_log (
    id              SERIAL PRIMARY KEY,
    project_id      INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,                          -- task_created | task_started | task_done | task_failed | verdict_set | finding_created | exception_set | planner_wake
    entity_type     TEXT DEFAULT '',                        -- task | result | finding | asset
    entity_id       INT DEFAULT 0,
    actor           TEXT DEFAULT '',                        -- planner | inspector_unix | consultant | system
    detail          JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_project ON event_log(project_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON event_log(event_type);
CREATE INDEX IF NOT EXISTS idx_events_time ON event_log(created_at DESC);

-- ============================================================
-- 6. 프로젝트 통계 뷰
-- ============================================================
CREATE OR REPLACE VIEW project_summary AS
SELECT
    p.id AS project_id,
    p.name,
    p.client_name,
    p.status,
    COUNT(DISTINCT a.id) AS total_assets,
    COUNT(DISTINCT dt.id) AS total_tasks,
    COUNT(DISTINCT dt.id) FILTER (WHERE dt.status = 'done') AS completed_tasks,
    COUNT(DISTINCT dt.id) FILTER (WHERE dt.status = 'failed') AS failed_tasks,
    COUNT(DISTINCT dr.id) AS total_results,
    COUNT(DISTINCT dr.id) FILTER (WHERE dr.verdict = 'pass') AS pass_count,
    COUNT(DISTINCT dr.id) FILTER (WHERE dr.verdict = 'fail') AS fail_count,
    COUNT(DISTINCT dr.id) FILTER (WHERE dr.verdict = 'manual_review') AS review_count,
    COUNT(DISTINCT f.id) AS total_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open') AS open_findings
FROM projects p
LEFT JOIN assets a ON a.project_id = p.id
LEFT JOIN diagnosis_tasks dt ON dt.project_id = p.id
LEFT JOIN diagnosis_results dr ON dr.project_id = p.id
LEFT JOIN findings f ON f.project_id = p.id
GROUP BY p.id;

-- 자산별 커버리지 뷰 (ARTEX의 asset coverage 개념 차용)
CREATE OR REPLACE VIEW asset_coverage AS
SELECT
    a.id AS asset_id,
    a.project_id,
    a.hostname,
    a.asset_type,
    COUNT(DISTINCT da.check_item_id) AS checked_items,
    COUNT(DISTINCT da.check_item_id) FILTER (WHERE da.verdict = 'pass') AS pass_items,
    COUNT(DISTINCT da.check_item_id) FILTER (WHERE da.verdict = 'fail') AS fail_items,
    COUNT(DISTINCT da.check_item_id) FILTER (WHERE da.verdict = 'pending') AS pending_items,
    CASE 
        WHEN COUNT(DISTINCT da.check_item_id) > 0 
        THEN ROUND(100.0 * COUNT(DISTINCT da.check_item_id) FILTER (WHERE da.verdict IN ('pass','fail')) / COUNT(DISTINCT da.check_item_id), 1)
        ELSE 0 
    END AS coverage_pct
FROM assets a
LEFT JOIN diagnosis_anchors da ON da.asset_id = a.id
GROUP BY a.id;
