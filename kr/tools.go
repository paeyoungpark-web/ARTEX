// kr/tools.go registers Korean compliance tools into ARTEX's agent tool system.
// These tools appear alongside ARTEX's built-in tools (graph_overview, report_finding, etc.)
// so the Planner and Worker can use them natively.
package kr

import (
	"context"
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
)

// RegisterTools returns the Korean compliance tools to be injected into
// ARTEX's agent tool catalog. Called during server startup.
func RegisterTools() []actool.CoreTool {
	return []actool.CoreTool{
		&krTool{
			name: "kr_diagnose",
			desc: "주통기 인프라 취약점 진단 실행. 대상 서버에 SSH 접속하여 주통기 항목(U-01~U-72 등)을 자동 점검하고 양호/취약을 판정합니다.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"hostname":   map[string]any{"type": "string", "description": "대상 서버 IP 또는 호스트명"},
					"asset_type": map[string]any{"type": "string", "enum": []string{"server_unix", "server_windows", "dbms", "network", "security"}, "description": "자산 유형"},
					"username":   map[string]any{"type": "string", "description": "SSH/WinRM 접속 계정"},
					"password":   map[string]any{"type": "string", "description": "접속 비밀번호"},
					"port":       map[string]any{"type": "integer", "description": "접속 포트 (기본 22)"},
				},
				"required": []string{"hostname", "asset_type"},
			},
			path: "/api/v1/diagnose",
		},
		&krTool{
			name: "kr_sast",
			desc: "소스코드 정적 분석(SAST) 실행. 지정된 디렉터리의 소스코드에서 SQL Injection, XSS, 하드코딩된 인증정보 등 취약점을 CWE 기준으로 탐지합니다. Java/Python/JavaScript/PHP 지원.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target_dir": map[string]any{"type": "string", "description": "분석할 소스코드 디렉터리 경로"},
				},
				"required": []string{"target_dir"},
			},
			path: "/api/v1/sast/analyze",
		},
		&krTool{
			name: "kr_dast",
			desc: "웹 애플리케이션 동적 분석(DAST) 실행. 대상 URL을 크롤링하고 SQL Injection, XSS, Command Injection 등 페이로드를 주입하여 취약점을 탐지합니다.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target_url": map[string]any{"type": "string", "description": "분석할 웹 애플리케이션 URL"},
					"depth":      map[string]any{"type": "integer", "description": "크롤링 깊이 (기본 2)"},
				},
				"required": []string{"target_url"},
			},
			path: "/api/v1/dast/scan",
		},
		&krTool{
			name: "kr_report_excel",
			desc: "주통기 취약점 진단 결과를 KHIDI 양식 Excel 보고서로 생성합니다. 표지, 점검대상, 요약 매트릭스, 장비별 상세 시트를 포함합니다.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_name": map[string]any{"type": "string", "description": "프로젝트명"},
					"client_name":  map[string]any{"type": "string", "description": "고객사명"},
					"assets":       map[string]any{"type": "array", "description": "자산 및 진단 결과 배열"},
				},
				"required": []string{"project_name", "client_name"},
			},
			path: "/api/v1/report/excel",
		},
		&krTool{
			name: "kr_report_pentest",
			desc: "모의해킹 보고서를 생성합니다. OWASP Top 10 매핑, SAST/DAST 결과, PoC, 조치방안을 포함한 Excel 보고서입니다.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_name":  map[string]any{"type": "string", "description": "프로젝트명"},
					"target_system": map[string]any{"type": "string", "description": "대상 시스템"},
					"findings":      map[string]any{"type": "array", "description": "발견 취약점 배열"},
					"sast_results":  map[string]any{"type": "array", "description": "SAST 결과"},
					"dast_results":  map[string]any{"type": "array", "description": "DAST 결과"},
				},
				"required": []string{"project_name"},
			},
			path: "/api/v1/report/pentest",
		},
		&krTool{
			name: "kr_frameworks",
			desc: "한국 컴플라이언스 프레임워크(주통기/국가핵심기술/ISMS-P) 점검 항목을 조회합니다.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework_id": map[string]any{"type": "string", "enum": []string{"jutonggi", "nct", "ismsp"}, "description": "프레임워크 ID"},
					"domain_id":    map[string]any{"type": "string", "description": "영역 ID (선택)"},
				},
			},
			path:   "/api/v1/frameworks",
			method: "GET",
		},
		&krTool{
			name: "kr_categories",
			desc: "취약점 진단 대상 카테고리 목록을 조회합니다 (Unix/Windows/DBMS/네트워크/보안장비/웹/PC/클라우드/ICS/모바일).",
			schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			path:   "/api/v1/categories",
			method: "GET",
		},
	}
}

// krTool wraps a Korean sidecar API endpoint as an ARTEX agent tool.
type krTool struct {
	name   string
	desc   string
	schema map[string]any
	path   string
	method string // "GET" or "" (default POST)
}

func (t *krTool) Name() string                  { return t.name }
func (t *krTool) Description() string           { return t.desc }
func (t *krTool) InputSchema() map[string]any   { return t.schema }

func (t *krTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var result json.RawMessage
	var err error

	if t.method == "GET" {
		result, err = getSidecar(ctx, t.path)
	} else {
		var payload any
		if len(input) > 0 {
			_ = json.Unmarshal(input, &payload)
		}
		result, err = callSidecar(ctx, t.path, payload)
	}

	if err != nil {
		return actool.Errorf("kr tool %s 오류: %v", t.name, err), nil
	}

	// Pretty-print for the LLM
	var pretty bytes.Buffer
	if json.Indent(&pretty, result, "", "  ") == nil {
		return actool.Text(pretty.String()), nil
	}
	return actool.Text(string(result)), nil
}

// Ensure krTool satisfies the CoreTool interface at compile time.
var _ actool.CoreTool = (*krTool)(nil)
