"""로뎀가드 FastAPI 메인 애플리케이션"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="로뎀가드(RotemGuard)",
    description="주통기 + ISMS-P 기반 AI 자동 취약점 진단 도구",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "rotemguard", "version": "0.2.0"}


@app.get("/api/v1/frameworks")
async def list_frameworks():
    """지원 컴플라이언스 프레임워크 목록 (주통기/국가핵심기술/ISMS-P)"""
    from ..core.frameworks import get_all_frameworks
    fws = get_all_frameworks()
    return {
        "total": len(fws),
        "frameworks": [
            {
                "id": f.id, "name": f.name, "full_name": f.full_name,
                "authority": f.authority, "legal_basis": f.legal_basis,
                "version": f.version, "total_items": f.total_items,
                "domains": [
                    {"id": d.id, "name": d.name, "item_count": len(d.items)}
                    for d in f.domains
                ],
            }
            for f in fws
        ],
    }


@app.get("/api/v1/frameworks/{framework_id}")
async def get_framework_detail(framework_id: str, domain_id: str = ""):
    """프레임워크 상세 항목 조회"""
    from ..core.frameworks import get_framework
    fw = get_framework(framework_id)
    if not fw:
        from fastapi import HTTPException
        raise HTTPException(404, f"Framework not found: {framework_id}")
    
    domains = fw.domains
    if domain_id:
        domains = [d for d in domains if d.id == domain_id]
    
    return {
        "id": fw.id, "name": fw.name, "full_name": fw.full_name,
        "authority": fw.authority, "legal_basis": fw.legal_basis,
        "domains": [
            {
                "id": d.id, "name": d.name,
                "items": d.items,
            }
            for d in domains
        ],
    }


@app.get("/api/v1/categories")
async def list_categories():
    """진단 대상 카테고리 목록"""
    from ..core.categories import get_all_categories
    cats = get_all_categories()
    return {
        "total": len(cats),
        "categories": [
            {
                "id": c.id, "name": c.name, "icon": c.icon,
                "prefix": c.jutonggi_prefix, "subcategories": c.subcategories,
                "inspector": c.inspector_type, "connection": c.connection_method,
                "item_range": c.item_count_range, "isms_p": c.isms_p_mapping,
                "description": c.description,
            }
            for c in cats
        ],
    }


@app.post("/api/v1/report/excel")
async def generate_excel_report(payload: dict):
    """Excel 취약점 진단 보고서 생성 (KHIDI 양식)"""
    from ..report.excel_report import ExcelReportGenerator
    from fastapi.responses import Response
    gen = ExcelReportGenerator()
    xlsx_bytes = gen.generate(payload)
    filename = f"취약점진단보고서_{payload.get('client_name','')}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/v1/report/pentest")
async def generate_pentest_report(payload: dict):
    """모의해킹 보고서 생성"""
    from ..report.pentest_report import PentestReportGenerator
    from fastapi.responses import Response
    gen = PentestReportGenerator()
    xlsx_bytes = gen.generate(payload)
    filename = f"모의해킹보고서_{payload.get('project_name','')}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/v1/sast/analyze")
async def run_sast(target_dir: str):
    """정적 분석 (SAST) 실행"""
    from ..sast.analyzer import SASTAnalyzer
    analyzer = SASTAnalyzer()
    findings = analyzer.analyze_directory(target_dir)
    return {
        "target": target_dir,
        "total_findings": len(findings),
        "by_severity": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [
            {
                "severity": f.severity, "cwe": f.cwe, "type": f.vuln_type,
                "file": f.file_path, "line": f.line,
                "snippet": f.code_snippet[:200], "description": f.description,
                "remediation": f.remediation, "method": f.method,
            }
            for f in findings
        ],
    }


@app.post("/api/v1/dast/scan")
async def run_dast(target_url: str, depth: int = 2):
    """동적 분석 (DAST) 실행"""
    from ..dast.scanner import DASTScanner
    scanner = DASTScanner()
    findings = await scanner.scan(target_url, depth=depth)
    return {
        "target": target_url,
        "total_findings": len(findings),
        "by_severity": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [
            {
                "severity": f.severity, "type": f.vuln_type, "owasp": f.owasp,
                "url": f.url, "parameter": f.parameter, "method": f.method,
                "payload": f.payload, "status_code": f.status_code,
                "evidence": f.evidence[:200], "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }


@app.get("/api/v1/check-items")
async def list_check_items(standard: str = "jutonggi", asset_type: str = None):
    """주통기/ISMS-P 체크 항목 목록 조회"""
    from ..planner.planner import DiagnosisPlanner
    planner = DiagnosisPlanner()

    if asset_type:
        item_ids = planner.get_applicable_items(asset_type)
        items = [planner._check_items[i] for i in item_ids if i in planner._check_items]
    else:
        items = [v for v in planner._check_items.values() if v.get("standard") == standard]

    return {
        "total": len(items),
        "items": [
            {
                "id": item["id"],
                "category": item.get("category", ""),
                "title": item.get("title", ""),
                "risk_level": item.get("risk_level", ""),
                "target_types": item.get("target_types", []),
                "ismsp_mapping": item.get("ismsp_mapping", []),
            }
            for item in items
        ],
    }


@app.post("/api/v1/projects/{project_id}/plan")
async def create_plan(project_id: int, assets: list[dict]):
    """프로젝트 진단 계획 수립"""
    from ..planner.planner import DiagnosisPlanner
    planner = DiagnosisPlanner()
    task_plans, todos = planner.create_initial_plan(assets)

    return {
        "project_id": project_id,
        "task_count": len(task_plans),
        "tasks": [
            {
                "asset_id": t.asset_id,
                "hostname": t.hostname,
                "inspector_type": t.inspector_type,
                "check_items": t.check_item_ids,
                "priority": t.priority,
            }
            for t in task_plans
        ],
        "todos": [
            {"id": t.id, "content": t.content, "status": t.status}
            for t in todos
        ],
    }


# === Sync API (맥미니: 현장 데이터 수신) ===

@app.post("/api/v1/sync/upload")
async def sync_upload(payload: dict):
    """현장 맥북프로에서 수집한 결과 벌크 수신
    
    Field Agent가 VPN을 통해 호출하거나,
    사무실 복귀 후 USB 이관 데이터를 import할 때 사용.
    """
    results = payload.get("results", [])
    if not results:
        return {"status": "empty", "count": 0}

    # TODO: DB에 저장 + 판정 엔진 큐에 등록
    # 현재는 수신 확인만
    received = []
    for r in results:
        received.append({
            "hostname": r.get("hostname", ""),
            "check_item_id": r.get("check_item_id", ""),
            "collected_at": r.get("collected_at", ""),
        })

    return {
        "status": "received",
        "count": len(received),
        "items": received[:10],  # 미리보기
        "note": "Queued for judgment + report generation",
    }


@app.get("/api/v1/sync/status")
async def sync_status(project_id: int = 0):
    """현장 동기화 상태 조회"""
    return {
        "project_id": project_id,
        "last_sync": None,
        "pending_judgment": 0,
        "completed_judgment": 0,
        "note": "Mac mini server status",
    }


@app.post("/api/v1/diagnose")
async def run_diagnosis(
    hostname: str,
    asset_type: str = "server_unix",
    username: str = "root",
    password: str = "",
    port: int = 22,
):
    """단일 자산 즉시 진단 실행 (테스트/데모용)"""
    from ..planner.planner import DiagnosisPlanner
    from ..inspectors.unix_inspector import UnixInspector
    from ..judgment.engine import JudgmentEngine

    # 1. 계획
    planner = DiagnosisPlanner()
    check_item_ids = planner.get_applicable_items(asset_type)
    check_items = [
        {
            "id": item_id,
            "script_ref": planner._check_items.get(item_id, {}).get("script_ref", ""),
        }
        for item_id in check_item_ids
    ]

    # 2. 수집
    inspector = UnixInspector()
    report = inspector.execute(
        task_id=0,
        asset_id=0,
        hostname=hostname,
        credential={"username": username, "password": password, "port": port},
        check_items=check_items,
    )

    # 3. 판정
    engine = JudgmentEngine()
    judgments = []
    for result in report.results:
        judgment = await engine.judge(
            check_item_id=result.check_item_id,
            asset_type=asset_type,
            parsed_data=result.parsed_data,
            raw_output=result.raw_output,
            asset_context={"hostname": hostname, "os_family": "", "os_version": ""},
        )
        judgments.append({
            "check_item_id": result.check_item_id,
            "title": planner._check_items.get(result.check_item_id, {}).get("title", ""),
            "verdict": judgment.verdict,
            "method": judgment.method,
            "confidence": judgment.confidence,
            "reason": judgment.reason,
            "raw_output_preview": result.raw_output[:200],
        })

    # 결과 요약
    pass_count = sum(1 for j in judgments if j["verdict"] == "pass")
    fail_count = sum(1 for j in judgments if j["verdict"] == "fail")

    return {
        "hostname": hostname,
        "asset_type": asset_type,
        "total_items": len(judgments),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "compliance_rate": round(100 * pass_count / len(judgments), 1) if judgments else 0,
        "results": judgments,
        "collection_success": report.success,
        "collection_errors": report.error_message,
    }
