"""보고서 생성 엔진 - 주통기 + ISMS-P 통합 보고서

한국 보안 컨설팅 현장 표준 양식에 맞는 보고서를 자동 생성합니다.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass
class ReportData:
    """보고서 생성에 필요한 데이터"""
    project_name: str
    client_name: str
    report_date: str
    consultant_name: str = "로뎀시스템"
    
    # 자산 요약
    total_assets: int = 0
    asset_summary: list[dict] = None  # [{type, count}]
    
    # 진단 결과 요약
    total_items: int = 0
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    manual_count: int = 0
    
    # 상세 결과
    results_by_asset: list[dict] = None   # [{asset, results: [{item_id, title, verdict, reason, remediation}]}]
    findings: list[dict] = None           # [{severity, title, asset, check_item, evidence, remediation}]
    
    # ISMS-P 매핑
    ismsp_coverage: list[dict] = None     # [{ismsp_item, title, related_checks, status}]
    
    def __post_init__(self):
        self.asset_summary = self.asset_summary or []
        self.results_by_asset = self.results_by_asset or []
        self.findings = self.findings or []
        self.ismsp_coverage = self.ismsp_coverage or []

    @property
    def compliance_rate(self) -> float:
        total = self.pass_count + self.fail_count
        return round(100 * self.pass_count / total, 1) if total > 0 else 0

    @property
    def severity_summary(self) -> dict:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            sev = f.get("severity", "medium")
            summary[sev] = summary.get(sev, 0) + 1
        return summary


class ReportGenerator:
    """보고서 생성기
    
    지원 형식:
    - Markdown (기본, 미리보기용)
    - HTML (대시보드 렌더링용)
    - Excel (고객 제출용, 추후 구현)
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        self._templates_dir = templates_dir or TEMPLATES_DIR

    def generate_markdown(self, data: ReportData) -> str:
        """주통기 취약점 진단 보고서 (Markdown)"""
        severity_summary = data.severity_summary
        
        lines = [
            f"# 기술적 취약점 진단 결과 보고서",
            f"",
            f"| 항목 | 내용 |",
            f"|---|---|",
            f"| 프로젝트 | {data.project_name} |",
            f"| 고객사 | {data.client_name} |",
            f"| 진단일 | {data.report_date} |",
            f"| 수행사 | {data.consultant_name} |",
            f"",
            f"---",
            f"",
            f"## 1. 진단 개요",
            f"",
            f"### 1.1 진단 대상",
            f"",
            f"| 자산 유형 | 수량 |",
            f"|---|---|",
        ]

        for item in data.asset_summary:
            lines.append(f"| {item['type']} | {item['count']} |")
        
        lines.append(f"| **합계** | **{data.total_assets}** |")
        lines.extend([
            f"",
            f"### 1.2 진단 기준",
            f"",
            f"- 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (최신판)",
            f"- ISMS-P 인증기준 (보호대책 요구사항)",
            f"",
            f"---",
            f"",
            f"## 2. 진단 결과 요약",
            f"",
            f"### 2.1 전체 현황",
            f"",
            f"| 구분 | 건수 | 비율 |",
            f"|---|---|---|",
            f"| 양호 | {data.pass_count} | {data.compliance_rate}% |",
            f"| 취약 | {data.fail_count} | {round(100 - data.compliance_rate, 1)}% |",
            f"| 해당없음 | {data.na_count} | - |",
            f"| 수동확인 | {data.manual_count} | - |",
            f"| **합계** | **{data.total_items}** | - |",
            f"",
            f"### 2.2 취약점 위험도별 현황",
            f"",
            f"| 위험도 | 건수 |",
            f"|---|---|",
            f"| 상 (Critical/High) | {severity_summary['critical'] + severity_summary['high']} |",
            f"| 중 (Medium) | {severity_summary['medium']} |",
            f"| 하 (Low) | {severity_summary['low']} |",
            f"",
            f"---",
            f"",
            f"## 3. 자산별 상세 결과",
            f"",
        ])

        for asset_result in data.results_by_asset:
            asset = asset_result["asset"]
            lines.extend([
                f"### {asset['hostname']} ({asset.get('ip_address', '')})",
                f"",
                f"- OS: {asset.get('os_family', '')} {asset.get('os_version', '')}",
                f"- 유형: {asset.get('asset_type', '')}",
                f"",
                f"| 항목 | 제목 | 판정 | 근거 |",
                f"|---|---|---|---|",
            ])
            for r in asset_result.get("results", []):
                verdict_mark = "✅" if r["verdict"] == "pass" else "❌" if r["verdict"] == "fail" else "⚠️"
                lines.append(f"| {r['check_item_id']} | {r['title']} | {verdict_mark} {r['verdict']} | {r.get('reason', '')[:50]} |")
            lines.append("")

        if data.findings:
            lines.extend([
                f"---",
                f"",
                f"## 4. 취약점 상세",
                f"",
            ])
            for i, f in enumerate(data.findings, 1):
                lines.extend([
                    f"### 4.{i} [{f.get('severity', 'medium').upper()}] {f['title']}",
                    f"",
                    f"- **대상**: {f.get('asset', '')}",
                    f"- **항목**: {f.get('check_item', '')}",
                    f"- **위험도**: {f.get('severity', 'medium')}",
                    f"",
                    f"**증거:**",
                    f"```",
                    f"{f.get('evidence', '')}",
                    f"```",
                    f"",
                    f"**조치 권고:**",
                    f"{f.get('remediation', '')}",
                    f"",
                ])

        if data.ismsp_coverage:
            lines.extend([
                f"---",
                f"",
                f"## 5. ISMS-P 매핑 결과",
                f"",
                f"| ISMS-P 항목 | 제목 | 관련 주통기 항목 | 상태 |",
                f"|---|---|---|---|",
            ])
            for item in data.ismsp_coverage:
                status = "✅ 충족" if item["status"] == "pass" else "❌ 미충족" if item["status"] == "fail" else "⚠️ 일부"
                checks = ", ".join(item.get("related_checks", [])[:5])
                lines.append(f"| {item['ismsp_item']} | {item['title']} | {checks} | {status} |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"*본 보고서는 로뎀가드(RotemGuard) 자동 진단 도구에 의해 생성되었습니다.*",
            f"*최종 검토: {data.consultant_name} ({data.report_date})*",
        ])

        return "\n".join(lines)
