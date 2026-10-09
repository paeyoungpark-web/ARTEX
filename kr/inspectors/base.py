"""Inspector 기본 클래스 - 모든 Inspector의 공통 인터페이스"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CollectionResult:
    """개별 체크 항목의 수집 결과"""
    check_item_id: str
    raw_output: str
    parsed_data: dict = field(default_factory=dict)
    success: bool = True
    error_message: str = ""
    collected_at: datetime = field(default_factory=datetime.now)


@dataclass
class InspectionReport:
    """Inspector 실행 전체 결과"""
    task_id: int
    asset_id: int
    inspector_type: str
    results: list[CollectionResult] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    success: bool = True
    error_message: str = ""

    @property
    def total_items(self) -> int:
        return len(self.results)

    @property
    def successful_items(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed_items(self) -> int:
        return sum(1 for r in self.results if not r.success)


class BaseInspector(ABC):
    """Inspector 기본 클래스
    
    ARTEX Worker와의 핵심 차이:
    1. 자체 방향 결정 불가 - Planner가 배정한 check_items만 실행
    2. read-only 스크립트만 실행 (시스템 변경 없음)
    3. LLM 사용하지 않음 (결정론적 수집)
    4. 수집과 판정 분리 (Inspector는 수집만, 판정은 JudgmentEngine)
    """

    inspector_type: str = "base"

    @abstractmethod
    def connect(self, hostname: str, credential: dict) -> None:
        """대상 시스템 연결"""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """연결 해제"""
        ...

    @abstractmethod
    def collect_item(self, check_item_id: str, script_ref: str) -> CollectionResult:
        """단일 체크 항목 수집 실행"""
        ...

    def execute(self, task_id: int, asset_id: int, hostname: str,
                credential: dict, check_items: list[dict]) -> InspectionReport:
        """전체 점검 실행 (템플릿 메서드 패턴)
        
        1. 연결
        2. 각 check_item에 대해 수집 스크립트 실행
        3. 결과 수집
        4. 연결 해제
        """
        report = InspectionReport(
            task_id=task_id,
            asset_id=asset_id,
            inspector_type=self.inspector_type,
            started_at=datetime.now(),
        )

        try:
            self.connect(hostname, credential)
            logger.info(f"[{self.inspector_type}] Connected to {hostname}, {len(check_items)} items to check")

            for item in check_items:
                item_id = item["id"]
                script_ref = item.get("script_ref", "")

                try:
                    result = self.collect_item(item_id, script_ref)
                    report.results.append(result)
                    logger.info(f"[{self.inspector_type}] {hostname} {item_id}: {'OK' if result.success else 'FAIL'}")
                except Exception as e:
                    logger.error(f"[{self.inspector_type}] {hostname} {item_id} error: {e}")
                    report.results.append(CollectionResult(
                        check_item_id=item_id,
                        raw_output="",
                        success=False,
                        error_message=str(e),
                    ))

        except Exception as e:
            report.success = False
            report.error_message = f"Connection failed: {e}"
            logger.error(f"[{self.inspector_type}] {hostname} connection error: {e}")
        finally:
            try:
                self.disconnect()
            except Exception:
                pass
            report.completed_at = datetime.now()

        return report
