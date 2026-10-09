"""판정 엔진 - 2단계 판정 (결정론적 룰 → LLM fallback)

로뎀가드 고유 컴포넌트. ARTEX는 Worker가 직접 판단하지만,
로뎀가드는 수집(Inspector)과 판정(JudgmentEngine)을 분리합니다.
"""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# 판정 룰 기본 경로
RULES_BASE = Path(__file__).parent.parent.parent / "knowledge" / "rules"


@dataclass
class JudgmentResult:
    """판정 결과"""
    check_item_id: str
    verdict: str           # pass | fail | manual_review | not_applicable
    method: str            # rule | llm | manual
    confidence: float      # 0.0 ~ 1.0
    reason: str            # 판정 근거
    remediation: str = ""  # 맞춤형 조치 권고


class RuleEngine:
    """결정론적 룰 기반 판정 (1단계)
    
    80%+ 항목은 규칙으로 자동 판정 가능.
    YAML 룰 파일을 로드하여 수집 데이터와 대조합니다.
    """

    def __init__(self, rules_base: Optional[Path] = None):
        self._rules_base = rules_base or RULES_BASE
        self._rules_cache: dict[str, dict] = {}

    def load_rule(self, check_item_id: str, asset_type: str) -> Optional[dict]:
        """판정 룰 로드"""
        cache_key = f"{asset_type}/{check_item_id}"
        if cache_key in self._rules_cache:
            return self._rules_cache[cache_key]

        # 타입별 서브디렉터리에서 룰 파일 탐색
        type_map = {
            "server_unix": "unix",
            "server_windows": "windows",
            "dbms": "dbms",
        }
        subdir = type_map.get(asset_type, "unix")
        rule_path = self._rules_base / subdir / f"{check_item_id}.rule.yaml"

        if not rule_path.exists():
            return None

        with open(rule_path) as f:
            rule = yaml.safe_load(f)

        self._rules_cache[cache_key] = rule
        return rule

    def evaluate(self, check_item_id: str, asset_type: str,
                 parsed_data: dict) -> Optional[JudgmentResult]:
        """룰 기반 판정 실행
        
        Returns:
            JudgmentResult if rule matches, None if no applicable rule found
        """
        rule = self.load_rule(check_item_id, asset_type)
        if not rule or "verdict_rules" not in rule:
            return None

        for r in rule["verdict_rules"]:
            if self._match_rule(r, parsed_data):
                return JudgmentResult(
                    check_item_id=check_item_id,
                    verdict=r["verdict"],
                    method="rule",
                    confidence=1.0,
                    reason=r.get("condition", "Rule matched"),
                )

        return None

    def _match_rule(self, rule: dict, data: dict) -> bool:
        """단일 룰 매칭"""
        field_name = rule.get("field", "")
        operator = rule.get("operator", "")
        expected = rule.get("value")

        actual = data.get(field_name)
        if actual is None:
            return False

        # 기본 조건 평가
        if not self._eval_condition(actual, operator, expected):
            return False

        # 추가 조건이 있으면 함께 평가
        extra_field = rule.get("extra_field")
        if extra_field:
            extra_actual = data.get(extra_field)
            extra_op = rule.get("extra_operator", "")
            extra_val = rule.get("extra_value")
            if extra_actual is not None:
                if not self._eval_condition(extra_actual, extra_op, extra_val):
                    return False

        return True

    def _eval_condition(self, actual, operator: str, expected) -> bool:
        """조건 평가"""
        if operator == "equals":
            return str(actual).lower() == str(expected).lower()
        elif operator == "not_equals":
            return str(actual).lower() != str(expected).lower()
        elif operator == "in":
            return str(actual).lower() in [str(v).lower() for v in expected]
        elif operator == "greater_than":
            return float(actual) > float(expected)
        elif operator == "less_than":
            return float(actual) < float(expected)
        elif operator == "perm_lte":
            return self._perm_compare(str(actual), str(expected)) <= 0
        elif operator == "perm_gt":
            return self._perm_compare(str(actual), str(expected)) > 0
        elif operator == "contains":
            return str(expected).lower() in str(actual).lower()
        return False

    def _perm_compare(self, actual: str, reference: str) -> int:
        """Unix 파일 퍼미션 비교 (각 자릿수별)
        
        644 vs 644 = 0 (같음)
        755 vs 644 = 1 (actual이 더 개방적)
        400 vs 644 = -1 (actual이 더 제한적)
        """
        a = actual.zfill(3)
        r = reference.zfill(3)
        for i in range(3):
            if int(a[i]) > int(r[i]):
                return 1
        if a == r:
            return 0
        return -1


class LLMJudge:
    """LLM 기반 판정 (2단계 fallback)
    
    결정론적 룰로 판정 불가한 항목에 대해 LLM이 맥락을 고려하여 판정.
    RAG로 규정 지식베이스를 참조합니다.
    """

    def __init__(self, llm_client=None, knowledge_base=None):
        self._llm = llm_client
        self._kb = knowledge_base

    async def evaluate(self, check_item_id: str, check_item_info: dict,
                       parsed_data: dict, raw_output: str,
                       asset_context: dict) -> JudgmentResult:
        """LLM 기반 판정"""
        if not self._llm:
            return JudgmentResult(
                check_item_id=check_item_id,
                verdict="manual_review",
                method="llm",
                confidence=0.0,
                reason="LLM not configured, requires manual review",
            )

        # 프롬프트 구성
        prompt = self._build_prompt(check_item_id, check_item_info, parsed_data, raw_output, asset_context)

        try:
            response = await self._llm.chat(
                messages=[
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )

            # 응답 파싱
            return self._parse_response(check_item_id, response)
        except Exception as e:
            logger.error(f"LLM judgment failed for {check_item_id}: {e}")
            return JudgmentResult(
                check_item_id=check_item_id,
                verdict="manual_review",
                method="llm",
                confidence=0.0,
                reason=f"LLM error: {e}",
            )

    def _build_prompt(self, check_item_id: str, info: dict,
                      parsed: dict, raw: str, ctx: dict) -> str:
        return f"""다음 주통기 취약점 진단 항목의 수집 결과를 판정해주세요.

## 점검 항목
- ID: {check_item_id}
- 제목: {info.get('title', '')}
- 양호 기준: {info.get('pass_criteria', '')}
- 취약 기준: {info.get('fail_criteria', '')}

## 대상 시스템
- 호스트명: {ctx.get('hostname', '')}
- OS: {ctx.get('os_family', '')} {ctx.get('os_version', '')}

## 수집 결과 (파싱)
{parsed}

## 수집 원본 출력
```
{raw[:2000]}
```

## 요청
위 수집 결과를 기반으로 판정해주세요. 반드시 아래 JSON 형식으로 응답하세요:
{{"verdict": "pass 또는 fail 또는 manual_review", "confidence": 0.0~1.0, "reason": "판정 근거", "remediation": "취약 시 조치 방법"}}
"""

    def _parse_response(self, check_item_id: str, response: str) -> JudgmentResult:
        """LLM 응답 파싱"""
        import json
        try:
            # JSON 블록 추출
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                return JudgmentResult(
                    check_item_id=check_item_id,
                    verdict=data.get("verdict", "manual_review"),
                    method="llm",
                    confidence=float(data.get("confidence", 0.5)),
                    reason=data.get("reason", ""),
                    remediation=data.get("remediation", ""),
                )
        except (json.JSONDecodeError, ValueError):
            pass

        return JudgmentResult(
            check_item_id=check_item_id,
            verdict="manual_review",
            method="llm",
            confidence=0.0,
            reason="Failed to parse LLM response",
        )


JUDGE_SYSTEM_PROMPT = """당신은 한국 주요정보통신기반시설 기술적 취약점 진단 전문가입니다.
수집 스크립트의 출력 결과를 분석하여 주통기 가이드라인에 따라 양호/취약 판정을 내립니다.

판정 원칙:
1. 수집 데이터에 근거한 객관적 판정만 수행합니다.
2. 양호 기준을 모두 충족하면 pass, 하나라도 미충족이면 fail입니다.
3. 데이터가 불충분하면 manual_review로 판정합니다.
4. confidence는 판정 확실성을 0.0~1.0으로 표현합니다.
5. 취약 판정 시 구체적인 조치 방법을 제시합니다.
"""


class JudgmentEngine:
    """통합 판정 엔진 - 2단계 판정 파이프라인
    
    1단계: RuleEngine (결정론적, 빠름, 비용 0)
    2단계: LLMJudge (맥락 기반, 느림, 비용 발생)
    
    1단계에서 판정되면 LLM을 호출하지 않습니다.
    """

    def __init__(self, rules_base: Optional[Path] = None, llm_client=None):
        self.rule_engine = RuleEngine(rules_base)
        self.llm_judge = LLMJudge(llm_client)
        self._check_items_cache: dict[str, dict] = {}

    def load_check_item(self, check_item_id: str) -> dict:
        """체크 항목 정보 로드"""
        if check_item_id in self._check_items_cache:
            return self._check_items_cache[check_item_id]

        # YAML에서 로드
        knowledge_base = Path(__file__).parent.parent.parent / "knowledge" / "jutonggi"
        for subdir in ["unix", "windows", "dbms", "network", "security", "web"]:
            path = knowledge_base / subdir / f"{check_item_id}.yaml"
            if path.exists():
                with open(path) as f:
                    info = yaml.safe_load(f)
                    self._check_items_cache[check_item_id] = info
                    return info
        return {}

    async def judge(self, check_item_id: str, asset_type: str,
                    parsed_data: dict, raw_output: str = "",
                    asset_context: dict = None) -> JudgmentResult:
        """2단계 판정 실행"""

        # 파일 미존재 등 특수 케이스
        if parsed_data.get("file_not_found"):
            return JudgmentResult(
                check_item_id=check_item_id,
                verdict="pass",
                method="rule",
                confidence=1.0,
                reason="해당 파일/서비스가 존재하지 않아 점검 대상 아님 (양호)",
            )

        # 1단계: 결정론적 룰
        rule_result = self.rule_engine.evaluate(check_item_id, asset_type, parsed_data)
        if rule_result:
            logger.info(f"[Judgment] {check_item_id}: Rule verdict = {rule_result.verdict}")
            return rule_result

        # 2단계: LLM fallback
        logger.info(f"[Judgment] {check_item_id}: No rule match, falling back to LLM")
        check_info = self.load_check_item(check_item_id)
        return await self.llm_judge.evaluate(
            check_item_id, check_info, parsed_data, raw_output,
            asset_context or {}
        )
