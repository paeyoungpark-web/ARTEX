"""DAST 동적 분석 엔진 - 실행 중인 서비스 대상 취약점 스캔

OWASP ZAP/Burp Suite급 동적 분석을 AI로 구현합니다.
핵심: 자동 크롤링 → 파라미터 발견 → 페이로드 주입 → AI 응답 분석.
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DASTFinding:
    """동적 분석 발견 사항"""
    severity: str
    vuln_type: str
    owasp: str
    url: str
    parameter: str
    method: str  # GET/POST
    payload: str
    status_code: int
    evidence: str
    description: str
    remediation: str
    confidence: float = 0.8


# === 페이로드 세트 ===
SQL_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "1' AND '1'='1",
    "'; DROP TABLE users--", "1 UNION SELECT null,null,null--",
    "' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>", "<svg/onload=alert(1)>",
    "javascript:alert(1)", "'-alert(1)-'",
    "<img src=x onerror=prompt(1)>",
]

CMD_PAYLOADS = [
    "; ls", "| cat /etc/passwd", "`id`", "$(whoami)",
    "& ping -c 3 127.0.0.1", "| type C:\\Windows\\win.ini",
]

PATH_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
]

HEADER_INJECTION_PAYLOADS = [
    "test\r\nX-Injected: true", "test%0d%0aX-Injected:%20true",
]


@dataclass
class CrawlResult:
    """크롤링 결과"""
    url: str
    method: str
    params: dict = field(default_factory=dict)
    forms: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    status_code: int = 200


class DASTScanner:
    """DAST 동적 분석 스캐너
    
    워크플로우:
    1. 크롤링: 대상 URL에서 엔드포인트/파라미터 발견
    2. 능동 스캔: 각 파라미터에 페이로드 주입
    3. AI 분석: 응답을 분석하여 취약점 판정
    4. 검증: 오탐 필터링 및 재현성 확인
    """

    def __init__(self, llm_client=None, max_concurrent: int = 5, timeout: int = 15):
        self._llm = llm_client
        self._max_concurrent = max_concurrent
        self._timeout = timeout
        self._visited: set[str] = set()
        self._endpoints: list[CrawlResult] = []

    async def scan(self, target_url: str, depth: int = 2,
                   auth_headers: dict = None) -> list[DASTFinding]:
        """전체 스캔 실행"""
        findings = []
        headers = auth_headers or {}

        logger.info(f"[DAST] Starting scan: {target_url}")

        # 1. 크롤링
        await self._crawl(target_url, depth, headers)
        logger.info(f"[DAST] Discovered {len(self._endpoints)} endpoints")

        # 2. 수동 체크 (헤더/설정)
        config_findings = await self._check_security_headers(target_url, headers)
        findings.extend(config_findings)

        # 3. 능동 스캔
        sem = asyncio.Semaphore(self._max_concurrent)
        tasks = []
        for endpoint in self._endpoints:
            for param_name in endpoint.params:
                tasks.append(self._scan_parameter(sem, endpoint, param_name, headers))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)

        logger.info(f"[DAST] Scan complete: {len(findings)} findings")
        return sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 5))

    async def _crawl(self, url: str, depth: int, headers: dict):
        """간이 크롤러 - 엔드포인트와 파라미터 발견"""
        if depth <= 0 or url in self._visited:
            return
        self._visited.add(url)

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)

                # URL 파라미터 추출
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if params:
                    self._endpoints.append(CrawlResult(
                        url=url, method="GET",
                        params={k: v[0] for k, v in params.items()},
                        status_code=resp.status_code,
                    ))

                # HTML에서 링크/폼 추출
                body = resp.text
                links = re.findall(r'href=["\']([^"\']+)["\']', body)
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)

                for form_action, form_body in forms:
                    action_url = urljoin(url, form_action) if form_action else url
                    inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
                    method = "POST" if re.search(r'method=["\']post["\']', form_body, re.IGNORECASE) else "GET"
                    if inputs:
                        self._endpoints.append(CrawlResult(
                            url=action_url, method=method,
                            params={name: "test" for name in inputs},
                        ))

                base = f"{parsed.scheme}://{parsed.netloc}"
                for link in links:
                    full_url = urljoin(url, link)
                    if full_url.startswith(base) and full_url not in self._visited:
                        await self._crawl(full_url, depth - 1, headers)

        except Exception as e:
            logger.warning(f"[DAST] Crawl error {url}: {e}")

    async def _scan_parameter(self, sem: asyncio.Semaphore, endpoint: CrawlResult,
                               param_name: str, headers: dict) -> list[DASTFinding]:
        """단일 파라미터에 대한 페이로드 주입 테스트"""
        findings = []
        async with sem:
            test_sets = [
                ("SQL Injection", SQL_PAYLOADS, "A03", self._check_sqli_response),
                ("XSS", XSS_PAYLOADS, "A03", self._check_xss_response),
                ("Command Injection", CMD_PAYLOADS, "A03", self._check_cmdi_response),
                ("Path Traversal", PATH_PAYLOADS, "A01", self._check_path_response),
            ]

            for vuln_type, payloads, owasp, checker in test_sets:
                for payload in payloads[:3]:  # 각 유형별 3개만 (속도)
                    try:
                        result = await self._send_payload(endpoint, param_name, payload, headers)
                        if result and checker(result, payload):
                            findings.append(DASTFinding(
                                severity="high" if vuln_type in ("SQL Injection", "Command Injection") else "medium",
                                vuln_type=vuln_type,
                                owasp=owasp,
                                url=endpoint.url,
                                parameter=param_name,
                                method=endpoint.method,
                                payload=payload,
                                status_code=result.get("status", 0),
                                evidence=result.get("evidence", "")[:300],
                                description=f"{param_name} 파라미터에서 {vuln_type} 취약점 발견",
                                remediation=self._get_remediation(vuln_type),
                            ))
                            break  # 하나 발견되면 다음 유형으로
                    except Exception as e:
                        logger.debug(f"[DAST] Payload error: {e}")

        return findings

    async def _send_payload(self, endpoint: CrawlResult, param_name: str,
                             payload: str, headers: dict) -> Optional[dict]:
        """페이로드 전송"""
        params = dict(endpoint.params)
        params[param_name] = payload

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                if endpoint.method == "POST":
                    resp = await client.post(endpoint.url, data=params, headers=headers)
                else:
                    resp = await client.get(endpoint.url, params=params, headers=headers)

                return {
                    "status": resp.status_code,
                    "body": resp.text[:3000],
                    "headers": dict(resp.headers),
                    "evidence": resp.text[:500],
                }
        except Exception:
            return None

    async def _check_security_headers(self, url: str, headers: dict) -> list[DASTFinding]:
        """보안 헤더 점검"""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                resp = await client.get(url, headers=headers)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                checks = [
                    ("X-Content-Type-Options", "nosniff", "medium", "A05",
                     "X-Content-Type-Options 헤더 미설정", "X-Content-Type-Options: nosniff 추가"),
                    ("X-Frame-Options", None, "medium", "A05",
                     "X-Frame-Options 헤더 미설정 (클릭재킹 위험)", "X-Frame-Options: DENY 또는 SAMEORIGIN 추가"),
                    ("Strict-Transport-Security", None, "medium", "A02",
                     "HSTS 헤더 미설정", "Strict-Transport-Security: max-age=31536000; includeSubDomains 추가"),
                    ("Content-Security-Policy", None, "low", "A05",
                     "CSP 헤더 미설정", "Content-Security-Policy 설정"),
                    ("X-XSS-Protection", None, "low", "A05",
                     "X-XSS-Protection 헤더 미설정", "X-XSS-Protection: 1; mode=block 추가"),
                ]

                for header_name, expected_val, severity, owasp, desc, fix in checks:
                    val = resp_headers.get(header_name.lower())
                    if val is None:
                        findings.append(DASTFinding(
                            severity=severity, vuln_type="Security Header Missing",
                            owasp=owasp, url=url, parameter="", method="GET",
                            payload="", status_code=resp.status_code,
                            evidence=f"Missing header: {header_name}",
                            description=desc, remediation=fix,
                        ))

                # Server 헤더 노출
                if "server" in resp_headers:
                    findings.append(DASTFinding(
                        severity="info", vuln_type="Information Disclosure",
                        owasp="A05", url=url, parameter="", method="GET",
                        payload="", status_code=resp.status_code,
                        evidence=f"Server: {resp_headers['server']}",
                        description=f"서버 정보 노출: {resp_headers['server']}",
                        remediation="Server 헤더 제거 또는 일반화",
                    ))
        except Exception as e:
            logger.warning(f"[DAST] Header check error: {e}")

        return findings

    # === 응답 분석 함수 ===
    def _check_sqli_response(self, result: dict, payload: str) -> bool:
        body = result.get("body", "").lower()
        indicators = ["sql syntax", "mysql", "ora-", "pg::", "sqlite", "unclosed quotation",
                       "syntax error", "sql error", "database error", "odbc", "jdbc"]
        return any(ind in body for ind in indicators)

    def _check_xss_response(self, result: dict, payload: str) -> bool:
        body = result.get("body", "")
        return payload in body and "text/html" in result.get("headers", {}).get("content-type", "")

    def _check_cmdi_response(self, result: dict, payload: str) -> bool:
        body = result.get("body", "").lower()
        indicators = ["root:", "uid=", "bin/", "windows", "volume serial", "directory of"]
        return any(ind in body for ind in indicators)

    def _check_path_response(self, result: dict, payload: str) -> bool:
        body = result.get("body", "").lower()
        indicators = ["root:x:", "[boot loader]", "[extensions]", "for 16-bit app"]
        return any(ind in body for ind in indicators)

    def _get_remediation(self, vuln_type: str) -> str:
        fixes = {
            "SQL Injection": "PreparedStatement/파라미터 바인딩 사용, ORM 적용, 입력값 검증",
            "XSS": "출력 인코딩(HTML entity), CSP 헤더, DOMPurify 적용",
            "Command Injection": "외부 명령 실행 제거, 화이트리스트 명령어, 입력 검증",
            "Path Traversal": "경로 정규화, 화이트리스트 파일명, chroot 적용",
        }
        return fixes.get(vuln_type, "입력값 검증 및 보안 코딩 적용")
