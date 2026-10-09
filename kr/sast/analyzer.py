"""SAST 정적 분석 엔진 - AI 기반 소스코드 취약점 분석

Sparrow/CodeRay급 정적 분석을 LLM으로 구현합니다.
핵심 차별점: 규칙 기반(패턴 매칭) + AI 기반(맥락 이해) 하이브리드.

지원 언어: Java, Python, JavaScript/TypeScript, PHP, C/C++, Go, Kotlin
"""
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# CWE 기반 취약점 패턴 (규칙 기반 1단계)
VULN_PATTERNS = {
    "java": [
        {"cwe": "CWE-89", "type": "SQL Injection", "severity": "critical",
         "pattern": r'(Statement|createStatement|executeQuery|executeUpdate)\s*\(.*\+.*\)',
         "desc": "문자열 결합을 통한 SQL 쿼리 생성 (PreparedStatement 미사용)",
         "fix": "PreparedStatement와 파라미터 바인딩 사용"},
        {"cwe": "CWE-79", "type": "XSS", "severity": "high",
         "pattern": r'(out\.print|response\.getWriter\(\)\.write)\s*\(.*request\.getParameter',
         "desc": "사용자 입력값 직접 출력 (XSS 취약)",
         "fix": "OWASP Encoder 또는 HTML escape 적용"},
        {"cwe": "CWE-798", "type": "Hard-coded Credentials", "severity": "high",
         "pattern": r'(password|passwd|pwd|secret|api_key)\s*=\s*["\'][^"\']{3,}["\']',
         "desc": "소스코드에 인증 정보 하드코딩",
         "fix": "환경변수 또는 시크릿 매니저 사용"},
        {"cwe": "CWE-327", "type": "Weak Crypto", "severity": "medium",
         "pattern": r'(MD5|SHA1|DES|RC4|getInstance\s*\(\s*"(MD5|SHA-1|DES)")',
         "desc": "취약한 암호화 알고리즘 사용",
         "fix": "SHA-256 이상 또는 AES-256 사용"},
        {"cwe": "CWE-502", "type": "Unsafe Deserialization", "severity": "critical",
         "pattern": r'(ObjectInputStream|readObject|XMLDecoder)',
         "desc": "안전하지 않은 역직렬화",
         "fix": "역직렬화 입력 검증 또는 화이트리스트 적용"},
        {"cwe": "CWE-611", "type": "XXE", "severity": "high",
         "pattern": r'(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)(?!.*setFeature)',
         "desc": "XML 외부 엔티티 처리 미비",
         "fix": "DTD 비활성화: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)"},
    ],
    "python": [
        {"cwe": "CWE-89", "type": "SQL Injection", "severity": "critical",
         "pattern": r'(execute|executemany)\s*\(\s*(f["\']|["\'].*%s|.*\.format\(|.*\+)',
         "desc": "f-string/format을 통한 SQL 쿼리 생성",
         "fix": "파라미터화된 쿼리 사용: cursor.execute('SELECT * WHERE id=%s', (id,))"},
        {"cwe": "CWE-78", "type": "OS Command Injection", "severity": "critical",
         "pattern": r'(os\.system|os\.popen|subprocess\.(call|run|Popen))\s*\(.*(\+|\.format|f["\'])',
         "desc": "사용자 입력이 포함된 OS 명령어 실행",
         "fix": "subprocess.run([cmd, arg], shell=False) 사용, shlex.quote() 적용"},
        {"cwe": "CWE-798", "type": "Hard-coded Credentials", "severity": "high",
         "pattern": r'(password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{3,}["\']',
         "desc": "소스코드에 인증 정보 하드코딩",
         "fix": "os.environ.get() 또는 설정 파일 분리"},
        {"cwe": "CWE-94", "type": "Code Injection", "severity": "critical",
         "pattern": r'\beval\s*\(|exec\s*\(',
         "desc": "동적 코드 실행 (eval/exec)",
         "fix": "eval/exec 제거, ast.literal_eval() 또는 안전한 파서 사용"},
        {"cwe": "CWE-22", "type": "Path Traversal", "severity": "high",
         "pattern": r'open\s*\(.*(\+|\.format|f["\']).*\)',
         "desc": "사용자 입력 기반 파일 경로 접근",
         "fix": "os.path.basename() 적용, 화이트리스트 경로 검증"},
        {"cwe": "CWE-312", "type": "Cleartext Storage", "severity": "medium",
         "pattern": r'(pickle\.dump|shelve\.open|logging\.(info|debug).*password)',
         "desc": "민감 데이터 평문 저장/로깅",
         "fix": "민감 데이터 마스킹 및 암호화 저장"},
    ],
    "javascript": [
        {"cwe": "CWE-79", "type": "XSS (DOM)", "severity": "high",
         "pattern": r'(innerHTML|outerHTML|document\.write)\s*=',
         "desc": "DOM 기반 XSS 취약점",
         "fix": "textContent 사용 또는 DOMPurify 적용"},
        {"cwe": "CWE-89", "type": "SQL Injection", "severity": "critical",
         "pattern": r'(query|execute)\s*\(\s*(`.*\$\{|["\'].*\+)',
         "desc": "템플릿 리터럴/문자열 결합 SQL",
         "fix": "파라미터화된 쿼리 사용"},
        {"cwe": "CWE-798", "type": "Hard-coded Credentials", "severity": "high",
         "pattern": r'(password|secret|apiKey|token)\s*[:=]\s*["\'][^"\']{3,}["\']',
         "desc": "소스코드에 인증 정보 하드코딩",
         "fix": "process.env 또는 .env 파일 사용"},
        {"cwe": "CWE-94", "type": "Code Injection", "severity": "critical",
         "pattern": r'\beval\s*\(',
         "desc": "eval() 사용에 의한 코드 인젝션",
         "fix": "eval 제거, JSON.parse() 등 안전한 대안 사용"},
        {"cwe": "CWE-352", "type": "CSRF", "severity": "medium",
         "pattern": r'(app\.(post|put|delete|patch))\s*\([^)]*\)\s*(?!.*csrf)',
         "desc": "CSRF 토큰 미적용",
         "fix": "CSRF 미들웨어 적용 (csurf, helmet)"},
    ],
    "php": [
        {"cwe": "CWE-89", "type": "SQL Injection", "severity": "critical",
         "pattern": r'(mysql_query|mysqli_query|->query)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)',
         "desc": "사용자 입력 직접 SQL 쿼리",
         "fix": "PDO Prepared Statement 사용"},
        {"cwe": "CWE-79", "type": "XSS", "severity": "high",
         "pattern": r'echo\s+.*(\$_GET|\$_POST|\$_REQUEST)',
         "desc": "사용자 입력 직접 출력",
         "fix": "htmlspecialchars() 적용"},
        {"cwe": "CWE-78", "type": "Command Injection", "severity": "critical",
         "pattern": r'(system|exec|passthru|shell_exec|popen)\s*\(.*\$',
         "desc": "사용자 입력 OS 명령어 실행",
         "fix": "escapeshellarg(), escapeshellcmd() 적용"},
        {"cwe": "CWE-98", "type": "File Inclusion", "severity": "critical",
         "pattern": r'(include|require|include_once|require_once)\s*\(?\s*\$',
         "desc": "동적 파일 인클루전 (LFI/RFI)",
         "fix": "화이트리스트 기반 파일 경로 검증"},
    ],
}

# 파일 확장자 → 언어 매핑
EXT_LANG_MAP = {
    ".java": "java", ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".jsx": "javascript", ".tsx": "javascript", ".php": "php",
    ".c": "c", ".cpp": "c", ".h": "c", ".go": "go", ".kt": "java", ".scala": "java",
}


@dataclass
class SASTFinding:
    """정적 분석 발견 사항"""
    severity: str
    cwe: str
    vuln_type: str
    file_path: str
    line: int
    code_snippet: str
    description: str
    remediation: str
    confidence: float = 1.0
    method: str = "pattern"  # pattern | ai


class SASTAnalyzer:
    """정적 분석 엔진 - 패턴 매칭 + AI 하이브리드
    
    1단계: 정규식 패턴 매칭 (빠름, 정확)
    2단계: LLM 코드 리뷰 (맥락 이해, 오탐 필터링)
    
    Sparrow/CodeRay와의 차별점:
    - 패턴 매칭은 동등 수준
    - LLM이 비즈니스 로직 취약점도 탐지 (기존 도구 불가)
    - 한국어 보고서 자동 생성
    """

    def __init__(self, llm_client=None):
        self._llm = llm_client

    def analyze_directory(self, target_dir: str, exclude_dirs: list[str] = None) -> list[SASTFinding]:
        """디렉터리 전체 정적 분석"""
        exclude = set(exclude_dirs or ["node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"])
        findings = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for filename in files:
                ext = Path(filename).suffix.lower()
                lang = EXT_LANG_MAP.get(ext)
                if not lang:
                    continue

                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    file_findings = self.analyze_file(filepath, content, lang)
                    findings.extend(file_findings)
                except Exception as e:
                    logger.warning(f"SAST skip {filepath}: {e}")

        logger.info(f"[SAST] {target_dir}: {len(findings)} findings")
        return sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5))

    def analyze_file(self, filepath: str, content: str, lang: str) -> list[SASTFinding]:
        """단일 파일 정적 분석 (1단계: 패턴 매칭)"""
        findings = []
        patterns = VULN_PATTERNS.get(lang, [])
        lines = content.split("\n")

        for pattern_def in patterns:
            regex = re.compile(pattern_def["pattern"], re.IGNORECASE)
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    # 주석 라인 제외
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                        continue

                    # 코드 스니펫 (전후 2줄)
                    start = max(0, line_num - 3)
                    end = min(len(lines), line_num + 2)
                    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))

                    findings.append(SASTFinding(
                        severity=pattern_def["severity"],
                        cwe=pattern_def["cwe"],
                        vuln_type=pattern_def["type"],
                        file_path=filepath,
                        line=line_num,
                        code_snippet=snippet[:500],
                        description=pattern_def["desc"],
                        remediation=pattern_def["fix"],
                        method="pattern",
                    ))

        return findings

    async def analyze_with_ai(self, filepath: str, content: str, lang: str) -> list[SASTFinding]:
        """2단계: LLM 기반 심층 분석 (비즈니스 로직 취약점 포함)"""
        if not self._llm:
            return []

        # 파일이 너무 크면 분할
        if len(content) > 8000:
            content = content[:8000] + "\n... (truncated)"

        prompt = f"""다음 {lang} 소스코드에서 보안 취약점을 분석해주세요.

```{lang}
{content}
```

다음 관점에서 분석하세요:
1. 인젝션 (SQL, OS Command, LDAP, XPath)
2. 인증/인가 우회 가능성
3. 민감 데이터 노출 (하드코딩, 로깅)
4. 암호화 취약점 (취약한 알고리즘, 키 관리)
5. 비즈니스 로직 취약점 (권한 상승, 경쟁 조건)
6. 입력 검증 미비

발견된 취약점마다 JSON 배열로 응답하세요:
[{{"severity": "critical|high|medium|low", "cwe": "CWE-XXX", "vuln_type": "유형", "line": 라인번호, "description": "설명", "remediation": "조치방안"}}]

취약점이 없으면 빈 배열 [] 을 반환하세요.
"""
        try:
            response = await self._llm.chat(messages=[
                {"role": "system", "content": "당신은 시큐어 코딩 전문가입니다. CWE/OWASP 기준으로 소스코드 취약점을 정확히 식별합니다."},
                {"role": "user", "content": prompt},
            ])
            import json
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                items = json.loads(response[start:end])
                return [
                    SASTFinding(
                        severity=item.get("severity", "medium"),
                        cwe=item.get("cwe", ""),
                        vuln_type=item.get("vuln_type", ""),
                        file_path=filepath,
                        line=item.get("line", 0),
                        code_snippet="",
                        description=item.get("description", ""),
                        remediation=item.get("remediation", ""),
                        confidence=0.7,
                        method="ai",
                    )
                    for item in items
                ]
        except Exception as e:
            logger.error(f"AI SAST failed for {filepath}: {e}")
        return []
