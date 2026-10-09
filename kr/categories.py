"""취약점 진단 대상 카테고리 체계

주통기 기준 10개 영역을 체계적으로 분류하고,
각 대상 유형별 점검 항목, Inspector 유형, 접속 방법을 정의합니다.
"""
from dataclasses import dataclass, field


@dataclass
class CheckCategory:
    """점검 카테고리 정의"""
    id: str                          # server_unix, dbms, ...
    name: str                        # 표시명
    icon: str                        # UI 아이콘
    jutonggi_prefix: str             # 주통기 항목 접두사 (U, W, D, N, S, ...)
    subcategories: list[str]         # 세부 분류
    inspector_type: str              # 담당 Inspector
    connection_method: str           # 접속 방법
    item_count_range: str            # 대략적 항목 수
    isms_p_mapping: list[str]        # 연관 ISMS-P 항목
    description: str = ""


# === 전체 카테고리 정의 ===
CATEGORIES: dict[str, CheckCategory] = {
    "server_unix": CheckCategory(
        id="server_unix",
        name="Unix/Linux 서버",
        icon="🐧",
        jutonggi_prefix="U",
        subcategories=["계정관리", "파일및디렉터리관리", "서비스관리", "패치관리", "로그관리"],
        inspector_type="unix_inspector",
        connection_method="SSH (22/tcp)",
        item_count_range="U-01 ~ U-72 (72개)",
        isms_p_mapping=["2.5.1", "2.5.2", "2.6.1", "2.9.1", "2.9.3", "2.10.1", "2.11.2"],
        description="CentOS, RHEL, Ubuntu, Debian, AIX, HP-UX 등",
    ),
    "server_windows": CheckCategory(
        id="server_windows",
        name="Windows 서버",
        icon="🪟",
        jutonggi_prefix="W",
        subcategories=["계정관리", "서비스관리", "패치관리", "로그관리", "보안관리", "DB관리"],
        inspector_type="windows_inspector",
        connection_method="WinRM (5985/tcp) / PowerShell Remoting",
        item_count_range="W-01 ~ W-84 (84개)",
        isms_p_mapping=["2.5.1", "2.5.2", "2.6.1", "2.9.1", "2.10.1", "2.11.2"],
        description="Windows Server 2016/2019/2022",
    ),
    "dbms": CheckCategory(
        id="dbms",
        name="데이터베이스 (DBMS)",
        icon="🗄️",
        jutonggi_prefix="D",
        subcategories=["계정관리", "접근관리", "옵션관리", "패치관리", "로그관리"],
        inspector_type="db_inspector",
        connection_method="DB 커넥터 (Oracle:1521, MySQL:3306, MSSQL:1433, PostgreSQL:5432)",
        item_count_range="D-01 ~ D-24 (24개)",
        isms_p_mapping=["2.5.1", "2.5.2", "2.6.1", "2.6.2", "2.7.1", "2.9.3"],
        description="Oracle, MySQL/MariaDB, MSSQL, PostgreSQL, Tibero",
    ),
    "network": CheckCategory(
        id="network",
        name="네트워크 장비",
        icon="🌐",
        jutonggi_prefix="N",
        subcategories=["계정관리", "접근관리", "패치관리", "로그관리", "기능관리"],
        inspector_type="net_inspector",
        connection_method="SSH/Telnet + SNMP (161/udp)",
        item_count_range="N-01 ~ N-28 (28개)",
        isms_p_mapping=["2.5.1", "2.6.1", "2.6.4", "2.10.1"],
        description="라우터, L3/L2 스위치 (Cisco, Juniper, 삼성SDS 등)",
    ),
    "security": CheckCategory(
        id="security",
        name="보안장비",
        icon="🛡️",
        jutonggi_prefix="S",
        subcategories=["계정관리", "접근관리", "패치관리", "로그관리", "기능관리"],
        inspector_type="security_inspector",
        connection_method="웹 콘솔 / SSH / SNMP",
        item_count_range="S-01 ~ S-24 (24개)",
        isms_p_mapping=["2.5.1", "2.6.1", "2.10.1", "2.11.1"],
        description="방화벽, IPS/IDS, WAF, NAC, VPN, DLP, 백신 등",
    ),
    "web": CheckCategory(
        id="web",
        name="웹 애플리케이션",
        icon="🌍",
        jutonggi_prefix="WEB",
        subcategories=["입력값 검증", "인증/인가", "세션관리", "정보노출", "파일 보안", "기타"],
        inspector_type="web_inspector",
        connection_method="HTTP/HTTPS (DAST 스캔)",
        item_count_range="WEB-01 ~ WEB-28 (28개, OWASP 기반)",
        isms_p_mapping=["2.8.1", "2.8.2", "2.8.3", "2.10.2", "2.11.2"],
        description="웹 취약점 (SQL Injection, XSS, CSRF 등) + SAST 정적분석",
    ),
    "pc": CheckCategory(
        id="pc",
        name="PC (업무용 단말)",
        icon="💻",
        jutonggi_prefix="PC",
        subcategories=["계정관리", "서비스관리", "패치관리", "보안관리"],
        inspector_type="windows_inspector",
        connection_method="WinRM / Agent 기반",
        item_count_range="PC-01 ~ PC-19 (19개)",
        isms_p_mapping=["2.5.2", "2.6.1", "2.9.1"],
        description="Windows 10/11 업무용 PC, Mac (보안 설정 점검)",
    ),
    "cloud": CheckCategory(
        id="cloud",
        name="클라우드",
        icon="☁️",
        jutonggi_prefix="CLD",
        subcategories=["접근통제", "보안관리", "네트워크보안", "데이터보호"],
        inspector_type="cloud_inspector",
        connection_method="CSP API (AWS/Azure/GCP/NCP)",
        item_count_range="CLD-01 ~ CLD-30+ (CSP별 상이)",
        isms_p_mapping=["2.6.1", "2.6.4", "2.7.1", "2.10.2"],
        description="AWS, Azure, GCP, NCP 클라우드 인프라 보안 설정",
    ),
    "ics": CheckCategory(
        id="ics",
        name="제어시스템 (OT/ICS)",
        icon="🏭",
        jutonggi_prefix="ICS",
        subcategories=["계정관리", "서비스관리", "패치관리", "네트워크접근통제",
                        "물리적접근통제", "보안위협탐지", "복구대응", "보안관리"],
        inspector_type="ics_inspector",
        connection_method="수동 점검 (가용성 우선)",
        item_count_range="ICS 별도 체계",
        isms_p_mapping=["2.6.1", "2.6.4", "2.10.1", "2.12.1"],
        description="SCADA, PLC, DCS 등 산업 제어시스템 (주의: 가용성 최우선)",
    ),
    "mobile": CheckCategory(
        id="mobile",
        name="모바일 앱",
        icon="📱",
        jutonggi_prefix="MOB",
        subcategories=["데이터저장", "통신보안", "인증/인가", "코드보안", "플랫폼보안"],
        inspector_type="mobile_inspector",
        connection_method="APK/IPA 정적분석 + 동적 프록시",
        item_count_range="MOB-01 ~ MOB-30+ (OWASP MASTG 기반)",
        isms_p_mapping=["2.7.1", "2.8.1", "2.8.2"],
        description="Android/iOS 모바일 앱 보안 점검",
    ),
}


def get_category(category_id: str) -> CheckCategory:
    return CATEGORIES.get(category_id)


def get_all_categories() -> list[CheckCategory]:
    return list(CATEGORIES.values())


def get_categories_for_isms_p(isms_p_item: str) -> list[CheckCategory]:
    """ISMS-P 항목과 연관된 카테고리 목록"""
    return [c for c in CATEGORIES.values() if isms_p_item in c.isms_p_mapping]
