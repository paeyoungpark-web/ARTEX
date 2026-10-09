"""컴플라이언스 프레임워크 정의

로뎀가드가 지원하는 모든 점검 기준 체계를 통합 관리합니다.
각 프레임워크는 독립적으로 또는 조합하여 사용할 수 있습니다.
"""
from dataclasses import dataclass, field


@dataclass
class FrameworkDomain:
    """프레임워크 내 점검 영역"""
    id: str
    name: str
    items: list[dict] = field(default_factory=list)  # [{id, title, description, risk, ...}]


@dataclass
class ComplianceFramework:
    """컴플라이언스 프레임워크"""
    id: str
    name: str
    full_name: str
    authority: str          # 주관 기관
    legal_basis: str        # 법적 근거
    version: str
    description: str
    domains: list[FrameworkDomain] = field(default_factory=list)
    total_items: int = 0


# ============================================================
# 1. 주요정보통신기반시설 기술적 취약점 진단 (주통기)
# ============================================================
JUTONGGI = ComplianceFramework(
    id="jutonggi",
    name="주통기",
    full_name="주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드",
    authority="과학기술정보통신부 / KISA",
    legal_basis="정보통신기반보호법 제9조",
    version="2025.12 개정판",
    description="주요정보통신기반시설로 지정된 시스템에 대한 기술적 취약점 진단 기준",
    total_items=313,
    domains=[
        FrameworkDomain(id="unix", name="Unix/Linux 서버", items=[
            # === 계정관리 (U-01 ~ U-04) ===
            {"id": "U-01", "cat": "계정관리", "title": "root 계정 원격접속 제한", "risk": "상"},
            {"id": "U-02", "cat": "계정관리", "title": "패스워드 복잡성 설정", "risk": "상"},
            {"id": "U-03", "cat": "계정관리", "title": "계정 잠금 임계값 설정", "risk": "상"},
            {"id": "U-04", "cat": "계정관리", "title": "패스워드 파일 보호", "risk": "상"},
            {"id": "U-44", "cat": "계정관리", "title": "root 이외의 UID가 '0' 금지", "risk": "중"},
            {"id": "U-45", "cat": "계정관리", "title": "root 계정 su 제한", "risk": "하"},
            {"id": "U-46", "cat": "계정관리", "title": "패스워드 최소 길이 설정", "risk": "중"},
            {"id": "U-47", "cat": "계정관리", "title": "패스워드 최대 사용기간 설정", "risk": "중"},
            {"id": "U-48", "cat": "계정관리", "title": "패스워드 최소 사용기간 설정", "risk": "중"},
            {"id": "U-49", "cat": "계정관리", "title": "불필요한 계정 제거", "risk": "하"},
            {"id": "U-50", "cat": "계정관리", "title": "관리자 그룹에 최소한의 계정 포함", "risk": "하"},
            {"id": "U-51", "cat": "계정관리", "title": "계정이 존재하지 않는 GID 금지", "risk": "하"},
            {"id": "U-52", "cat": "계정관리", "title": "동일한 UID 금지", "risk": "중"},
            {"id": "U-53", "cat": "계정관리", "title": "사용자 shell 점검", "risk": "하"},
            {"id": "U-54", "cat": "계정관리", "title": "Session Timeout 설정", "risk": "하"},
            # === 파일 및 디렉터리 관리 (U-05 ~ U-18) ===
            {"id": "U-05", "cat": "파일및디렉터리관리", "title": "root홈, 패스 디렉터리 권한 및 패스 설정", "risk": "상"},
            {"id": "U-06", "cat": "파일및디렉터리관리", "title": "파일 및 디렉터리 소유자 설정", "risk": "상"},
            {"id": "U-07", "cat": "파일및디렉터리관리", "title": "/etc/passwd 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-08", "cat": "파일및디렉터리관리", "title": "/etc/shadow 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-09", "cat": "파일및디렉터리관리", "title": "/etc/hosts 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-10", "cat": "파일및디렉터리관리", "title": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-11", "cat": "파일및디렉터리관리", "title": "/etc/syslog.conf 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-12", "cat": "파일및디렉터리관리", "title": "/etc/services 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-13", "cat": "파일및디렉터리관리", "title": "SUID,SGID 설정 파일점검", "risk": "상"},
            {"id": "U-14", "cat": "파일및디렉터리관리", "title": "사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-15", "cat": "파일및디렉터리관리", "title": "world writable 파일 점검", "risk": "상"},
            {"id": "U-16", "cat": "파일및디렉터리관리", "title": "/dev에 존재하지 않는 device 파일 점검", "risk": "상"},
            {"id": "U-17", "cat": "파일및디렉터리관리", "title": "$HOME/.rhosts, hosts.equiv 사용 금지", "risk": "상"},
            {"id": "U-18", "cat": "파일및디렉터리관리", "title": "접속 IP 및 포트 제한", "risk": "상"},
            {"id": "U-55", "cat": "파일및디렉터리관리", "title": "hosts.lpd 파일 소유자 및 권한 설정", "risk": "하"},
            {"id": "U-56", "cat": "파일및디렉터리관리", "title": "UMASK 설정 관리", "risk": "중"},
            {"id": "U-57", "cat": "파일및디렉터리관리", "title": "홈 디렉터리 소유자 및 권한 설정", "risk": "중"},
            {"id": "U-58", "cat": "파일및디렉터리관리", "title": "홈 디렉터리로 지정한 디렉터리의 존재 관리", "risk": "중"},
            {"id": "U-59", "cat": "파일및디렉터리관리", "title": "숨겨진 파일 및 디렉터리 검색 및 제거", "risk": "하"},
            # === 서비스 관리 (U-19 ~ U-41) ===
            {"id": "U-19", "cat": "서비스관리", "title": "Finger 서비스 비활성화", "risk": "상"},
            {"id": "U-20", "cat": "서비스관리", "title": "Anonymous FTP 비활성화", "risk": "상"},
            {"id": "U-21", "cat": "서비스관리", "title": "r 계열 서비스 비활성화", "risk": "상"},
            {"id": "U-22", "cat": "서비스관리", "title": "crond 파일 소유자 및 권한 설정", "risk": "상"},
            {"id": "U-23", "cat": "서비스관리", "title": "DoS 공격에 취약한 서비스 비활성화", "risk": "상"},
            {"id": "U-24", "cat": "서비스관리", "title": "NFS 서비스 비활성화", "risk": "상"},
            {"id": "U-25", "cat": "서비스관리", "title": "NFS 접근 통제", "risk": "상"},
            {"id": "U-26", "cat": "서비스관리", "title": "automountd 제거", "risk": "상"},
            {"id": "U-27", "cat": "서비스관리", "title": "RPC 서비스 확인", "risk": "상"},
            {"id": "U-28", "cat": "서비스관리", "title": "NIS, NIS+ 점검", "risk": "상"},
            {"id": "U-29", "cat": "서비스관리", "title": "tftp, talk 서비스 비활성화", "risk": "상"},
            {"id": "U-30", "cat": "서비스관리", "title": "Sendmail 버전 점검", "risk": "상"},
            {"id": "U-31", "cat": "서비스관리", "title": "스팸 메일 릴레이 제한", "risk": "상"},
            {"id": "U-32", "cat": "서비스관리", "title": "일반사용자의 Sendmail 실행 방지", "risk": "상"},
            {"id": "U-33", "cat": "서비스관리", "title": "DNS 보안 버전 패치", "risk": "상"},
            {"id": "U-34", "cat": "서비스관리", "title": "DNS Zone Transfer 설정", "risk": "상"},
            {"id": "U-35", "cat": "서비스관리", "title": "Apache 디렉터리 리스팅 제거", "risk": "상"},
            {"id": "U-36", "cat": "서비스관리", "title": "Apache 웹프로세스 권한 제한", "risk": "상"},
            {"id": "U-37", "cat": "서비스관리", "title": "Apache 상위 디렉터리 접근 금지", "risk": "상"},
            {"id": "U-38", "cat": "서비스관리", "title": "Apache 불필요한 파일 제거", "risk": "상"},
            {"id": "U-39", "cat": "서비스관리", "title": "Apache 링크 사용 금지", "risk": "상"},
            {"id": "U-40", "cat": "서비스관리", "title": "Apache 파일 업로드 및 다운로드 제한", "risk": "상"},
            {"id": "U-41", "cat": "서비스관리", "title": "Apache 웹 서비스 영역의 분리", "risk": "상"},
            {"id": "U-60", "cat": "서비스관리", "title": "ssh 원격접속 허용", "risk": "중"},
            {"id": "U-61", "cat": "서비스관리", "title": "ftp 서비스 확인", "risk": "하"},
            {"id": "U-62", "cat": "서비스관리", "title": "ftp 계정 shell 제한", "risk": "중"},
            {"id": "U-63", "cat": "서비스관리", "title": "ftpusers 파일 소유자 및 권한 설정", "risk": "하"},
            {"id": "U-64", "cat": "서비스관리", "title": "ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)", "risk": "중"},
            {"id": "U-65", "cat": "서비스관리", "title": "at 서비스 권한 설정", "risk": "중"},
            {"id": "U-66", "cat": "서비스관리", "title": "SNMP 서비스 구동 점검", "risk": "중"},
            {"id": "U-67", "cat": "서비스관리", "title": "SNMP 서비스 Community String의 복잡성 설정", "risk": "중"},
            # === 패치 관리 (U-42) ===
            {"id": "U-42", "cat": "패치관리", "title": "최신 보안패치 및 벤더 권고사항 적용", "risk": "상"},
            {"id": "U-68", "cat": "패치관리", "title": "로그온 시 경고 메시지 제공", "risk": "하"},
            # === 로그 관리 (U-43, U-69~U-72) ===
            {"id": "U-43", "cat": "로그관리", "title": "로그의 정기적 검토 및 보고", "risk": "상"},
            {"id": "U-69", "cat": "로그관리", "title": "NFS 설정파일 접근권한", "risk": "중"},
            {"id": "U-70", "cat": "로그관리", "title": "expn, vrfy 명령어 제한", "risk": "중"},
            {"id": "U-71", "cat": "로그관리", "title": "Apache 웹서비스 정보 숨김", "risk": "중"},
            {"id": "U-72", "cat": "로그관리", "title": "정책에 따른 시스템 로깅 설정", "risk": "하"},
        ]),
        FrameworkDomain(id="windows", name="Windows 서버", items=[
            {"id": "W-01", "cat": "계정관리", "title": "Administrator 계정 이름 바꾸기", "risk": "상"},
            {"id": "W-02", "cat": "계정관리", "title": "Guest 계정 비활성화", "risk": "상"},
            {"id": "W-03", "cat": "계정관리", "title": "불필요한 계정 제거", "risk": "상"},
            {"id": "W-04", "cat": "계정관리", "title": "계정 잠금 임계값 설정", "risk": "상"},
            {"id": "W-05", "cat": "계정관리", "title": "해독 가능한 암호화를 사용하여 암호 저장 해제", "risk": "상"},
            {"id": "W-06", "cat": "계정관리", "title": "관리자 그룹에 최소한의 사용자 포함", "risk": "상"},
            {"id": "W-07", "cat": "서비스관리", "title": "공유 권한 및 사용자 그룹 설정", "risk": "상"},
            {"id": "W-08", "cat": "서비스관리", "title": "하드디스크 기본 공유 제거", "risk": "상"},
            {"id": "W-09", "cat": "서비스관리", "title": "불필요한 서비스 제거", "risk": "상"},
            {"id": "W-10", "cat": "서비스관리", "title": "IIS 디렉터리 리스팅 제거", "risk": "상"},
            {"id": "W-11", "cat": "서비스관리", "title": "IIS CGI 실행 제한", "risk": "상"},
            {"id": "W-12", "cat": "서비스관리", "title": "IIS 상위 디렉터리 접근 금지", "risk": "상"},
            {"id": "W-13", "cat": "서비스관리", "title": "IIS 불필요한 파일 제거", "risk": "상"},
            {"id": "W-14", "cat": "서비스관리", "title": "IIS 웹프로세스 권한 제한", "risk": "상"},
            {"id": "W-15", "cat": "서비스관리", "title": "IIS 링크 사용 금지", "risk": "상"},
            {"id": "W-16", "cat": "서비스관리", "title": "IIS 파일 업로드 및 다운로드 제한", "risk": "상"},
            {"id": "W-17", "cat": "서비스관리", "title": "IIS DB 연결 취약점 점검", "risk": "상"},
            {"id": "W-18", "cat": "서비스관리", "title": "IIS 가상 디렉터리 삭제", "risk": "상"},
            {"id": "W-19", "cat": "패치관리", "title": "최신 서비스 팩 적용", "risk": "상"},
            {"id": "W-20", "cat": "로그관리", "title": "이벤트 로그 관리", "risk": "하"},
            {"id": "W-21", "cat": "보안관리", "title": "원격 레지스트리 서비스 비활성화", "risk": "상"},
            # ... W-22~W-84 추가 가능
        ]),
        FrameworkDomain(id="dbms", name="DBMS", items=[
            {"id": "D-01", "cat": "계정관리", "title": "기본 계정의 패스워드, 정책 등을 변경하여 사용", "risk": "상"},
            {"id": "D-02", "cat": "계정관리", "title": "Scott 등 Demonstration 및 불필요 계정 제거", "risk": "상"},
            {"id": "D-03", "cat": "계정관리", "title": "패스워드의 사용기간 및 복잡도 설정", "risk": "중"},
            {"id": "D-04", "cat": "계정관리", "title": "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 허용", "risk": "상"},
            {"id": "D-05", "cat": "접근관리", "title": "데이터베이스에 대해 최소 권한의 유저로 운영", "risk": "상"},
            {"id": "D-06", "cat": "접근관리", "title": "원격에서 DB 서버로의 접속 제한", "risk": "상"},
            {"id": "D-07", "cat": "접근관리", "title": "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근 제한", "risk": "중"},
            {"id": "D-08", "cat": "옵션관리", "title": "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거", "risk": "하"},
            {"id": "D-09", "cat": "옵션관리", "title": "데이터베이스의 주요 설정파일, 패스워드 파일 등의 접근 권한 관리", "risk": "중"},
            {"id": "D-10", "cat": "옵션관리", "title": "관리자 외 사용자의 오브젝트 소유 제한", "risk": "중"},
            {"id": "D-11", "cat": "패치관리", "title": "데이터베이스의 접근, 변경, 삭제 등의 감사기록 관리", "risk": "상"},
            {"id": "D-12", "cat": "로그관리", "title": "보안 패치 및 벤더 권고사항 적용", "risk": "상"},
        ]),
        FrameworkDomain(id="network", name="네트워크 장비", items=[
            {"id": "N-01", "cat": "계정관리", "title": "패스워드 설정", "risk": "상"},
            {"id": "N-02", "cat": "계정관리", "title": "패스워드 복잡성 설정", "risk": "상"},
            {"id": "N-03", "cat": "계정관리", "title": "암호화된 패스워드 사용", "risk": "상"},
            {"id": "N-04", "cat": "접근관리", "title": "VTY 접근(ACL) 설정", "risk": "상"},
            {"id": "N-05", "cat": "접근관리", "title": "Session Timeout 설정", "risk": "상"},
            {"id": "N-06", "cat": "접근관리", "title": "VTY 접속 시 안전한 프로토콜 사용", "risk": "상"},
            {"id": "N-07", "cat": "패치관리", "title": "최신 보안 패치 적용", "risk": "상"},
            {"id": "N-08", "cat": "로그관리", "title": "로깅 설정", "risk": "상"},
            {"id": "N-09", "cat": "기능관리", "title": "SNMP Community String 복잡성 설정", "risk": "상"},
            {"id": "N-10", "cat": "기능관리", "title": "SNMP ACL 설정", "risk": "상"},
            {"id": "N-11", "cat": "기능관리", "title": "불필요한 보조 입출력 포트 사용 금지", "risk": "상"},
        ]),
        FrameworkDomain(id="security", name="보안장비", items=[
            {"id": "S-01", "cat": "계정관리", "title": "보안장비 Default 계정 변경", "risk": "상"},
            {"id": "S-02", "cat": "계정관리", "title": "보안장비 Default 패스워드 변경", "risk": "상"},
            {"id": "S-03", "cat": "계정관리", "title": "보안장비 계정별 권한 설정", "risk": "상"},
            {"id": "S-04", "cat": "계정관리", "title": "보안장비 계정 관리", "risk": "상"},
            {"id": "S-05", "cat": "접근관리", "title": "보안장비 원격 관리 접근 통제", "risk": "상"},
            {"id": "S-06", "cat": "접근관리", "title": "보안장비 보안 접속", "risk": "상"},
            {"id": "S-07", "cat": "접근관리", "title": "보안장비 Session Timeout 설정", "risk": "상"},
            {"id": "S-08", "cat": "패치관리", "title": "보안장비 최신 패치 적용", "risk": "상"},
            {"id": "S-09", "cat": "로그관리", "title": "보안장비 로그 설정", "risk": "중"},
            {"id": "S-10", "cat": "로그관리", "title": "보안장비 정책 백업 설정", "risk": "중"},
            {"id": "S-11", "cat": "기능관리", "title": "보안장비 보안정책 관리", "risk": "상"},
        ]),
        FrameworkDomain(id="web", name="웹 취약점", items=[
            {"id": "WEB-01", "cat": "입력값검증", "title": "SQL Injection", "risk": "상"},
            {"id": "WEB-02", "cat": "입력값검증", "title": "Cross Site Scripting (XSS)", "risk": "상"},
            {"id": "WEB-03", "cat": "입력값검증", "title": "운영체제 명령 실행", "risk": "상"},
            {"id": "WEB-04", "cat": "입력값검증", "title": "파일 업로드", "risk": "상"},
            {"id": "WEB-05", "cat": "입력값검증", "title": "파일 다운로드", "risk": "상"},
            {"id": "WEB-06", "cat": "입력값검증", "title": "디렉터리 인덱싱", "risk": "중"},
            {"id": "WEB-07", "cat": "정보노출", "title": "관리자 페이지 노출", "risk": "상"},
            {"id": "WEB-08", "cat": "정보노출", "title": "경로 추적", "risk": "중"},
            {"id": "WEB-09", "cat": "입력값검증", "title": "LDAP 인젝션", "risk": "상"},
            {"id": "WEB-10", "cat": "세션관리", "title": "크로스사이트 리퀘스트 변조 (CSRF)", "risk": "상"},
        ]),
    ],
)

# ============================================================
# 2. 국가핵심기술 보호조치 점검
# ============================================================
NCT_PROTECTION = ComplianceFramework(
    id="nct",
    name="국가핵심기술 보호",
    full_name="국가핵심기술 보호조치 이행 실태점검",
    authority="산업통상자원부 / 국가정보원 / 산업기술보호협회(KAITS)",
    legal_basis="산업기술의 유출방지 및 보호에 관한 법률 제11조, 산업기술보호지침(2026.6.30 개정)",
    version="2026",
    description="국가핵심기술 보유·관리 기관의 기술보호 실태를 점검하는 기준 (71개 기술 분야)",
    total_items=78,
    domains=[
        FrameworkDomain(id="nct_mgmt", name="1. 관리적 보호조치", items=[
            {"id": "NCT-M01", "cat": "보호체계수립", "title": "기술보호 정책 및 절차 수립", "risk": "상",
             "desc": "국가핵심기술 보호를 위한 내규·지침 수립 및 주기적 검토"},
            {"id": "NCT-M02", "cat": "보호체계수립", "title": "기술보호 전담조직 및 관리책임자 지정", "risk": "상",
             "desc": "산업기술보호법 제10조에 따른 산업기술 보호 전담부서 및 관리책임자 지정"},
            {"id": "NCT-M03", "cat": "보호체계수립", "title": "국가핵심기술 등록·관리 현황", "risk": "상",
             "desc": "보유한 국가핵심기술 목록의 등록 및 변경사항 관리"},
            {"id": "NCT-M04", "cat": "보호체계수립", "title": "기술보호 교육·훈련 실시", "risk": "중",
             "desc": "연 1회 이상 기술보호 교육 실시 및 기록 관리"},
            {"id": "NCT-M05", "cat": "보호체계수립", "title": "기술보호 예산 편성 및 집행", "risk": "중",
             "desc": "기술보호 활동을 위한 별도 예산 확보"},
            {"id": "NCT-M06", "cat": "인력관리", "title": "핵심기술 취급인력 지정 및 관리", "risk": "상",
             "desc": "국가핵심기술 취급 전문인력 명단 관리 및 보안서약서 징구"},
            {"id": "NCT-M07", "cat": "인력관리", "title": "퇴직자 관리 및 전직 제한", "risk": "상",
             "desc": "퇴직·이직 시 비밀유지 서약 및 핵심기술 자료 반납 확인"},
            {"id": "NCT-M08", "cat": "인력관리", "title": "외부 인력(용역·파견 등) 관리", "risk": "상",
             "desc": "외부인력의 핵심기술 접근 제한 및 보안관리"},
            {"id": "NCT-M09", "cat": "인력관리", "title": "핵심기술 관련 신원조사", "risk": "중",
             "desc": "신규 채용 시 보안 적격성 확인"},
            {"id": "NCT-M10", "cat": "자산관리", "title": "핵심기술 자료의 분류·표시", "risk": "상",
             "desc": "핵심기술 관련 문서·도면·데이터에 보안등급 표시"},
            {"id": "NCT-M11", "cat": "자산관리", "title": "핵심기술 자료의 생산·보관·폐기 관리", "risk": "상",
             "desc": "자료 생애주기별 보안관리 절차 수립 및 이행"},
            {"id": "NCT-M12", "cat": "자산관리", "title": "핵심기술 관련 연구노트 관리", "risk": "중",
             "desc": "연구개발 과정의 기록물(연구노트) 체계적 관리"},
            {"id": "NCT-M13", "cat": "유출대응", "title": "기술유출 사고 대응 절차 수립", "risk": "상",
             "desc": "기술유출 의심·인지 시 보고·조사·대응 절차"},
            {"id": "NCT-M14", "cat": "유출대응", "title": "유출 사고 신고 체계", "risk": "상",
             "desc": "산업통상자원부/KAITS/경찰 신고 절차 및 연락체계"},
            {"id": "NCT-M15", "cat": "유출대응", "title": "기술보호 실태 자체점검 실시", "risk": "중",
             "desc": "연 1회 이상 기술보호 자체점검 실시 및 개선"},
        ]),
        FrameworkDomain(id="nct_physical", name="2. 물리적 보호조치", items=[
            {"id": "NCT-P01", "cat": "보호구역", "title": "보호구역 설정 및 관리", "risk": "상",
             "desc": "핵심기술 연구·생산 시설의 보호구역(제한/통제/금지구역) 설정"},
            {"id": "NCT-P02", "cat": "보호구역", "title": "출입통제 시스템 운영", "risk": "상",
             "desc": "생체인식/카드키 등 출입통제 시스템 설치 및 운영"},
            {"id": "NCT-P03", "cat": "보호구역", "title": "방문자 관리", "risk": "중",
             "desc": "외부 방문자 사전 승인, 에스코트, 기록 관리"},
            {"id": "NCT-P04", "cat": "보호구역", "title": "CCTV 설치 및 영상 관리", "risk": "중",
             "desc": "보호구역 내 CCTV 설치 및 영상 보관(30일 이상)"},
            {"id": "NCT-P05", "cat": "반출입통제", "title": "휴대용 저장매체(USB 등) 반출입 통제", "risk": "상",
             "desc": "USB, 외장하드, 카메라 등 저장매체 반출입 검사"},
            {"id": "NCT-P06", "cat": "반출입통제", "title": "모바일 기기 반입 통제", "risk": "상",
             "desc": "스마트폰, 태블릿 등 촬영·녹음 가능 기기 통제"},
            {"id": "NCT-P07", "cat": "반출입통제", "title": "핵심기술 자료 반출 승인 절차", "risk": "상",
             "desc": "핵심기술 자료의 외부 반출 시 승인·기록·회수 절차"},
            {"id": "NCT-P08", "cat": "시설보안", "title": "연구시설 잠금장치 관리", "risk": "중",
             "desc": "핵심기술 보관 캐비닛·서버룸 등 잠금장치 관리"},
            {"id": "NCT-P09", "cat": "시설보안", "title": "문서 파기 장비 구비", "risk": "하",
             "desc": "보안 문서 세단기 등 파기 장비 구비 및 사용"},
        ]),
        FrameworkDomain(id="nct_tech", name="3. 기술적 보호조치", items=[
            {"id": "NCT-T01", "cat": "접근통제", "title": "핵심기술 정보시스템 접근통제", "risk": "상",
             "desc": "핵심기술 관련 서버·DB·네트워크에 대한 접근권한 관리"},
            {"id": "NCT-T02", "cat": "접근통제", "title": "네트워크 분리(망분리) 적용", "risk": "상",
             "desc": "핵심기술 네트워크의 물리적/논리적 분리"},
            {"id": "NCT-T03", "cat": "접근통제", "title": "원격 접근 통제", "risk": "상",
             "desc": "VPN 등 원격 접속 시 인증 및 접근통제"},
            {"id": "NCT-T04", "cat": "데이터보호", "title": "핵심기술 데이터 암호화", "risk": "상",
             "desc": "저장 및 전송 시 암호화 적용 (AES-256 이상)"},
            {"id": "NCT-T05", "cat": "데이터보호", "title": "DRM/DLP 솔루션 적용", "risk": "상",
             "desc": "디지털 권한관리(DRM) 또는 데이터유출방지(DLP) 솔루션 운영"},
            {"id": "NCT-T06", "cat": "데이터보호", "title": "이메일 보안 (첨부파일 통제)", "risk": "중",
             "desc": "핵심기술 자료 이메일 첨부 제한 및 모니터링"},
            {"id": "NCT-T07", "cat": "데이터보호", "title": "출력물 통제", "risk": "중",
             "desc": "프린터 출력 로그 관리, 워터마크 적용"},
            {"id": "NCT-T08", "cat": "단말보안", "title": "단말기 보안 소프트웨어 설치", "risk": "상",
             "desc": "백신, 매체제어, 화면캡처방지 등 보안 SW 설치"},
            {"id": "NCT-T09", "cat": "단말보안", "title": "클라우드 서비스 사용 통제", "risk": "상",
             "desc": "개인 클라우드(드롭박스, 구글드라이브 등) 사용 차단"},
            {"id": "NCT-T10", "cat": "모니터링", "title": "보안 로그 모니터링 및 분석", "risk": "상",
             "desc": "이상 접근·대량 다운로드·비정상 시간 접속 등 모니터링"},
            {"id": "NCT-T11", "cat": "모니터링", "title": "취약점 점검 및 보안 패치", "risk": "중",
             "desc": "핵심기술 관련 시스템의 정기적 취약점 점검 (주통기 연계)"},
            {"id": "NCT-T12", "cat": "모니터링", "title": "백업 및 복구 체계 운영", "risk": "중",
             "desc": "핵심기술 데이터 정기 백업 및 복구 테스트"},
        ]),
        FrameworkDomain(id="nct_export", name="4. 수출·해외이전 통제", items=[
            {"id": "NCT-E01", "cat": "수출승인", "title": "수출승인 신청 절차 이행", "risk": "상",
             "desc": "국가핵심기술 수출 시 산업통상자원부 사전 승인 절차"},
            {"id": "NCT-E02", "cat": "수출승인", "title": "수출신고 절차 이행", "risk": "상",
             "desc": "국가연구개발사업 미수반 핵심기술 수출 시 신고"},
            {"id": "NCT-E03", "cat": "해외인수합병", "title": "해외 M&A 시 사전 신고", "risk": "상",
             "desc": "외국인의 국가핵심기술 보유 기업 인수·합병 시 신고 의무"},
            {"id": "NCT-E04", "cat": "기술이전", "title": "기술이전·공동연구 시 보안 조치", "risk": "상",
             "desc": "외국 기관과의 공동연구·기술이전 시 보안관리 계획 수립"},
            {"id": "NCT-E05", "cat": "기술이전", "title": "해외 학회·전시회 참가 시 보안관리", "risk": "중",
             "desc": "핵심기술 관련 발표자료 사전 보안성 검토"},
        ]),
    ],
)

# ============================================================
# 3. ISMS-P (기존, 참조용)
# ============================================================
ISMS_P = ComplianceFramework(
    id="ismsp",
    name="ISMS-P",
    full_name="정보보호 및 개인정보보호 관리체계 인증",
    authority="과학기술정보통신부 / 개인정보보호위원회 / KISA",
    legal_basis="정보통신망법 제47조, 개인정보보호법 제32조의2",
    version="2023",
    description="정보보호 및 개인정보보호 관리체계 인증 기준 (102개 항목)",
    total_items=102,
    domains=[
        FrameworkDomain(id="ismsp_1", name="1. 관리체계 수립 및 운영 (16개)", items=[]),
        FrameworkDomain(id="ismsp_2", name="2. 보호대책 요구사항 (64개)", items=[]),
        FrameworkDomain(id="ismsp_3", name="3. 개인정보 처리단계별 요구사항 (22개)", items=[]),
    ],
)

# === 전체 프레임워크 등록 ===
ALL_FRAMEWORKS: dict[str, ComplianceFramework] = {
    "jutonggi": JUTONGGI,
    "nct": NCT_PROTECTION,
    "ismsp": ISMS_P,
}


def get_framework(framework_id: str) -> ComplianceFramework:
    return ALL_FRAMEWORKS.get(framework_id)


def get_all_frameworks() -> list[ComplianceFramework]:
    return list(ALL_FRAMEWORKS.values())
