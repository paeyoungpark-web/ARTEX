"""Unix/Linux Inspector - SSH 기반 주통기 U-xx 항목 수집"""
import logging
import re
from pathlib import Path
from typing import Optional

from ..connectors.ssh import SSHConnector, SSHCredential
from .base import BaseInspector, CollectionResult

logger = logging.getLogger(__name__)

# 스크립트 기본 경로
SCRIPTS_BASE = Path(__file__).parent.parent.parent / "knowledge" / "scripts" / "unix"


class UnixInspector(BaseInspector):
    """Unix/Linux 서버 점검 Inspector
    
    SSH를 통해 원격 서버에 접속하여 주통기 U-01~U-72 수집 스크립트를 실행하고
    결과를 파싱하여 반환합니다. 시스템을 변경하지 않는 read-only 수집만 수행합니다.
    """

    inspector_type = "unix_inspector"

    def __init__(self, scripts_base: Optional[Path] = None, ssh_timeout: int = 30):
        self._ssh: Optional[SSHConnector] = None
        self._scripts_base = scripts_base or SCRIPTS_BASE
        self._ssh_timeout = ssh_timeout

    def connect(self, hostname: str, credential: dict) -> None:
        cred = SSHCredential(
            hostname=hostname,
            port=credential.get("port", 22),
            username=credential.get("username", "root"),
            password=credential.get("password"),
            key_filename=credential.get("key_filename"),
        )
        self._ssh = SSHConnector(cred, timeout=self._ssh_timeout)
        self._ssh.connect()

    def disconnect(self) -> None:
        if self._ssh:
            self._ssh.disconnect()
            self._ssh = None

    def collect_item(self, check_item_id: str, script_ref: str) -> CollectionResult:
        """단일 주통기 항목 수집 실행"""
        if not self._ssh:
            return CollectionResult(
                check_item_id=check_item_id,
                raw_output="",
                success=False,
                error_message="SSH not connected",
            )

        # 스크립트 파일 찾기
        if script_ref:
            script_path = self._scripts_base.parent.parent / script_ref
        else:
            script_path = self._scripts_base / f"{check_item_id}.sh"

        if not script_path.exists():
            return CollectionResult(
                check_item_id=check_item_id,
                raw_output="",
                success=False,
                error_message=f"Script not found: {script_path}",
            )

        # 원격 실행
        result = self._ssh.execute_script(str(script_path), timeout=60)

        # 출력 파싱
        parsed = self._parse_output(check_item_id, result.stdout)

        return CollectionResult(
            check_item_id=check_item_id,
            raw_output=result.stdout,
            parsed_data=parsed,
            success=result.success,
            error_message=result.stderr if not result.success else "",
        )

    def _parse_output(self, check_item_id: str, output: str) -> dict:
        """스크립트 출력을 구조화된 데이터로 파싱
        
        각 항목별 파서를 호출하고, 범용 파서를 fallback으로 사용
        """
        parser_map = {
            "U-01": self._parse_u01,
            "U-04": self._parse_u04,
            "U-05": self._parse_u05,
            "U-07": self._parse_file_perm,
            "U-08": self._parse_file_perm,
            "U-09": self._parse_file_perm,
            "U-10": self._parse_file_perm,
        }

        parser = parser_map.get(check_item_id, self._parse_generic)
        try:
            return parser(output)
        except Exception as e:
            logger.warning(f"Parse error for {check_item_id}: {e}")
            return self._parse_generic(output)

    def _parse_u01(self, output: str) -> dict:
        """U-01: root 계정 원격접속 제한"""
        data = {}

        # SSH PermitRootLogin
        match = re.search(r"PermitRootLogin\s+(\S+)", output, re.IGNORECASE)
        if match:
            data["ssh_permit_root_login"] = match.group(1).lower()
        elif "PermitRootLogin_NOT_SET" in output:
            data["ssh_permit_root_login"] = "NOT_SET"

        # Telnet
        data["telnet_active"] = "TELNET_INACTIVE" not in output

        # securetty pts count
        match = re.search(r"^(\d+)$", output, re.MULTILINE)
        if match and "securetty" in output:
            data["securetty_pts_count"] = int(match.group(1))
        else:
            data["securetty_pts_count"] = 0

        return data

    def _parse_u04(self, output: str) -> dict:
        """U-04: 패스워드 파일 보호"""
        data = {}
        match = re.search(r"EXPOSED_COUNT=(\d+)", output)
        if match:
            data["exposed_count"] = int(match.group(1))
        else:
            data["exposed_count"] = 0
        data["shadow_exists"] = "SHADOW_NOT_FOUND" not in output
        return data

    def _parse_u05(self, output: str) -> dict:
        """U-05: root PATH 설정"""
        data = {}
        match = re.search(r"DOT_IN_PATH=(\S+)", output)
        data["dot_in_path"] = match.group(1) == "YES" if match else False
        match = re.search(r"EMPTY_ELEMENT=(\S+)", output)
        data["empty_element"] = match.group(1) == "YES" if match else False
        match = re.search(r"ROOT_PATH=(.+)", output)
        data["root_path"] = match.group(1).strip() if match else ""
        return data

    def _parse_file_perm(self, output: str) -> dict:
        """U-07~U-10: 파일 소유자 및 권한"""
        data = {}
        match = re.search(r"OWNER=(\S+)", output)
        data["owner"] = match.group(1) if match else "unknown"
        match = re.search(r"PERM=(\d+)", output)
        data["perm"] = match.group(1) if match else "unknown"
        data["file_not_found"] = "NOT_FOUND" in output
        return data

    def _parse_generic(self, output: str) -> dict:
        """범용 파서: KEY=VALUE 패턴 추출"""
        data = {}
        for line in output.split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#") and not line.startswith("["):
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key and value:
                    data[key] = value
        data["raw_lines"] = [l.strip() for l in output.split("\n") if l.strip() and not l.startswith("===")]
        return data
