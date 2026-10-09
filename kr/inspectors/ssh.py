"""SSH 커넥터 - Unix/Linux 서버 원격 스크립트 실행"""
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import paramiko

logger = logging.getLogger(__name__)


@dataclass
class SSHCredential:
    hostname: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_filename: Optional[str] = None
    passphrase: Optional[str] = None


@dataclass
class SSHResult:
    stdout: str
    stderr: str
    exit_code: int
    success: bool


class SSHConnector:
    """SSH를 통한 원격 스크립트 실행 (read-only)"""

    def __init__(self, credential: SSHCredential, timeout: int = 30):
        self.credential = credential
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        """SSH 연결 수립"""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.credential.hostname,
            "port": self.credential.port,
            "username": self.credential.username,
            "timeout": self.timeout,
        }

        if self.credential.key_filename:
            connect_kwargs["key_filename"] = self.credential.key_filename
            if self.credential.passphrase:
                connect_kwargs["passphrase"] = self.credential.passphrase
        elif self.credential.password:
            connect_kwargs["password"] = self.credential.password

        try:
            self._client.connect(**connect_kwargs)
            logger.info(f"SSH connected: {self.credential.hostname}:{self.credential.port}")
        except Exception as e:
            logger.error(f"SSH connection failed: {self.credential.hostname} - {e}")
            raise

    def disconnect(self) -> None:
        """SSH 연결 해제"""
        if self._client:
            self._client.close()
            self._client = None
            logger.info(f"SSH disconnected: {self.credential.hostname}")

    def execute_command(self, command: str, timeout: Optional[int] = None) -> SSHResult:
        """원격 명령어 실행"""
        if not self._client:
            raise RuntimeError("SSH not connected. Call connect() first.")

        t = timeout or self.timeout
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=t)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            return SSHResult(
                stdout=out,
                stderr=err,
                exit_code=exit_code,
                success=(exit_code == 0),
            )
        except Exception as e:
            logger.error(f"Command execution failed on {self.credential.hostname}: {e}")
            return SSHResult(stdout="", stderr=str(e), exit_code=-1, success=False)

    def execute_script(self, script_path: str, timeout: Optional[int] = None) -> SSHResult:
        """로컬 스크립트 파일을 원격에서 실행
        
        스크립트 내용을 stdin으로 전달하여 실행 (파일 업로드 불필요)
        """
        script_content = Path(script_path).read_text(encoding="utf-8")

        # bash에 stdin으로 스크립트 전달 (서버에 파일 남기지 않음)
        return self.execute_command(f"bash << 'ROTEMGUARD_SCRIPT_EOF'\n{script_content}\nROTEMGUARD_SCRIPT_EOF", timeout)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
