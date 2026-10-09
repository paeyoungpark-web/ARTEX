"""Field Agent - 현장 맥북프로에서 구동되는 경량 수집 에이전트

맥미니의 풀스택 서버와 분리된 독립 실행 단위.
고객사 내부망에서 Inspector를 실행하고 결과를 로컬 SQLite에 저장한 뒤,
VPN 연결 시 맥미니로 동기화합니다.

핵심 원칙:
- 수집만 담당 (판정/보고서는 맥미니)
- 오프라인 동작 가능 (SQLite 버퍼)
- 16GB 맥북프로에서 가볍게 실행
"""
import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..inspectors.unix_inspector import UnixInspector

logger = logging.getLogger(__name__)

# === 설정 ===
FIELD_DATA_DIR = Path(os.getenv("FIELD_DATA_DIR", "./field_data"))
SYNC_TARGET_URL = os.getenv("SYNC_TARGET_URL", "")
SYNC_API_KEY = os.getenv("SYNC_API_KEY", "")
OFFLINE_MODE = os.getenv("OFFLINE_MODE", "true").lower() == "true"

# === SQLite 로컬 저장소 ===
DB_PATH = FIELD_DATA_DIR / "field.db"


def init_db():
    """로컬 SQLite DB 초기화"""
    FIELD_DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS collection_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            asset_hostname TEXT NOT NULL,
            asset_ip TEXT DEFAULT '',
            asset_type TEXT NOT NULL,
            check_item_id TEXT NOT NULL,
            raw_output TEXT DEFAULT '',
            parsed_data TEXT DEFAULT '{}',
            success INTEGER DEFAULT 1,
            error_message TEXT DEFAULT '',
            synced INTEGER DEFAULT 0,
            collected_at TEXT NOT NULL,
            synced_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS evidence_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id INTEGER REFERENCES collection_results(id),
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            synced INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            result_count INTEGER DEFAULT 0,
            success INTEGER DEFAULT 1,
            error_message TEXT DEFAULT '',
            synced_at TEXT NOT NULL
        );
    """)
    conn.close()


init_db()

# === FastAPI ===
app = FastAPI(
    title="로뎀가드 Field Agent",
    description="현장 수집 전용 에이전트 (맥북프로)",
    version="0.1.0",
)


class CollectRequest(BaseModel):
    """수집 요청"""
    project_id: int = 1
    hostname: str
    ip_address: str = ""
    asset_type: str = "server_unix"
    username: str = "root"
    password: str = ""
    port: int = 22
    key_filename: str = ""
    check_item_ids: list[str] = []  # 비어있으면 해당 유형 전체


class SyncRequest(BaseModel):
    """동기화 요청"""
    target_url: str = ""  # 비어있으면 환경변수 사용


@app.get("/health")
async def health():
    conn = sqlite3.connect(str(DB_PATH))
    unsynced = conn.execute("SELECT COUNT(*) FROM collection_results WHERE synced=0").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM collection_results").fetchone()[0]
    conn.close()
    return {
        "status": "ok",
        "service": "rotemguard-field",
        "version": "0.1.0",
        "offline_mode": OFFLINE_MODE,
        "sync_target": SYNC_TARGET_URL or "(not configured)",
        "local_results": total,
        "unsynced": unsynced,
    }


@app.post("/collect")
async def collect(req: CollectRequest):
    """단일 자산 수집 실행
    
    고객사 서버에 SSH 접속하여 주통기 항목 수집 후 로컬 SQLite에 저장.
    """
    from ..planner.planner import DiagnosisPlanner

    planner = DiagnosisPlanner()

    # 수집할 항목 결정
    if req.check_item_ids:
        item_ids = req.check_item_ids
    else:
        item_ids = planner.get_applicable_items(req.asset_type)

    if not item_ids:
        raise HTTPException(400, f"No check items for asset type: {req.asset_type}")

    check_items = [
        {"id": item_id, "script_ref": planner._check_items.get(item_id, {}).get("script_ref", "")}
        for item_id in item_ids
    ]

    # Inspector 선택 및 실행
    if req.asset_type in ("server_unix", "cloud"):
        inspector = UnixInspector()
    else:
        raise HTTPException(400, f"Inspector not yet implemented for: {req.asset_type}")

    credential = {
        "username": req.username,
        "password": req.password,
        "port": req.port,
    }
    if req.key_filename:
        credential["key_filename"] = req.key_filename

    report = inspector.execute(
        task_id=0,
        asset_id=0,
        hostname=req.hostname,
        credential=credential,
        check_items=check_items,
    )

    # 로컬 SQLite에 저장
    conn = sqlite3.connect(str(DB_PATH))
    saved_count = 0
    for result in report.results:
        conn.execute(
            """INSERT INTO collection_results 
               (project_id, asset_hostname, asset_ip, asset_type, check_item_id,
                raw_output, parsed_data, success, error_message, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                req.project_id,
                req.hostname,
                req.ip_address or req.hostname,
                req.asset_type,
                result.check_item_id,
                result.raw_output,
                json.dumps(result.parsed_data, ensure_ascii=False),
                1 if result.success else 0,
                result.error_message,
                datetime.now().isoformat(),
            ),
        )
        saved_count += 1

    # 증적 저장
    evidence_dir = FIELD_DATA_DIR / "evidence" / req.hostname
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for result in report.results:
        if result.raw_output:
            evidence_file = evidence_dir / f"{result.check_item_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            evidence_file.write_text(result.raw_output, encoding="utf-8")

    conn.commit()
    conn.close()

    # VPN 연결 시 자동 동기화 시도
    if not OFFLINE_MODE and SYNC_TARGET_URL:
        try:
            sync_result = await _sync_to_server()
            return {
                "status": "collected_and_synced",
                "hostname": req.hostname,
                "items_collected": saved_count,
                "items_successful": report.successful_items,
                "items_failed": report.failed_items,
                "sync": sync_result,
            }
        except Exception as e:
            logger.warning(f"Auto-sync failed (will retry later): {e}")

    return {
        "status": "collected_locally",
        "hostname": req.hostname,
        "items_collected": saved_count,
        "items_successful": report.successful_items,
        "items_failed": report.failed_items,
        "stored_at": str(DB_PATH),
        "note": "Use POST /sync to upload to Mac mini",
    }


@app.get("/results")
async def list_results(synced: Optional[int] = None, hostname: str = ""):
    """로컬 수집 결과 조회"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM collection_results WHERE 1=1"
    params = []
    if synced is not None:
        query += " AND synced=?"
        params.append(synced)
    if hostname:
        query += " AND asset_hostname=?"
        params.append(hostname)
    query += " ORDER BY collected_at DESC"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return {
        "total": len(rows),
        "results": [dict(r) for r in rows],
    }


@app.post("/sync")
async def sync(req: SyncRequest = SyncRequest()):
    """맥미니로 수집 결과 동기화"""
    target = req.target_url or SYNC_TARGET_URL
    if not target:
        raise HTTPException(400, "Sync target URL not configured. Set SYNC_TARGET_URL or pass target_url.")

    result = await _sync_to_server(target)
    return result


@app.post("/export")
async def export_data(output_dir: str = ""):
    """오프라인 내보내기 (USB 이관용)
    
    SQLite DB + 증적 파일을 하나의 디렉터리로 복사
    """
    export_dir = Path(output_dir) if output_dir else FIELD_DATA_DIR / "export" / datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir.mkdir(parents=True, exist_ok=True)

    import shutil

    # DB 복사
    shutil.copy2(str(DB_PATH), str(export_dir / "field.db"))

    # 증적 복사
    evidence_src = FIELD_DATA_DIR / "evidence"
    if evidence_src.exists():
        shutil.copytree(str(evidence_src), str(export_dir / "evidence"), dirs_exist_ok=True)

    return {
        "status": "exported",
        "path": str(export_dir),
        "note": "USB로 맥미니에 복사 후 POST /api/v1/sync/import 호출",
    }


async def _sync_to_server(target_url: str = "") -> dict:
    """맥미니 서버로 미동기화 결과 전송"""
    target = target_url or SYNC_TARGET_URL

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM collection_results WHERE synced=0").fetchall()

    if not rows:
        conn.close()
        return {"status": "nothing_to_sync", "count": 0}

    # 벌크 업로드
    payload = [
        {
            "project_id": r["project_id"],
            "hostname": r["asset_hostname"],
            "ip_address": r["asset_ip"],
            "asset_type": r["asset_type"],
            "check_item_id": r["check_item_id"],
            "raw_output": r["raw_output"],
            "parsed_data": json.loads(r["parsed_data"]),
            "success": bool(r["success"]),
            "error_message": r["error_message"],
            "collected_at": r["collected_at"],
        }
        for r in rows
    ]

    headers = {}
    if SYNC_API_KEY:
        headers["Authorization"] = f"Bearer {SYNC_API_KEY}"

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{target}/api/v1/sync/upload",
            json={"results": payload},
            headers=headers,
        )
        resp.raise_for_status()

    # 동기화 완료 표시
    now = datetime.now().isoformat()
    row_ids = [r["id"] for r in rows]
    placeholders = ",".join("?" * len(row_ids))
    conn.execute(f"UPDATE collection_results SET synced=1, synced_at=? WHERE id IN ({placeholders})", [now] + row_ids)
    conn.execute(
        "INSERT INTO sync_log (action, result_count, success, synced_at) VALUES (?, ?, 1, ?)",
        ("upload", len(rows), now),
    )
    conn.commit()
    conn.close()

    return {"status": "synced", "count": len(rows), "target": target}
