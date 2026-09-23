"""Small SQLite history store; authentication/identity is supplied by the host app."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class HistoryStore:
    def __init__(self, path: str = "scamshield.db", retention_days: int = 30):
        self.path = path
        self.retention_days = retention_days
        self._init()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL,
                kind TEXT NOT NULL, result_json TEXT NOT NULL,
                created_at TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS scans_owner_created ON scans(owner_id, created_at)")

    def purge(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self._connect() as db:
            db.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))

    def add(self, owner_id: str, kind: str, result: dict[str, Any]) -> int:
        self.purge()
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            cur = db.execute("INSERT INTO scans(owner_id,kind,result_json,created_at) VALUES(?,?,?,?)",
                             (owner_id, kind, json.dumps(result), now))
            return int(cur.lastrowid)

    def list(self, owner_id: str, limit: int = 50) -> list[dict[str, Any]]:
        self.purge()
        with self._connect() as db:
            rows = db.execute("SELECT id,kind,result_json,created_at FROM scans "
                              "WHERE owner_id=? ORDER BY id DESC LIMIT ?", (owner_id, limit)).fetchall()
        return [{"id": row[0], "kind": row[1], "result": json.loads(row[2]), "created_at": row[3]} for row in rows]

    def delete(self, owner_id: str, scan_id: int) -> bool:
        with self._connect() as db:
            cur = db.execute("DELETE FROM scans WHERE id=? AND owner_id=?", (scan_id, owner_id))
            return cur.rowcount == 1
