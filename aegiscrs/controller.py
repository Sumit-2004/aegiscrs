import json
import sqlite3
import time
import uuid


class Controller:
    """State machine + audit log (plan §11.1). SQLite-backed, one row per event."""

    def __init__(self, db_path: str = "aegiscrs_state.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self):
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY, target TEXT, status TEXT, created_at REAL
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT, ts REAL, stage TEXT, payload TEXT
            )"""
        )
        self._conn.commit()

    def start_campaign(self, target_name: str) -> str:
        campaign_id = uuid.uuid4().hex[:12]
        self._conn.execute(
            "INSERT INTO campaigns (id, target, status, created_at) VALUES (?, ?, ?, ?)",
            (campaign_id, target_name, "running", time.time()),
        )
        self._conn.commit()
        self.log(campaign_id, "controller", {"event": "campaign_started", "target": target_name})
        return campaign_id

    def log(self, campaign_id: str, stage: str, payload: dict):
        self._conn.execute(
            "INSERT INTO events (campaign_id, ts, stage, payload) VALUES (?, ?, ?, ?)",
            (campaign_id, time.time(), stage, json.dumps(payload, default=str)),
        )
        self._conn.commit()

    def set_status(self, campaign_id: str, status: str):
        self._conn.execute("UPDATE campaigns SET status = ? WHERE id = ?", (status, campaign_id))
        self._conn.commit()
        self.log(campaign_id, "controller", {"event": "status_changed", "status": status})

    def elapsed_seconds(self, campaign_id: str) -> float:
        row = self._conn.execute(
            "SELECT created_at FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        return time.time() - row[0] if row else 0.0

    def events(self, campaign_id: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT ts, stage, payload FROM events WHERE campaign_id = ? ORDER BY id", (campaign_id,)
        )
        return [{"ts": ts, "stage": stage, "payload": json.loads(payload)} for ts, stage, payload in cur.fetchall()]
