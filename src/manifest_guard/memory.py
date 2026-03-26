from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .models import Finding, FixAction


SCHEMA = '''
CREATE TABLE IF NOT EXISTS remediation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    namespace TEXT,
    issue_code TEXT NOT NULL,
    signature TEXT NOT NULL,
    severity TEXT NOT NULL,
    patch_name TEXT,
    applied INTEGER NOT NULL,
    success INTEGER NOT NULL,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_signature ON remediation_history(signature);
CREATE INDEX IF NOT EXISTS idx_history_issue_code ON remediation_history(issue_code);
'''


class MemoryStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def record(self, run_id: str, finding: Finding, action: FixAction | None, success: bool) -> None:
        patch_name = action.patch_name if action else None
        applied = 1 if action and action.applied else 0
        details = action.details if action else {}
        self.conn.execute(
            '''
            INSERT INTO remediation_history (
                run_id, created_at, resource_kind, resource_name, namespace,
                issue_code, signature, severity, patch_name, applied, success, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                run_id,
                int(time.time()),
                finding.resource_kind,
                finding.resource_name,
                finding.namespace,
                finding.issue_code if hasattr(finding, "issue_code") else finding.code,
                finding.signature or "",
                finding.severity,
                patch_name,
                applied,
                1 if success else 0,
                str(details),
            ),
        )
        self.conn.commit()

    def best_patch_for_signature(self, signature: str) -> str | None:
        rows = self.conn.execute(
            '''
            SELECT patch_name,
                   SUM(success) AS successes,
                   COUNT(*) AS total
            FROM remediation_history
            WHERE signature = ? AND patch_name IS NOT NULL
            GROUP BY patch_name
            HAVING total >= 1
            ORDER BY (CAST(successes AS FLOAT) / total) DESC, total DESC
            LIMIT 1
            ''',
            (signature,),
        ).fetchall()
        return rows[0][0] if rows else None

    def stats_for_signature(self, signature: str) -> dict[str, float | int]:
        row = self.conn.execute(
            '''
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(success), 0) AS successes
            FROM remediation_history
            WHERE signature = ?
            ''',
            (signature,),
        ).fetchone()
        total = int(row[0]) if row else 0
        successes = int(row[1]) if row else 0
        rate = round(successes / total, 3) if total else 0.0
        return {"total": total, "successes": successes, "success_rate": rate}
