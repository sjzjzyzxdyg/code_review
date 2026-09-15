import hashlib
from datetime import datetime

from app.core.db import Database, get_db


def _fingerprint(file_path: str, rule_id: str | None, line: int) -> str:
    raw = f"{file_path}|{rule_id or ''}|{line}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SuppressionService:
    """Tracks issues a user has marked as false positives.

    Keyed by (project_id, file_path, rule_id, line) so the same finding is
    filtered out of future scans of the same project instead of resurfacing
    every run. Line-based matching means a suppression can go stale once
    surrounding code shifts the line number — acceptable for a first cut,
    but worth revisiting if that turns out to be noisy in practice.
    """

    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_db()

    def suppress(self, project_id: str, file_path: str, rule_id: str | None, line: int) -> None:
        doc_id = f"{project_id}:{_fingerprint(file_path, rule_id, line)}"
        self._db.upsert(
            "suppressions", doc_id, project_id, datetime.utcnow().isoformat(),
            {"project_id": project_id, "file_path": file_path, "rule_id": rule_id, "line": line},
        )

    def is_suppressed(self, project_id: str, file_path: str, rule_id: str | None, line: int) -> bool:
        doc_id = f"{project_id}:{_fingerprint(file_path, rule_id, line)}"
        return self._db.get("suppressions", doc_id) is not None

    def list_suppressions(self, project_id: str) -> list[dict]:
        return self._db.list("suppressions", parent_id=project_id)


suppression_service = SuppressionService()
