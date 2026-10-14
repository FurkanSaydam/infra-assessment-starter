"""Append-only JSON Lines audit events."""
import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event, **fields):
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
