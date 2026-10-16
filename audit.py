"""Append-only JSONL audit log."""
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

class AuditLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def log(self, event, **fields):
        record = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
                  "event": event, **fields}
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
