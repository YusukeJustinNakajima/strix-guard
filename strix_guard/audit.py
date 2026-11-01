"""監査ログ: verdicts.jsonl / decisions の記録"""
import json
import os
import time


class Audit:
    def __init__(self, run_dir: str | None = None):
        self.run_dir = run_dir
        if run_dir:
            os.makedirs(run_dir, exist_ok=True)
            self.path = os.path.join(run_dir, "verdicts.jsonl")
        else:
            self.path = None

    def record(self, rec: dict, source: str = "exec"):
        rec = dict(rec)
        rec.setdefault("ts", time.time())
        rec["source"] = source
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec
