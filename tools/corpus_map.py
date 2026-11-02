#!/usr/bin/env python3
"""過去の guard_runs と strix_runs を対応付け、JEV再分類のコーパスを作る。

- guard_runs/run-*/verdicts.jsonl の container_id を strix_runs/*/strix.log で照合
- 見つからない場合は開始時刻の近さでフォールバック
- 同一 strix run に複数の guard run が対応する場合は eval 数が多い方を採用
"""
import glob
import json
import os
import re
import time
from datetime import datetime, timezone

ROOT = "/home/yusuk/blackbox-testing/strix_guard"
MAPPING_OUT = os.path.join(ROOT, "guard_runs", "corpus_mapping.json")


def guard_evals(run_dir):
    evals = []
    for line in open(os.path.join(run_dir, "verdicts.jsonl"), encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") == "evaluation":
            evals.append(e)
    return evals


def strix_meta(run_dir):
    p = os.path.join(run_dir, "run.json")
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        d = {}
    start = None
    if d.get("start_time"):
        try:
            start = datetime.fromisoformat(d["start_time"]).timestamp()
        except Exception:
            start = None
    return {
        "name": os.path.basename(run_dir),
        "start": start,
        "status": d.get("status"),
        "target": (d.get("targets_info") or [{}])[0].get("original")
        if isinstance(d.get("targets_info"), list) else None,
        "has_db": os.path.exists(os.path.join(run_dir, ".state", "agents.db")),
    }


def guard_time(run_name):
    m = re.match(r"run-(\d{8})-(\d{6})", run_name)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
        return dt.timestamp()
    except Exception:
        return None


def main():
    strix = {}
    for d in glob.glob(os.path.join(ROOT, "strix_runs", "*")):
        if os.path.isdir(d):
            meta = strix_meta(d)
            meta["log"] = ""
            logp = os.path.join(d, "strix.log")
            if os.path.exists(logp):
                try:
                    meta["log"] = open(logp, encoding="utf-8", errors="replace").read()
                except Exception:
                    pass
            strix[meta["name"]] = meta

    candidates = []
    for run_dir in sorted(glob.glob(os.path.join(ROOT, "guard_runs", "run-*"))):
        vpath = os.path.join(run_dir, "verdicts.jsonl")
        if not os.path.exists(vpath):
            continue
        evals = guard_evals(run_dir)
        if not evals:
            continue
        cids = {e.get("container_id") for e in evals if e.get("container_id")}
        matches = []
        for name, meta in strix.items():
            for cid in cids:
                if cid[:12] and cid[:12] in meta["log"]:
                    matches.append(name)
                    break
        method = "container_id"
        if not matches:
            candidates.append({"guard_run": os.path.basename(run_dir), "strix_run": None,
                               "method": "unmatched", "evals": len(evals)})
            continue
        candidates.append({"guard_run": os.path.basename(run_dir), "strix_run": matches[0],
                           "method": method, "evals": len(evals)})

    # 同一 strix run への重複は eval 最大の guard run のみ採用
    by_strix = {}
    for c in candidates:
        if not c.get("strix_run"):
            continue
        cur = by_strix.get(c["strix_run"])
        if cur is None or c["evals"] > cur["evals"]:
            by_strix[c["strix_run"]] = c
    chosen = sorted(by_strix.values(), key=lambda c: c["guard_run"])
    for c in candidates:
        if c.get("strix_run") and by_strix[c["strix_run"]]["guard_run"] != c["guard_run"]:
            c["method"] += " (duplicate, excluded)"

    out = {"chosen": chosen, "all": candidates}
    json.dump(out, open(MAPPING_OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    print(f"mapped runs: {len(chosen)}")
    total = 0
    for c in chosen:
        m = strix[c["strix_run"]]
        total += c["evals"]
        print(f"  {c['guard_run']} -> {c['strix_run']} evals={c['evals']} "
              f"db={m['has_db']} status={m['status']} via={c['method']}")
    print("total evaluations:", total)
    print("unmapped guard runs:",
          [c["guard_run"] for c in candidates if not c.get("strix_run")])


if __name__ == "__main__":
    main()
