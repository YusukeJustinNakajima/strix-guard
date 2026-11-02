#!/usr/bin/env python3
"""親ディレクトリの全 Strix 実行 (136) から exec_command を抽出し、モデル情報も付与する。"""
import glob
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter

sys.path.insert(0, "/home/yusuk/blackbox-testing/strix_guard")
from strix_guard.ledger import build_ledger_from_db, resolve_script  # noqa: E402
from strix_guard.policy import sandbox_internal  # noqa: E402

ROOT = "/home/yusuk/blackbox-testing"
OUT = "/home/yusuk/blackbox-testing/strix_guard/guard_runs/corpus_parent_attempts.jsonl"
RUNS_OUT = "/home/yusuk/blackbox-testing/strix_guard/guard_runs/corpus_parent_runs.json"


def short_model(name: str) -> str:
    s = (name or "").strip()
    if not s:
        return "unknown"
    s = s.split("/")[-1]
    return s


def run_info(run_dir: str):
    meta = {}
    try:
        meta = json.load(open(os.path.join(run_dir, "run.json"), encoding="utf-8"))
    except Exception:
        pass
    usage = meta.get("llm_usage") or {}
    agents = usage.get("agents") or []
    session_models = {}
    model_requests = Counter()
    for a in agents:
        aid = a.get("agent_id")
        model = short_model(a.get("model"))
        req = int(a.get("requests") or 0)
        if aid:
            session_models[aid] = model
        model_requests[model] += req
    dominant = model_requests.most_common(1)[0][0] if model_requests else "unknown"
    return {
        "run": os.path.basename(run_dir),
        "target": (meta.get("targets_info") or [{}])[0].get("original")
        if isinstance(meta.get("targets_info"), list) else None,
        "status": meta.get("status"),
        "start_time": meta.get("start_time"),
        "models": dict(model_requests),
        "dominant_model": dominant,
        "session_models": session_models,
    }


def main():
    runs = sorted(d for d in glob.glob(os.path.join(ROOT, "strix_runs", "*"))
                  if os.path.isdir(d))
    run_meta = {}
    attempts = []
    total_cmds = 0
    script_resolved = 0
    keys = set()
    safe_attempts = 0
    with_db = 0
    for d in runs:
        info = run_info(d)
        run = info["run"]
        run_meta[run] = {k: v for k, v in info.items() if k != "session_models"}
        db = os.path.join(d, ".state", "agents.db")
        if not os.path.exists(db):
            continue
        with_db += 1
        try:
            ledger = build_ledger_from_db(db)
        except Exception as e:
            print(f"ledger error {run}: {e}", file=sys.stderr)
            ledger = {}
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT id, session_id, message_data FROM agent_messages ORDER BY id").fetchall()
        finally:
            con.close()
        for mid, session, md in rows:
            try:
                m = json.loads(md)
            except Exception:
                continue
            if m.get("type") != "function_call" or m.get("name") != "exec_command":
                continue
            try:
                cmd = json.loads(m.get("arguments") or "{}").get("cmd", "")
            except Exception:
                continue
            if not cmd:
                continue
            script = resolve_script(ledger, cmd)
            model = info["session_models"].get(session) or info["dominant_model"]
            h = hashlib.sha256()
            h.update(cmd.encode("utf-8", "replace"))
            h.update(b"\x00")
            h.update((script or "").encode("utf-8", "replace"))
            key = h.hexdigest()
            keys.add(key)
            total_cmds += 1
            if script:
                script_resolved += 1
            if sandbox_internal(cmd):
                safe_attempts += 1
            attempts.append({
                "run": run, "model": model, "session": session,
                "cmd": cmd, "has_script": bool(script), "script_len": len(script or ""),
                "key": key,
            })
    print("runs:", len(runs), "with db:", with_db)
    print("exec commands:", total_cmds, "unique(cmd+script):", len(keys),
          "script resolved attempts:", script_resolved,
          "sandbox_internal:", safe_attempts)
    model_counts = Counter()
    for a in attempts:
        model_counts[a["model"]] += 1
    print("models by exec count:", model_counts.most_common())
    with open(OUT, "w", encoding="utf-8") as f:
        for a in attempts:
            f.write(json.dumps(a) + "\n")
    json.dump(run_meta, open(RUNS_OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("wrote", OUT, RUNS_OUT)


if __name__ == "__main__":
    main()
