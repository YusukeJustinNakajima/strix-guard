#!/usr/bin/env python3
"""親ディレクトリの全 Strix 実行 (136) から exec_command を抽出して規模を確認する。"""
import glob
import hashlib
import json
import os
import sqlite3
import sys

sys.path.insert(0, "/home/yusuk/blackbox-testing/strix_guard")
from strix_guard.ledger import build_ledger_from_db, resolve_script  # noqa: E402
from strix_guard.policy import sandbox_internal  # noqa: E402

ROOT = "/home/yusuk/blackbox-testing"
OUT = "/home/yusuk/blackbox-testing/strix_guard/guard_runs/corpus_parent_attempts.jsonl"


def main():
    runs = sorted(d for d in glob.glob(os.path.join(ROOT, "strix_runs", "*"))
                  if os.path.isdir(d))
    names = []
    tool_names = {}
    attempts = []
    total_cmds = 0
    with_db = 0
    script_resolved = 0
    keys = set()
    no_db = []
    for d in runs:
        name = os.path.basename(d)
        db = os.path.join(d, ".state", "agents.db")
        if not os.path.exists(db):
            no_db.append(name)
            continue
        with_db += 1
        try:
            ledger = build_ledger_from_db(db)
        except Exception as e:
            print(f"ledger error {name}: {e}", file=sys.stderr)
            ledger = {}
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT message_data FROM agent_messages ORDER BY id").fetchall()
        finally:
            con.close()
        n_run = 0
        for (md,) in rows:
            try:
                m = json.loads(md)
            except Exception:
                continue
            if m.get("type") != "function_call":
                continue
            name_tool = m.get("name")
            tool_names[name_tool] = tool_names.get(name_tool, 0) + 1
            if name_tool != "exec_command":
                continue
            try:
                cmd = json.loads(m.get("arguments") or "{}").get("cmd", "")
            except Exception:
                continue
            if not cmd:
                continue
            script = resolve_script(ledger, cmd)
            h = hashlib.sha256()
            h.update(cmd.encode("utf-8", "replace"))
            h.update(b"\x00")
            h.update((script or "").encode("utf-8", "replace"))
            keys.add(h.hexdigest())
            n_run += 1
            total_cmds += 1
            if script:
                script_resolved += 1
            attempts.append({"run": name, "cmd": cmd, "has_script": bool(script),
                             "script_len": len(script or ""),
                             "key": h.hexdigest()})
        names.append((name, n_run))
    print("runs:", len(runs), "with db:", with_db, "no db:", len(no_db))
    print("exec commands:", total_cmds, "unique(cmd+script):", len(keys),
          "script resolved attempts:", script_resolved)
    safe = 0
    for a in attempts:
        if sandbox_internal(a["cmd"]):
            safe += 1
    print("sandbox_internal attempts:", safe, "-> JEV candidates unique <= ", len(keys))
    print("tool names:", sorted(tool_names.items(), key=lambda x: -x[1])[:12])
    print("top runs:")
    for name, n in sorted(names, key=lambda x: -x[1])[:10]:
        print("  ", name, n)
    print("no db runs:", no_db[:10], "..." if len(no_db) > 10 else "")
    with open(OUT, "w", encoding="utf-8") as f:
        for a in attempts:
            f.write(json.dumps(a) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
