"""replay: 記録済み exec_command 群を Decision Service に通して分類を検証するCLI

使い方:
  python3 -m strix_guard.replay <exec_cmds.jsonl> [--limit 20] [--offline] [--no-jev]
"""
import argparse
import json
import sys
import time

from .decision import DecisionService
from .ledger import build_ledger_from_db, resolve_script
from .policy import ui_label


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmds_jsonl")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--offline", action="store_true", help="JEVを使わずヒューリスティックのみ")
    ap.add_argument("--runs-root", default="/home/yusuk/blackbox-testing/strix_runs")
    args = ap.parse_args(argv)

    svc = DecisionService(use_jev=not args.offline, summarize=False)
    ledgers: dict[str, dict] = {}

    n = 0
    t0 = time.time()
    t_sum = 0.0
    for line in open(args.cmds_jsonl, encoding="utf-8"):
        d = json.loads(line)
        rid = d["run_id"]
        if rid not in ledgers:
            ledgers[rid] = build_ledger_from_db(f"{args.runs_root}/{rid}/.state/agents.db")
        content = resolve_script(ledgers[rid], d["cmd"])
        t1 = time.time()
        ev = svc.evaluate(d["cmd"], script_content=content)
        t_sum += time.time() - t1
        n += 1
        print(f"[{ui_label(ev.decision):7s}] {ev.decision.verdict.value:9s} "
              f"(d={ev.risk.destructiveness:.2f} l={ev.risk.load:.2f} e={ev.risk.data_exposure:.2f} "
              f"src={ev.risk.source}, resolved={'yes' if content else 'no'}) "
              f"{d['cmd'][:90]!r}")
        if n >= args.limit:
            break
    dt = time.time() - t0
    print(f"\n{n} cmds in {dt:.1f}s (avg {t_sum/max(n,1)*1000:.0f} ms/decision)")


if __name__ == "__main__":
    sys.exit(main())
