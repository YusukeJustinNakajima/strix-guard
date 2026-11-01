"""承認ポップアップ用ヘルパー（tmux display-popup -E から実行される）

引数: payload.json decision.json timeout_sec
stdin（ポップアップのTTY）からキー入力を受け、decision.json に結果を書く。
言語は環境変数 STRIX_GUARD_LANG（en/ja、既定 en）。
"""
import json
import os
import select
import sys
import time

from . import i18n

LANG = os.environ.get("STRIX_GUARD_LANG", "en")
L = lambda k, **kw: i18n.t(LANG, k, **kw)


def main():
    payload_path, decision_path, timeout_s = sys.argv[1], sys.argv[2], float(sys.argv[3])
    try:
        p = json.load(open(payload_path, encoding="utf-8"))
    except Exception:
        p = {}
    card = p.get("card") or ""
    cmd = p.get("cmd") or ""
    summary = p.get("summary") or {}
    revision = p.get("revision") or None

    print("=" * 68)
    if revision:
        print("--- " + L("rev_prev") + " ---")
        print(revision.get("instruction") or "-")
        print("--- " + L("rev_diff") + " ---")
        print(revision.get("diff") or "-")
        if (revision.get("diff") or "") in (L("rev_unchanged"), "変更なし", "変更なし"):
            print("  -> " + L("rev_unchanged"))
        if revision.get("constraint_note"):
            lead = L("rev_ok") if revision.get("constraint_ok") is True else L("rev_insufficient")
            print("  -> " + lead + str(revision.get("constraint_note")))
        print("-" * 68)
    print(card or L("no_summary"))
    print("-" * 68)
    print(L("popup_cmd_label"))
    print(cmd[:900] + ("…" if len(cmd) > 900 else ""))
    print("-----------------")
    print(f"[policy] {json.dumps(summary, ensure_ascii=False)[:300]}")
    print()
    print(" " + L("popup_keys_a"))
    print(" " + L("popup_keys_b"))
    print(" " + L("popup_timeout", n=int(timeout_s)))
    sys.stdout.write(L("popup_prompt"))
    sys.stdout.flush()

    decision = None
    deadline = time.time() + timeout_s
    while decision is None:
        remain = max(0.0, deadline - time.time())
        r, _, _ = select.select([sys.stdin], [], [], remain)
        if not r:
            decision = {"action": "deny", "message": L("msg_timeout")}
            break
        line_raw = sys.stdin.readline()
        if line_raw == "":
            decision = {"action": "deny", "message": L("msg_eof")}
            break
        line = line_raw.strip().lower()
        if line in ("a", "allow"):
            decision = {"action": "allow", "cache_pattern": False}
        elif line in ("p", "pattern"):
            decision = {"action": "allow", "cache_pattern": True}
        elif line in ("e", "edit", "revise"):
            print(L("popup_retry_prompt"))
            sys.stdout.write(L("popup_prompt"))
            sys.stdout.flush()
            text = (sys.stdin.readline() or "").strip()
            decision = {"action": "revise",
                        "message": L("msg_revise_prefix") + (text or L("msg_revise_default"))}
        elif line in ("c", "cat"):
            print("\n--- raw command ---")
            print(cmd[:2000])
            print("--- end ---")
            sys.stdout.write(L("popup_prompt"))
            sys.stdout.flush()
        elif line in ("d", "deny"):
            decision = {"action": "deny", "message": L("msg_denied")}
        else:
            sys.stdout.write(L("popup_prompt"))
            sys.stdout.flush()

    with open(decision_path, "w", encoding="utf-8") as f:
        json.dump(decision, f, ensure_ascii=False)


if __name__ == "__main__":
    main()
