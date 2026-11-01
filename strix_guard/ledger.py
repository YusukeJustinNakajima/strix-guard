"""run単位のファイル台帳: apply_patch / heredoc 書き込みから path→content を再構築"""
import json
import os
import re
import sqlite3


def _apply_hunks(content_lines: list[str], hunk_lines: list[str]) -> list[str]:
    out: list[str] = []
    idx = 0
    for line in hunk_lines:
        if line.startswith("+"):
            out.append(line[1:])
        elif line.startswith("-"):
            idx += 1
        else:
            out.append(content_lines[idx] if idx < len(content_lines) else line[1:])
            idx += 1
    out.extend(content_lines[idx:])
    return out


def _norm_path(path: str) -> str:
    p = os.path.normpath(path.strip().strip("'\""))
    if p.startswith("/workspace/"):
        p = p[len("/workspace/"):]
    return p


def _find_key(ledger: dict, path: str) -> str | None:
    target = _norm_path(path)
    for k in ledger:
        if _norm_path(k) == target:
            return k
    base = os.path.basename(target)
    matches = [k for k in ledger if os.path.basename(_norm_path(k)) == base]
    return matches[0] if len(matches) == 1 else None


def build_ledger_from_db(db_path: str) -> dict[str, str]:
    """agents.db から ledger を構築（path -> content text）"""
    ledger: dict[str, list[str]] = {}
    if not os.path.exists(db_path):
        return {}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        for _, md in con.execute("SELECT id, message_data FROM agent_messages ORDER BY id"):
            try:
                m = json.loads(md)
            except Exception:
                continue
            if m.get("type") != "function_call":
                continue
            name = m.get("name")
            args = m.get("arguments") or ""
            if name == "apply_patch":
                try:
                    a = json.loads(args)
                except Exception:
                    continue
                patch = a.get("patch") or a.get("input") or ""
                cur_path, mode, buf = None, None, []
                def flush():
                    if cur_path is None:
                        return
                    if mode == "add":
                        ledger[cur_path] = [l[1:] if l.startswith("+") else l for l in buf]
                    elif mode == "update":
                        old = ledger.get(cur_path)
                        ledger[cur_path] = _apply_hunks(old, buf) if old is not None else list(buf)
                    elif mode == "delete":
                        ledger.pop(cur_path, None)
                for line in patch.splitlines():
                    if line.startswith("*** Add File: "):
                        flush(); cur_path = line[len("*** Add File: "):].strip(); mode = "add"; buf = []
                    elif line.startswith("*** Update File: "):
                        flush(); cur_path = line[len("*** Update File: "):].strip(); mode = "update"; buf = []
                    elif line.startswith("*** Delete File: "):
                        flush(); cur_path = line[len("*** Delete File: "):].strip(); mode = "delete"; buf = []
                    elif line.startswith("*** "):
                        flush(); cur_path, mode, buf = None, None, []
                    elif mode in ("add", "update"):
                        buf.append(line)
                flush()
            elif name == "exec_command":
                try:
                    cmd = json.loads(args).get("cmd", "")
                except Exception:
                    continue
                for mm in re.finditer(r"cat\s*>>?\s*([\w./-]+)\s*<<\s*'?(\w+)'?\n(.*?)\n\2", cmd, re.S):
                    ledger[mm.group(1)] = mm.group(3).splitlines()
                for mm in re.finditer(
                        r"(?:^|&&|;|\|\||\n)\s*(?:sudo\s+)?(cp|mv)\s+(?:-[A-Za-z]+\s+)*"
                        r"(?:--\s+)?([^\s;&|<>]+)\s+([^\s;&|<>]+)", cmd):
                    op, src, dst = mm.group(1), mm.group(2), mm.group(3)
                    key = _find_key(ledger, src)
                    if key is None:
                        continue
                    content = list(ledger[key])
                    dst = dst.strip().strip("'\"")
                    if op == "mv":
                        ledger.pop(key, None)
                    ledger[dst] = content
    finally:
        con.close()
    return {k: "\n".join(v) for k, v in ledger.items()}


def resolve_script(ledger: dict[str, str], cmd: str):
    """実行コマンドから参照されたローカルスクリプトの内容を解決"""
    m = re.search(r"(?:python3?|node|bash|sh|ruby|perl)(?:\s+-{1,2}[\w-]+)*\s+([./\w-]+\.(?:py|js|sh|rb|pl))\b", cmd)
    if not m:
        return None
    path = m.group(1)
    base = os.path.basename(path)
    for cand in (path, "./" + path, "/workspace/" + path, path.lstrip("./")):
        if cand in ledger:
            return ledger[cand]
    for k, v in ledger.items():
        if os.path.basename(k) == base:
            return v
    return None
