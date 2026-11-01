#!/usr/bin/env python3
"""ゲート検証: アクセスログ付きHTTPサーバを立て、ブロック/修正が本当に到達しないか確認する。

使用方法:
  python3 tools/verify_gate.py [--image alpine:latest] [--keep]

検証内容:
  1. 許可コマンド        -> ターゲットに到達する（ログに残る）
  2. ブロックコマンド    -> ターゲットに到達しない
  3. 修正(revise)コマンド-> ターゲットに到達しない
  4. スクリプト内容ブロック (コンテナ内ファイルを読んで判定) -> 到達しない
  5. ログに上記以外のパスが無い（意図しないアクセスなし）
"""
import argparse
import http.client
import io
import json
import os
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from strix_guard.docker_proxy import DockerProxy


class LogHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        entry = {
            "ts": time.time(),
            "client": self.client_address[0],
            "method": "GET",
            "path": urlparse(self.path).path,
            "ua": self.headers.get("User-Agent", ""),
        }
        with self.server.loglock:
            with open(self.server.logpath, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def docker_req(addr, method, path, body=None, timeout=60):
    c = http.client.HTTPConnection(addr[0], addr[1], timeout=timeout)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    status = r.status
    c.close()
    return status, data


def read_container_file(addr, api, cid, path):
    """Docker archive API でコンテナ内ファイルを読む（tarを解析）"""
    st, data = docker_req(addr, "GET", f"{api}/containers/{cid}/archive?path={path}")
    if st != 200:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf.getmembers():
                if m.isfile():
                    f = tf.extractfile(m)
                    return f.read().decode("utf-8", errors="replace") if f else None
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="alpine:latest")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logpath = os.path.join(base_dir, "guard_runs", f"gate_verify_{int(time.time())}.jsonl")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)

    # 1) アクセスログ付きHTTPサーバ（コンテナから見えるよう 0.0.0.0 にバインド）
    srv = ThreadingHTTPServer(("0.0.0.0", 0), LogHandler)
    srv.logpath = logpath
    srv.loglock = threading.Lock()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = f"http://host.docker.internal:{port}"
    print(f"[1] access-log target: 0.0.0.0:{port} -> {logpath}")

    # 2) テスト用ゲート（実際のDockerProxyと同じ enforcement 経路）
    records = []

    def judge(container_id, argv, spec):
        cmd = " ".join(argv)
        if "BLOCKED_TEST" in cmd:
            return ("deny", "[strix-guard instruction] TEST blocked: this request must not reach the target")
        if "REVISE_TEST" in cmd:
            return ("revise", "[strix-guard instruction] TEST revise: this request must not reach the target")
        # スクリプト実行はコンテナ内の内容を読んで判定（内容ベースのブロック）
        if re_match_script(cmd):
            path = re_script_path(cmd)
            content = read_container_file(proxy.address, api, container_id, path)
            if content and "/script-blocked" in content:
                return ("deny", "[strix-guard instruction] TEST blocked by script content")
        return ("allow", None)

    import re as _re

    def re_match_script(cmd):
        return bool(_re.search(r"(?<![\w-])(?:sh|bash)\s+(/tmp/[\w./-]+\.sh)\b", cmd))

    def re_script_path(cmd):
        m = _re.search(r"(?<![\w-])(?:sh|bash)\s+(/tmp/[\w./-]+\.sh)\b", cmd)
        return m.group(1) if m else ""

    def on_exec(cid, argv, spec):
        dec = judge(cid, argv, spec)
        records.append((cid, " ".join(argv), dec))
        return dec

    proxy = DockerProxy(upstream=("unix", "/var/run/docker.sock"),
                        on_exec=on_exec).start()
    addr = proxy.address
    st, ver = docker_req(addr, "GET", "/version")
    api = "/v" + json.loads(ver)["ApiVersion"]
    print(f"[2] docker proxy: {addr[0]}:{addr[1]} api={api}")

    # 3) 検証用コンテナ
    st, d = docker_req(addr, "POST", f"{api}/containers/create", json.dumps({
        "Image": args.image,
        "Cmd": ["sleep", "180"],
        "HostConfig": {"ExtraHosts": ["host.docker.internal:host-gateway"]},
    }).encode())
    assert st == 201, (st, d[:200])
    cid = json.loads(d)["Id"]
    st, _ = docker_req(addr, "POST", f"{api}/containers/{cid}/start")
    assert st in (204, 304), st
    print(f"[3] container started: {cid[:12]}")

    def exec_cmd(cmd):
        st, d = docker_req(addr, "POST", f"{api}/containers/{cid}/exec", json.dumps({
            "Cmd": ["sh", "-c", cmd], "AttachStdout": True, "AttachStderr": True,
        }).encode())
        if st != 201:
            return st, d
        eid = json.loads(d)["Id"]
        docker_req(addr, "POST", f"{api}/exec/{eid}/start", json.dumps(
            {"Detach": True, "Tty": False}).encode())
        return st, eid

    def read_log():
        if not os.path.exists(logpath):
            return []
        return [json.loads(l) for l in open(logpath, encoding="utf-8") if l.strip()]

    # 4) ケース実行
    print("[4] running cases...")
    exec_cmd(f"wget -q -O /dev/null {base}/allowed-1")
    exec_cmd(f"wget -q -O /dev/null {base}/allowed-2")
    exec_cmd(f"wget -q -O /dev/null {base}/blocked-1 # BLOCKED_TEST")
    exec_cmd(f"wget -q -O /dev/null {base}/revised-1 # REVISE_TEST")
    # スクリプト内容ブロック: スクリプトを作成 → 作成完了を待つ → 内容を読んで判定 → 実行は拒否
    exec_cmd(f"printf 'wget -q -O /dev/null {base}/script-blocked\\n' > /tmp/t.sh")
    for _ in range(50):
        if read_container_file(addr, api, cid, "/tmp/t.sh"):
            break
        time.sleep(0.1)
    exec_cmd("sh /tmp/t.sh")
    time.sleep(3)

    entries = read_log()
    paths = [e["path"] for e in entries]
    print("\n[5] access log:")
    for e in entries:
        print(f"   {e['method']} {e['path']}  client={e['client']}  ua={e['ua']}")

    allowed_ok = "/allowed-1" in paths and "/allowed-2" in paths
    blocked_ok = not any("/blocked" in p for p in paths)
    revised_ok = not any("/revised" in p for p in paths)
    script_ok = "/script-blocked" not in paths
    unexpected = sorted(set(p for p in paths if p not in ("/allowed-1", "/allowed-2")))
    no_unexpected = not unexpected

    print("\n[6] verdicts:")
    print(f"   allowed paths reached      : {'PASS' if allowed_ok else 'FAIL'}")
    print(f"   blocked request blocked    : {'PASS' if blocked_ok else 'FAIL'}")
    print(f"   revised request blocked    : {'PASS' if revised_ok else 'FAIL'}")
    print(f"   script-content blocked     : {'PASS' if script_ok else 'FAIL'}")
    print(f"   no unexpected access       : {'PASS' if no_unexpected else 'FAIL {}'.format(unexpected)}")
    print(f"   gate records: {len(records)} (allow/deny/revise in audit)")

    ok = allowed_ok and blocked_ok and revised_ok and script_ok and no_unexpected

    # 5) cleanup
    if not args.keep:
        docker_req(addr, "DELETE", f"{api}/containers/{cid}?force=1")
    proxy.stop()
    srv.shutdown()
    srv.server_close()
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
