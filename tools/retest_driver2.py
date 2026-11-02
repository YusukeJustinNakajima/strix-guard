#!/usr/bin/env python3
"""Apacheターゲット経由の直接ゲート検証ドライバ v3 (2フェーズ).

Phase 1 (--no-http-enforce): execゲート単体の実ポリシーパイプライン。
  許可GETはApacheに到達し、BLOCKは実行されない(通知+exit 1)ことを
  Apacheアクセスログと突き合わせて証明する。
Phase 2 (サイドカー有効): サイドカーによる実行時メソッド/上限/CONNECT制御。

Phase 2ではサイドカー上流のCaido(サンドボックス同梱)が未初期化で500を返すため、
Apacheへの正向け到達はPhase 1で証明する(サイドカー経由の転送記録は監査で確認)。
"""
import http.client
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

REPO = "/home/yusuk/blackbox-testing/strix_guard"
APACHE_LOG = os.path.join(REPO, "e2e_target", "logs", "access_log")
TARGET = "http://host.docker.internal:8081"
IMAGE = "ghcr.io/usestrix/strix-sandbox:1.3.0"

RESULTS = []


def rec(name, ok, detail=""):
    RESULTS.append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)


def http_req(addr, method, path, body=None, timeout=120):
    c = http.client.HTTPConnection(addr[0], addr[1], timeout=timeout)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    st = r.status
    c.close()
    return st, data


def start_launcher(extra_args, policy_path):
    env = os.environ.copy()
    env.pop("DOCKER_HOST", None)
    cmd = [sys.executable, "-m", "strix_guard.launcher",
           "--dry-run", "--ui", "noninteractive", "--on-ask", "deny",
           "--adjudicator", "auto", "--adjudicator-review-blocks",
           "--policy-preset", "reference_only", "--policy", policy_path,
           "--language", "en", "--environment", "benchmark",
           "--test-accounts", "alice,bob"] + extra_args
    print("$", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, cwd=REPO, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines, port, audit_dir, sha = [], None, None, None

    def reader():
        for line in proc.stdout:
            lines.append(line.rstrip())

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + 90
    while time.time() < deadline:
        joined = "\n".join(lines)
        m = re.search(r"docker proxy on 127\.0\.0\.1:(\d+)", joined)
        if m:
            port = int(m.group(1))
        m = re.search(r"audit dir: (\S+)", joined)
        if m:
            audit_dir = m.group(1)
        m = re.search(r"policy=(\S+) sha256=([0-9a-f]+)", joined)
        if m:
            sha = m.group(2)
        if port and audit_dir:
            break
        time.sleep(0.3)
    return proc, port, audit_dir, sha, lines


def stop_launcher(proc):
    try:
        proc.send_signal(signal.SIGINT)
        for _ in range(15):
            if proc.poll() is not None:
                return
            time.sleep(1)
        proc.kill()
    except Exception:
        pass


def phase(name, extra_args, policy_path, cases, cap=None, wait_sidecar=False):
    print(f"\n########## {name} ##########", flush=True)
    proc, port, audit_dir, sha, lines = start_launcher(extra_args, policy_path)
    if not port:
        rec(f"{name}: proxy起動", False, "\n".join(lines[-5:]))
        return None
    rec(f"{name}: FR-09 sha256表示", bool(sha), f"sha256={sha}")
    addr = ("127.0.0.1", port)
    st, d = http_req(addr, "GET", "/version")
    api = "/v" + json.loads(d)["ApiVersion"]

    st, d = http_req(addr, "POST", f"{api}/containers/create", json.dumps({
        "Image": IMAGE, "Cmd": ["sleep", "900"],
        "HostConfig": {"ExtraHosts": ["host.docker.internal:host-gateway"]},
    }).encode())
    assert st == 201, (st, d[:300])
    cid = json.loads(d)["Id"]
    st, _ = http_req(addr, "POST", f"{api}/containers/{cid}/start")
    assert st in (204, 304), st
    print(f"container: {cid[:12]}", flush=True)

    sidecar_log = None
    if wait_sidecar:
        for _ in range(60):
            vpath = os.path.join(audit_dir, "verdicts.jsonl")
            if os.path.exists(vpath):
                for line in open(vpath, encoding="utf-8"):
                    e = json.loads(line)
                    if e.get("kind") == "sidecar_started":
                        sidecar_log = e.get("log")
            if sidecar_log:
                break
            time.sleep(0.5)
        rec(f"{name}: FR-18 サイドカー起動", bool(sidecar_log), sidecar_log or "not started")

    def run_exec(cmd, timeout=150):
        st, d = http_req(addr, "POST", f"{api}/containers/{cid}/exec", json.dumps({
            "Cmd": ["sh", "-c", cmd], "AttachStdout": True, "AttachStderr": True,
            "Tty": False}).encode())
        if st != 201:
            return None, f"exec create {st}"
        eid = json.loads(d)["Id"]
        st, d2 = http_req(addr, "GET", f"{api}/exec/{eid}/json")
        spec_cmd = json.loads(d2).get("Cmd")
        c = http.client.HTTPConnection(addr[0], addr[1], timeout=timeout)
        c.request("POST", f"{api}/exec/{eid}/start",
                  json.dumps({"Detach": False, "Tty": False}),
                  {"Content-Type": "application/json"})
        r = c.getresponse()
        out = r.read()
        c.close()
        st, d3 = http_req(addr, "GET", f"{api}/exec/{eid}/json")
        code = json.loads(d3).get("ExitCode")
        return {"exit": code, "out": out.decode("utf-8", "replace"),
                "spec_cmd": spec_cmd, "eid": eid}, None

    for case in cases:
        marker = case["marker"]
        r, err = run_exec(case["cmd"])
        if err:
            rec(f"{name} case {marker}", False, err)
            continue
        ev = None
        vpath = os.path.join(audit_dir, "verdicts.jsonl")
        deadline = time.time() + 90
        while time.time() < deadline and ev is None:
            if os.path.exists(vpath):
                for line in open(vpath, encoding="utf-8"):
                    e = json.loads(line)
                    if e.get("kind") == "evaluation" and marker in (e.get("cmd") or ""):
                        ev = e
            time.sleep(0.4)
        v = (ev or {}).get("verdict")
        src = ((ev or {}).get("risk") or {}).get("source")
        reasons = (ev or {}).get("reasons") or []
        ok = True
        det = f"verdict={v} src={src} exit={r['exit']}"
        if case.get("expect_verdict"):
            ok &= v == case["expect_verdict"]
        if case.get("expect_src"):
            ok &= src == case["expect_src"]
            det += f"(src=={case['expect_src']})"
        if case.get("expect_exit") is not None:
            ok &= r["exit"] == case["expect_exit"]
        if case.get("expect_verdict") == "BLOCK":
            if r["spec_cmd"]:
                joined = " ".join(r["spec_cmd"])
                ok &= "printf" in joined and "exit 1" in joined
                det += " replaced=yes" if ("printf" in joined) else " replaced=NO"
        time.sleep(1.2)
        with open(APACHE_LOG, encoding="utf-8", errors="replace") as f:
            logtxt = f.read()
        if case.get("apache_expect"):
            hit = apache_expect_hit(case["apache_expect"], logtxt)
            ok &= hit
            det += f" apache[{case['apache_expect']}]={'yes' if hit else 'MISSING'}"
        if case.get("apache_absent"):
            hit = case["apache_absent"] in logtxt
            ok &= not hit
            det += f" apache[{case['apache_absent']}]={'PRESENT!' if hit else 'no'}"
        for key in ("check_out", "check_out2"):
            if case.get(key) is not None:
                hit = case[key] in (r["out"] or "")
                ok &= hit
                det += f" {key}={hit}"
        if case.get("info"):
            det += " | " + case["info"]
        rec(f"{name} case {marker}", ok, det)

    http_req(addr, "DELETE", f"{api}/containers/{cid}?force=1", timeout=60)
    stop_launcher(proc)
    return audit_dir, sidecar_log


def apache_expect_hit(marker, logtxt):
    return marker in logtxt


def main():
    pol1 = os.path.join(REPO, "guard_runs", "retest_policy_p1.json")
    with open(pol1, "w", encoding="utf-8") as f:
        json.dump({"preset": "reference_only", "http": {"enforce": False}}, f)
    pol2 = os.path.join(REPO, "guard_runs", "retest_policy_p2.json")
    with open(pol2, "w", encoding="utf-8") as f:
        json.dump({"preset": "reference_only", "http": {"max_requests": 4}}, f)

    phase1_cases = [
        {"marker": "m=san", "cmd": "python3 -c 'import requests; print(1)' # m=san",
         "expect_verdict": "ALLOW", "expect_exit": 0},
        {"marker": "c=g01", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-1.html?c=g01'",
         "expect_verdict": "ALLOW", "expect_exit": 0, "apache_expect": "?c=g01"},
        {"marker": "c=p01", "cmd": f"curl -s -o /dev/null -X POST -d 'u=admin&p=secret' '{TARGET}/login?c=p01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=p01", "check_out": "[strix-guard"},
        {"marker": "c=s01", "cmd": f"curl -s -o /dev/null '{TARGET}/search?q=1%27;DROP TABLE users;--&c=s01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=s01"},
        {"marker": "c=u01", "cmd": f"curl -s -o /dev/null -F 'f=@/etc/hostname' '{TARGET}/upload?c=u01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=u01"},
        {"marker": "c=e01", "cmd": "curl -s -o /dev/null --max-time 8 'http://example.com/?c=e01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=e01"},
        {"marker": "c=e02", "cmd": "python3 -c \"import requests; "
         "print(requests.get('http://example.com/?c=e02', timeout=8).status_code)\" # c=e02",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1},
        {"marker": "c=d01", "cmd": "rm -rf /etc /usr /bin # c=d01",
         "expect_verdict": "BLOCK", "expect_exit": 1,
         "info": "FR-17 破壊コマンドのハードブロック(裁定で緩和されない)"},
    ]
    p1 = phase("Phase1 execゲート", ["--no-http-enforce", "--", "--target", TARGET],
               pol1, phase1_cases)
    if p1:
        rec("Phase1 完了", True, p1[0])
        audit1 = p1[0]
        br = []
        vpath = os.path.join(audit1, "verdicts.jsonl")
        for line in open(vpath, encoding="utf-8"):
            e = json.loads(line)
            if e.get("kind") == "block_review" and "c=d01" in (e.get("cmd") or ""):
                br.append(e)
        rec("FR-16/17 d01 block_review記録(block_kind=hard, 緩和なし)",
            bool(br) and br[-1].get("block_kind") == "hard",
            f"reviews={len(br)} action={br[-1].get('action') if br else '-'} model={br[-1].get('model') if br else '-'}")

    phase2_cases = [
        {"marker": "m=san", "cmd": "python3 -c 'import requests; print(1)' # m=san",
         "expect_verdict": "ALLOW", "expect_exit": 0},
        {"marker": "m=env", "cmd": "env | grep -iE '^(http_proxy|https_proxy|no_proxy|all_proxy)=' | sort # m=env",
         "expect_verdict": "ALLOW", "check_out": "48081", "check_out2": "api.caido.io",
         "info": "FR-18 exec環境へのプロキシ注入 + FR-21 NO_PROXY"},
        {"marker": "c=g01", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-1.html?c=g01'",
         "expect_verdict": "ALLOW",
         "info": "サイドカー許可→上流Caido未初期化のため500(既知制約)"},
        {"marker": "c=c01", "cmd": f"curl -s -o /dev/null '{TARGET.replace('http://', 'https://')}/?c=c01'",
         "expect_verdict": "ALLOW", "apache_absent": "?c=c01",
         "info": "FR-22 CONNECTをサイドカーが拒否"},
        {"marker": "c=r1", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-2.html?c=r1'",
         "expect_verdict": "ALLOW"},
        {"marker": "c=r2", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-2.html?c=r2'",
         "expect_verdict": "ALLOW"},
        {"marker": "c=r3", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-2.html?c=r3'",
         "expect_verdict": "ALLOW"},
        {"marker": "c=r4", "cmd": f"curl -s -o /dev/null '{TARGET}/allowed-2.html?c=r4'",
         "expect_verdict": "ALLOW",
         "info": "FR-19 execはALLOWだがサイドカーがrequest_capで403"},
        {"marker": "c=p01", "cmd": f"curl -s -o /dev/null -X POST -d 'u=a&p=b' '{TARGET}/login?c=p01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=p01", "check_out": "[strix-guard"},
        {"marker": "c=x01", "cmd": "python3 -c \"import requests; m='PO'+'ST'; "
         f"print(requests.request(m,'{TARGET}/login?c=x01',data={{'u':'a'}},timeout=10).status_code)\" # c=x01",
         "expect_verdict": "ALLOW", "check_out": "403", "apache_absent": "?c=x01",
         "info": "FR-20 難読化POSTをサイドカーが遮断"},
        {"marker": "c=e01", "cmd": "curl -s -o /dev/null --max-time 8 'http://example.com/?c=e01'",
         "expect_verdict": "BLOCK", "expect_src": "policy_rule", "expect_exit": 1,
         "apache_absent": "?c=e01"},
        {"marker": "c=i01", "cmd": "curl -s -o /dev/null --max-time 5 'http://127.0.0.1:48080/?c=i01'",
         "expect_verdict": "ALLOW",
         "info": "FR-21 infraホストはメソッド制限から除外"},
    ]
    p2 = phase("Phase2 サイドカー", ["--no-gray-review", "--", "--target", TARGET],
               pol2, phase2_cases, wait_sidecar=True)

    audit2, sidecar_log = p2 if p2 else (None, None)
    side = []
    if sidecar_log and os.path.exists(sidecar_log):
        side = [json.loads(l) for l in open(sidecar_log, encoding="utf-8") if l.strip()]

    rec("FR-20 サイドカー: method_not_allowed(POST)",
        any(e.get("method") == "POST" and e.get("verdict") == "method_not_allowed" for e in side),
        f"POST拒否={sum(1 for e in side if e.get('method')=='POST' and e.get('verdict')=='method_not_allowed')}件")
    rec("FR-22 サイドカー: connect_not_allowed",
        any(e.get("method") == "CONNECT" and e.get("verdict") == "connect_not_allowed" for e in side),
        f"CONNECT拒否={sum(1 for e in side if e.get('method')=='CONNECT' and e.get('verdict')=='connect_not_allowed')}件")
    rec("FR-19 サイドカー: request_cap",
        any(e.get("verdict") == "request_cap" for e in side),
        f"cap拒否={sum(1 for e in side if e.get('verdict')=='request_cap')}件")
    rec("FR-18 サイドカー: 転送レコード",
        any(e.get("verdict") == "allow" for e in side),
        f"allow={sum(1 for e in side if e.get('verdict')=='allow')}件(上流Caidoは500)")

    if audit2:
        snap = os.path.join(audit2, "policy.json")
        ok = os.path.exists(snap)
        if ok:
            p = json.load(open(snap, encoding="utf-8"))
            ok = p.get("preset") == "reference_only" and \
                p.get("http", {}).get("max_requests") == 4
        rec("FR-07/08/09 --policy上書き+スナップショット", ok,
            f"max_requests=4 in snapshot={ok}")

    out = {"results": RESULTS}
    with open(os.path.join(REPO, "guard_runs", "retest_summary.json"), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    nfail = sum(1 for r in RESULTS if not r["ok"])
    print(f"\nRESULT: {'PASS' if nfail == 0 else 'FAIL'} ({len(RESULTS)-nfail}/{len(RESULTS)})")
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
