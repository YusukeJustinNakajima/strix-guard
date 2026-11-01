"""Web承認UI: ローカルHTTPサーバ + ブラウザ用カードUI（en/ja）"""
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import i18n


class ApprovalBroker:
    def __init__(self, timeout_s: float = 180.0):
        self.timeout_s = timeout_s
        self.pending: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.counter = 0

    def request(self, payload: dict, timeout_s: float | None = None) -> dict:
        with self.lock:
            self.counter += 1
            pid = str(self.counter)
            ev = threading.Event()
            self.pending[pid] = {"payload": payload, "event": ev, "decision": None,
                                 "created": __import__("time").time()}
        ev.wait(timeout_s if timeout_s is not None else self.timeout_s)
        with self.lock:
            entry = self.pending.pop(pid, None)
        if entry and entry["decision"]:
            return entry["decision"]
        return {"action": "deny",
                "message": i18n.t("en", "msg_timeout")}

    def decide(self, pid: str, decision: dict) -> bool:
        with self.lock:
            e = self.pending.get(pid)
            if not e:
                return False
            e["decision"] = decision
            e["event"].set()
            return True

    def snapshot(self) -> list:
        with self.lock:
            return [{"id": pid, **e["payload"]} for pid, e in self.pending.items()]


PAGE = """<!doctype html>
<html lang="__HTML_LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#0f1115;--card:#1a1d24;--line:#2a2f3a;--fg:#e8ecf1;--dim:#9aa4b2;
--green:#2ea043;--blue:#2f81f7;--amber:#d29922;--red:#da3633}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.6 ui-sans-serif,system-ui,'Segoe UI',Roboto,Helvetica,Arial}
header{display:flex;align-items:center;gap:12px;padding:16px 24px;border-bottom:1px solid var(--line);flex-wrap:wrap}
header h1{font-size:19px;margin:0;font-weight:600}
.badge{font-size:13.5px;color:var(--dim)}
main{padding:24px;display:grid;grid-template-columns:minmax(0,1fr);gap:16px;max-width:1120px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;
min-width:0;overflow:hidden}
.card h2{font-size:14px;margin:0 0 12px;color:var(--dim);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.summary{white-space:pre-wrap;margin:0 0 12px;font-size:16px;line-height:1.65}
.revision{border-left:3px solid var(--amber);background:#151820;border-radius:8px;padding:12px 14px;margin:0 0 14px}
.revision .rev-label{font-size:12.5px;color:var(--dim);margin:0 0 4px;letter-spacing:.04em;text-transform:uppercase}
.revision .rev-inst{font-size:15px;margin:0 0 10px}
.revision pre.diff{background:#0b0d11;border:1px solid var(--line);border-radius:6px;padding:10px 12px;
white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;margin:0;max-height:180px;overflow:auto;
font:14.5px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.rev-check{margin:10px 0 0;padding:8px 10px;border-radius:6px;font-size:14.5px}
.rev-check.ok{background:#12261a;border:1px solid #2ea043;color:#7ee787}
.rev-check.bad{background:#2d1214;border:1px solid #da3633;color:#ffb3b8}
pre.cmd{background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:14px;
overflow:auto;max-height:320px;max-width:100%;margin:16px 0 0;white-space:pre-wrap;
word-break:break-word;overflow-wrap:anywhere;
font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.chip{font-size:12.5px;border:1px solid var(--line);border-radius:999px;padding:3px 10px;color:var(--dim)}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
button{border:0;border-radius:8px;padding:12px 16px;font-size:15.5px;font-weight:600;color:#fff;cursor:pointer}
.a{background:var(--green)}.p{background:var(--blue)}.e{background:var(--amber)}.d{background:var(--red)}
input[type=text]{grid-column:1/-1;width:100%;background:#0b0d11;border:1px solid var(--line);
border-radius:8px;color:var(--fg);padding:11px 12px;font-size:15.5px}
.empty{color:var(--dim);text-align:center;padding:56px;font-size:16px}
.flash{position:fixed;right:20px;bottom:20px;background:#1f6feb;color:#fff;padding:10px 16px;
border-radius:8px;font-size:15px;opacity:0;transition:opacity .25s}
</style></head><body>
<header><h1>__TITLE__</h1><span class="badge" id="count">__PENDING_LABEL__ 0</span>
<span class="badge">__TIMEOUT_HINT__</span>
<span class="badge">__ALWAYS_HINT__</span></header>
<main id="list"><div class="empty">__EMPTY_LABEL__</div></main>
<div class="flash" id="flash"></div>
<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const L = __L10N_JSON__;
const esc = s => (s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function flash(msg){const f=document.getElementById('flash');f.textContent=msg;f.style.opacity=1;
setTimeout(()=>f.style.opacity=0,1200);}
async function decide(id, action, cache){
  let message=null;
  if(action==='revise'){
    const el=document.getElementById('m_'+id);
    message=(el && el.value.trim()) || null;
  }
  const r=await fetch('/api/decide?t='+encodeURIComponent(TOKEN),{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id,action:action,message:message,cache_pattern:!!cache})});
  const j=await r.json(); flash(j.ok?L.flash_sent:L.flash_already); refresh(true);
}
function card(p){
  const card=p.card||''; const cmd=p.cmd||''; const s=p.summary||{};
  const probs=s.verdict?`verdict=${esc(s.verdict)}`:'';
  const cons=s.constraints&&Object.keys(s.constraints).length?JSON.stringify(s.constraints):'';
  const rev=p.revision||null;
  let revHtml='';
  if(rev){
    const unchanged = !rev.diff || rev.diff===L.rev_unchanged;
    let chk='';
    if(rev.constraint_note){
      const cls = rev.constraint_ok===true?'ok':(rev.constraint_ok===false?'bad':'');
      const lead = rev.constraint_ok===false?L.rev_insufficient:L.rev_ok;
      chk=`<div class="rev-check ${cls}">${lead}${esc(rev.constraint_note)}</div>`;
    }
    if(unchanged) chk=`<div class="rev-check bad">${esc(L.rev_unchanged)}</div>`+chk;
    revHtml=`<div class="revision">
    <div class="rev-label">${esc(L.rev_prev)}</div>
    <div class="rev-inst">${esc(rev.instruction||'-')}</div>
    <div class="rev-label">${esc(L.rev_diff)}</div>
    <pre class="diff">${esc(rev.diff||'?')}</pre>${chk}</div>`;
  }
  return `<div class="card"><h2>${esc(L.card_title.replace('{id}', p.id))}</h2>
  ${revHtml}
  <div class="summary">${esc(card||L.no_summary)}</div>
  <div class="meta"><span class="chip">${probs}</span>
  ${cons?`<span class="chip">${esc(L.constraints_label)}: ${esc(cons)}</span>`:''}</div>
  <div class="row">
    <input type="text" id="m_${esc(p.id)}" placeholder="${esc(L.placeholder_revise)}">
    <button class="a" onclick="decide('${esc(p.id)}','allow',false)">${esc(L.btn_allow_once)}</button>
    <button class="p" onclick="decide('${esc(p.id)}','allow',true)">${esc(L.btn_allow_always)}</button>
    <button class="e" onclick="decide('${esc(p.id)}','revise',false)">${esc(L.btn_revise)}</button>
    <button class="d" onclick="decide('${esc(p.id)}','deny',false)">${esc(L.btn_deny)}</button>
  </div>
  <pre class="cmd">${esc(cmd)}</pre></div>`;
}
let lastSig='';
function sigOf(pending){
  return pending.map(p=>[p.id,(p.cmd||'').length,(p.card||'').length,
    JSON.stringify(p.summary||{}).length].join(':')).join(',');
}
async function refresh(force){
  try{
    const r=await fetch('/api/pending?t='+encodeURIComponent(TOKEN));
    const j=await r.json();
    const s=sigOf(j.pending);
    if(!force && s===lastSig) return;
    const vals={}; document.querySelectorAll('input[type=text]').forEach(el=>{vals[el.id]=el.value;});
    const focused=document.activeElement && document.activeElement.id;
    lastSig=s;
    document.getElementById('count').textContent=L.pending+' '+j.pending.length;
    const list=document.getElementById('list');
    list.innerHTML = j.pending.length? j.pending.map(card).join('') :
      `<div class="empty">${esc(L.empty)}</div>`;
    Object.keys(vals).forEach(id=>{const el=document.getElementById(id); if(el) el.value=vals[id];});
    if(focused){const el=document.getElementById(focused); if(el) el.focus();}
  }catch(e){}
}
setInterval(()=>refresh(false), 800); refresh(true);
</script></body></html>
"""


def render_page(lang: str, timeout_s: float) -> str:
    l10n = {
        "pending": i18n.t(lang, "pending"),
        "btn_allow_once": i18n.t(lang, "btn_allow_once"),
        "btn_allow_always": i18n.t(lang, "btn_allow_always"),
        "btn_revise": i18n.t(lang, "btn_revise"),
        "btn_deny": i18n.t(lang, "btn_deny"),
        "placeholder_revise": i18n.t(lang, "placeholder_revise"),
        "empty": i18n.t(lang, "empty"),
        "flash_sent": i18n.t(lang, "flash_sent"),
        "flash_already": i18n.t(lang, "flash_already"),
        "no_summary": i18n.t(lang, "no_summary"),
        "constraints_label": i18n.t(lang, "constraints_label"),
        "card_title": i18n.t(lang, "card_title"),
        "rev_prev": i18n.t(lang, "rev_prev"),
        "rev_diff": i18n.t(lang, "rev_diff"),
        "rev_unchanged": i18n.t(lang, "rev_unchanged"),
        "rev_insufficient": i18n.t(lang, "rev_insufficient"),
        "rev_ok": i18n.t(lang, "rev_ok"),
    }
    page = PAGE
    page = page.replace("__HTML_LANG__", lang)
    page = page.replace("__TITLE__", i18n.t(lang, "title"))
    page = page.replace("__PENDING_LABEL__", i18n.t(lang, "pending"))
    page = page.replace("__TIMEOUT_HINT__", i18n.t(lang, "timeout_hint", n=int(timeout_s)))
    page = page.replace("__ALWAYS_HINT__", i18n.t(lang, "always_hint"))
    page = page.replace("__EMPTY_LABEL__", i18n.t(lang, "empty"))
    page = page.replace("__L10N_JSON__", json.dumps(l10n, ensure_ascii=False))
    return page


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _token_ok(self, query: dict) -> bool:
        return bool(query.get("t") and query["t"][0] == self.server.token)

    def _json(self, status: int, obj: dict):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/" and self._token_ok(q):
            data = render_page(self.server.lang, self.server.broker.timeout_s).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif u.path == "/api/pending" and self._token_ok(q):
            self._json(200, {"pending": self.server.broker.snapshot()})
        elif u.path in ("/", "/api/pending"):
            self._json(403, {"error": "invalid token"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path != "/api/decide" or not self._token_ok(q):
            return self._json(403, {"error": "invalid token"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "bad json"})
        pid = str(body.get("id"))
        action = body.get("action")
        if action not in ("allow", "deny", "revise"):
            return self._json(400, {"error": "bad action"})
        decision = {"action": action}
        lang = self.server.lang
        if action == "revise":
            decision["message"] = (i18n.t(lang, "msg_revise_prefix")
                                   + (body.get("message") or i18n.t(lang, "msg_revise_default")))
        elif action == "deny":
            decision["message"] = body.get("message") or i18n.t(lang, "msg_denied")
        if body.get("cache_pattern"):
            decision["cache_pattern"] = True
        ok = self.server.broker.decide(pid, decision)
        self._json(200, {"ok": ok})


class WebApprovalServer:
    def __init__(self, broker: ApprovalBroker, host: str = "127.0.0.1", port: int = 0,
                 lang: str = "en"):
        self.token = secrets.token_urlsafe(16)
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.broker = broker
        self.httpd.token = self.token
        self.httpd.lang = lang if lang in i18n.LANGS else "en"
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}/?t={self.token}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
