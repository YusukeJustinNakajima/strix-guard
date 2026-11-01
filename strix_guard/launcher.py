"""launcher: Docker APIプロキシを起動し、DOCKER_HOSTを注入して strix を実行する

M1スケルトン。実runでの検証は Docker が利用可能な環境で行う。

使い方:
  python3 -m strix_guard.launcher --dry-run --target http://host.docker.internal:5000
  python3 -m strix_guard.launcher --target ... -- <strix args...>
"""
import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

from . import i18n
from .audit import Audit
from .ledger import build_ledger_from_db, resolve_script
from .decision import DecisionService
from .docker_proxy import DockerProxy
from .ui import CliApproval, NonInteractivePolicy, TuxPopupApproval, WebApproval
from .policy import ui_label
from .policy_config import policy_summary, resolve_policy, review_band_hits, write_snapshot
from .policy_guard import check_exec_policy, infra_only
from .sidecar_manager import make_hooks as make_sidecar_hooks, prepare as prepare_sidecar


def resolve_docker_endpoint() -> tuple:
    """DOCKER_HOST -> docker context -> default socket の順で解決（strixと同じ規則）"""
    dh = os.environ.get("DOCKER_HOST")
    if dh:
        if dh.startswith("unix://"):
            return ("unix", dh[len("unix://"):])
        if dh.startswith("tcp://"):
            hostport = dh[len("tcp://"):]
            host, _, port = hostport.partition(":")
            return ("tcp", host, int(port or 2375))
    return ("unix", "/var/run/docker.sock")


def find_docker_cli() -> str | None:
    """docker CLI を探索（PATH→snap→標準パス）。strixのプリフライト用"""
    import glob
    p = shutil.which("docker")
    if p:
        return p
    cands = sorted(glob.glob("/snap/docker/*/bin/docker")) + ["/usr/bin/docker", "/usr/local/bin/docker"]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


_URL_RE = re.compile(r"https?://[^\s'\"<>`]+")


def _inner_command(cmd: str) -> str:
    """PTYラッパーやシェル起動ラッパーを剥がして、実際のコマンドを取り出す"""
    s = cmd.strip()
    if "sandbox-docker-archive" in s:
        for marker in ("bash -lc ", " sh -lc "):
            if marker in s:
                s = s.split(marker, 1)[1].strip()
                break
    m = re.match(r"^(?:bash|sh|zsh)\s+-lc\s+(.*)$", s, re.S)
    if m:
        s = m.group(1).strip().strip("'\"")
    return s


def _family(cmd: str) -> str:
    """コマンド系統（ツール + 対象）のキー。修正後の再試行の自動許可に使う"""
    inner = _inner_command(cmd)
    parts = inner.split()
    tool = os.path.basename(parts[0]) if parts else "?"
    m = _URL_RE.search(inner)
    if m:
        try:
            from urllib.parse import urlsplit
            p = urlsplit(m.group(0))
            path = p.path.split("/FUZZ")[0]
            port = f":{p.port}" if p.port else ""
            target = f"{p.scheme}://{p.hostname or ''}{port}{path}"
        except Exception:
            target = m.group(0)
    else:
        m2 = re.search(r"([\w./-]+\.(?:py|sh|js|rb|pl))\b", inner)
        target = m2.group(1) if m2 else ""
    return f"{tool}|{target}"


_PARALLEL_RE = re.compile(
    r"(?:^|\s)-t\s*(\d+)|--threads[= ](\d+)|max_workers\s*=\s*(\d+)|ThreadPoolExecutor\(\s*max_workers\s*=\s*(\d+)")


def _parallel_of(cmd: str) -> int | None:
    """コマンドから並列数を推定（不明なら None）"""
    best = None
    for m in _PARALLEL_RE.finditer(cmd):
        for g in m.groups():
            if g:
                v = int(g)
                best = v if best is None else max(best, v)
    return best


class LedgerCache:
    """runディレクトリの agents.db から path->content 台帳を遅延構築（mtimeで更新）"""

    def __init__(self, runs_dir: str):
        self.runs_dir = os.path.abspath(runs_dir)
        self.current_dir: str | None = None
        self.ledger: dict[str, str] = {}
        self._mtime = 0.0
        self._last_scan = 0.0

    def _newest_run_dir(self) -> str | None:
        try:
            dirs = [os.path.join(self.runs_dir, d) for d in os.listdir(self.runs_dir)]
            dirs = [d for d in dirs if os.path.isdir(d)]
            return max(dirs, key=lambda d: os.path.getmtime(d)) if dirs else None
        except Exception:
            return None

    def get(self) -> dict[str, str]:
        now = time.time()
        if now - self._last_scan > 1.0:
            self._last_scan = now
            d = self._newest_run_dir()
            if d and d != self.current_dir:
                self.current_dir = d
                self._mtime = 0.0
        if not self.current_dir:
            return {}
        db = os.path.join(self.current_dir, ".state", "agents.db")
        try:
            mt = os.path.getmtime(db)
        except Exception:
            return self.ledger
        if mt != self._mtime:
            self._mtime = mt
            try:
                self.ledger = build_ledger_from_db(db)
            except Exception:
                pass
        return self.ledger


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", default="./strix_runs")
    ap.add_argument("--audit-dir", default=os.path.expanduser("~/blackbox-testing/strix_guard/guard_runs"))
    ap.add_argument("--dry-run", action="store_true", help="strixを起動せずproxyだけ起動")
    ap.add_argument("--ui", choices=["auto", "cli", "tmux", "web", "noninteractive"], default="auto")
    ap.add_argument("--on-ask", choices=["deny", "allow"], default="deny")
    ap.add_argument("--strict", action="store_true", help="しきい値を下げてaskを出やすくする（デモ用）")
    ap.add_argument("--no-jev", action="store_true")
    ap.add_argument("--approval-timeout", type=float, default=180.0,
                    help="承認待ちのタイムアウト秒（超えたら自動拒否）")
    ap.add_argument("--auto-allow-revised", action="store_true",
                    help="修正後の同系統コマンドを自動許可（既定: 修正後も人間が確認）")
    ap.add_argument("--adjudicator", choices=["off", "advisory", "hybrid", "auto"], default="off",
                    help="非ALLOWの裁定: off=人間 / advisory=提案のみ / hybrid=低リスクは自動 / auto=全自動")
    ap.add_argument("--adjudicator-model", default="openai/gpt-6-sol")
    ap.add_argument("--adjudicator-fallback-models",
                    default="google/gemini-3.8-flash,anthropic/claude-opus-4.6",
                    help="カンマ区切りのフォールバックモデル（provider拒否・失敗時に順に試す）")
    ap.add_argument("--adjudicator-max-calls", type=int, default=200)
    ap.add_argument("--adjudicator-max-cost", type=float, default=3.0)
    ap.add_argument("--policy", default=None, help="JSONポリシーファイル（プリセットに上書き）")
    ap.add_argument("--policy-preset", choices=["full", "reference_only", "recon"], default=None,
                    help="テスト方針プリセット（既定: full）")
    ap.add_argument("--no-gray-review", action="store_true",
                    help="ALLOWでもreview_band以上のリスクを強モデルに再審査しない")
    ap.add_argument("--no-http-enforce", action="store_true",
                    help="ポリシーがhttp.enforceでもコンテナ内HTTPプロキシを起動しない")
    ap.add_argument("--adjudicator-review-blocks", action="store_true",
                    help="BLOCKも強モデルに再審査させ理由を監査に残す（soft blockはダウングレード可）")
    ap.add_argument("--pii-policy", choices=["test_data_ok", "strict"], default="test_data_ok",
                    help="benchmarkではシード/テストアカウントのデータを機微扱いしない（既定）")
    ap.add_argument("--setup", action="store_true", help="起動時に設定ウィザードを表示")
    ap.add_argument("--no-setup", action="store_true", help="ウィザードを表示しない")
    ap.add_argument("--language", choices=["en", "ja"], default="en")
    ap.add_argument("--environment", choices=["benchmark", "staging", "production"], default="benchmark")
    ap.add_argument("--test-accounts", default=os.environ.get("STRIX_GUARD_TEST_ACCOUNTS", ""),
                    help="読み取り/変更を許可するテストアカウント（カンマ区切り）")
    ap.add_argument("--no-wrap", action="store_true", help="tmux自動ラップを無効化（内部用）")
    ap.add_argument("strix_args", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)

    # 端末UI（TUI）と承認プロンプトの衝突を避けるため、tmux内で自分自身を再実行する
    wants_tty = args.ui in ("auto", "cli", "tmux")
    if (wants_tty and not args.no_wrap and not os.environ.get("STRIX_GUARD_NO_WRAP")
            and sys.stdin.isatty() and not os.environ.get("TMUX") and shutil.which("tmux")):
        sess = f"strix-guard-{os.getpid()}"
        # tmux はシェル経由で実行するため、引数は必ず shlex.join でクォートする
        inner = [sys.executable, "-m", "strix_guard.launcher"] + list(sys.argv[1:])
        print(f"[strix-guard] tmux session '{sess}' を起動します（終了で元のシェルへ戻ります）", flush=True)
        env2 = dict(os.environ, STRIX_GUARD_NO_WRAP="1")
        rc = subprocess.call(["tmux", "new-session", "-s", sess, "-c", os.getcwd(),
                              shlex.join(inner)], env=env2)
        sys.exit(rc)

    setup_scale = 1.0
    setup_policy_preset = None
    setup_policy_file = None
    should_setup = (args.setup or (not args.no_setup and not args.dry_run
                    and args.ui != "noninteractive" and sys.stdin.isatty()
                    and not os.environ.get("STRIX_GUARD_NO_SETUP")))
    if should_setup:
        from .setup import run_setup
        hints = " ".join(a for a in args.strix_args
                         if re.match(r"^https?://", a) or re.match(r"^[\w.-]+:\d{2,5}$", a))
        res = run_setup(targets_hint=hints)
        args.environment = res.environment
        args.language = res.language
        args.pii_policy = res.pii_policy
        args.adjudicator = res.adjudicator
        args.adjudicator_model = res.adjudicator_model
        args.adjudicator_max_cost = res.adjudicator_max_cost
        args.approval_timeout = res.approval_timeout
        args.test_accounts = ",".join(res.test_accounts or [])
        setup_scale = res.threshold_scale
        setup_policy_preset = res.policy_preset
        setup_policy_file = res.policy_file or None

    preset = args.policy_preset or setup_policy_preset or "full"
    if preset == "custom":
        preset = "full"
    policy_path = args.policy or setup_policy_file
    try:
        guard_policy = resolve_policy(preset=preset, path=policy_path)
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"[strix-guard] policy error: {e}", flush=True)
        return 2

    acct_args = [a.strip() for a in (args.test_accounts or "").split(",") if a.strip()]
    if acct_args:
        guard_policy["data"]["allowed_test_accounts"] = acct_args
    test_accounts = acct_args or list(guard_policy["data"].get("allowed_test_accounts") or [])

    policy = None
    if args.strict or setup_scale != 1.0 or guard_policy.get("thresholds"):
        import copy
        from .policy import DEFAULT_POLICY
        policy = copy.deepcopy(DEFAULT_POLICY)
        if guard_policy.get("thresholds"):
            policy["thresholds"].update(guard_policy["thresholds"])
        if args.strict:
            policy["thresholds"]["load_ask"] = 0.20
            policy["thresholds"]["destructiveness_ask"] = 0.30
        if setup_scale != 1.0:
            for k in list(policy["thresholds"]):
                if k.endswith("_ask"):
                    policy["thresholds"][k] = max(0.05, policy["thresholds"][k] * setup_scale)

    env_label = "benchmark/sandbox" if args.environment == "benchmark" else args.environment
    svc = DecisionService(use_jev=not args.no_jev, summarize=True, policy=policy,
                          environment=env_label, pii_policy=args.pii_policy,
                          language=args.language, test_accounts=test_accounts)
    run_tag = time.strftime("%Y%m%d-%H%M%S")
    audit_dir = os.path.join(args.audit_dir, f"run-{run_tag}")
    audit = Audit(audit_dir)
    policy_sha = write_snapshot(guard_policy, audit_dir)
    print(f"[strix-guard] audit dir: {audit_dir}", flush=True)
    print(f"[strix-guard] policy={guard_policy.get('preset')} sha256={policy_sha[:16]} "
          f"gray_review={'off' if args.no_gray_review else 'on'}", flush=True)
    sidecar = None
    if not args.no_http_enforce:
        try:
            sidecar = prepare_sidecar(guard_policy, args.strix_args)
            if sidecar:
                print(f"[strix-guard] http sidecar: {sidecar['base']} "
                      f"methods={','.join(sidecar['policy']['allowed_methods'])} "
                      f"hosts={','.join(sidecar['policy']['allowed_hosts']) or '(in-scope)'}",
                      flush=True)
        except Exception as e:
            print(f"[strix-guard] http sidecar setup failed: {e}", flush=True)
    elif guard_policy.get("http", {}).get("enforce"):
        print("[strix-guard] http enforce disabled by --no-http-enforce", flush=True)
    ledger_cache = LedgerCache(args.runs_dir)
    adjudicator = None
    if args.adjudicator != "off":
        from .adjudicator import Adjudicator
        fallbacks = [m.strip() for m in (args.adjudicator_fallback_models or "").split(",") if m.strip()]
        adjudicator = Adjudicator(svc.api_key, model=args.adjudicator_model,
                                  fallback_models=fallbacks,
                                  max_calls=args.adjudicator_max_calls,
                                  max_cost_usd=args.adjudicator_max_cost)
        print(f"[strix-guard] adjudicator={args.adjudicator} model={args.adjudicator_model} "
              f"fallbacks={','.join(fallbacks) or '-'}", flush=True)
    web_server = None
    if args.ui == "noninteractive" or (not sys.stdin.isatty() and args.ui != "web"):
        ui = NonInteractivePolicy(on_ask=args.on_ask, lang=args.language)
    elif args.ui == "web" or (args.ui == "auto" and not shutil.which("tmux")):
        from .webui import ApprovalBroker, WebApprovalServer
        broker = ApprovalBroker(timeout_s=args.approval_timeout)
        web_server = WebApprovalServer(broker, lang=args.language).start()
        print(f"[strix-guard] 承認UI(ブラウザ): {web_server.url()}", flush=True)
        ui = WebApproval(broker, timeout_s=args.approval_timeout)
    elif os.environ.get("TMUX") and shutil.which("tmux"):
        ui = TuxPopupApproval(timeout_s=args.approval_timeout, lang=args.language)
    else:
        ui = CliApproval(lang=args.language)

    pending: dict[str, tuple] = {}
    pending_lock = threading.Lock()
    approved_patterns: set[str] = set()
    approved_envelopes: dict[str, dict] = {}
    revise_history: dict[str, dict] = {}

    def _sig(cmd: str) -> str:
        """ラッパー経由のPTY実行は内側コマンドを署名にする（リトライ重複の排除）"""
        if "sandbox-docker-archive" in cmd:
            for marker in ("bash -lc ", " sh -lc "):
                if marker in cmd:
                    return cmd.split(marker, 1)[1].strip()
        return cmd.strip()

    def _apply_adjudication(adj: dict, fam: str, cmd: str, ev) -> tuple | None:
        """Adjudicatorの裁定を実行アクションに変換（Noneはescalate/不明）"""
        action = adj.get("action")
        cons = adj.get("constraints") or {}
        if action == "allow":
            try:
                par_lim = int(cons.get("max_parallel") or 10)
            except Exception:
                par_lim = 10
            approved_envelopes[fam] = {"max_load": min(1.0, max(0.5, ev.risk.load)),
                                       "max_parallel": max(par_lim, 10)}
            return ("allow", None)
        if action == "revise":
            instr = adj.get("instruction_for_agent") or \
                "Reduce request volume and scope to your own test data, then retry."
            extra = []
            if cons.get("max_parallel"):
                extra.append(f"max_parallel={cons['max_parallel']}")
            if cons.get("max_requests"):
                extra.append(f"max_requests={cons['max_requests']}")
            if cons.get("scope"):
                extra.append(f"scope={cons['scope']}")
            msg = i18n.t(args.language, "msg_revise_prefix") + instr + \
                ((" (" + ", ".join(extra) + ")") if extra else "")
            revise_history[fam] = {"cmd": cmd, "cmd_inner": _inner_command(cmd), "instruction": msg}
            return ("revise", msg)
        if action == "deny":
            return ("deny", "[strix-guard] adjudicator denied: " + (adj.get("rationale") or ""))
        return None

    def on_exec(container_id: str, cmd_argv: list, spec: dict):
        cmd = " ".join(cmd_argv) if isinstance(cmd_argv, list) else str(cmd_argv)
        script = None
        try:
            ledger = ledger_cache.get()
            if ledger:
                script = resolve_script(ledger, cmd)
        except Exception:
            script = None
        policy_ctx = policy_summary(guard_policy)
        if infra_only(cmd, script, guard_policy):
            audit.record({"kind": "evaluation", "container_id": container_id, "cmd": cmd,
                          "verdict": "ALLOW", "ui": "allow",
                          "risk": {"source": "infra"}, "reasons": ["infra_host"],
                          "resolved": bool(script), "script_len": len(script or ""),
                          "card": None})
            return ("allow", None)
        violations = check_exec_policy(cmd, script, guard_policy)
        if violations:
            v = violations[0]
            audit.record({"kind": "evaluation", "container_id": container_id, "cmd": cmd,
                          "verdict": "BLOCK", "ui": "deny",
                          "risk": {"source": "policy_rule"}, "reasons": [x.kind for x in violations],
                          "resolved": bool(script), "script_len": len(script or ""),
                          "card": None, "detail": v.detail}, source="policy_rule")
            return ("deny", v.message)
        ev = svc.evaluate(cmd, script_content=script,
                          context={"environment": env_label, "guard_policy": policy_ctx},
                          want_card=True)
        summary = ev.decision.as_dict()
        audit.record({"kind": "evaluation", "container_id": container_id, "cmd": cmd,
                      "verdict": ev.decision.verdict.value,
                      "ui": ui_label(ev.decision),
                      "risk": ev.risk.__dict__, "reasons": ev.decision.reasons,
                      "resolved": bool(script), "script_len": len(script or ""),
                      "card": ev.card})
        if ev.decision.verdict.value == "ALLOW":
            if adjudicator and args.adjudicator != "off" and not args.no_gray_review:
                hits = review_band_hits(ev.risk, guard_policy)
                if hits:
                    fam = _family(cmd)
                    gray = adjudicator.adjudicate(
                        cmd=cmd, script_content=script, risk=ev.risk, decision=ev.decision,
                        context={"environment": env_label, "family": fam,
                                 "allowed_test_accounts": test_accounts,
                                 "guard_policy": policy_ctx,
                                 "review_mode": "gray_zone",
                                 "review_band_hits": hits},
                        history=revise_history.get(fam))
                    audit.record({"kind": "gray_review", "container_id": container_id,
                                  "cmd": cmd, "hits": hits,
                                  "action": (gray or {}).get("action"),
                                  "constraints": (gray or {}).get("constraints"),
                                  "rationale": (gray or {}).get("rationale"),
                                  "instruction": (gray or {}).get("instruction_for_agent"),
                                  "confidence": (gray or {}).get("confidence"),
                                  "model": (gray or {}).get("model"),
                                  "fallback": (gray or {}).get("fallback"),
                                  "cost": (gray or {}).get("cost"),
                                  "error": (None if gray else getattr(adjudicator, "last_error", None))})
                    if gray:
                        applied = _apply_adjudication(gray, fam, cmd, ev)
                        if applied:
                            return applied
            return ("allow", None)
        fam = _family(cmd)
        # ハードブロックはユーザーに聞かず即遮断。soft blockは任意で強モデル再審査
        if ev.decision.verdict.value == "BLOCK":
            reasons = set(ev.decision.reasons or [])
            hard = bool(reasons & {"third_party_attack", "out_of_scope",
                                   "irreversible_destruction", "dos_scale_load"})
            if adjudicator and args.adjudicator_review_blocks:
                rev = adjudicator.adjudicate(cmd=cmd, script_content=script, risk=ev.risk,
                                             decision=ev.decision,
                                             context={"environment": env_label,
                                                      "policy_block": sorted(reasons),
                                                      "block_kind": "hard" if hard else "soft",
                                                      "allowed_test_accounts": test_accounts,
                                                      "guard_policy": policy_ctx},
                                             history=revise_history.get(fam))
                audit.record({"kind": "block_review", "container_id": container_id, "cmd": cmd,
                              "policy_reasons": sorted(reasons),
                              "block_kind": "hard" if hard else "soft",
                              "action": (rev or {}).get("action"),
                              "constraints": (rev or {}).get("constraints"),
                              "rationale": (rev or {}).get("rationale"),
                              "instruction": (rev or {}).get("instruction_for_agent"),
                              "confidence": (rev or {}).get("confidence"),
                              "model": (rev or {}).get("model"),
                              "cost": (rev or {}).get("cost"),
                              "error": (None if rev else getattr(adjudicator, "last_error", None))})
                if (not hard) and rev and rev.get("action") in ("allow", "revise"):
                    try:
                        conf = float(rev.get("confidence") or 0)
                    except Exception:
                        conf = 0.0
                    if conf >= 0.8 and args.adjudicator in ("auto", "hybrid"):
                        applied = _apply_adjudication(rev, fam, cmd, ev)
                        if applied:
                            audit.record({"kind": "block_downgrade", "container_id": container_id,
                                          "cmd": cmd, "to": rev.get("action"),
                                          "confidence": conf})
                            return applied
            return ("deny", "[strix-guard] ポリシーにより遮断（" + ",".join(ev.decision.reasons)
                    + "）。制約を満たす形に修正してください。")
        # 「修正して再試行」で承認した系統は、より軽い再試行を自動許可（承認の繰り返しを防ぐ）
        envp = approved_envelopes.get(fam)
        if args.auto_allow_revised and envp:
            par = int((ev.risk.facts or {}).get("parallel") or 0)
            if ev.risk.load <= envp["max_load"] and par <= envp["max_parallel"]:
                audit.record({"kind": "envelope_hit", "container_id": container_id, "cmd": cmd,
                              "family": fam, "load": ev.risk.load, "parallel": par})
                return ("allow", None)
        # 非ALLOWは強モデル（Adjudicator）で裁定（mode: auto/hybrid/advisory）
        adj = None
        if adjudicator and ev.decision.verdict.value in ("REVISE", "HOLD", "NEED_INFO"):
            adj = adjudicator.adjudicate(cmd=cmd, script_content=script, risk=ev.risk,
                                         decision=ev.decision,
                                         context={"environment": env_label, "family": fam,
                                                  "allowed_test_accounts": test_accounts,
                                                  "guard_policy": policy_ctx},
                                         history=revise_history.get(fam))
            audit.record({"kind": "adjudication", "container_id": container_id, "cmd": cmd,
                          "action": (adj or {}).get("action"),
                          "constraints": (adj or {}).get("constraints"),
                          "rationale": (adj or {}).get("rationale"),
                          "instruction": (adj or {}).get("instruction_for_agent"),
                          "confidence": (adj or {}).get("confidence"),
                          "model": (adj or {}).get("model"),
                          "fallback": (adj or {}).get("fallback"),
                          "cost": (adj or {}).get("cost"),
                          "error": (None if adj else getattr(adjudicator, "last_error", None))})
            apply_now = False
            if adj:
                a = adj.get("action")
                try:
                    conf = float(adj.get("confidence") or 0.0)
                except Exception:
                    conf = 0.0
                if args.adjudicator == "auto":
                    apply_now = True
                elif args.adjudicator == "hybrid" and a in ("allow", "revise", "deny") and conf >= 0.7:
                    apply_now = True
            if apply_now and adj:
                applied = _apply_adjudication(adj, fam, cmd, ev)
                if applied:
                    return applied
                if args.adjudicator == "auto":
                    return ("deny", "[strix-guard] adjudicator escalated; denied in auto mode. "
                            + (adj.get("rationale") or ""))
            elif args.adjudicator == "auto":
                err = (getattr(adjudicator, "last_error", None) or "no response")[:300]
                return ("deny", "[strix-guard] adjudicator unavailable; denied (auto mode). " + err)
        key = _sig(cmd)
        if key in approved_patterns:
            return ("allow", None)
        with pending_lock:
            entry = pending.get(key)
            owner = entry is None
            if owner:
                entry = (threading.Event(), {})
                pending[key] = entry
        if not owner:
            entry[0].wait(timeout=args.approval_timeout + 60)
            d = dict(entry[1])
            if d.get("action"):
                return (d["action"], d.get("message"))
            return ("deny", "[strix-guard] 同一コマンドの承認待ちがタイムアウトしました。")
        hist = revise_history.get(fam)
        extra = None
        if hist:
            from .diff import command_diff
            old_inner = hist.get("cmd_inner") or _inner_command(hist.get("cmd", ""))
            new_inner = _inner_command(cmd)
            expected_par = None
            mnum = re.search(r"(\d+)", hist.get("instruction") or "")
            if mnum:
                expected_par = int(mnum.group(1))
            else:
                try:
                    expected_par = int((ev.decision.constraints or {}).get("max_parallel"))
                except Exception:
                    expected_par = None
            par = _parallel_of(new_inner)
            c_ok = None
            c_note = ""
            if expected_par:
                if par is not None:
                    c_ok = par <= expected_par
                    c_note = f"並列{par}（指定{expected_par}{'以内' if c_ok else 'を超過'}）"
                else:
                    c_note = f"並列数が不明（指定{expected_par}）"
            extra = {"previous_cmd": old_inner,
                     "instruction": hist.get("instruction", ""),
                     "diff": command_diff(old_inner, new_inner),
                     "constraint_ok": c_ok, "constraint_note": c_note}
        if adj and args.adjudicator in ("advisory", "hybrid"):
            extra = extra or {}
            extra["adjudicator"] = {"action": adj.get("action"),
                                    "rationale": adj.get("rationale"),
                                    "confidence": adj.get("confidence"),
                                    "instruction": adj.get("instruction_for_agent")}
        try:
            d = ui.ask(ev.card, cmd, summary, extra)
            if d.cache_pattern:
                approved_patterns.add(key)
            entry[1].update({"action": d.action, "message": d.message})
            if d.action == "allow":
                return ("allow", None)
            if d.action == "revise":
                revise_history[fam] = {"cmd": cmd, "cmd_inner": _inner_command(cmd),
                                       "instruction": (d.message or "")}
                cons = ev.decision.constraints or {}
                try:
                    load_ask = float(svc.policy["thresholds"]["load_ask"])
                except Exception:
                    load_ask = 0.2
                par = int((ev.risk.facts or {}).get("parallel") or 0)
                approved_envelopes[fam] = {
                    "max_load": min(1.0, max(load_ask, ev.risk.load * 0.75)),
                    "max_parallel": max(int(cons.get("max_parallel") or 10), par, 10),
                }
                msg = d.message or ""
                extra = []
                if cons.get("max_parallel"):
                    extra.append(f"max_parallel={cons['max_parallel']}")
                if cons.get("max_requests"):
                    extra.append(f"max_requests={cons['max_requests']}")
                if extra:
                    msg = (msg + " (" + ", ".join(extra) + ")").strip()
                return ("revise", msg)
            return ("deny", d.message or "[strix-guard] denied")
        finally:
            with pending_lock:
                pending.pop(key, None)
            entry[0].set()

    upstream = resolve_docker_endpoint()
    sc_create, sc_start = (None, None)
    if sidecar:
        sc_create, sc_start = make_sidecar_hooks(
            sidecar, upstream, lambda rec: audit.record(rec))
    proxy = DockerProxy(upstream=upstream, on_exec=on_exec,
                        audit=lambda rec: audit.record({**rec, "kind": "action"}),
                        on_container_create=sc_create,
                        on_container_start=sc_start,
                        exec_env_proxy=("http://127.0.0.1:48081" if sidecar else None)).start()
    host, port = proxy.address
    print(f"[strix-guard] docker proxy on 127.0.0.1:{port} -> {upstream}", flush=True)

    if args.dry_run:
        print("[strix-guard] dry-run: proxy running. Ctrl-C to stop.", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            proxy.stop()
            if web_server:
                web_server.stop()
            return 0

    strix = shutil.which("strix") or os.path.expanduser("~/.strix/bin/strix")
    env = dict(os.environ)
    # DOCKER_HOST を guard 経由に差し替え
    env["DOCKER_HOST"] = f"tcp://127.0.0.1:{port}"
    # docker CLI を探索して PATH に注入（strixのプリフライト対策）
    docker_cli = find_docker_cli()
    if docker_cli:
        env["PATH"] = os.path.dirname(docker_cli) + os.pathsep + env.get("PATH", "")
        try:
            out = subprocess.run([docker_cli, "version", "--format", "{{.Server.Version}}"],
                                 env=env, capture_output=True, text=True, timeout=30)
            ver = (out.stdout or out.stderr).strip().splitlines()[-1] if (out.stdout or out.stderr) else "?"
            print(f"[strix-guard] docker CLI: {docker_cli} (server via proxy: {ver})", flush=True)
        except Exception as e:
            print(f"[strix-guard] docker CLI preflight failed: {e}", flush=True)
    else:
        print("[strix-guard] WARNING: docker CLI not found; strix may refuse to start", flush=True)
    cmdline = [strix] + [a for a in args.strix_args if a != "--"]
    print(f"[strix-guard] launching: {' '.join(cmdline)}", flush=True)
    try:
        proc = subprocess.Popen(cmdline, env=env)
        rc = proc.wait()
    finally:
        proxy.stop()
        if web_server:
            web_server.stop()
        if sidecar:
            try:
                import glob
                for p in glob.glob(os.path.join(sidecar["log_dir"], "http-*.jsonl")):
                    shutil.copy2(p, os.path.join(audit_dir, os.path.basename(p)))
                print(f"[strix-guard] http access log: {sidecar['log_dir']}", flush=True)
            except Exception as e:
                print(f"[strix-guard] http log copy failed: {e}", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
