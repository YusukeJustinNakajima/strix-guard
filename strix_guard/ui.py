"""承認UI: tmuxポップアップ（第一） / CLI対話 / 非対話ポリシー（en/ja）"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass

from . import i18n


@dataclass
class Decision:
    action: str            # allow | deny | revise
    message: str | None = None
    cache_pattern: bool = False


class CliApproval:
    """端末上で [a]1回だけ許可 [p]常に許可 [e]修正 [d]拒否 [c]内容確認"""

    def __init__(self, input_fn=input, output_fn=print, lang: str = "en"):
        self.input = input_fn
        self.output = output_fn
        self.lang = lang if lang in i18n.LANGS else "en"

    def t(self, key: str, **kw) -> str:
        return i18n.t(self.lang, key, **kw)

    def ask(self, card: str | None, cmd: str, decision_summary: dict, extra: dict | None = None) -> Decision:
        self.output("=" * 60)
        if extra:
            self.output("--- " + self.t("rev_prev") + " ---")
            self.output(extra.get("instruction") or "-")
            self.output("--- " + self.t("rev_diff") + " ---")
            self.output(extra.get("diff") or "-")
            if extra.get("constraint_note"):
                lead = self.t("rev_ok") if extra.get("constraint_ok") is True else self.t("rev_insufficient")
                self.output("  -> " + lead + str(extra.get("constraint_note")))
            self.output("-" * 60)
        self.output(card or cmd[:400])
        self.output(f"[policy] {decision_summary}")
        self.output(f"[a] {self.t('btn_allow_once')}   [p] {self.t('btn_allow_always')}   "
                    f"[e] {self.t('btn_revise')}   [d] {self.t('btn_deny')}   [c] raw")
        ans = (self.input("> ") or "").strip().lower()
        if ans in ("a", "allow"):
            return Decision("allow")
        if ans in ("p", "pattern"):
            return Decision("allow", cache_pattern=True)
        if ans in ("e", "edit", "revise"):
            text = self.input(self.t("placeholder_revise") + ": ")
            return Decision("revise", message=self.t("msg_revise_prefix")
                            + (text or self.t("msg_revise_default")))
        if ans in ("c", "cat"):
            self.output(cmd[:2000])
            return self.ask(card, cmd, decision_summary, extra)
        return Decision("deny", message=self.t("msg_denied"))


class TuxPopupApproval:
    """tmux display-popup で承認カードを出す（strixのTUIに上書きされない）"""

    def __init__(self, timeout_s: float = 180, width: str = "82%", height: str = "62%",
                 lang: str = "en"):
        self.timeout_s = timeout_s
        self.width = width
        self.height = height
        self.lang = lang if lang in i18n.LANGS else "en"
        self._lock = threading.Lock()
        self.dir = tempfile.mkdtemp(prefix="strix-guard-approve-")

    def ask(self, card: str | None, cmd: str, decision_summary: dict, extra: dict | None = None) -> Decision:
        if not os.environ.get("TMUX"):
            raise RuntimeError("TuxPopupApproval requires tmux")
        uid = uuid.uuid4().hex[:10]
        payload = os.path.join(self.dir, f"{uid}.json")
        decision = os.path.join(self.dir, f"{uid}.decision.json")
        with open(payload, "w", encoding="utf-8") as f:
            json.dump({"card": card, "cmd": cmd, "summary": decision_summary,
                       "revision": extra}, f, ensure_ascii=False)
        inner = ("%s -m strix_guard.approve %s %s %s"
                 % (shlex.quote(sys.executable), shlex.quote(payload),
                    shlex.quote(decision), self.timeout_s))
        env = dict(os.environ, STRIX_GUARD_LANG=self.lang)
        with self._lock:
            try:
                subprocess.run(["tmux", "display-popup", "-E", "-w", self.width, "-h", self.height,
                                inner], check=False, env=env)
            except Exception:
                pass
        try:
            with open(decision, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {"action": "deny", "message": i18n.t(self.lang, "msg_result_missing")}
        return Decision(d.get("action", "deny"), d.get("message"), bool(d.get("cache_pattern")))


class WebApproval:
    """ブラウザ承認UI（WebApprovalServer + ApprovalBroker）"""

    def __init__(self, broker, timeout_s: float | None = None):
        self.broker = broker
        self.timeout_s = timeout_s

    def ask(self, card: str | None, cmd: str, decision_summary: dict, extra: dict | None = None) -> Decision:
        d = self.broker.request({"card": card or "", "cmd": cmd, "summary": decision_summary,
                                 "revision": extra}, timeout_s=self.timeout_s)
        return Decision(d.get("action", "deny"), d.get("message"),
                        bool(d.get("cache_pattern")))


class NonInteractivePolicy:
    """人間不在時: NEED_INFO/REVISE/HOLD の扱いを設定で決める"""

    def __init__(self, on_ask: str = "deny", on_need_info: str = "deny", lang: str = "en"):
        assert on_ask in ("deny", "allow")
        assert on_need_info in ("deny", "allow")
        self.on_ask = on_ask
        self.on_need_info = on_need_info
        self.lang = lang if lang in i18n.LANGS else "en"

    def ask(self, card, cmd, decision_summary, extra: dict | None = None) -> Decision:
        v = decision_summary.get("verdict")
        if v == "ALLOW":
            return Decision("allow")
        if v == "NEED_INFO":
            return Decision(self.on_need_info, message=i18n.t(self.lang, "msg_noninteractive_needinfo"))
        return Decision(self.on_ask, message=i18n.t(self.lang, "msg_noninteractive_deny"))
