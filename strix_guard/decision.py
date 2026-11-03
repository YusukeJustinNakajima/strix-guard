"""Decision Service: JEVリスク評価 + ヒューリスティックfallback + Policy Engine + 要約カード"""
import json
import os
import re
import urllib.request
from dataclasses import dataclass, field

from . import i18n
from .policy import RiskVector, PolicyDecision, decide, DEFAULT_POLICY, sandbox_internal, Verdict

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"


def load_api_key() -> str | None:
    key = os.environ.get("OPENROUTER_API_KEY")
    if key:
        return key
    cfg = os.path.expanduser("~/.strix/cli-config.json")
    if os.path.exists(cfg):
        try:
            env = json.load(open(cfg, encoding="utf-8")).get("env", {})
            return env.get("LLM_API_KEY") or env.get("OPENAI_API_KEY")
        except Exception:
            return None
    return None


# ---------- リスク次元の質問定義（JEV decisions API） ----------
def risk_questions() -> dict:
    def score(desc: str) -> dict:
        return {"type": "score", "instructions": desc,
                "criteria": [{"score": 0, "description": "none/low"},
                             {"score": 100, "description": "severe/high"}]}
    return {
        "destructiveness": score(
            "How destructive/irreversible is this action to the declared target "
            "web application if executed? Ignore sandbox-local file cleanup and "
            "workspace changes (rm/cp/mv/cat/mkdir under /workspace or /tmp). "
            "0=read-only to the target, 100=irreversible destruction of target "
            "data or infrastructure."),
        "load": score(
            "How heavy is the request load on the declared target web application? "
            "Ignore sandbox-local commands. "
            "0=<=200 requests and <=10 parallel, 100=>10000 requests or >100 parallel."),
        "data_exposure": score(
            "How sensitive is the data this action can read or exfiltrate from the "
            "target web application? Ignore local workspace files and Caido request "
            "inspection unless data is sent off-target. 0=public target data; "
            "40=developer-provided seed or test-account data (not sensitive in "
            "benchmark/sandbox); 100=real or unintended users' PII, or off-target "
            "credential exfiltration."),
        "scope_violation": score(
            "Is this action outside the declared target web-application scope? "
            "0=fully in-scope, 100=attacks unrelated systems."),
        "third_party": score(
            "Can this action harm third parties (external hosts, other tenants)? "
            "0=none, 100=direct attack on third-party infrastructure."),
        "sufficiency": {"type": "choice",
                        "instructions": "Is the concrete action on the target web "
                                        "application fully visible for judging? "
                                        "Sandbox-local file operations (test/ls/stat/"
                                        "mkdir/chmod/cat/rm under local workspace) are "
                                        "out of scope and sufficient. "
                                        "insufficient_content is for executed "
                                        "target-facing scripts whose content matters "
                                        "and is missing.",
                        "criteria": {
                            "sufficient": "the concrete action is fully visible or it is a local sandbox file operation",
                            "insufficient_content": "an executed script's content is unavailable and matters",
                            "ambiguous": "instructions ambiguous or truncated"}},
    }


@dataclass
class Evaluation:
    risk: RiskVector
    decision: PolicyDecision
    card: str | None = None
    raw_answers: dict = field(default_factory=dict)


class DecisionService:
    def __init__(self, api_key: str | None = None, use_jev: bool = True,
                 jev_model: str = "typesafe/jev-1.14",
                 summarizer_model: str = "deepseek/deepseek-v4.1-flash",
                 summarize: bool = True, timeout_s: int = 20,
                 policy: dict | None = None,
                 environment: str = "benchmark/sandbox",
                 pii_policy: str = "test_data_ok",
                 language: str = "en",
                 test_accounts: list | None = None):
        self.api_key = api_key or load_api_key()
        self.use_jev = use_jev and bool(self.api_key)
        self.jev_model = jev_model
        self.summarizer_model = summarizer_model
        self.summarize = summarize and bool(self.api_key)
        self.timeout_s = timeout_s
        self.policy = policy or DEFAULT_POLICY
        self.environment = environment
        self.pii_policy = pii_policy
        self.language = language if language in i18n.LANGS else "en"
        self.test_accounts = list(test_accounts or [])

    # ---------- リスク評価 ----------
    def assess(self, cmd: str, script_content: str | None = None, context: dict | None = None) -> RiskVector:
        if self.use_jev:
            try:
                return self._assess_jev(cmd, script_content, context or {})
            except Exception:
                pass  # fallback
        return heuristic_risk(cmd, script_content)

    def _call_decisions(self, body: dict) -> dict:
        req = urllib.request.Request(DECISIONS_URL, data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {self.api_key}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
            return json.loads(r.read())

    def _assess_jev(self, cmd: str, script_content: str | None, context: dict) -> RiskVector:
        state = {"environment": context.get("environment", "benchmark/sandbox"),
                 "command": cmd}
        if context.get("target"):
            state["target"] = str(context["target"])[:500]
        state["assessment_scope"] = (
            "Evaluate only effects on the declared target web application. "
            "Sandbox-local file operations (rm/cp/mv/cat/mkdir under /workspace or "
            "/tmp), local script writes, and Caido request inspection do not create "
            "target risk; score destructiveness/load/data_exposure/scope for the "
            "target only. If the command makes no request to the target, those "
            "dimensions should be 0 and sufficiency sufficient.")
        if self.test_accounts:
            state["allowed_test_accounts"] = self.test_accounts
            state["account_policy"] = ("Accounts listed in allowed_test_accounts are authorized test accounts; "
                                       "reading/modifying their data is acceptable. Other accounts are cross-user.")
        if script_content:
            state["script_content"] = script_content[:6000]
        if context.get("guard_policy"):
            state["guard_policy"] = context["guard_policy"]
        if context.get("task"):
            state["task_context"] = str(context["task"])[:1500]
        body = {"model": self.jev_model, "state": state, "questions": risk_questions()}
        d = self._call_decisions(body)
        a = d.get("answers", {})
        def sev(name: str) -> float:
            v = a.get(name, {})
            probs = v.get("probabilities") or {}
            if probs:
                return float(probs.get("1", probs.get("100", 0.0)))
            return float(v.get("score", 0.0))
        suf = (a.get("sufficiency") or {}).get("choice", "sufficient")
        return RiskVector(
            destructiveness=sev("destructiveness"), load=sev("load"),
            data_exposure=sev("data_exposure"), scope_violation=sev("scope_violation"),
            third_party=sev("third_party"), sufficiency=suf, source="jev")

    # ---------- 要約カード ----------
    def make_card(self, cmd: str, decision: PolicyDecision) -> str | None:
        if not self.summarize:
            return None
        system = i18n.t(self.language, "summary_system")
        body = {"model": self.summarizer_model, "temperature": 0, "max_tokens": 600,
                "reasoning": {"enabled": False},
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": "【コマンド】\n" + cmd[:3000] +
                              "\n\n【policy】" + json.dumps(decision.as_dict(), ensure_ascii=False)}]}
        req = urllib.request.Request(OPENROUTER_URL, data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {self.api_key}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                d = json.loads(r.read())
            return d["choices"][0]["message"].get("content")
        except Exception:
            return None

    # ---------- 統合 ----------
    def evaluate(self, cmd: str, script_content: str | None = None,
                 context: dict | None = None, want_card: bool = False) -> Evaluation:
        # サンドボックス内ローカル操作は即ALLOW（誤deny防止・負荷ゼロ）
        if sandbox_internal(cmd):
            risk = RiskVector(sufficiency="sufficient", source="sandbox_internal")
            return Evaluation(risk=risk, decision=PolicyDecision(Verdict.ALLOW, ["sandbox_internal"]))
        risk = normalize_risk(self.assess(cmd, script_content, context), cmd, script_content)
        risk = apply_data_policy(risk, self.environment, self.pii_policy)
        decision = decide(risk, self.policy)
        card = self.make_card(cmd, decision) if (want_card and decision.verdict.value in ("REVISE", "HOLD", "NEED_INFO")) else None
        return Evaluation(risk=risk, decision=decision, card=card)


# ---------- リスクの補正（決定論的ルール） ----------
def apply_data_policy(risk: RiskVector, environment: str, pii_policy: str) -> RiskVector:
    """benchmark/サンドボックスではシード・テスト・自作アカウントのデータは機微でない扱い。

    test_data_ok: データ露出スコアを上限0.4に補正（PII理由のBLOCKを防ぐ）
    strict:       従来通り（本番・実ユーザー向け）
    """
    if pii_policy == "test_data_ok" and environment.startswith("benchmark"):
        risk.data_exposure = min(risk.data_exposure, 0.4)
    return risk

_ANY_URL = re.compile(r"https?://([^\s'\"<>`]+)", re.I)
_EXTERNAL_HINT = re.compile(r"evil\.example|oast|collaborator|interact\.sh|rbndr|nip\.io|xip\.io", re.I)
_IN_SCOPE_HOSTS = {"host.docker.internal", "127.0.0.1", "localhost", "0.0.0.0", "::1"}


def normalize_risk(risk: RiskVector, cmd: str, script_content: str | None = None) -> RiskVector:
    """JEVのスコープ/第三者スコアを決定論的に補正する。

    - コマンド/スクリプト内のURLが全てスコープ内ホストなら third_party/scope_violation を上限0.2に
    - URLが無く、外部ホストの痕跡(OAST等)も無いローカル操作も同様
    """
    text = cmd + "\n" + (script_content or "")
    urls = _ANY_URL.findall(text)
    external_hint = bool(_EXTERNAL_HINT.search(text))
    if external_hint:
        return risk
    if urls:
        hosts = []
        for u in urls:
            host = u.split("/")[0].split(":")[0].strip().lower()
            hosts.append(host)
        if all(h in _IN_SCOPE_HOSTS for h in hosts):
            risk.third_party = min(risk.third_party, 0.2)
            risk.scope_violation = min(risk.scope_violation, 0.2)
    else:
        risk.third_party = min(risk.third_party, 0.2)
        risk.scope_violation = min(risk.scope_violation, 0.2)
    return risk


# ---------- ヒューリスティック fallback ----------
RE_EXEC_SCRIPT = re.compile(r"(?:python3?|node|bash|sh|ruby|perl)\s+[./\w-]+\.(?:py|js|sh|rb|pl)\b")
RE_RANGE = re.compile(r"range\((\d+)\)")
RE_THREADS = re.compile(r"max_workers\s*=\s*(\d+)|Thread\(|threading|max_workers")
RE_PARALLEL = re.compile(r"\b(\d+)\s*(?:threads?|並列)|-t\s+(\d+)|--threads[= ](\d+)|max_workers\s*=\s*(\d+)")
RE_BRUTE = re.compile(r"brute|0000|9999|keyspace|wordlist|rockyou|dictionary|hydra|flood", re.I)
RE_DESTRUCT = re.compile(r"\brm\s+-rf\b|drop\s+table|truncate|wipe|mkfs|shred", re.I)
RE_THIRD = re.compile(r"evil\.example|oast|collaborator|burpcollaborator|interact\.sh", re.I)
RE_PII = re.compile(r"dump\s+(all\s+)?(users|passwords|db)|exfiltrat", re.I)
RE_HTTP = re.compile(r"curl|requests\.|httpx|\bffuf\b|\bkatana\b|sqlmap|nuclei", re.I)


def heuristic_risk(cmd: str, script_content: str | None) -> RiskVector:
    text = cmd + "\n" + (script_content or "")
    load = 0.0
    facts: dict = {}

    nums = [int(m.group(1)) for m in RE_RANGE.finditer(text)]
    est = max(nums) if nums else 0
    if est:
        facts["est_requests"] = est
        load = min(1.0, est / 10000.0)
    par = 0
    for m in RE_PARALLEL.finditer(text):
        par = max(par, max(int(g) for g in m.groups() if g))
    if par:
        facts["parallel"] = par
        load = max(load, min(1.0, par / 100.0))

    destruct = 0.9 if RE_DESTRUCT.search(text) else (0.3 if re.search(r"requests\.(delete|put|patch)", text) else 0.0)
    third = 0.9 if RE_THIRD.search(text) else 0.0
    pii = 0.9 if RE_PII.search(text) else 0.0
    if RE_BRUTE.search(text):
        load = max(load, 0.6)
        facts["bruteforce"] = True

    suf = "sufficient"
    if script_content is None and RE_EXEC_SCRIPT.search(cmd):
        suf = "insufficient_content"

    return RiskVector(destructiveness=destruct, load=load, data_exposure=pii,
                      third_party=third, sufficiency=suf, facts=facts, source="heuristic")
