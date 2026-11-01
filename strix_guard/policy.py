"""Policy Engine: リスク評価（JEV）とは独立に、最終的な実行可否を決定する。

決定値:
- ALLOW   : 実行
- REVISE  : 制約付きで再試行を促す（差分制約を返す）
- HOLD    : 人間承認が必要（制約なしの保留）
- BLOCK   : 遮断
- NEED_INFO: 情報不足（内容解決ループへ）— fail-closed 設定では BLOCK に写像
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVISE = "REVISE"
    HOLD = "HOLD"
    BLOCK = "BLOCK"
    NEED_INFO = "NEED_INFO"


@dataclass
class RiskVector:
    destructiveness: float = 0.0      # 0..1 不可逆性・破壊性
    load: float = 0.0                 # 0..1 リクエスト量・並列
    data_exposure: float = 0.0        # 0..1 越権/機微データ露出
    scope_violation: float = 0.0      # 0..1 スコープ外度
    third_party: float = 0.0          # 0..1 第三者被害
    sufficiency: str = "sufficient"   # sufficient | insufficient_content | ambiguous
    facts: dict[str, Any] = field(default_factory=dict)
    source: str = "heuristic"         # heuristic | jev


DEFAULT_POLICY: dict[str, Any] = {
    "thresholds": {
        "destructiveness_block": 0.85, "destructiveness_ask": 0.50,
        "load_block": 0.85, "load_ask": 0.50,
        "exposure_block": 0.85, "exposure_ask": 0.60,
        "scope_block": 0.70,
        "third_party_block": 0.50,
    },
    # REVISEで付ける標準制約（組織の上限）
    "revise_constraints": {
        "max_requests": 500,
        "max_parallel": 10,
        "scope": "own_test_account",
    },
    "fail_closed": True,  # NEED_INFO を BLOCK として扱うか（HOLDにする選択も可）
}


@dataclass
class PolicyDecision:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "reasons": self.reasons,
                "constraints": self.constraints}


def decide(risk: RiskVector, policy: dict[str, Any] = DEFAULT_POLICY) -> PolicyDecision:
    t = policy["thresholds"]

    # 1) 情報不足（判定不能）
    if risk.sufficiency != "sufficient":
        if policy.get("fail_closed", True):
            return PolicyDecision(Verdict.NEED_INFO, [f"sufficiency:{risk.sufficiency}"])
        return PolicyDecision(Verdict.HOLD, [f"sufficiency:{risk.sufficiency}"])

    # 2) ハードブロック（組織の絶対禁止条件）
    if risk.third_party >= t["third_party_block"]:
        return PolicyDecision(Verdict.BLOCK, ["third_party_attack"])
    if risk.scope_violation >= t["scope_block"]:
        return PolicyDecision(Verdict.BLOCK, ["out_of_scope"])
    if risk.destructiveness >= t["destructiveness_block"]:
        return PolicyDecision(Verdict.BLOCK, ["irreversible_destruction"])
    if risk.data_exposure >= t["exposure_block"]:
        return PolicyDecision(Verdict.BLOCK, ["pii_or_credential_exfiltration"])
    if risk.load >= t["load_block"]:
        return PolicyDecision(Verdict.BLOCK, ["dos_scale_load"])

    # 3) 承認/修正ゾーン
    reasons: list[str] = []
    constraints: dict[str, Any] = {}
    if risk.destructiveness >= t["destructiveness_ask"]:
        reasons.append("destructive_write")
        constraints["require_reversible"] = True
    if risk.load >= t["load_ask"]:
        reasons.append("high_load")
        constraints["max_requests"] = policy["revise_constraints"]["max_requests"]
        constraints["max_parallel"] = policy["revise_constraints"]["max_parallel"]
    if risk.data_exposure >= t["exposure_ask"]:
        reasons.append("cross_user_or_sensitive_data")
        constraints["scope"] = policy["revise_constraints"]["scope"]
    if reasons:
        verdict = Verdict.REVISE if constraints else Verdict.HOLD
        return PolicyDecision(verdict, reasons, constraints)

    # 4) 閾値以下
    return PolicyDecision(Verdict.ALLOW, ["below_thresholds"])


def ui_label(decision: PolicyDecision) -> str:
    """UI 4値（allow/ask/deny/unknown）へのマッピング"""
    v = decision.verdict
    if v == Verdict.ALLOW:
        return "allow"
    if v in (Verdict.REVISE, Verdict.HOLD):
        return "ask"
    if v == Verdict.BLOCK:
        return "deny"
    return "unknown"


# ---------- サンドボックス内コマンドの許可規則（誤deny防止） ----------
import os
import re as _re

_FORBIDDEN = _re.compile(
    r"(?<![\w/-])(curl|wget|requests|httpx|ffuf|katana|nmap|sqlmap|nc|ssh|docker|systemctl|scp)(?![\w/-])|://",
    _re.I)
_FS_ALLOW = {"test", "ls", "stat", "mkdir", "chmod", "chown", "touch", "rm", "mv", "cp",
             "cat", "head", "tail", "readlink", "realpath", "pwd", "echo", "sleep",
             "which", "command", "printf", "true", "false", "cd", "set", "trap", "exit",
             "shift", "dirname", "basename", "sed", "awk", "grep", "cmp", "id", "uname"}
_PATH_RESTRICTED = {"rm", "mv", "cp", "chmod", "chown"}
_LOCAL_PATH = _re.compile(r"/(?:tmp|workspace|home/pentester)(?:/|\s|$)")


def sandbox_internal(cmd: str) -> bool:
    """サンドボックス内のローカル操作のみで完結するコマンド（GET等は含まない）"""
    if "INSTALL_RUNTIME_HELPER" in cmd:
        return True
    # sandbox SDK のファイル書込ヘルパー（ワークスペースへの安全な書き込み）
    if _re.match(r"^sh -c n=\$1;", cmd.strip()):
        return True
    if "<<" in cmd:
        return False
    if _FORBIDDEN.search(cmd):
        return False
    for seg in _re.split(r"&&|;|\|\|", cmd):
        seg = seg.strip()
        if not seg:
            continue
        token = seg.split()[0]
        if token.startswith("/tmp/openai-agents/"):
            continue  # sandbox SDK の内部ヘルパー
        base = os.path.basename(token.split("=")[0])
        if base not in _FS_ALLOW:
            return False
        if base in _PATH_RESTRICTED:
            if ".." in seg or not _LOCAL_PATH.search(seg):
                return False
    return True
