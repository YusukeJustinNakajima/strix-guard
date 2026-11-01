"""Guard policy: プリセット、JSONポリシーの読み込み・検証、review band、監査スナップショット。"""
import copy
import hashlib
import json
import os

from .policy import DEFAULT_POLICY

DIMS = ("destructiveness", "load", "data_exposure", "scope_violation", "third_party")
KNOWN_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
TOP_KEYS = {"version", "preset", "description", "review_band", "http", "egress", "data", "thresholds"}
HTTP_KEYS = {"enforce", "allowed_methods", "max_requests", "max_parallel", "max_rps",
             "allow_uploads", "allow_connect"}
EGRESS_KEYS = {"allow_external", "allowed_hosts", "infra_hosts"}
DATA_KEYS = {"allowed_test_accounts", "allow_other_accounts", "allow_writes", "restore_after_write"}

_READ_METHODS = ["GET", "HEAD", "OPTIONS"]
_BAND = {d: 0.30 for d in DIMS}

PRESETS = {
    "full": {
        "version": 1,
        "preset": "full",
        "description": "Active testing with bounded load and reversible writes.",
        "review_band": dict(_BAND),
        "http": {"enforce": False, "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
                 "max_requests": 500, "max_parallel": 10, "max_rps": 10, "allow_uploads": True,
                 "allow_connect": True},
        "egress": {"allow_external": True, "allowed_hosts": [],
                   "infra_hosts": ["127.0.0.1:48080", "localhost:48080"]},
        "data": {"allowed_test_accounts": [], "allow_other_accounts": True,
                 "allow_writes": True, "restore_after_write": True},
    },
    "reference_only": {
        "version": 1,
        "preset": "reference_only",
        "description": "Read-only assessment: only GET/HEAD/OPTIONS, no uploads or data writes.",
        "review_band": {d: 0.25 for d in DIMS},
        "http": {"enforce": True, "allowed_methods": list(_READ_METHODS),
                 "max_requests": 500, "max_parallel": 10, "max_rps": 10,
                 "allow_uploads": False, "allow_connect": False},
        "egress": {"allow_external": False, "allowed_hosts": [],
                   "infra_hosts": ["127.0.0.1:48080", "localhost:48080"]},
        "data": {"allowed_test_accounts": [], "allow_other_accounts": False,
                 "allow_writes": False, "restore_after_write": True},
    },
    "recon": {
        "version": 1,
        "preset": "recon",
        "description": "Passive reconnaissance: low-rate GET/HEAD, no exploitation tools.",
        "review_band": {d: 0.25 for d in DIMS},
        "http": {"enforce": True, "allowed_methods": list(_READ_METHODS),
                 "max_requests": 200, "max_parallel": 5, "max_rps": 5,
                 "allow_uploads": False, "allow_connect": False},
        "egress": {"allow_external": False, "allowed_hosts": [],
                   "infra_hosts": ["127.0.0.1:48080", "localhost:48080"]},
        "data": {"allowed_test_accounts": [], "allow_other_accounts": False,
                 "allow_writes": False, "restore_after_write": True},
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def validate_policy(p: dict) -> dict:
    _require(isinstance(p, dict), "policy must be a JSON object")
    unknown = set(p) - TOP_KEYS
    _require(not unknown, f"unknown policy keys: {', '.join(sorted(unknown))}")
    if "preset" in p:
        _require(p["preset"] in ("full", "reference_only", "recon", "custom"),
                 "preset must be full|reference_only|recon|custom")
    if "review_band" in p:
        _require(isinstance(p["review_band"], dict), "review_band must be an object")
        for k, v in p["review_band"].items():
            _require(k in DIMS, f"unknown review_band dimension: {k}")
            _require(isinstance(v, (int, float)) and 0.0 <= float(v) <= 1.0,
                     f"review_band.{k} must be between 0 and 1")
    if "http" in p:
        h = p["http"]
        _require(isinstance(h, dict), "http must be an object")
        _require(not (set(h) - HTTP_KEYS), f"unknown http keys: {', '.join(sorted(set(h) - HTTP_KEYS))}")
        if "allowed_methods" in h:
            _require(isinstance(h["allowed_methods"], list) and h["allowed_methods"],
                     "http.allowed_methods must be a non-empty list")
            for m in h["allowed_methods"]:
                _require(isinstance(m, str) and m.upper() in KNOWN_METHODS,
                         f"unknown HTTP method: {m}")
        for k in ("max_requests", "max_parallel", "max_rps"):
            if k in h:
                _require(isinstance(h[k], int) and h[k] > 0, f"http.{k} must be a positive integer")
        if "enforce" in h:
            _require(isinstance(h["enforce"], bool), "http.enforce must be boolean")
        if "allow_uploads" in h:
            _require(isinstance(h["allow_uploads"], bool), "http.allow_uploads must be boolean")
        if "allow_connect" in h:
            _require(isinstance(h["allow_connect"], bool), "http.allow_connect must be boolean")
    if "egress" in p:
        e = p["egress"]
        _require(isinstance(e, dict), "egress must be an object")
        _require(not (set(e) - EGRESS_KEYS), f"unknown egress keys: {', '.join(sorted(set(e) - EGRESS_KEYS))}")
        if "allowed_hosts" in e:
            _require(isinstance(e["allowed_hosts"], list), "egress.allowed_hosts must be a list")
        if "infra_hosts" in e:
            _require(isinstance(e["infra_hosts"], list), "egress.infra_hosts must be a list")
        if "allow_external" in e:
            _require(isinstance(e["allow_external"], bool), "egress.allow_external must be boolean")
    if "data" in p:
        d = p["data"]
        _require(isinstance(d, dict), "data must be an object")
        _require(not (set(d) - DATA_KEYS), f"unknown data keys: {', '.join(sorted(set(d) - DATA_KEYS))}")
        if "allowed_test_accounts" in d:
            _require(isinstance(d["allowed_test_accounts"], list), "data.allowed_test_accounts must be a list")
        for k in ("allow_other_accounts", "allow_writes", "restore_after_write"):
            if k in d:
                _require(isinstance(d[k], bool), f"data.{k} must be boolean")
    if "thresholds" in p:
        _require(isinstance(p["thresholds"], dict), "thresholds must be an object")
        allowed = set(DEFAULT_POLICY["thresholds"])
        _require(not (set(p["thresholds"]) - allowed),
                 f"unknown threshold keys: {', '.join(sorted(set(p['thresholds']) - allowed))}")
        for k, v in p["thresholds"].items():
            _require(isinstance(v, (int, float)) and 0.0 <= float(v) <= 1.0,
                     f"thresholds.{k} must be between 0 and 1")
    return p


def find_policy_file(explicit: str | None = None) -> str | None:
    if explicit:
        if not os.path.exists(explicit):
            raise FileNotFoundError(f"policy file not found: {explicit}")
        return explicit
    env = os.environ.get("STRIX_GUARD_POLICY")
    if env:
        if not os.path.exists(env):
            raise FileNotFoundError(f"STRIX_GUARD_POLICY not found: {env}")
        return env
    for p in ("./guard_policy.json", os.path.expanduser("~/.config/strix-guard/policy.json")):
        if os.path.exists(p):
            return p
    return None


def resolve_policy(preset: str = "full", path: str | None = None) -> dict:
    """プリセットにJSONファイルを重ねて実効ポリシーを作る。未知キーはエラー。"""
    file_path = find_policy_file(path)
    data = {}
    if file_path:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
        _require(isinstance(data, dict), "policy file must contain a JSON object")
        validate_policy(data)
    chosen = data.get("preset") if data.get("preset") in PRESETS else preset
    if chosen not in PRESETS:
        chosen = "full"
    merged = _deep_merge(PRESETS[chosen], data)
    merged["preset"] = data.get("preset") or chosen
    if merged["preset"] == "custom":
        merged["preset"] = chosen
    return validate_policy(merged)


def policy_summary(policy: dict) -> dict:
    """JEV/強モデルへ渡すコンパクトなポリシー（アカウント情報は含めない）。"""
    http = policy.get("http") or {}
    egress = policy.get("egress") or {}
    data = policy.get("data") or {}
    return {
        "preset": policy.get("preset"),
        "http": {k: http.get(k) for k in ("allowed_methods", "max_requests", "max_parallel",
                                          "max_rps", "allow_uploads", "allow_connect")},
        "egress": {"allow_external": egress.get("allow_external"),
                   "allowed_hosts": egress.get("allowed_hosts") or [],
                   "infra_hosts": egress.get("infra_hosts") or []},
        "data": {"allow_other_accounts": data.get("allow_other_accounts"),
                 "allow_writes": data.get("allow_writes")},
        "review_band": policy.get("review_band") or {},
    }


def review_band_hits(risk, policy: dict) -> list[dict]:
    """ALLOWだがreview_band以上のリスク次元を返す。"""
    band = policy.get("review_band") or {}
    hits = []
    for dim in DIMS:
        try:
            b = float(band.get(dim) or 0.0)
            v = float(getattr(risk, dim, 0.0) or 0.0)
        except Exception:
            continue
        if b > 0 and v >= b:
            hits.append({"dimension": dim, "value": round(v, 3), "band": b})
    return hits


def write_snapshot(policy: dict, directory: str) -> str:
    os.makedirs(directory, exist_ok=True)
    text = json.dumps(policy, indent=2, sort_keys=True, ensure_ascii=False)
    with open(os.path.join(directory, "policy.json"), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
