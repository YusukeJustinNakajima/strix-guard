"""設定読み込み（JSON）。既定は英語。

探索順:
  1. --config PATH
  2. 環境変数 STRIX_GUARD_CONFIG
  3. ./guard_config.json
  4. ~/.config/strix-guard/config.json
環境変数 STRIX_GUARD_LANG は言語のみ上書き。
"""
import json
import os

DEFAULTS = {
    "language": "en",          # en | ja
    "approval_timeout": 180.0,
    "on_ask": "deny",          # deny | allow（非対話モード）
}


def find_config(explicit: str | None = None) -> str | None:
    if explicit and os.path.exists(explicit):
        return explicit
    env = os.environ.get("STRIX_GUARD_CONFIG")
    if env and os.path.exists(env):
        return env
    for p in ("./guard_config.json", os.path.expanduser("~/.config/strix-guard/config.json")):
        if os.path.exists(p):
            return p
    return None


def load_config(explicit: str | None = None) -> tuple[dict, str | None]:
    cfg = dict(DEFAULTS)
    path = find_config(explicit)
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                cfg.update(data)
        except Exception:
            pass
    env_lang = os.environ.get("STRIX_GUARD_LANG")
    if env_lang in ("en", "ja"):
        cfg["language"] = env_lang
    if cfg.get("language") not in ("en", "ja"):
        cfg["language"] = "en"
    if cfg.get("on_ask") not in ("deny", "allow"):
        cfg["on_ask"] = "deny"
    return cfg, path
