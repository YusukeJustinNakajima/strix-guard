"""起動時の質問（環境・言語・裁定モードなど）と環境プロファイル"""
import os
from dataclasses import dataclass

PROFILES = {
    "benchmark": {
        "label": "benchmark / sandbox（使い捨ての検証環境）",
        "pii_policy": "test_data_ok",
        "adjudicator": "auto",
        "approval_timeout": 180.0,
        "threshold_scale": 1.0,
        "adjudicator_max_cost": 3.0,
        "policy_preset": "full",
    },
    "staging": {
        "label": "staging（検証だが実データに近い）",
        "pii_policy": "strict",
        "adjudicator": "hybrid",
        "approval_timeout": 120.0,
        "threshold_scale": 0.5,
        "adjudicator_max_cost": 1.5,
        "policy_preset": "full",
    },
    "production": {
        "label": "production（本番）",
        "pii_policy": "strict",
        "adjudicator": "hybrid",
        "approval_timeout": 60.0,
        "threshold_scale": 0.1,
        "adjudicator_max_cost": 1.0,
        "policy_preset": "reference_only",
    },
}


@dataclass
class SetupResult:
    environment: str = "benchmark"
    language: str = "en"
    pii_policy: str = "test_data_ok"
    adjudicator: str = "auto"
    adjudicator_model: str = "openai/gpt-6-sol"
    adjudicator_max_cost: float = 3.0
    approval_timeout: float = 180.0
    threshold_scale: float = 1.0
    test_accounts: list = None
    policy_preset: str = "full"
    policy_file: str = ""


def _ask(prompt, default, choices=None, input_fn=input, output_fn=print):
    suffix = f" [{default}]"
    if choices:
        suffix += " (" + "/".join(choices) + ")"
    while True:
        try:
            raw = input_fn(prompt + suffix + ": ").strip()
        except (EOFError, KeyboardInterrupt):
            return default
        v = raw or default
        if choices and v not in choices:
            output_fn(f"  -> choose one of: {', '.join(choices)}")
            continue
        return v


def run_setup(targets_hint: str = "", input_fn=input, output_fn=print) -> SetupResult:
    output_fn("")
    output_fn("=" * 62)
    output_fn(" strix-guard setup")
    output_fn("=" * 62)
    if targets_hint:
        output_fn(f" target(s): {targets_hint}")
    env = _ask("1) Environment (benchmark/staging/production)", "benchmark",
               list(PROFILES.keys()), input_fn, output_fn)
    prof = PROFILES[env]

    # テスト方針（プリセット or カスタムJSON）
    policy = _ask("2) Testing policy (full/reference_only/recon/custom)",
                  prof["policy_preset"], ["full", "reference_only", "recon", "custom"],
                  input_fn, output_fn)
    policy_file = ""
    if policy == "custom":
        while True:
            policy_file = _ask("2b) Policy file (JSON path)", "./guard_policy.json",
                               None, input_fn, output_fn)
            if os.path.exists(policy_file):
                break
            output_fn(f"  -> not found: {policy_file}")

    # 環境ごとの設定を提示して確認
    default_mode = prof["adjudicator"]
    mode = _ask("3) Approval/adjudication mode (auto/hybrid/advisory/off)",
                default_mode, ["auto", "hybrid", "advisory", "off"], input_fn, output_fn)
    lang = _ask("4) Language (en/ja)", "en", ["en", "ja"], input_fn, output_fn)
    pii = _ask(f"5) PII policy (test_data_ok/strict)  [env default: {prof['pii_policy']}]",
               prof["pii_policy"], ["test_data_ok", "strict"], input_fn, output_fn)
    model = _ask("6) Adjudicator model", "openai/gpt-6-sol", None, input_fn, output_fn)
    timeout = _ask("7) Approval timeout seconds", str(int(prof["approval_timeout"])),
                   None, input_fn, output_fn)
    try:
        timeout_f = float(timeout)
    except Exception:
        timeout_f = prof["approval_timeout"]
    acct_raw = _ask("8) Allowed test accounts (comma-separated usernames/IDs/emails; "
                    "empty = benchmark: all data is test / staging+production: agent-created only)",
                    "", None, input_fn, output_fn)
    test_accounts = [a.strip() for a in str(acct_raw).split(",") if a.strip()]

    result = SetupResult(
        environment=env,
        language=lang,
        pii_policy=pii,
        adjudicator=mode,
        adjudicator_model=model,
        adjudicator_max_cost=float(prof["adjudicator_max_cost"]),
        approval_timeout=timeout_f,
        threshold_scale=float(prof["threshold_scale"]),
        test_accounts=test_accounts,
        policy_preset=policy,
        policy_file=policy_file,
    )
    output_fn("-" * 62)
    output_fn(f" environment : {prof['label']}")
    output_fn(f" policy      : {result.policy_preset}"
              + (f" ({result.policy_file})" if result.policy_file else ""))
    output_fn(f" mode        : {result.adjudicator}")
    output_fn(f" language    : {result.language}")
    output_fn(f" PII policy  : {result.pii_policy}")
    output_fn(f" test accts  : {', '.join(result.test_accounts) if result.test_accounts else '(none specified)'}")
    output_fn(f" model       : {result.adjudicator_model} (max ${result.adjudicator_max_cost})")
    output_fn(f" timeout     : {int(result.approval_timeout)}s")
    output_fn(f" thresholds  : x{result.threshold_scale} (ask感度)")
    ok = _ask("Start with these settings? (Y/n)", "y", ["y", "n"], input_fn, output_fn)
    if ok == "n":
        output_fn("aborted.")
        raise SystemExit(1)
    return result
