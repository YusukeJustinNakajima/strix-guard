# strix-guard

**English** | [日本語](README.ja.md)

strix-guard is a non-invasive policy and safety layer for [Strix](https://strix.ai). It gates every `exec_command` before the command reaches the sandbox, sends ambiguous cases to a strong model, and can enforce HTTP methods and request limits from inside the sandbox. It does not modify Strix, its prompts, or its sandbox image.

> Use this only for authorized security testing. You are responsible for scope, permission, and the impact of the scan.

## Problem

Attackers increasingly use AI agents to find application vulnerabilities. They can point the same tools and models at a target and let the agent try destructive paths. A failed attempt, or a damaged target, costs them little.

Defenders need the same attacker's-eye view. They need to use the same tools and models, find what an external attacker would find, fix it by risk, and release. As models improve, the set of findable issues changes, so the work continues after every release and every model upgrade.

The two sides are not symmetric. An attacker can drop a table, overwrite a file, or lock an account and treat the damage as part of the test. A defender cannot. The test has to stay non-destructive: read-only where possible, writes limited to test data and accounts, request volume bounded, and state restored. The defender also has to prove the agent stayed inside those limits.

That is not something a prompt can guarantee. The agent chooses the next command, and the model can miss a destructive path or a mutating HTTP method hidden in a script. A blocked command needs a reason the agent can act on. After the run, the team needs evidence of what was attempted, what was blocked, and what reached the target.

Examples of the asymmetry:

- An attacker can run `DROP TABLE` or delete an admin account to prove impact. A defender needs the same proof but cannot leave the data destroyed. The test has to use a disposable record and restore it, or stop at a read-only proof.
- An attacker can send 100,000 login attempts. A defender needs to know whether rate limiting works, but must stop at a bounded number and avoid locking out real users.
- An attacker can upload a webshell. A defender needs to test upload handling without executing a payload or leaving a file behind.
- An attacker can point the agent at any third-party host. A defender must keep the agent inside the declared scope and show that it stayed there.
- An attacker can adopt a new model as soon as it ships. A defender needs to re-run the same checks after each model upgrade, with the same policy and a reproducible record.

## Solution

strix-guard is the control layer for the defender's side of this asymmetry. It inserts two enforcement points without touching Strix.

1. **Docker API proxy.** The launcher starts a local proxy and sets `DOCKER_HOST` for the Strix process. Every container create, start, and exec call passes through it. The proxy reads the command, checks the policy, and either forwards the command or replaces it with a notice. The original command is never executed.
2. **In-container HTTP sidecar.** For `reference_only` and `recon`, the guard starts a small proxy inside the sandbox. The container's `http_proxy` points to the sidecar, and the sidecar chains to Strix's existing Caido proxy. It enforces allowed methods, hosts, request counts, and rates even when the command uses an obfuscated method that the exec check cannot see.

Control flow:

```text
Strix
  │ DOCKER_HOST
  ▼
strix-guard Docker proxy ──────────────▶ Docker daemon
  │
  ├─ ledger: apply_patch / heredoc / cp / mv → full script text
  ├─ deterministic policy: methods, uploads, SQL writes, egress, tools
  ├─ JEV risk: typesafe/jev-1.14
  ├─ Policy Engine: thresholds → ALLOW / REVISE / HOLD / BLOCK / NEED_INFO
  ├─ strong model: gpt-6-sol → gemini-3.8-flash → claude-opus-4.6
  └─ audit: verdicts.jsonl / policy.json / http-*.jsonl

Sandbox
  http_proxy :48081 ─▶ HTTP sidecar ─▶ Caido :48080 ─▶ target
```

All hard policy checks run before the models. The models handle ambiguity and write instructions for the agent; they are not the enforcement mechanism.

## How it enforces control

### 1. Exec gate

The proxy sees `POST /containers/{id}/exec` and calls the decision pipeline. Three outcomes are possible.

- **Allow.** The exec request is forwarded. When the HTTP sidecar is active, the exec environment also points at the sidecar.
- **Revise.** The agent must change the command. The guard returns a new exec that prints the instruction and exits with code 1.
  ```sh
  sh -c "printf '%s\n' '<guard instruction>'; exit 1"
  ```
  The original command never runs.
- **Deny.** Same rewrite, with a hard block message.

The rewrite preserves Strix's PTY wrapper when it is present, so the notice can reach the agent through the normal tool output. If Strix itself returns an empty output for a non-TTY session, the agent still sees exit code 1; the text remains in the audit log.

### 2. Deterministic policy

For `reference_only` and `recon`, the guard checks the command and the full script text from the ledger before it calls JEV.

It blocks or holds:

- HTTP methods outside the allowlist (`curl -X`, `-d`, `-F`, `-T`, `wget --post-*`, `requests/httpx/axios/session` calls, `fetch(..., {method})`, `ffuf -X`, and similar)
- file uploads
- SQL writes (`INSERT`, `UPDATE`, `DELETE FROM`, `DROP TABLE`, `TRUNCATE`, `ALTER TABLE`)
- external egress when `egress.allow_external` is false
- exploitation tools in `recon`

Strix's own proxy (`127.0.0.1:48080`) is in `egress.infra_hosts`. Commands that only touch that host are treated as infrastructure and are not subject to the target method policy.

### 3. Risk assessment and the strong model

JEV returns five risk dimensions: destructiveness, load, data exposure, scope violation, and third-party impact, plus a sufficiency answer. The Policy Engine applies thresholds and produces the verdict.

The strong model is called only when needed:

- **Non-ALLOW verdicts** (`REVISE`, `HOLD`, `NEED_INFO`) go to the adjudicator.
- **Hard blocks** are reported to the agent; `--adjudicator-review-blocks` records a second opinion but cannot downgrade them. Soft blocks can be downgraded at high confidence.
- **Gray zone.** If a command is below every policy threshold but above `review_band`, it is sent to the adjudicator as an advisory review. The default band is 0.30 for `full` and 0.25 for `reference_only` and `recon`.

The default adjudicator chain is:

```text
openai/gpt-6-sol → google/gemini-3.8-flash → anthropic/claude-opus-4.6
```

The fallback matters because providers can refuse security content. If the primary returns a `cyber_policy` refusal, the next model reviews the same payload. If every model fails, the command is denied. A gray-zone review that fails is allowed, because the policy already returned ALLOW, and the error is recorded.

### 4. HTTP sidecar

The exec check cannot see a method built at runtime, for example:

```sh
python3 -c "import requests; m='PO'+'ST'; requests.request(m, 'http://host.docker.internal:5000/login')"
```

For `reference_only` and `recon`, the guard starts `http_sidecar.py` inside each sandbox container after the container starts. The sidecar:

- listens on `127.0.0.1:48081`
- receives the container's `http_proxy`, `https_proxy`, and `ALL_PROXY`
- chains to Strix's Caido proxy at `127.0.0.1:48080`
- allows only the configured HTTP methods and hosts
- enforces `max_requests`, `max_rps`, and `max_parallel`
- writes a JSONL access log to a host-mounted directory

`NO_PROXY` includes `localhost`, `127.0.0.1`, and `api.caido.io`, so Strix's own proxy and telemetry do not loop back through the sidecar.

HTTPS CONNECT is blocked by default for `reference_only`. A CONNECT tunnel hides the method from the sidecar. Set `"allow_connect": true` only when you accept that limitation.

### 5. Audit and reproducibility

Each run writes an audit directory under `guard_runs/run-<timestamp>/`:

- `verdicts.jsonl` — evaluations, actions, adjudications, gray reviews, block reviews, sidecar events
- `policy.json` — the resolved policy snapshot
- `http-*.jsonl` — HTTP sidecar access logs, copied after the run

The launcher prints the policy SHA-256 prefix at startup. The same policy and target arguments reproduce the same decision rules.

### 6. What happens when something fails

- JEV error: the heuristic fallback is used.
- Adjudicator error or provider refusal: the next fallback model is tried; if all fail, the exec is denied.
- Gray review error: the command is allowed and the error is recorded, because the policy already passed it.
- Sidecar start error: recorded in the audit. The container's proxy still points at the sidecar, so target requests through it will fail until the sidecar is available. Treat that run as not HTTP-enforced.
- Non-TTY exec output: Strix may return empty output even for allowed commands. The exit code still distinguishes a block from a success. TTY commands show the text.

## Usage

### Requirements

- Python 3.10 or newer (the code uses modern type hints)
- Strix installed and able to run (`~/.strix/bin/strix` or `strix` on `PATH`)
- Docker socket access (`/var/run/docker.sock`) and the Docker CLI
- `tmux` for the popup approval UI; optional

There is no package to install. Run from the project root:

```bash
cd strix_guard
python3 -m unittest discover -s tests
```

### Quick start: setup wizard

```bash
python3 -m strix_guard.launcher --setup -- \
  --target http://host.docker.internal:5000
```

The wizard asks for the environment, testing policy, adjudication mode, language, PII policy, model, timeout, and test accounts. The production profile defaults to `reference_only`.

### Non-interactive auto mode

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --on-ask deny \
  --adjudicator auto --adjudicator-review-blocks \
  --pii-policy test_data_ok \
  -- --target http://host.docker.internal:5000 --non-interactive
```

Strix keeps its own defaults (`deep` scan mode, 500 turns per agent, no budget cap). To bound the run, pass Strix's own flags after `--`:

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --adjudicator auto \
  -- --target http://host.docker.internal:5000 --non-interactive \
  --scan-mode standard --max-turns 30 --max-budget 2.0
```

### Read-only testing

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --adjudicator auto --adjudicator-review-blocks \
  --policy-preset reference_only \
  -- --target http://host.docker.internal:5000 --non-interactive
```

`reference_only` enables the HTTP sidecar. It allows only `GET`, `HEAD`, and `OPTIONS`, blocks uploads and SQL writes, and blocks external egress. `recon` is similar but with lower rate limits and no exploitation tools.

To turn off the sidecar while keeping the exec rules:

```bash
--policy-preset reference_only --no-http-enforce
```

### Custom policy file

```bash
python3 -m strix_guard.launcher \
  --policy ./guard_policy.json \
  --ui noninteractive --adjudicator auto \
  -- --target http://host.docker.internal:5000 --non-interactive
```

Example `guard_policy.json`:

```json
{
  "version": 1,
  "preset": "reference_only",
  "review_band": {
    "destructiveness": 0.30,
    "load": 0.30,
    "data_exposure": 0.30,
    "scope_violation": 0.30,
    "third_party": 0.30
  },
  "http": {
    "enforce": true,
    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    "max_requests": 500,
    "max_parallel": 10,
    "max_rps": 10,
    "allow_uploads": false,
    "allow_connect": false
  },
  "egress": {
    "allow_external": false,
    "allowed_hosts": ["host.docker.internal:5000"],
    "infra_hosts": ["127.0.0.1:48080", "localhost:48080"]
  },
  "data": {
    "allowed_test_accounts": ["alice", "bob"],
    "allow_other_accounts": false,
    "allow_writes": false,
    "restore_after_write": true
  }
}
```

Policy lookup order:

1. `--policy FILE`
2. `STRIX_GUARD_POLICY`
3. `./guard_policy.json`
4. `~/.config/strix-guard/policy.json`
5. the selected preset

Unknown keys are rejected at startup. The resolved policy is written to `guard_runs/<run>/policy.json`.

### Gray-zone review

Gray-zone review is on by default when the adjudicator is on.

```bash
# Default: review ALLOW commands whose risk reaches the band
--policy-preset reference_only --adjudicator auto

# Disable the extra review
--policy-preset reference_only --adjudicator auto --no-gray-review
```

Set a band per dimension in the policy file. A value of `0` disables that dimension.

### Fallback models

```bash
--adjudicator-model openai/gpt-6-sol \
--adjudicator-fallback-models google/gemini-3.8-flash,anthropic/claude-opus-4.6
```

### Test accounts and PII

```bash
--test-accounts "alice,bob" --pii-policy test_data_ok
```

`benchmark` with `test_data_ok` treats seed and agent-created accounts as test data and caps the data-exposure risk. `strict` keeps the normal PII policy for staging and production.

### Approval UIs

```bash
# tmux popup (default on a TTY)
--ui tmux

# browser approval page
--ui web

# simple CLI prompts
--ui cli

# no human; auto-policy or deny
--ui noninteractive --on-ask deny
```

### Dry run, gate verification, replay

```bash
# Start the Docker proxy and policy checks without launching Strix
python3 -m strix_guard.launcher --dry-run --policy-preset reference_only

# Verify that blocked/revised commands never reach an access-log target
python3 tools/verify_gate.py

# Replay a command catalogue through the decision pipeline
python3 -m strix_guard.replay <exec_cmds.jsonl> --limit 20
```

### Environment profiles

```bash
--environment benchmark   # disposable lab
--environment staging     # staging data
--environment production  # production; policy default is reference_only
```

The profile sets the PII policy, adjudication mode, approval timeout, threshold scale, and cost limit. The setup wizard uses the same profiles.

### Audit files

```text
guard_runs/run-20261101-145329/
  verdicts.jsonl       decisions, actions, gray reviews, sidecar events
  policy.json          resolved policy snapshot
  http-2b6e....jsonl   HTTP sidecar access log
```

### Troubleshooting

- `policy error: unknown ...` — the JSON has a key the guard does not know. Remove it or fix the spelling.
- `http sidecar setup failed` — check that the Docker daemon can read the cache directory and bind-mount it. The sidecar lives under `~/.cache/strix-guard-http-*`.
- The agent says the command returned no output — Strix can return empty output for non-TTY execs. Check exit code 1 and the audit log; the command was blocked and did not run.
- HTTPS is blocked in `reference_only` — CONNECT hides the method. Set `allow_connect` to `true` only if you accept that.
- `--target-list` targets are not in the sidecar allowlist — add them to `egress.allowed_hosts` in a policy file. The sidecar reads CLI target URLs and that list.
- A provider refuses security content — the fallback model gets the same payload. If all models fail, the command is denied. The audit records the provider error.

## Tests

The repository has 120 unit and integration tests:

```bash
python3 -m unittest discover -s tests
```

The suite covers the policy engine, JEV integration glue, adjudicator fallbacks, Docker proxy rewrites, the real Docker API, the ledger (`apply_patch`, heredoc, `cp`, `mv`), the HTTP sidecar, the sidecar manager, the setup wizard, the web UI, and the approval broker.

End-to-end results and the full test matrix are in [docs/TEST_REPORT.md](docs/TEST_REPORT.md). Functional requirements are in [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

Highlights:

- A standard auto-adjudicated run completed with 631 exec evaluations, 6 adjudications, and 19 findings.
- A default `deep` run with no turn or budget cap completed with 845 evaluations, 9 adjudications, and 17 findings for $0.87.
- `tools/verify_gate.py` passed all five checks: allowed requests reached the target; blocked, revised, and script-content cases produced zero access.
- A dynamic `POST` built with `m='PO'+'ST'` passed the exec check and was blocked by the HTTP sidecar (`method_not_allowed`).

## Scope and limitations

- strix-guard is not a sandbox or a network firewall. Tools that ignore `http_proxy`, raw sockets, and direct egress can bypass the HTTP sidecar. For a hard read-only guarantee, use read-only credentials or network egress rules at the target.
- The guard trusts the Docker API and the host. A compromised host can bypass it.
- Model judgments are advisory. Hard policy rules and the HTTP sidecar are the enforcement layers.
- CONNECT tunnels are not method-inspected without TLS interception.
- The sidecar depends on Python inside the Strix sandbox image (`python3`).
- Strix can return empty output for non-TTY execs. The guard cannot change that; the audit still records the command and decision.

## Documentation

- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) — functional and non-functional requirements
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — test matrix, end-to-end runs, known failures
- [DESIGN.md](DESIGN.md) — design notes and background
