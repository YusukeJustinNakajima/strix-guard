# strix-guard テスト報告

この文書は、実装した機能をどのように確かめたかをまとめたものです。テストの実行方法、機能要件との対応、E2E の結果、既知の制約を順に示します。

## 1. テストの実行

```bash
cd strix_guard
python3 -m unittest discover -s tests
```

最終実行: 120 件すべて成功（Python 3.14.4、Linux、Docker 29.8.0）。

E2E は、ローカルの脆弱性検証アプリ `http://host.docker.internal:5000` に対して実行しました。ガードの監査は `guard_runs/`、Strix の実行結果は `strix_runs/` に残しています。

## 2. テストの構成

| ファイル | 確かめていること |
|---|---|
| `tests/test_policy.py` | しきい値、判定の優先順位、サンドボックス内操作の許可 |
| `tests/test_policy_config.py` | プリセット、JSON の上書き、未知キーの拒否、review_band、スナップショット |
| `tests/test_policy_guard.py` | メソッド、アップロード、SQL 書き込み、外部通信、攻撃ツール、インフラホストの除外 |
| `tests/test_adjudicator.py` | JSON の解析、予算上限、プロバイダ拒否、フォールバック、全滅時の理由記録 |
| `tests/test_docker_proxy.py` | 透過、exec の許可、deny/revise の通知差し替え、PTY ラッパーの維持、exec 環境のプロキシ差し替え |
| `tests/test_docker_real.py` | 実 Docker API での ping、コンテナ作成、exec の拒否、通知出力、終了コード |
| `tests/test_ledger.py` | `apply_patch`、heredoc、`cp`、`mv`、`python3 -u` の解決 |
| `tests/test_http_sidecar.py` | HTTP 転送、メソッド拒否、ホスト拒否、インフラ除外、回数上限、CONNECT 拒否、ログ |
| `tests/test_sidecar_manager.py` | 対象ホストの抽出、ポリシー生成、env と bind の注入、サイドカー起動 |
| `tests/test_setup.py` | 環境ごとの既定値、カスタムポリシーのパス、テストアカウント |
| `tests/test_accounts_context.py` | テストアカウントを JEV と裁定モデルへ渡す経路 |
| `tests/test_launcher_helpers.py` | コマンドの分解、ファミリ判定、差分の補助 |
| `tests/test_webui.py` | 承認ページ、タイムアウト、状態遷移 |
| `tests/test_approve.py` | 承認、修正、拒否、入力終了 |
| `tests/test_diff.py` | 修正前後のコマンド差分 |

## 3. 機能要件との対応

| 要件 | 主なテスト | 結果 |
|---|---|---|
| FR-01 非侵襲 | E2E（`DOCKER_HOST` のみ）、`test_docker_proxy` | Strix を変更せずに動作 |
| FR-02 exec 判定 | `test_policy`、`test_docker_proxy`、E2E | ALLOW / REVISE / DENY / NEED_INFO を確認 |
| FR-03 遮断を実行しない | `test_docker_proxy`、`test_docker_real`、`verify_gate` | 元コマンドの実行 0 件 |
| FR-04 理由を返す | `test_docker_real`、E2E の agents.db | 通知と終了コード 1 を確認。非 TTY は本文が空になる場合あり |
| FR-05 スクリプト全文 | `test_ledger`、E2E の台帳解決 | `python3 -u`、`cp`、`mv` を解決 |
| FR-06 決定論的ポリシー | `test_policy_guard`、E2E の `policy_rule` | 実行時メソッドを遮断 |
| FR-07 プリセットとファイル | `test_policy_config`、`test_setup` | 上書きと検証を確認 |
| FR-08 優先順位 | `test_policy_config`、起動ログ | ファイルがプリセットを上書き |
| FR-09 スナップショット | `test_policy_config`、E2E | `policy.json` と SHA-256 を確認 |
| FR-10 JEV | `test_accounts_context`、E2E | 次元評価とコンテキストを確認 |
| FR-11 Policy Engine | `test_policy` | しきい値と 4 値写像 |
| FR-12 強モデル裁定 | `test_adjudicator`、E2E | revise / allow / deny を確認 |
| FR-13 プロバイダ拒否 | `test_adjudicator`、実 API の拒否テスト | 403 `cyber_policy` を検知 |
| FR-14 フォールバック | `test_adjudicator`、実 API | gpt-6-sol 拒否後に Gemini が allow |
| FR-15 グレーゾーン | `test_policy_config`、E2E `run-20261101-133508` | 51 ALLOW 中 2 件を再審査 |
| FR-16 失敗の記録 | `test_adjudicator`、E2E | モデル、コスト、エラーを保存 |
| FR-17 ハードブロック | `test_policy`、E2E `run-20261031-222938` | 3 件を遮断、ダウングレードなし |
| FR-18 HTTP サイドカー | `test_http_sidecar`、`test_sidecar_manager`、E2E | 起動、env 注入、チェーンを確認 |
| FR-19 HTTP 許可条件 | `test_http_sidecar` | メソッド、ホスト、回数、レート、並列 |
| FR-20 実行時メソッド | E2E `run-20261101-145329` | `method_not_allowed` で遮断 |
| FR-21 インフラ分離 | `test_policy_guard`、`test_http_sidecar` | 48080 と `api.caido.io` を除外 |
| FR-22 CONNECT | `test_http_sidecar` | 既定で拒否 |
| FR-23 テストアカウントと PII | `test_accounts_context`、`test_policy` | state と context へ反映 |
| FR-24 承認 UI | `test_webui`、`test_approve` | timeout、deny、revise |
| FR-25 セットアップ | `test_setup` | 8 項目の質問と既定値 |
| FR-26 監査と再現 | E2E の監査ファイル | `verdicts.jsonl`、`policy.json`、`http-*.jsonl` |
| FR-27 ゲート検証 | `tools/verify_gate.py` | 5 項目 PASS |
| FR-28 多言語 | `test_webui`、`test_setup` | en / ja の切り替え |

## 4. E2E の結果

### 4.1 標準の auto 裁定（`run-20261031-220451` / `host-docker-internal-5000_7be0`）

- 条件: `standard`、30 ターン、`--adjudicator auto --adjudicator-review-blocks`
- exec 評価: 631 件（ALLOW 625、REVISE 2、NEED_INFO 4）
- 裁定: 6 回、$0.0276。すべて revise
- 検出: 19 件（Critical 6、High 5、Medium 8）
- LLM コスト: $0.632、463 リクエスト
- 修正指示の到達: 6 件中 4 件がツール出力に本文ごと出現。残り 2 件は非 TTY で出力が空だった

### 4.2 既定の deep（`run-20261031-222938` / `host-docker-internal-5000_613d`）

- 条件: Strix の既定（`deep`、ターン上限 500、予算上限なし）
- exec 評価: 845 件（ALLOW 833、REVISE 5、NEED_INFO 4、BLOCK 3）
- 裁定: 9 回、$0.0292。revise 5、allow 1、失敗 3
- 検出: 17 件（Critical 5、High 4、Medium 8）
- LLM コスト: $0.874、557 リクエスト、約 24 分
- 修正指示の到達: 5 件すべて本文ごと出現
- 失敗 3 件は、mass-assignment PoC に対するプロバイダの `cyber_policy` 拒否
- ハードブロック 3 件は `irreversible_destruction`
- 台帳: スクリプト解決 18 件。`cp` のコピー先も解決できることを確認

### 4.3 グレーゾーン（`run-20261101-133508` / `host-docker-internal-5000_8acb`）

- 条件: `quick`、12 ターン、`full`、グレーゾーン有効
- exec 評価: 51 件、すべて ALLOW
- グレーゾーン再審査: 2 件。どちらも gpt-6-sol が allow（各約 $0.005）
- 全体コスト: $0.043

### 4.4 参照のみ（exec 層、`run-20261101-134521`）

- 条件: `reference_only`、`quick`、4 ターン
- exec 評価: 9 件（ALLOW 8、BLOCK 1）
- `curl -X POST` を `policy_http_method` で遮断
- 監査の `source` が `policy_rule` になることを確認

### 4.5 HTTP サイドカー（`run-20261101-145329` / `host-docker-internal-5000_2b36`）

- 条件: `reference_only`、`quick`、4 ターン、グレーゾーン無効
- 実行時メソッドの例:
  ```sh
  python3 -c "import requests; m='PO'+'ST'; requests.request(m, 'http://host.docker.internal:5000/login', data={'username':'admin','password':'x'}, timeout=10)"
  ```
- exec 層: ALLOW（`policy_rule` は出ない）
- HTTP サイドカー: `POST /login` を `method_not_allowed` で拒否
- サイドカーのログを `guard_runs/run-20261101-145329/http-*.jsonl` へコピー
- GET は exec 層で許可された。別の短い run では `curl` の GET が終了コード 0 で完了したが、サイドカーのログには残らなかった。curl が環境変数以外の経路（ログインシェルの設定など）で Caido へ直接向かった可能性がある。GET の転送自体は `test_http_sidecar` で確認している

### 4.6 ゲート検証（`tools/verify_gate.py`）

5 項目すべて PASS。

| 項目 | 結果 |
|---|---|
| 許可したパスへのアクセス | 到達した |
| 遮断したパスへのアクセス | 0 件 |
| 修正したパスへのアクセス | 0 件 |
| スクリプト内容で遮断したパス | 0 件 |
| 意図しないアクセス | 0 件 |

アクセスログには `GET /allowed-1` と `GET /allowed-2` だけが残りました。

### 4.7 フォールバック（実 API）

- 対象: mass-assignment PoC のスクリプト
- 結果: `openai/gpt-6-sol` は 403 `cyber_policy` で拒否。`google/gemini-3.8-flash` が `allow` を返した
- 制約: `max_parallel=1`、`max_requests=10`
- コスト: $0.0038

## 5. 既知の失敗と制約

| 事象 | 原因 | 対応 |
|---|---|---|
| 非 TTY の exec で通知本文が空になる | Strix の exec ツールが非 TTY の出力を返さないことがある。許可した GET でも発生 | 終了コード 1 と監査ログで確認する。TTY 指定時は本文が届く |
| mass-assignment PoC の裁定が 3 回失敗 | プロバイダの `cyber_policy` 拒否 | フォールバックを追加済み。すべて拒否された場合は exec を拒否 |
| CONNECT の中のメソッドが見えない | TLS トンネル | `reference_only` は CONNECT を既定で拒否。必要なら `allow_connect` を true にする |
| サイドカーを迂回できる | `http_proxy` を無視するツール、生のソケット、直接通信 | 参照のみを確実にするなら、読み取り専用の資格情報か対象側のネットワーク制御を使う |
| `--target-list` のホストがサイドカーの許可リストにない | サイドカーは CLI の URL と `egress.allowed_hosts` からホストを決める | ポリシーファイルの `egress.allowed_hosts` に追加する |
| サイドカーの GET ログが残らないことがある | `curl` などがログインシェルの設定や別の経路で Caido へ直接向かう可能性がある | サイドカーの転送は `test_http_sidecar` で確認する。実運用ではプロキシ環境の統一を確認する |

## 6. 未カバー

- `replay` の自動テストはありません。手動での動作確認のみです。
- tmux ポップアップの自動テストはありません。Web と CLI の承認経路で代替しています。
- HTTPS の TLS 傍受は実装していません。CONNECT の許可・拒否だけをテストしています。
- 複数コンテナを同時に走らせる場合のサイドカーポート競合は、コンテナごとに独立した 127.0.0.1 なので発生しませんが、E2E では 1 コンテナのみ確認しています。
