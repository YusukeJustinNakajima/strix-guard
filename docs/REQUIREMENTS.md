# strix-guard 機能要件

この文書は、strix-guard が満たす機能と非機能の要件を整理したものです。実装の詳細は README とソースコードを参照してください。

## 1. 目的と前提

- Strix 本体、プロンプト、サンドボックスイメージを変更しない。
- すべての `exec_command` を、サンドボックスで実行される前に判定する。
- 判定の根拠を監査ログに残し、同じポリシーと同じ引数で再現できるようにする。
- 許可されたテストにだけ使う。対象の範囲と権限は利用者が管理する。

## 2. 機能要件

| ID | 要件 | 受け入れ条件 |
|---|---|---|
| FR-01 | Strix を変更せずに制御する | `DOCKER_HOST` をガードのプロキシへ向けるだけで動作し、Strix のバイナリ、プロンプト、イメージを書き換えない |
| FR-02 | exec を実行前に判定する | `POST /containers/{id}/exec` を捕捉し、ALLOW / REVISE / HOLD / BLOCK / NEED_INFO のいずれかを返す |
| FR-03 | 遮断したコマンドを実行しない | deny と revise では、元の `Cmd` を通知用の `sh -c "printf ...; exit 1"` に差し替える。元のコマンドは一度も実行されない |
| FR-04 | 遮断理由をエージェントへ返す | 通知用 exec の stdout に理由を出し、終了コード 1 を返す。Strix の PTY ラッパーがあるときは、そのラッパーを残す |
| FR-05 | スクリプト全文を判定に使う | `apply_patch`、heredoc、`cp`、`mv` から path と内容の台帳を作り、実行コマンドが参照するスクリプトを解決する。解決した内容は切り詰めずに決定論的検査へ渡す |
| FR-06 | 決定論的なハードポリシーを持つ | `reference_only` と `recon` では、JEV を呼ぶ前に、許可外メソッド、アップロード、SQL 書き込み、外部通信、攻撃ツールを検査する |
| FR-07 | ポリシーをプリセットとファイルで指定できる | `full` / `reference_only` / `recon` のプリセット、および JSON ファイルによる上書きに対応する。未知キーは起動時にエラーにする |
| FR-08 | ポリシーの優先順位を固定する | `--policy` > `STRIX_GUARD_POLICY` > `./guard_policy.json` > `~/.config/strix-guard/policy.json` > プリセット、の順で解決する |
| FR-09 | 実効ポリシーを保存する | 解決後のポリシーを `guard_runs/<run>/policy.json` に保存し、SHA-256 を表示する |
| FR-10 | JEV でリスクを評価する | 破壊性、負荷、データ露出、スコープ違反、第三者への影響、情報の十分性を評価する。JEV の失敗時はヒューリスティックに切り替える |
| FR-11 | Policy Engine で最終判定を出す | しきい値から ALLOW / REVISE / HOLD / BLOCK / NEED_INFO を決める。UI の 4 値（allow / ask / deny / unknown）へ写像する |
| FR-12 | 強モデルで非 ALLOW を裁定する | `REVISE` / `HOLD` / `NEED_INFO` を裁定モデルへ渡し、allow / revise / deny / escalate の結果を適用する |
| FR-13 | プロバイダ拒否に対応する | 裁定モデルの `error`（例: `cyber_policy`）を検知し、次のフォールバックモデルを試す。すべて失敗したら拒否する |
| FR-14 | フォールバックモデルを指定できる | 既定は `openai/gpt-6-sol` → `google/gemini-3.8-flash` → `anthropic/claude-opus-4.6`。`--adjudicator-fallback-models` で変更できる |
| FR-15 | グレーゾーンを再審査する | ALLOW でも `review_band` 以上のリスク次元があれば、裁定モデルに助言を求める。既定は `full` が 0.30、`reference_only` と `recon` が 0.25。`--no-gray-review` で止められる |
| FR-16 | 裁定の失敗を記録する | モデル、フォールバックの有無、コスト、エラーを監査に残す。グレーゾーンの失敗は ALLOW とし、exec の失敗は拒否とする |
| FR-17 | ハードブロックを守る | `third_party_attack`、`out_of_scope`、`irreversible_destruction`、`dos_scale_load` は、裁定モデルが再審査してもダウングレードしない |
| FR-18 | コンテナ内 HTTP プロキシでメソッドを制御する | `reference_only` と `recon` では、コンテナ起動後に `http_sidecar.py` を起動し、`http_proxy` を `127.0.0.1:48081` へ向け、Caido（`127.0.0.1:48080`）へチェーンする |
| FR-19 | HTTP の許可条件を守る | 許可メソッド、許可ホスト、`max_requests`、`max_rps`、`max_parallel` を検査し、拒否したリクエストを JSONL に記録する |
| FR-20 | 実行時メソッドの迂回を止める | exec 検査が見落とす、実行時に組み立てた `POST` などを HTTP サイドカーで止める |
| FR-21 | インフラ通信を分離する | `127.0.0.1:48080` など `egress.infra_hosts` の通信は、対象へのメソッド制限から外す。`NO_PROXY` には `localhost`、`127.0.0.1`、`api.caido.io` を入れる |
| FR-22 | HTTPS の制限を明示する | `reference_only` の CONNECT は既定で拒否する。`allow_connect` を true にした場合だけトンネルを通し、メソッドを検査できないことを記録する |
| FR-23 | テストアカウントと PII を扱う | `--test-accounts` を JEV の state と裁定モデルの context へ渡す。`test_data_ok` では benchmark のデータ露出を 0.4 に抑える |
| FR-24 | 承認 UI を提供する | tmux ポップアップ、Web、CLI、非対話を選べる。非対話では `--on-ask deny|allow` に従う |
| FR-25 | セットアップウィザードを提供する | 環境、テスト方針、裁定モード、言語、PII 方針、モデル、タイムアウト、テストアカウントを聞き、実行へ反映する |
| FR-26 | 監査と再現性を提供する | `verdicts.jsonl`、`policy.json`、`http-*.jsonl` を保存する。`replay` でコマンドカタログを判定パイプラインに通せる |
| FR-27 | ゲートを検証する | `tools/verify_gate.py` で、許可・遮断・修正・スクリプト内容・意図しないアクセスの 5 項目を確認できる |
| FR-28 | 多言語 UI を提供する | UI と要約プロンプトは en と ja を切り替えられる。既定は en |

## 3. ポリシー仕様

### 3.1 プリセット

| プリセット | 許可メソッド | HTTP 強制 | アップロード | データ書き込み | 外部通信 | review_band |
|---|---|---|---|---|---|---|
| `full` | GET / HEAD / OPTIONS / POST / PUT / PATCH / DELETE | なし | 許可 | 許可 | 許可 | 0.30 |
| `reference_only` | GET / HEAD / OPTIONS | あり | 禁止 | 禁止 | 禁止 | 0.25 |
| `recon` | GET / HEAD / OPTIONS | あり | 禁止 | 禁止 | 禁止 | 0.25 |

### 3.2 ポリシーファイルの主なキー

| キー | 意味 |
|---|---|
| `preset` | `full` / `reference_only` / `recon` / `custom` |
| `review_band` | 次元ごとのグレーゾーン下限（0〜1） |
| `http.allowed_methods` | 許可する HTTP メソッド |
| `http.enforce` | コンテナ内 HTTP サイドカーを起動するか |
| `http.max_requests` / `max_parallel` / `max_rps` | リクエスト数、並列数、毎秒の上限 |
| `http.allow_uploads` | アップロードを許可するか |
| `http.allow_connect` | HTTPS の CONNECT を許可するか |
| `egress.allow_external` | 外部ホストへの通信を許可するか |
| `egress.allowed_hosts` | 通信を許可するホスト（`host` または `host:port`） |
| `egress.infra_hosts` | メソッド制限から外すインフラホスト |
| `data.allowed_test_accounts` | 読み書きを許可するテストアカウント |
| `data.allow_other_accounts` | テストアカウント以外のデータを許可するか |
| `data.allow_writes` | SQL の書き込みを許可するか |
| `data.restore_after_write` | 書き込み後に状態を戻す前提か |
| `thresholds` | Policy Engine のしきい値の上書き |

## 4. 非機能要件

| ID | 要件 | 受け入れ条件 |
|---|---|---|
| NFR-01 | 非侵襲 | Strix のファイルを変更しない。`DOCKER_HOST` の差し替えだけで動く |
| NFR-02 | Fail-closed | exec の判定に失敗したら実行しない。グレーゾーンの失敗だけは ALLOW とし、理由を記録する |
| NFR-03 | 再現性 | ポリシーのスナップショットと SHA-256 を残す。同じ入力と同じポリシーで同じ判断になる |
| NFR-04 | コスト制御 | JEV は全 exec、強モデルは非 ALLOW とグレーゾーンだけ。呼び出し回数と費用の上限を持つ |
| NFR-05 | 監査性 | 判定、アクション、再審査、HTTP アクセスを JSONL で残す |
| NFR-06 | 互換性 | Python 3.10 以上。Strix 1.3.0 と Docker API で動作を確認する。tmux は任意 |
| NFR-07 | 国際化 | UI と要約プロンプトを en / ja で切り替えられる |
| NFR-08 | テスト | ユニット、統合、実 Docker、E2E、ゲート検証を含むテストを持つ |
| NFR-09 | 安全な既定値 | `on_ask` の既定は deny。`reference_only` の CONNECT は拒否。外部通信は拒否 |
| NFR-10 | 失敗の可視化 | サイドカー、裁定、プロバイダ拒否の失敗を監査と標準出力に残す |

## 5. 制約

- HTTP サイドカーは、`http_proxy` を無視するツール、生のソケット、直接の通信を止められない。参照のみを確実に守るには、読み取り専用の資格情報か、対象側のネットワーク制御が必要である。
- CONNECT のトンネルは、TLS を傍受しない限りメソッドを検査できない。
- Strix が非 TTY の exec で空の出力を返す場合、通知本文がエージェントに表示されないことがある。終了コードと監査ログで確認する。
- プロバイダがセキュリティ内容を拒否した場合、フォールバックモデルも拒否することがある。すべて失敗したら exec は拒否される。
- `--target-list` を使う場合、サイドカーの許可ホストは CLI の URL から決まる。追加のホストは `egress.allowed_hosts` に書く。
