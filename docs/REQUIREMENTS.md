# strix-guard 機能要件

この文書は、strix-guard が満たす機能と非機能の要件を整理したものです。実装の詳細は README とソースコードを参照してください。

## 1. 目的と前提

- 攻撃者は自律型 AI エージェントを活用して Web アプリケーションの脆弱性を探索し、破壊的な試行も許容できる。防御側も同等のツールとモデルを用い、リリースやモデル更新のたびに継続的なセキュリティ検証を行う必要がある。
- 防御側は非破壊の範囲内で安全にテストを実施し、エージェントがポリシーで定められた制限事項を逸脱しなかったことを客観的に証明する必要がある。
- Strix 本体のバイナリ、システムプロンプト、サンドボックスコンテナイメージを一切変更しない。
- すべての `exec_command` コールを、サンドボックスで実行される前にインターセプトしてポリシー判定を行う。
- 判定根拠を網羅的に監査ログへ記録し、同一ポリシーおよび同一引数のもとで判定結果を完全に再現可能とする。
- 許可を得た正当なテストにのみ使用する。対象スコープの定義および検証権限の管理は利用者の責任とする。

## 2. 機能要件

| ID | 要件 | 受け入れ条件 |
|---|---|---|
| FR-01 | Strix を変更せずに制御する | `DOCKER_HOST` をガードのプロキシへ向けるだけで動作し、Strix のバイナリ、プロンプト、イメージを書き換えない |
| FR-02 | exec を実行前に判定する | `POST /containers/{id}/exec` を捕捉し、ALLOW / REVISE / HOLD / BLOCK / NEED_INFO のいずれかを返す |
| FR-03 | 遮断したコマンドを実行しない | deny と revise では、元の `Cmd` を通知用の `sh -c "printf ...; exit 1"` に差し替える。元のコマンドは一度も実行されない |
| FR-04 | 遮断理由をエージェントへ返す | 通知用 exec の stdout に理由を出力し、終了コード 1 を返す。Strix の PTY ラッパーがあるときは、そのラッパー構造を維持する |
| FR-05 | スクリプト全文を判定に使う | `apply_patch`、heredoc、`cp`、`mv` からパスと内容の台帳を作り、実行コマンドが参照するスクリプトを解決する。解決した内容は切り詰めずに決定論的検査へ渡す |
| FR-06 | 決定論的なハードポリシーを持つ | `reference_only` と `recon` では、JEV を呼ぶ前に、許可外メソッド、アップロード、SQL 書き込み、外部通信、攻撃ツールを高速に静的検査する |
| FR-07 | ポリシーをプリセットとファイルで指定できる | `full` / `reference_only` / `recon` のプリセット、および JSON ファイルによる上書きに対応する。未知のキーが含まれる場合は起動時にエラーとする |
| FR-08 | ポリシーの優先順位を固定する | `--policy` > `STRIX_GUARD_POLICY` > `./guard_policy.json` > `~/.config/strix-guard/policy.json` > プリセット、の順で解決する |
| FR-09 | 実効ポリシーを保存する | 解決後の実効ポリシーを `guard_runs/<run>/policy.json` に保存し、SHA-256 ハッシュ値を表示する |
| FR-10 | JEV でリスクを評価する | 破壊性、負荷、データ露出、スコープ違反、第三者への影響、情報の十分性をスコアリングする。JEV の失敗時はヒューリスティック判定に切り替える |
| FR-11 | Policy Engine で最終判定を出す | 設定しきい値から ALLOW / REVISE / HOLD / BLOCK / NEED_INFO を決定し、UI 向けの 4 値（allow / ask / deny / unknown）へ写像する |
| FR-12 | 裁定モデル（上位LLM）で非 ALLOW を裁定する | `REVISE` / `HOLD` / `NEED_INFO` を裁定モデルへ渡し、テスト文脈を踏まえた allow / revise / deny / escalate の裁定結果を適用する |
| FR-13 | プロバイダ拒否に対応する | 裁定モデルのセーフティ拒絶エラー（例: `cyber_policy`）を検知し、後続のフォールバックモデルを試す。全モデルが失敗した場合は安全側に倒して拒否する |
| FR-14 | フォールバックモデルを指定できる | 既定順は `openai/gpt-6-sol` → `google/gemini-3.8-flash` → `anthropic/claude-opus-4.6`。`--adjudicator-fallback-models` で変更可能とする |
| FR-15 | グレーゾーンを再審査する | ALLOW でも `review_band` 以上のリスク次元があれば、裁定モデルに助言を求める。既定は `full` が 0.30、`reference_only` と `recon` が 0.25。`--no-gray-review` で無効化できる |
| FR-16 | 裁定の失敗を記録する | モデル名、フォールバック有無、コスト、エラー内容を監査ログに残す。グレーゾーンの失敗時は ALLOW として実行を通し、通常 exec の失敗時は拒否とする |
| FR-17 | ハードブロックを守る | `third_party_attack`、`out_of_scope`、`irreversible_destruction`、`dos_scale_load` は、裁定モデルが再審査してもダウングレード（緩和）しない |
| FR-18 | コンテナ内 HTTP プロキシでメソッドを制御する | `reference_only` と `recon` では、コンテナ起動後に `http_sidecar.py` を起動し、`http_proxy` を `127.0.0.1:48081` へ向け、Caido（`127.0.0.1:48080`）へ多段中継する |
| FR-19 | HTTP の許可条件を守る | 許可メソッド、許可ホスト、`max_requests`、`max_rps`、`max_parallel` を検査し、拒否したリクエストを JSONL に記録する |
| FR-20 | 実行時メソッドの迂回を止める | exec の静的検査では検知できない、実行時に動的生成された `POST` などを HTTP サイドカーで遮断する |
| FR-21 | インフラ通信を分離する | `127.0.0.1:48080` など `egress.infra_hosts` の通信は、テスト対象へのメソッド制限から除外する。`NO_PROXY` には `localhost`、`127.0.0.1`、`api.caido.io` を設定する |
| FR-22 | HTTPS の制限を明示する | `reference_only` の CONNECT は既定で拒否する。`allow_connect` を true に設定した場合のみトンネルを通し、内部メソッドを検査できない旨を記録する |
| FR-23 | テストアカウントと PII を扱う | `--test-accounts` を JEV の state と裁定モデルの context へ渡す。`test_data_ok` では benchmark 環境でのデータ露出リスク評価を 0.4 に抑制する |
| FR-24 | 承認 UI を提供する | tmux ポップアップ、Web、CLI、非対話モードを選択可能とする。非対話モードでは `--on-ask deny|allow` の指定に従う |
| FR-25 | セットアップウィザードを提供する | 環境、テスト方針、裁定モード、言語、PII 方針、モデル、タイムアウト、テストアカウントを対話形式で設定し、実行引数へ反映する |
| FR-26 | 監査と再現性を提供する | `verdicts.jsonl`、`policy.json`、`http-*.jsonl` を保存する。`replay` コマンドでコマンドカタログを判定パイプラインに再投入可能とする |
| FR-27 | ゲートを検証する | `tools/verify_gate.py` により、許可・遮断・修正・スクリプト検査・意図しないアクセスの遮断の 5 項目を自動確認できる |
| FR-28 | 多言語 UI を提供する | UI 表示および要約プロンプトは en（英語）と ja（日本語）を切り替え可能とする（既定は en） |

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
| NFR-04 | コスト制御 | JEV は全 exec を対象とし、上位の裁定モデルは非 ALLOW およびグレーゾーンのみ呼び出す。呼び出し回数と費用の上限を設ける |
| NFR-05 | 監査性 | 判定、アクション、再審査、HTTP アクセスを JSONL で残す |
| NFR-06 | 互換性 | Python 3.10 以上。Strix 1.3.0 と Docker API で動作を確認する。tmux は任意 |
| NFR-07 | 国際化 | UI と要約プロンプトを en / ja で切り替えられる |
| NFR-08 | テスト | ユニット、統合、実 Docker、E2E、ゲート検証を含むテストを持つ |
| NFR-09 | 安全な既定値 | `on_ask` の既定は deny。`reference_only` の CONNECT は拒否。外部通信は拒否 |
| NFR-10 | 失敗の可視化 | サイドカー、裁定、プロバイダ拒否の失敗を監査と標準出力に残す |

## 5. 制約事項

- HTTP サイドカーは、プロキシ環境変数（`http_proxy` 等）を無視するツールや低レベルな生ソケットによる直接通信を遮断できません。参照限定のテストを確実に担保するには、読み取り専用のアクセス資格情報を用いるか、ターゲット環境側でネットワーク通信を制御してください。
- CONNECT トンネル経由の HTTPS 通信は、TLS のインターセプト・復号を行わない限り内部メソッドを検査できません。
- Strix 本体の仕様上、非 TTY 環境の exec 実行で標準出力が空になる場合があります（コマンドの成否は終了コード 1 と監査ログで確認可能です）。
- AI プロバイダがセキュリティ検証内容を規約違反等で拒絶した場合、後続のフォールバックモデルも同様に拒絶する可能性があります。すべてのモデルが失敗した場合は fail-closed 方針によりコマンド実行を拒否します。
- `--target-list` を用いて複数ターゲットを検証する場合、サイドカーの許可ホストは CLI で指定された単一の `--target` URL から自動設定されます。追加の対象ホストはポリシーファイルの `egress.allowed_hosts` に明示的に設定してください。
