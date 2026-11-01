# strix-guard

[English](README.md) | **日本語**

[Strix](https://strix.ai) は、実際の攻撃オペレーションでも利用される自律型のペネトレーションテストエージェントです。strix-guard は、Strix 本体のコードやプロンプトに一切変更を加えることなく、エージェントが発行するシェルコマンドや HTTP リクエストに対して安全ポリシーを強制するガードレイヤーです。すべての `exec_command` コールをサンドボックス到達前にインターセプトして検査し、判断が曖昧なケースは上位の裁定モデル（フロンティアLLM）へ委譲します。さらにサンドボックス内部から HTTP メソッドやリクエスト頻度を制限することも可能です。Strix 本体、プロンプト、サンドボックスイメージはいずれも無改変のまま動作します。

> 本ツールは許可を得た正当なセキュリティテストにのみ使用してください。テスト対象のスコープ定義および実施権限の管理は、すべて利用者の責任となります。

## 目次

- [課題](#課題)
- [解決策](#解決策)
  - [アーキテクチャ](#アーキテクチャ)
- [実際にどう制御するのか](#実際にどう制御するのか)
  - [exec ゲート](#1-exec-ゲート)
  - [決定論的ポリシー](#2-決定論的ポリシー)
  - [リスク評価と裁定モデル（上位LLM）](#3-リスク評価と裁定モデル上位llm)
  - [HTTP サイドカー](#4-http-サイドカー)
- [使い方](#使い方)
- [テスト](#テスト)
- [対象と制限](#対象と制限)
- [ドキュメント](#ドキュメント)

## 課題

近年、攻撃者は AI エージェントを活用して Web アプリケーションの脆弱性を自動探索するようになっています。最新鋭のモデルとツールをターゲットに向け、破壊的なアプローチも含めて自由に試行できます。攻撃者にとっては、試行が失敗したり対象システムが破損したりしても痛手にはならず、探索コストは極めて低いと言えます。

防御側にとっても、攻撃者と同じ視点を持つことが不可欠です。同じツールとモデルを使い、外部の攻撃者に見つかり得る脆弱性を事前に洗い出し、リスクに応じて改修したうえでリリースするサイクルが求められます。また、LLM が進化すれば過去に検出できなかった脆弱性が新たに顕在化する可能性があるため、テストは一度きりで終わらせず、リリースやモデル更新のたびに継続的に実施する必要があります。

しかし、ここには防御側特有の大きな非対称性が存在します。攻撃者はテーブル削除やファイル上書き、アカウントのロックといった破壊的操作を平然と行い、その結果を侵入成功の証拠にできます。一方、防御側は本番や本番同等の環境でエージェントを無制限に実行させるわけにはいきません。テストは非破壊であることが絶対条件です。読み取り操作を中心に据え、書き込みは検証用データやテストアカウントのみに限定し、リクエスト数にも上限を設けたうえで、変更した状態は元に戻さなければなりません。さらに、エージェントがこれらの制約を厳格に守って動作したことを客観的に証明する必要があります。

この安全性をプロンプトの指示だけで担保することは不可能です。次に実行するコマンドを決定するのはエージェント自身であり、モデルが破壊的な実行パスを選択したり、スクリプト内に隠蔽された更新系リクエストを見落としたりするリスクが常に存在するためです。また、危険なコマンドを遮断した際には、エージェントが別のアプローチへと自律的に切り替えられるよう、具体的な理由をフィードバックする必要があります。テスト完了後には、エージェントが何を試み、何が遮断され、どのリクエストが対象に到達したかを証明する監査証跡も欠かせません。

非対称性の具体例:

- **データ破壊**: 攻撃者は `DROP TABLE` や管理者アカウントの削除で影響を証明できます。防御側も同等の検証が必要ですが、データを破壊したままにはできません。使い捨てレコードで検証して元に戻すか、読み取り専用の証拠採取にとどめる必要があります。
- **高負荷・DoS**: 攻撃者は10万回もの連続ログイン試行を送信できます。防御側もレート制限の有効性を確認したいものの、試行回数には上限を設け、実ユーザーのロックアウトやサービス障害を防ぐ必要があります。
- **不正ファイル設置**: 攻撃者はウェブシェルをアップロードして実証できます。防御側はアップロード機能の処理を検証しつつも、危険なペイロードを実行させず、サーバーに不正ファイルを残さない制御が求められます。
- **スコープ逸脱**: 攻撃者はエージェントを第三者のホストへ向けることができます。防御側は宣言したテストスコープの外へ一切通信を出さず、かつ逸脱がなかったことを証明する必要があります。
- **モデル進化への追従**: 攻撃者は新しいモデルが登場すれば即座に実戦投入できます。防御側もモデル更新のたびに同一検査を再実行し、同一ポリシー下での再現可能な記録を蓄積する必要があります。

## 解決策

strix-guard は、この非対称性の中で防御側が安全にペネトレーションテストを実施するための制御層（セーフティゲート）です。Strix 本体を一切変更することなく、2つの制御点を挿入します。

1. **Docker API プロキシ**: ランチャーがローカルプロキシを立ち上げ、Strix プロセスの `DOCKER_HOST` をこのプロキシに向けます。コンテナの作成、起動、exec コールはすべてプロキシを経由します。プロキシは実行コマンドを解析してポリシーを照合し、安全なコマンドはそのまま転送し、ポリシー違反時は警告通知コマンドへと差し替えます。差し替えられた場合、元のコマンドは一切実行されません。
2. **コンテナ内 HTTP サイドカー**: `reference_only` や `recon` プリセットでは、サンドボックスコンテナ内に軽量プロキシを常駐させます。コンテナの `http_proxy` をこのサイドカーに向け、サイドカーから Strix 既存の Caido プロキシへ中継します。これにより、シェルコマンドの静的検査では検知できない、実行時に動的生成された HTTP メソッドであっても確実に捕捉・遮断できます。

### アーキテクチャ

![strix-guard のアーキテクチャ: ホスト側の判定パイプラインとサンドボックス内のHTTP経路](docs/assets/architecture.ja.svg)

上図は2つの信頼境界を示しています。ホスト側の判定パイプラインがコマンド単位のポリシー検査とモデル裁定を担当し、サンドボックス内のサイドカーが HTTP メソッドやアクセス先ホストの制限を担います。各コンポーネントと実装コードの対応は以下のとおりです。

| 層 | 動作環境 | 主な役割 | 実装ファイル |
|---|---|---|---|
| ランチャー | ホスト | ポリシー解決、対話セットアップ、環境変数注入、UI、監査管理 | `strix_guard/launcher.py` |
| Docker API プロキシ | ホスト | コンテナ作成・起動・exec コールのインターセプト、通知コマンドへの差し替え | `strix_guard/docker_proxy.py` |
| 台帳（Ledger） | ホスト | `apply_patch`、heredoc、`cp`、`mv` 等のファイル書き込み履歴からスクリプト全文を復元 | `strix_guard/ledger.py` |
| 決定論的ポリシー | ホスト | HTTP メソッド、アップロード、SQL 書き込み、外部通信、攻撃ツールの高速な静的検査 | `strix_guard/policy_guard.py`、`strix_guard/policy_config.py` |
| Decision service | ホスト | JEV によるリスク次元評価と Policy Engine による判定の統合 | `strix_guard/decision.py`、`strix_guard/policy.py` |
| 裁定モデル（Adjudicator） | ホスト | 非 ALLOW 判定およびグレーゾーンコマンドの再審査、フォールバック制御 | `strix_guard/adjudicator.py` |
| サイドカーマネージャ | ホスト | サイドカーの構成準備、環境変数・バインドマウントの注入、プロセス起動 | `strix_guard/sidecar_manager.py` |
| HTTP サイドカー | サンドボックス | HTTP メソッド、ホスト、リクエスト件数、レート、並列数の制限、JSONL ログ出力 | `strix_guard/http_sidecar.py` |
| 監査ストア | ホスト | 判定ログ、ポリシースナップショット、サイドカーアクセスログの永続化 | `strix_guard/audit.py` |

ガード本体はホスト上で稼働し、Docker ソケット経由で制御を行います。HTTP サイドカーはサンドボックスコンテナ内部で動作し、ポリシーファイルを読み取り専用でマウント、アクセスログはホスト側のディレクトリへ直接出力します。LLM の API コールは設定されたプロバイダへ直接送信され、Strix 本体には一切改変を加えません。

決定論的なハードポリシーの検証は、LLM を呼び出す前に完了させます。LLM は境界線上の曖昧な判断や、エージェントに対する具体的なコマンド修正指示の生成を担い、LLM 単独に実行可否の全判断を委ねることはしません。

## 実際にどう制御するのか

### 1. exec ゲート

Docker API プロキシは `POST /containers/{id}/exec` リクエストを捕捉し、コマンド実行前のゲート判定を行います。結果は以下の3通りです。

- **許可（Allow）**: exec リクエストをそのまま Docker デーモンへ転送します。HTTP サイドカーが有効な構成では、exec プロセスの環境変数（`http_proxy` 等）もサイドカー宛てに自動設定されます。
- **修正（Revise）**: エージェントにコマンドの安全な修正を促します。ガードはコマンドを修正指示の出力と終了コード 1 を返すスクリプトに差し替えます。
  ```sh
  sh -c "printf '%s\n' '<修正指示メッセージ>'; exit 1"
  ```
  このとき、元のコマンドは一度も実行されません。
- **拒否（Deny）**: 同様の差し替えにより、コマンドの実行を即座に遮断してその理由をエージェントに返します。

```mermaid
sequenceDiagram
  autonumber
  participant A as Strix エージェント
  participant P as Docker プロキシ
  participant R as 決定論的ポリシー
  participant D as Decision service
  participant M as 裁定モデル（上位LLM）
  participant X as Docker デーモン

  A->>P: exec 作成リクエスト
  P->>R: コマンドとスクリプト全文
  alt ポリシー違反
    R-->>P: 遮断（BLOCK）
    P->>X: 通知用 exec
    X-->>A: 終了コード 1 と理由
  else ポリシー通過
    P->>D: リスク評価と判定
    alt ALLOW（review_band 未満）
      D-->>P: ALLOW
      P->>X: 元の exec
      X-->>A: コマンド実行結果
    else 非 ALLOW またはグレーゾーン
      D-->>P: 判定結果 / 該当band
      P->>M: 裁定依頼
      M-->>P: allow / revise / deny
      alt allow
        P->>X: 元の exec
        X-->>A: コマンド実行結果
      else revise または deny
        P->>X: 通知用 exec
        X-->>A: 終了コード 1 と指示・理由
      end
    end
  end
```

Strix の PTY ラッパーが存在する場合は、ラッパー構造を維持したまま通知メッセージを差し込みます。これにより、Strix が標準出力を取得できる環境であればエージェントは通知内容を直接読み取ることができます。なお、Strix が非 TTY の exec で出力を空として返す場合でも終了コード 1 は確実に伝わり、通知本文も監査ログに記録されます。

### 2. 決定論的ポリシー

`reference_only` や `recon` プリセットでは、コストのかかるモデル評価を呼ぶ前に、シェルコマンドおよび台帳から復元したスクリプト全文を決定論的に静的検査します。

主な遮断対象:

- **許可外 HTTP メソッド**: 許可リストにないメソッド（`curl -X`、`-d`、`-F`、`-T`、`wget --post-*`、Python の `requests` / `httpx`、Node.js の `axios` / `fetch(..., {method})`、`ffuf -X` 等の呼び出し）
- **ファイルアップロード**: マルチパート送信やファイル転送フラグ
- **SQL 更新・破壊クエリ**: `INSERT`、`UPDATE`、`DELETE FROM`、`DROP TABLE`、`TRUNCATE`、`ALTER TABLE` 等
- **無許可の外部通信**: `egress.allow_external` が false の場合の外部宛て通信
- **攻撃ツール**: `recon` プリセットにおける高負荷スキャナや攻撃エクスプロイトツール

なお、Strix 自身の内部プロキシ（`127.0.0.1:48080`）は `egress.infra_hosts` に登録されています。このホスト宛ての通信のみを行うコマンドはエージェントのインフラ操作とみなされ、テスト対象向けメソッド制限の対象外となります。

### 3. リスク評価と裁定モデル（上位LLM）

JEV（判定エンジン）は、破壊性・サーバー負荷・データ露出・スコープ違反・第三者影響という5つのリスク次元と、判断材料の十分性をスコアリングします。これを受け、Policy Engine が設定されたしきい値に基づいて最終判定（ALLOW / REVISE / HOLD / BLOCK / NEED_INFO）を下します。

推論能力の高い上位モデル（裁定モデル / Adjudicator）を呼び出すのは、以下の場合に限られます。

- **非 ALLOW 判定の裁定**: `REVISE`、`HOLD`、`NEED_INFO` と判定されたコマンドを裁定モデルへ渡し、テスト文脈を考慮した最終判断（allow / revise / deny / escalate）と修正指示を生成させます。
- **ハードブロックの通知**: 明確な危険操作は即座にエージェントへ遮断を通知します。`--adjudicator-review-blocks` を指定した場合は再審査結果が監査ログに記録されますが、ハードブロック判定が緩和されることはありません（ソフトブロックのみ、モデルの確信度が十分高い場合に判定が緩和されます）。
- **グレーゾーンの再審査**: ALLOW のしきい値内であっても、いずれかのリスク次元が `review_band` を超過したコマンドは、セーフティネットとして裁定モデルへ助言を求めます（既定値は `full` が 0.30、`reference_only` と `recon` が 0.25）。

裁定モデルの既定フォールバック順:

```text
openai/gpt-6-sol → google/gemini-3.8-flash → anthropic/claude-opus-4.6
```

フォールバック機構を設けているのは、AI プロバイダの利用規約・セーフティ機構（例: `cyber_policy`）によってセキュリティ検証コマンドのプロンプトが拒絶されるケースがあるためです。優先モデルが拒絶した場合は後続のフォールバックモデルが自動的に審査を引き継ぎます。すべてのモデルが失敗した場合は fail-closed（安全側遮断）方針に従ってコマンドを拒否します。なお、グレーゾーン再審査時のエラーについては、ポリシー判定上すでに ALLOW が確定しているためコマンド実行は許可し、エラー詳細を監査ログに記録します。

| 状況 | Policy Engine 判定 | 裁定モデル（上位LLM） | 実行可否 |
|---|---|---|---|
| 決定論的ポリシー違反 | `BLOCK`（`policy_rule`） | 呼び出さない | 実行しない |
| ハードブロック | `BLOCK` | 再審査は任意（緩和不可） | 実行しない |
| ソフトブロック | `BLOCK` | 再審査（確信度 0.8 以上で緩和可） | 裁定結果による |
| `REVISE` / `HOLD` / `NEED_INFO` | 非 ALLOW | 裁定を実行 | allow / revise / deny に従う |
| `ALLOW` かつ `review_band` 以上 | `ALLOW` | グレーゾーン再審査 | allow / revise / deny に従う |
| `ALLOW` かつ band 未満 | `ALLOW` | 呼び出さない | そのまま実行 |
| JEV の障害・評価失敗 | ヒューリスティック判定 | 上記と同様に処理 | 上記と同様に処理 |
| すべての裁定モデルが失敗 | 非 ALLOW | 裁定エラー | 実行しない（fail-closed） |
| グレーゾーン再審査が失敗 | `ALLOW` | 裁定エラー | 実行する（ログにエラー記録） |

### 4. HTTP サイドカー

シェルコマンド文字列の静的検査だけでは、難読化されたコードや実行時に動的生成される HTTP メソッドを検知できません。たとえば以下のようなケースです。

```sh
python3 -c "import requests; m='PO'+'ST'; requests.request(m, 'http://host.docker.internal:5000/login')"
```

こうした迂回を防ぐため、`reference_only` および `recon` プリセットでは、サンドボックス起動時にコンテナ内で軽量プロキシ `http_sidecar.py` を常駐させます。サイドカーの主な機能は以下のとおりです。

- `127.0.0.1:48081` でリクエストを待機
- コンテナ内の `http_proxy`、`https_proxy`、`ALL_PROXY` 環境変数を引き受けてトラフィックを受信
- Strix 既存の Caido プロキシ（`127.0.0.1:48080`）へ多段中継
- 許可リストにある安全なメソッド（GET/HEAD等）とホストのみを通過させ、無許可リクエストには即座に 403 を返却
- `max_requests`（件数上限）、`max_rps`（秒間レート）、`max_parallel`（同時並列数）の上限値を強制
- ホスト側ディレクトリへ直接マウントされた領域に、JSONL 形式で全アクセスログを記録

なお、`NO_PROXY` には `localhost`、`127.0.0.1`、`api.caido.io` を事前設定し、Strix 本体の内部通信やテレメトリがサイドカーでループ・誤遮断されないように分離しています。

```mermaid
flowchart LR
  Tool["curl / Python / スキャナ"] -->|HTTP_PROXY 127.0.0.1:48081| Sidecar["HTTP サイドカー"]
  Sidecar -->|許可したメソッドとホスト| Caido["Caido 127.0.0.1:48080"]
  Caido --> Target["スコープ内の対象"]
  Sidecar -->|拒否| Reply["403 を返す"]
  Sidecar -->|JSONL| Log["ホスト側のログ"]
  Bypass["http_proxy を無視するツール / 生ソケット"] -.->|対象外| Target
```

※ HTTP サイドカーが制御できるのは、プロキシ環境変数に従う標準的な通信に限られます。環境変数を意図的に無視するツールや低レベルな生ソケット通信はサイドカーを迂回可能です。参照限定のテストを確実に担保するには、読み取り専用のアクセス資格情報を用いるか、ターゲット側のネットワーク設定で書き込みを遮断してください。

```mermaid
sequenceDiagram
  autonumber
  participant S as Strix
  participant P as Docker プロキシ
  participant D as Docker デーモン
  participant C as サンドボックスコンテナ

  S->>P: コンテナ作成
  P->>D: env 48081 とマウントを付けて作成
  S->>P: コンテナ起動
  P->>D: 起動
  P->>D: http_sidecar を exec
  D-->>C: 48081 で待ち受け
  P->>P: ready ファイルを待つ
  P-->>S: 起動応答
```

`reference_only` では、HTTPS の CONNECT トンネリングを既定で拒否します。暗号化された CONNECT トンネル内部の HTTP メソッドは外部から検査できないためです。この制約を許容しトンネルを許可する場合に限り、ポリシーで `"allow_connect": true` を指定してください。

### 5. 監査証跡と再現性

テスト実行ごとに、`guard_runs/run-<timestamp>/` ディレクトリ配下へ以下の監査ファイルが出力されます。

- `verdicts.jsonl` — 全コマンドの評価結果、アクション、裁定モデルの判断、グレーゾーン再審査、ブロック再審査、サイドカーイベント
- `policy.json` — 実行時に実際に適用された実効ポリシースナップショット
- `http-*.jsonl` — サンドボックス内 HTTP サイドカーのアクセスログ（実行完了時に自動コピー）

ランチャー起動時には、適用ポリシーの SHA-256 ハッシュ値が表示されます。同一のポリシー設定とテスト引数を用いることで、まったく同じ判定基準のもとでテストを完全に再現・検証できます。

### 6. 障害発生時のフェイルセーフ動作

- **JEV（判定エンジン）の障害時**: ルールベースのヒューリスティック評価へと自動的にフォールバックして判定を継続します。
- **裁定モデルのエラー・プロバイダ拒絶時**: 設定されたフォールバックモデル順に審査を委譲し、全モデルで失敗した場合は安全側に倒して exec を拒否します。
- **グレーゾーン再審査のエラー時**: ポリシー判定上すでに ALLOW が確定しているためコマンド実行は通し、監査ログにエラー詳細を記録します。
- **サイドカーの起動失敗時**: 監査ログにエラーを記録します。コンテナのプロキシ設定はサイドカーを向いているため、サイドカーが稼働しない間の対象宛リクエストはすべて失敗し、制御外での勝手な通信を防ぎます。
- **非 TTY exec 時の出力欠落**: Strix 本体の仕様により、非 TTY 実行時にコマンド出力が空として返される場合があります。コマンドの成否は終了コード（遮断時は 1）で判断し、通知メッセージの詳細は監査ログ側で確認してください。

## 使い方

### 必要なもの

- Python 3.10 以上（新しい型ヒントを使っています）
- Strix が実行できること（`~/.strix/bin/strix` か、`PATH` 上の `strix`）
- Docker ソケット（`/var/run/docker.sock`）と Docker CLI
- tmux（ポップアップ承認を使う場合のみ必要。任意）

インストールするパッケージはありません。プロジェクトのルートで実行します。

```bash
cd strix_guard
python3 -m unittest discover -s tests
```

### 最短の起動: セットアップウィザード

```bash
python3 -m strix_guard.launcher --setup -- \
  --target http://host.docker.internal:5000
```

ウィザードは、環境、テスト方針、裁定モード、言語、PII 方針、モデル、タイムアウト、テストアカウントを対話形式で確認します。production の既定は `reference_only` です。

### 非対話の自動裁定

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --on-ask deny \
  --adjudicator auto --adjudicator-review-blocks \
  --pii-policy test_data_ok \
  -- --target http://host.docker.internal:5000 --non-interactive
```

Strix の既定（`deep`、エージェントごとのターン上限 500、予算上限なし）をそのまま使います。実行を区切りたいときは、`--` の後ろに Strix の引数を渡します。

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --adjudicator auto \
  -- --target http://host.docker.internal:5000 --non-interactive \
  --scan-mode standard --max-turns 30 --max-budget 2.0
```

### 参照のみのテスト

```bash
python3 -m strix_guard.launcher \
  --ui noninteractive --adjudicator auto --adjudicator-review-blocks \
  --policy-preset reference_only \
  -- --target http://host.docker.internal:5000 --non-interactive
```

`reference_only` は HTTP サイドカーを有効にします。`GET`、`HEAD`、`OPTIONS` だけを中継し、アップロードと SQL の書き込み、外部通信を止めます。`recon` も同様ですが、レート上限が低く、攻撃ツールを使いません。

exec のルールは残したまま、サイドカーだけを止める場合:

```bash
--policy-preset reference_only --no-http-enforce
```

### カスタムポリシー

```bash
python3 -m strix_guard.launcher \
  --policy ./guard_policy.json \
  --ui noninteractive --adjudicator auto \
  -- --target http://host.docker.internal:5000 --non-interactive
```

`guard_policy.json` の例:

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

ポリシーの読み込み順:

1. `--policy FILE`
2. `STRIX_GUARD_POLICY`
3. `./guard_policy.json`
4. `~/.config/strix-guard/policy.json`
5. 選択したプリセット

未定義のキーが含まれていると、起動時にエラーになります。解決後のポリシーは `guard_runs/<run>/policy.json` に保存します。

### グレーゾーン再審査

裁定モデルを有効にすると、グレーゾーン再審査も既定で有効になります。

```bash
# 既定: review_band 以上の ALLOW を再審査する
--policy-preset reference_only --adjudicator auto

# 再審査を止める
--policy-preset reference_only --adjudicator auto --no-gray-review
```

次元ごとの band はポリシーファイルで指定します。`0` にすると、その次元は再審査しません。

### フォールバックモデル

```bash
--adjudicator-model openai/gpt-6-sol \
--adjudicator-fallback-models google/gemini-3.8-flash,anthropic/claude-opus-4.6
```

### テストアカウントと PII

```bash
--test-accounts "alice,bob" --pii-policy test_data_ok
```

`benchmark` と `test_data_ok` の組み合わせでは、シードアカウントとエージェントが作ったアカウントをテストデータとして扱い、データ露出のリスクを抑えます。`strict` は staging と production 向けの通常の PII 方針です。

### 承認 UI

```bash
# tmux ポップアップ（TTY での既定）
--ui tmux

# ブラウザの承認ページ
--ui web

# CLI の質問
--ui cli

# 人間を置かず、自動裁定か拒否にする
--ui noninteractive --on-ask deny
```

### dry-run、ゲート検証、リプレイ

```bash
# Strix を起動せず、Docker プロキシとポリシーだけを動かす
python3 -m strix_guard.launcher --dry-run --policy-preset reference_only

# 遮断・修正したコマンドが対象へ届いていないことをアクセスログで確かめる
python3 tools/verify_gate.py

# コマンドカタログを判定パイプラインに通す
python3 -m strix_guard.replay <exec_cmds.jsonl> --limit 20
```

### 環境プロファイル

```bash
--environment benchmark   # 使い捨ての検証環境（テストデータ許可、制約緩和）
--environment staging     # 実データに近いステージング環境（厳格な PII 保護）
--environment production  # 本番環境（ポリシー既定値は reference_only）
```

環境プロファイルは、PII 保護方針・裁定モード・承認タイムアウト・判定しきい値の倍率・コスト上限などを一括定義します。セットアップウィザードもこのプロファイル定義に準拠します。

### 監査ファイル

```text
guard_runs/run-20261101-145329/
  verdicts.jsonl       判定結果、アクション、グレーゾーン再審査、サイドカーイベント
  policy.json          実行時に適用された実効ポリシー
  http-2b6e....jsonl   HTTP サイドカーのアクセスログ
```

### トラブルシューティング（困ったとき）

- `policy error: unknown ...` — ポリシー JSON に未定義のキーが含まれています。不要なキーを削除するか、スペルを確認してください。
- `http sidecar setup failed` — Docker デーモンがキャッシュディレクトリを読み取れるか、バインドマウントが許可されているかを確認してください（サイドカーは `~/.cache/strix-guard-http-*` 配下に配置されます）。
- エージェントが「コマンド出力が得られない」と報告する — Strix の仕様上、非 TTY 環境の exec 実行時に標準出力が空になる場合があります。終了コード 1 および監査ログを確認してください。コマンド自体は正しく遮断されており、サンドボックス内で実行されていません。
- `reference_only` で HTTPS 通信が通らない — 暗号化された CONNECT トンネル内部の HTTP メソッドは外部から検査できません。この制限を許容できる場合のみ、ポリシーで `allow_connect` を `true` に設定してください。
- `--target-list` で指定した対象がサイドカーの許可リストに含まれない — ポリシーファイルの `egress.allowed_hosts` に対象ホストを追加してください。サイドカーは CLI で指定された単一の `--target` URL と本リストを参照します。
- AI プロバイダがセキュリティ内容を拒絶する — 設定されたフォールバックモデルが順次再審査を行います。全モデルで拒絶された場合は安全側に倒してコマンドを拒否し、プロバイダのエラー内容を監査ログへ記録します。

## テスト

ユニットテストおよび統合テスト（計120件）を用意しています。

```bash
python3 -m unittest discover -s tests
```

テスト対象には、Policy Engine、JEV 連携、裁定モデルのフォールバック、Docker プロキシのコマンド差し替え、実 Docker API 連携、スクリプト台帳（`apply_patch`、heredoc、`cp`、`mv`）、HTTP サイドカー、サイドカーマネージャ、セットアップウィザード、Web UI、承認ブローカーが含まれます。

実行結果の詳細およびテストマトリクスは [docs/TEST_REPORT.md](docs/TEST_REPORT.md)、機能要件一覧は [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) を参照してください。

主な検証実績:

- **標準 auto 裁定ラン**: exec 評価 631 件、裁定 6 回、脆弱性検出 19 件。
- **既定 deep ラン（ターン上限・予算上限なし）**: 評価 845 件、裁定 9 回、検出 17 件、コスト $0.87。
- **ゲート検証（`tools/verify_gate.py`）**: 5 項目すべて PASS。許可リクエストのみが対象へ到達し、遮断・修正・スクリプト検査の各ケースで不正アクセス 0 件を実証。
- **難読化リクエストの遮断**: `m='PO'+'ST'` で動的生成された `POST` リクエストは exec 静的検査をすり抜けましたが、HTTP サイドカーが `method_not_allowed` により確実に遮断しました。

## 対象と制限事項

- strix-guard はサンドボックス環境そのものやネットワークファイアウォールではありません。`http_proxy` 設定を無視するツールや低レベルな生ソケットによる直接通信は、HTTP サイドカーを迂回可能です。参照限定のテストを確実に担保するには、読み取り専用のアクセス資格情報を用いるか、ターゲット環境側でネットワーク通信を制御してください。
- ガードは Docker API およびホスト環境の安全性を前提としています。ホスト自体が侵害された場合は本制御を迂回される可能性があります。
- LLM による判定はあくまで助言レイヤーです。決定論的ハードポリシーと HTTP サイドカーこそが確実な強制レイヤーを構成します。
- CONNECT トンネル経由の通信は、TLS のインターセプト・復号を行わない限り内部メソッドを検査できません。
- HTTP サイドカーの実行は、Strix のサンドボックスイメージ内に存在する Python（`python3`）に依存します。
- Strix 本体の仕様上、非 TTY の exec 実行で標準出力が空になる現象はガード側から制御できません（遮断判定と終了コード 1 は監査ログに記録されます）。

## ドキュメント

- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) — 機能要件および非機能要件の一覧
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — テストマトリクス、実行結果、既知の制限事項
- [DESIGN.md](DESIGN.md) — 設計書・アーキテクチャ背景資料
