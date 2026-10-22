# Remediation Proposal AIエージェント

`feature/remediation-mcp-client`をベースに、WorkerからOpenAI Responses APIを呼び出す生成処理を追加する。

## 処理

1. Coreから対象Findingを取得し、対象AWSアカウントとAssumeRole先の一致を確認する。
2. 一時認証情報でMCP Proxyを起動する。
3. MCPツール一覧から`call_aws`、`search_documentation`、`read_documentation`のみをOpenAIへ公開する。
4. OpenAIのツール呼び出しをMCPへ渡し、結果を会話へ追加する。`run_script`や未公開ツールは呼び出さない。
5. `call_aws`の成功後、修復計画を構造化出力で生成し、内容を検証する。
6. CoreへJSON、生成日時、`SUCCEEDED`をまとめて保存する。失敗時は既存のエラー処理で`FAILED`と公開用の定型メッセージを保存する。

修復コマンドは提案するだけで、自動実行しない。読み取り専用のAWS IAMロールを使用することが前提であり、プロンプトやツール名の許可リストだけでAWS APIの読み取り専用性を保証するものではない。

## 設定

| 環境変数 | 内容 |
|---|---|
| `OPEN_AI_TOKEN` | OpenAI APIキー。必須。Coreと同じ命名を使用 |
| `CHAT_GPT_MODEL` | ツール呼び出し・構造化出力に対応するモデル名。必須 |

既存のAWS、Core、SQS、MCP設定も使用する。OpenAIのキーはWorkerのみが使用し、MCP Proxyには渡さない。Proxyの環境変数は一時AWS認証情報とリージョンの5項目のみ。

生成処理全体は150秒、MCP初期化は10秒、各MCPリクエストは最大1分。MCP呼び出しは合計20回まで。OpenAIへの各リクエストの出力上限は8,000トークンで、一時エラーはSDKが最大2回再試行する。OpenAI側のレスポンス保存は無効にし、会話履歴はWorker内で引き継ぐ。

## 保存JSON

ADRにあるサマリ・現状・修復ステップ・メタデータを次の形で表現する。日時とモデルはAIの出力ではなくWorkerが設定する。

```json
{
  "finding_id": 123,
  "remediation_plan": {
    "summary": "問題と修復内容の概要",
    "current_state": ["MCPで確認した対象リソースの現状"],
    "steps": [
      {
        "order": 1,
        "title": "修復ステップ",
        "command": "環境固有値を {resource_name} 等で置換した修復コマンド",
        "verification_command": "実行前後に使う読み取り専用の確認コマンド"
      }
    ],
    "metadata": {
      "generated_at": 1,
      "model": "設定されたモデル名"
    }
  }
}
```

すでに解決済みの場合は、現状を説明し`steps`を空配列にする。確認ツールの失敗・不正JSON・必須項目の欠落は成功扱いにしない。

## 検証範囲

テストは差し替えたHTTP応答と疑似MCP子プロセスを使用する。実際のOpenAI / AWSへの通信や課金、AWSリソースの変更は行わない。運用前に読み取り専用IAM、必要な環境変数、実際のモデルとAWS Managed MCPとの接続を確認する必要がある。
