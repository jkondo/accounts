# アプリへの既存ログイン状態の引き継ぎ（レビュー用）

HTTPSでのアプリ復帰とネイティブ側でのCookie設定を支える、Accounts側の実装です。デフォルト無効です。既存のWebログイン・セッション基盤を使い、認証方式を別に作りません。

## 追加設定

`handoff_clients` に登録されたクライアントだけが利用できます。例えば独立した検証環境では次のように設定します。クライアント側Webサーバーは、`source_context` と `target_context` を自身が使う既存のセッションcontextと同じにすることで、既存APIをそのまま利用できます。ブラウザとWebViewは別のキーを持つ独立セッションです。

```json
{"handoff_clients":{"iphone-preview":{
  "source_context":"web-preview",
  "target_context":"web-preview",
  "redirect_uri":"https://preview.example/account/app/return",
  "terms_version":4,
  "providers":["google"]
}}}
```

HTTP復帰、任意のクライアント／復帰URL、外部サービスのトークンコピーは扱いません。`terms_version` はクライアント側Webサーバーと同じ値に保つ必要があります。

## 通信

全操作は従来のサーバー間Bearer認証が必要です。

1. `/session` で未認証セッションを作り、既存 `/login` に `handoff_client`, `handoff_state`（32〜128文字）, `handoff_challenge`（S256・43文字）を追加します。既存OAuthのstate、コールバック、アカウント選択は変えません。
2. 既存OAuthが完了すると、本人ID・実際の認証時刻・OAuthサービス名を保留情報に結び付け、`has_handoff` を返します。必要なら既存 `/agree` で規約同意を完了します。最初の要求から10分で保留情報を失効させます。
3. `/session/handoff/issue`（`sk`, `sk_context`）は、有効な本人・規約・元セッションを確認し、`code`, `state`, `redirect_uri` を返します。保留情報を消費するため、発行も一回限りです。
4. `/session/handoff/redeem`（`client_id`, `code`, `code_verifier`, 元の `sk_context`）は、60秒以内のコードとS256を検証し、元セッションと本人の有効性を再確認します。通常セッション発行・ログ記録・コード削除を一つのDBトランザクションにし、`sk`, `sk_expires`, `set_sk` をサーバーへ返します。

既存の `session` 表を使い、スキーマ変更はありません。Handoffはハッシュ化したキー、専用context `app-handoff-v1` で保存し、通常セッションに必要な `session_id` とトップレベルの `account_id` を持たないため、通常APIの本人確認には使えません。既存 `BINARY(100)` に合わせ、保存キーは100バイト固定です。

元の認証時刻を保存し、`finalize_login_session` を再実行して認証を新しく見せません。通常セッションの寿命・ログアウト・期限切れ削除は既存どおりです。元セッションをログアウトした場合、未使用Handoffは拒否されます。交換済みのセッションは独立して失効／ログアウトします。

交換応答の喪失やアプリ終了からの自動復旧、長期トークン、高度な冪等性は対象外です。失敗したら最初からログインし直します。発行済みで未利用の通常セッションは既存の期限で失効します。

## 検証

`t_deps/handoff-integration.py` は使い捨てDB・HTTPサーバー用です。実アカウントDBでは実行しないでください。固定の架空Bearer・アカウントを使用し、正常交換、同時交換、再利用拒否、誤verifier、別環境、期限、規約未同意／取り下げ、利用停止、元ログアウト、通常セッションの再利用を確認します。OAuthプロバイダー確認済みという前提はfixtureで置き、実Google認証を検証済みとは扱いません。

運用環境への設定追加や反映は別途レビューと調整が必要です。
