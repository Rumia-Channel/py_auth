# PyAuth - 多要素認証サービス

WebAuthn/Passkey、TOTP（Google Authenticator互換）、パスワード認証に対応した多要素認証サービス。
**Nginx auth_requestと連携して、複数のサイトを一括保護する認証ゲートウェイとして動作します。**

## 特徴

- 🔐 **WebAuthn/Passkey**: パスワードレス認証（FIDO2対応）
- 📱 **TOTP認証**: Google Authenticator、Authy等の2FAアプリ対応
- 🔑 **パスワード認証**: 基本的なユーザー名/パスワード認証
- 🌐 **認証ゲートウェイ**: Nginx auth_requestで複数サイトを一括保護（SSO）
- 🌐 **REST API**: 他のアプリケーションから認証機能を利用可能
- 🛡️ **セキュリティ**: CSRF保護、セッション管理、NTP時刻同期
- 💾 **SQLite**: 軽量なデータベース（PostgreSQL/MySQL等にも変更可能）

## 使い方

### パターン1: 認証ゲートウェイ（推奨）

複数のNginxサイトを一括で保護します。

```
ユーザー → サイトA (未認証)
             ↓
         PyAuth認証ページ
             ↓ (認証成功)
         サイトAにリダイレクト ✅
```

**詳細**: [NGINX_AUTH_GATEWAY.md](NGINX_AUTH_GATEWAY.md) を参照

### パターン2: REST API

他のアプリケーションから認証APIを呼び出します。

**詳細**: 本README下部の「API エンドポイント」を参照

## 対応環境

- **Python**: 3.10以上
- **ブラウザ**: WebAuthn対応ブラウザ（Chrome, Edge, Firefox, Safari）
- **パスワードマネージャー**: Proton Pass, 1Password, Bitwarden等（本番環境）
- **認証デバイス**: Windows Hello, Touch ID, セキュリティキー（YubiKey等）

## クイックスタート

### 1. インストール

```bash
# リポジトリをクローン
git clone https://github.com/your-org/py_auth.git
cd py_auth

# 依存関係のインストール（uvを使用）
uv sync
```

### 2. 環境設定

```bash
# .envファイルを作成
cp .env.example .env

# .envを編集（開発環境）
nano .env
```

**.env（開発環境）**:
```env
FLASK_USE_SSL=true
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

SECRET_KEY=your-secret-key-here

RP_ID=127.0.0.1
RP_NAME=PyAuth Service
ORIGIN=https://127.0.0.1:5000

INITIAL_USERNAME=admin
INITIAL_PASSWORD=admin123
```

### 3. SSL証明書の生成（開発環境）

```bash
uv run python generate_cert.py
```

### 4. アプリケーション起動

```bash
uv run python app.py
```

ブラウザで `https://127.0.0.1:5000` にアクセス

---

## API仕様

### 基本情報

- **Base URL**: `https://your-domain.com`
- **認証**: セッションベース（Cookie）
- **Content-Type**: `application/json`

### 認証フロー

```
1. ログイン → セッション確立
2. 2FA検証（TOTP）
3. Passkey登録（オプション）
4. API利用
```

---

## API エンドポイント

### 認証系API

#### 1. ログイン

**POST** `/login`

ユーザー名とパスワードでログイン。

**リクエスト**:
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**レスポンス（成功）**:
```json
{
  "success": true,
  "message": "ログイン成功",
  "requires_2fa": true,
  "redirect": "/verify-2fa"
}
```

**レスポンス（失敗）**:
```json
{
  "success": false,
  "error": "ユーザー名またはパスワードが正しくありません"
}
```

**cURL例**:
```bash
curl -X POST https://your-domain.com/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

#### 2. 2FA検証（TOTP）

**POST** `/verify-2fa`

TOTPコードで2要素認証を検証。

**リクエスト**:
```json
{
  "totp_code": "123456"
}
```

**レスポンス（成功）**:
```json
{
  "success": true,
  "message": "認証成功",
  "redirect": "/dashboard"
}
```

**cURL例**:
```bash
curl -X POST https://your-domain.com/verify-2fa \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "totp_code": "123456"
  }'
```

#### 3. ログアウト

**POST** `/logout`

セッションを破棄してログアウト。

**cURL例**:
```bash
curl -X POST https://your-domain.com/logout \
  -b cookies.txt
```

---

### WebAuthn/Passkey API

#### 1. Passkey登録開始

**POST** `/api/webauthn/register/begin`

Passkey登録のチャレンジを取得。

**リクエスト**: Body不要

**レスポンス**:
```json
{
  "publicKey": {
    "challenge": "ランダムチャレンジ（Base64）",
    "rp": {
      "id": "your-domain.com",
      "name": "PyAuth Service"
    },
    "user": {
      "id": "ユーザーID（Base64）",
      "name": "username",
      "displayName": "username"
    },
    "pubKeyCredParams": [...],
    "timeout": 60000,
    "authenticatorSelection": {
      "residentKey": "preferred",
      "userVerification": "preferred"
    }
  }
}
```

**JavaScript例**:
```javascript
// チャレンジ取得
const response = await fetch('/api/webauthn/register/begin', {
  method: 'POST',
  credentials: 'include'
});
const options = await response.json();

// Base64デコード（詳細は後述）
options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
options.publicKey.user.id = base64urlToArrayBuffer(options.publicKey.user.id);

// WebAuthn登録
const credential = await navigator.credentials.create({ publicKey: options.publicKey });
```

#### 2. Passkey登録完了

**POST** `/api/webauthn/register/complete`

WebAuthnクレデンシャルを登録。

**リクエスト**:
```json
{
  "id": "credential-id",
  "rawId": "credential-id-base64",
  "response": {
    "attestationObject": "attestation-object-base64",
    "clientDataJSON": "client-data-json-base64"
  },
  "type": "public-key",
  "authenticatorAttachment": "platform",
  "transports": ["internal"]
}
```

**レスポンス（成功）**:
```json
{
  "success": true,
  "message": "Passkeyが登録されました"
}
```

**JavaScript例**:
```javascript
// クレデンシャルをサーバーに送信
const credentialResponse = {
  id: credential.id,
  rawId: arrayBufferToBase64url(credential.rawId),
  response: {
    attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
    clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON)
  },
  type: credential.type,
  authenticatorAttachment: credential.authenticatorAttachment,
  transports: credential.response.getTransports?.()
};

const result = await fetch('/api/webauthn/register/complete', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify(credentialResponse)
});
```

#### 3. Passkey認証開始

**POST** `/api/webauthn/authenticate/begin`

Passkey認証のチャレンジを取得。

**リクエスト**: Body不要

**レスポンス**:
```json
{
  "publicKey": {
    "challenge": "ランダムチャレンジ（Base64）",
    "timeout": 60000,
    "rpId": "your-domain.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "credential-id-base64"
      }
    ],
    "userVerification": "preferred"
  }
}
```

#### 4. Passkey認証完了

**POST** `/api/webauthn/authenticate/complete`

WebAuthn認証を完了。

**リクエスト**:
```json
{
  "id": "credential-id",
  "rawId": "credential-id-base64",
  "response": {
    "authenticatorData": "authenticator-data-base64",
    "clientDataJSON": "client-data-json-base64",
    "signature": "signature-base64",
    "userHandle": "user-handle-base64"
  },
  "type": "public-key"
}
```

**レスポンス（成功）**:
```json
{
  "success": true,
  "message": "認証成功"
}
```

#### 5. Passkey一覧取得

**GET** `/api/passkeys`

登録済みPasskey一覧を取得。

**レスポンス**:
```json
[
  {
    "id": 1,
    "name": "Passkey 1",
    "created_at": "2025-01-01T00:00:00"
  }
]
```

#### 6. Passkey削除

**DELETE** `/api/passkeys/<passkey_id>`

指定したPasskeyを削除。

**レスポンス**:
```json
{
  "success": true,
  "message": "Passkeyを削除しました"
}
```

---

### ユーザー管理API（管理者用）

#### 1. ユーザー一覧

**GET** `/admin/api/users`

全ユーザーの一覧を取得（管理者のみ）。

**レスポンス**:
```json
[
  {
    "id": 1,
    "username": "admin",
    "is_admin": true,
    "totp_enabled": true,
    "passkey_count": 2,
    "created_at": "2025-01-01T00:00:00"
  }
]
```

#### 2. ユーザー作成

**POST** `/admin/api/users`

新規ユーザーを作成（管理者のみ）。

**リクエスト**:
```json
{
  "username": "newuser",
  "password": "password123",
  "is_admin": false
}
```

**レスポンス**:
```json
{
  "success": true,
  "message": "ユーザーを作成しました",
  "user_id": 2
}
```

#### 3. ユーザー削除

**DELETE** `/admin/api/users/<user_id>`

ユーザーを削除（管理者のみ）。

**レスポンス**:
```json
{
  "success": true,
  "message": "ユーザーを削除しました"
}
```

---

## 外部アプリケーションからの利用例

### Python（Requests）

```python
import requests

# セッション作成
session = requests.Session()

# 1. ログイン
response = session.post('https://your-domain.com/login', json={
    'username': 'admin',
    'password': 'admin123'
})
print(response.json())

# 2. 2FA検証
response = session.post('https://your-domain.com/verify-2fa', json={
    'totp_code': '123456'
})
print(response.json())

# 3. Passkey一覧取得
response = session.get('https://your-domain.com/api/passkeys')
print(response.json())

# 4. ログアウト
session.post('https://your-domain.com/logout')
```

### JavaScript（Fetch API）

```javascript
// 1. ログイン
const loginResponse = await fetch('https://your-domain.com/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',  // Cookie送信
  body: JSON.stringify({
    username: 'admin',
    password: 'admin123'
  })
});
const loginData = await loginResponse.json();
console.log(loginData);

// 2. 2FA検証
const tfaResponse = await fetch('https://your-domain.com/verify-2fa', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    totp_code: '123456'
  })
});
const tfaData = await tfaResponse.json();
console.log(tfaData);

// 3. Passkey一覧
const passkeysResponse = await fetch('https://your-domain.com/api/passkeys', {
  credentials: 'include'
});
const passkeys = await passkeysResponse.json();
console.log(passkeys);
```

### cURL（シェルスクリプト）

```bash
#!/bin/bash

DOMAIN="https://your-domain.com"
COOKIES="cookies.txt"

# 1. ログイン
curl -X POST "$DOMAIN/login" \
  -H "Content-Type: application/json" \
  -c "$COOKIES" \
  -d '{"username":"admin","password":"admin123"}'

# 2. 2FA検証
curl -X POST "$DOMAIN/verify-2fa" \
  -H "Content-Type: application/json" \
  -b "$COOKIES" \
  -d '{"totp_code":"123456"}'

# 3. Passkey一覧
curl -X GET "$DOMAIN/api/passkeys" \
  -b "$COOKIES"

# 4. ログアウト
curl -X POST "$DOMAIN/logout" \
  -b "$COOKIES"
```

---

## WebAuthn Base64変換ヘルパー関数

WebAuthn APIを使用する場合、Base64 URLエンコーディングの変換が必要です。

```javascript
// Base64 URL → ArrayBuffer
function base64urlToArrayBuffer(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray.buffer;
}

// ArrayBuffer → Base64 URL
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

---

## 本番環境デプロイ

### Nginx + Let's Encrypt

詳細は [DEPLOYMENT.md](DEPLOYMENT.md) を参照。

**要点**:
1. `.env`で`FLASK_USE_SSL=false`に設定
2. NginxがSSL終端を担当
3. Let's Encryptで証明書取得
4. Gunicornでアプリケーション起動

```bash
# .env設定
FLASK_USE_SSL=false
FLASK_HOST=127.0.0.1
ORIGIN=https://your-domain.com
RP_ID=your-domain.com

# Gunicornで起動
uv run gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

---

## セキュリティ

### 認証要件

- **セッション**: HTTP-Only Cookie
- **CSRF保護**: Flask-WTF
- **パスワード**: Werkzeugでハッシュ化
- **TOTP**: pyotp、NTP時刻同期
- **WebAuthn**: FIDO2仕様準拠

### 本番環境での推奨事項

1. **強力なSECRET_KEY**: 32文字以上のランダム文字列
2. **HTTPS必須**: WebAuthnはHTTPS必須
3. **ファイアウォール**: 必要なポートのみ開放（80, 443）
4. **レート制限**: ログイン試行回数の制限（Nginx設定）
5. **定期バックアップ**: データベースのバックアップ

---

## トラブルシューティング

### Passkey登録エラー

**症状**: `InsecureLocalhostNotAllowed`

**原因**: Proton Passなどは自己署名証明書を拒否

**解決**: 
- 開発環境: Windows HelloやChromeの内蔵Authenticatorを使用
- 本番環境: Let's Encryptなど信頼された証明書を使用

### TOTP認証失敗

**症状**: 正しいコードでも認証失敗

**原因**: サーバー時刻がずれている

**解決**:
```bash
# NTP同期確認（Linux）
sudo systemctl status systemd-timesyncd

# 時刻同期（Windows）
w32tm /resync
```

### CSRF検証エラー

**症状**: `400 Bad Request - CSRF token missing`

**原因**: CSRFトークンが送信されていない

**解決**: HTMLフォームに`{{ csrf_token() }}`を含める、またはAPIリクエストに`X-CSRFToken`ヘッダーを追加

---

## ライセンス

MIT License

## 貢献

プルリクエストを歓迎します。大きな変更の場合は、まずIssueを開いて変更内容を議論してください。

## サポート

- **Issue**: https://github.com/your-org/py_auth/issues
- **Wiki**: https://github.com/your-org/py_auth/wiki
- **Discussions**: https://github.com/your-org/py_auth/discussions

