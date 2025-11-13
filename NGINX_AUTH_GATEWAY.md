# Nginx認証ゲートウェイ設定ガイド

## 概要

PyAuthをNginxの`auth_request`モジュールと連携させて、他のサイトへのアクセス前に認証を要求するゲートウェイとして動作させます。

## アーキテクチャ

```
ユーザー → サイトA (http://site-a.example.com)
             ↓ (未認証の場合)
         PyAuth認証 (http://auth.example.com)
             ↓ (認証成功)
         サイトAにリダイレクト
```

## フロー

1. ユーザーが保護されたサイト（サイトA）にアクセス
2. NginxがPyAuthに認証確認リクエスト（`auth_request`）
3. 未認証の場合、PyAuthのログイン画面にリダイレクト
4. ログイン成功後、元のサイトAにリダイレクト
5. 以降はセッションが有効な間、認証不要でアクセス可能

---

## セットアップ

### 1. PyAuth側の設定

#### 認証確認用エンドポイントの追加

`src/py_auth/auth.py`に以下を追加：

```python
from flask import Blueprint, session, request, redirect, url_for

auth_request_bp = Blueprint('auth_request', __name__)

@auth_request_bp.route('/auth/verify', methods=['GET'])
def verify_auth():
    """Nginx auth_request用の認証確認エンドポイント"""
    # セッションに認証済みユーザーがいるか確認
    if 'user_id' in session and session.get('authenticated', False):
        # 認証済み: 200 OK
        return '', 200
    else:
        # 未認証: 401 Unauthorized
        return '', 401

@auth_request_bp.route('/auth/login-redirect', methods=['GET'])
def login_redirect():
    """認証が必要な場合のログインページへのリダイレクト"""
    # 元のURLを保存
    original_url = request.args.get('url', request.referrer or '/')
    session['redirect_after_login'] = original_url
    
    # ログインページにリダイレクト
    return redirect(url_for('auth.login'))
```

#### `__init__.py`でBlueprint登録

`src/py_auth/__init__.py`に追加：

```python
from .auth import auth_bp, auth_request_bp

app.register_blueprint(auth_bp)
app.register_blueprint(auth_request_bp)
```

#### ログイン成功後のリダイレクト処理

`src/py_auth/auth.py`のログイン処理に追加：

```python
@auth_bp.route('/login', methods=['POST'])
def login():
    # ... 既存のログイン処理 ...
    
    if login_successful:
        # リダイレクト先を確認
        redirect_url = session.pop('redirect_after_login', None)
        if redirect_url:
            return jsonify({
                'success': True,
                'redirect': redirect_url
            })
        else:
            return jsonify({
                'success': True,
                'redirect': '/dashboard'
            })
```

---

### 2. Nginx設定

#### PyAuth用の設定（auth.example.com）

```nginx
# PyAuth認証サーバー
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;
    
    # SSL証明書
    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    
    # SSL設定
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    # ログ
    access_log /var/log/nginx/auth_access.log;
    error_log /var/log/nginx/auth_error.log;
    
    # PyAuthアプリケーション
    location / {
        proxy_pass http://127.0.0.1:5000;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # セッションCookie設定（重要）
        proxy_cookie_path / "/; SameSite=Lax";
        proxy_cookie_domain localhost auth.example.com;
    }
    
    # 認証確認用エンドポイント（内部使用）
    location = /auth/verify {
        internal;  # 外部からの直接アクセス不可
        proxy_pass http://127.0.0.1:5000;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
    }
}
```

#### 保護されたサイトの設定（site-a.example.com）

```nginx
# サイトA（認証が必要なサイト）
server {
    listen 80;
    server_name site-a.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name site-a.example.com;
    
    # SSL証明書
    ssl_certificate /etc/letsencrypt/live/site-a.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/site-a.example.com/privkey.pem;
    
    # ログ
    access_log /var/log/nginx/site_a_access.log;
    error_log /var/log/nginx/site_a_error.log;
    
    # 認証確認（すべてのリクエストに適用）
    auth_request /auth-check;
    
    # 認証失敗時のエラーハンドリング
    error_page 401 = @error401;
    
    # 認証確認用の内部リクエスト
    location = /auth-check {
        internal;
        
        # PyAuthの認証確認エンドポイントに転送
        proxy_pass https://auth.example.com/auth/verify;
        
        # 元のリクエスト情報を送信
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        
        # Cookieを転送（重要）
        proxy_set_header Cookie $http_cookie;
    }
    
    # 401エラー時の処理（ログインページへリダイレクト）
    location @error401 {
        # 現在のURLをエンコードしてログインページへ
        return 302 https://auth.example.com/auth/login-redirect?url=https://$server_name$request_uri;
    }
    
    # サイトAのコンテンツ
    location / {
        # 認証成功後にここに到達
        root /var/www/site-a;
        index index.html;
        
        # または他のアプリケーションへプロキシ
        # proxy_pass http://127.0.0.1:8080;
    }
    
    # 静的ファイルは認証不要（オプション）
    location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg)$ {
        auth_request off;  # 認証をスキップ
        root /var/www/site-a;
        expires 30d;
    }
}
```

---

## PyAuth側のコード修正

### 1. `src/py_auth/auth.py`に追加

```python
from flask import Blueprint, request, session, redirect, url_for, jsonify

# 既存のBlueprint
auth_bp = Blueprint('auth', __name__)

# 新しいBlueprint（認証確認用）
auth_request_bp = Blueprint('auth_request', __name__)

@auth_request_bp.route('/auth/verify', methods=['GET', 'HEAD'])
def verify_auth():
    """
    Nginx auth_request用の認証確認エンドポイント
    
    Returns:
        200: 認証済み
        401: 未認証
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # セッションから認証状態を確認
    user_id = session.get('user_id')
    authenticated = session.get('authenticated', False)
    
    # 元のリクエストURL（デバッグ用）
    original_uri = request.headers.get('X-Original-URI', 'unknown')
    
    if user_id and authenticated:
        logger.info(f"認証確認成功: user_id={user_id}, uri={original_uri}")
        return '', 200
    else:
        logger.info(f"認証確認失敗: uri={original_uri}")
        return '', 401

@auth_request_bp.route('/auth/login-redirect', methods=['GET'])
def login_redirect():
    """
    未認証時のログインページへのリダイレクト
    元のURLを保存して、ログイン後に戻る
    """
    # 元のURLをクエリパラメータから取得
    original_url = request.args.get('url', '/')
    
    # セッションに保存
    session['redirect_after_login'] = original_url
    
    # ログインページにリダイレクト
    return redirect(url_for('auth.login'))
```

### 2. `src/py_auth/__init__.py`に追加

```python
def create_app():
    app = Flask(__name__)
    
    # ... 既存の設定 ...
    
    # ブループリントの登録
    from .auth import auth_bp, auth_request_bp
    from .admin import admin_bp
    from .api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(auth_request_bp)  # 追加
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    return app
```

### 3. ログイン成功後のリダイレクト処理

`src/py_auth/auth.py`のログイン処理を修正：

```python
@auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa_submit():
    """2FA検証処理"""
    # ... 既存の検証処理 ...
    
    if verification_successful:
        # 認証完了フラグを設定
        session['authenticated'] = True
        session.permanent = True
        
        # リダイレクト先を確認
        redirect_url = session.pop('redirect_after_login', None)
        
        if redirect_url and redirect_url.startswith('http'):
            # 外部サイトへのリダイレクト
            return jsonify({
                'success': True,
                'redirect': redirect_url
            })
        else:
            # デフォルトのダッシュボードへ
            return jsonify({
                'success': True,
                'redirect': url_for('auth.dashboard')
            })
```

---

## Cookie設定の重要ポイント

### PyAuthの.env設定

```env
# Cookieドメイン設定（サブドメイン間で共有）
SESSION_COOKIE_DOMAIN=.example.com
SESSION_COOKIE_SAMESITE=Lax
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
```

### Flaskアプリケーション設定

`src/py_auth/__init__.py`:

```python
def create_app():
    app = Flask(__name__)
    
    # セッションCookie設定
    app.config['SESSION_COOKIE_DOMAIN'] = os.getenv('SESSION_COOKIE_DOMAIN', '.example.com')
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS必須
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_NAME'] = 'pyauth_session'
    
    return app
```

---

## テスト手順

### 1. PyAuthを起動

```bash
# .env設定
FLASK_USE_SSL=false
FLASK_HOST=127.0.0.1
ORIGIN=https://auth.example.com
RP_ID=auth.example.com
SESSION_COOKIE_DOMAIN=.example.com

# 起動
uv run gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

### 2. Nginx設定を適用

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 3. 動作確認

1. **未認証でサイトAにアクセス**:
   ```
   https://site-a.example.com
   → https://auth.example.com/login にリダイレクト
   ```

2. **ログイン**:
   ```
   ユーザー名・パスワード入力
   → 2FA検証
   → https://site-a.example.com にリダイレクト
   ```

3. **認証済みでアクセス**:
   ```
   https://site-a.example.com
   → 直接表示（リダイレクトなし）
   ```

---

## 複数サイトの保護

同じPyAuthで複数のサイトを保護できます：

```nginx
# サイトB
server {
    listen 443 ssl http2;
    server_name site-b.example.com;
    
    auth_request /auth-check;
    error_page 401 = @error401;
    
    location = /auth-check {
        internal;
        proxy_pass https://auth.example.com/auth/verify;
        proxy_set_header Cookie $http_cookie;
    }
    
    location @error401 {
        return 302 https://auth.example.com/auth/login-redirect?url=https://$server_name$request_uri;
    }
    
    location / {
        root /var/www/site-b;
    }
}

# サイトC
server {
    listen 443 ssl http2;
    server_name site-c.example.com;
    
    # 同様の設定
}
```

---

## トラブルシューティング

### Cookieが共有されない

**原因**: Cookie設定が正しくない

**解決**:
- `SESSION_COOKIE_DOMAIN=.example.com`（ドットが重要）
- すべてのサイトが同じルートドメイン配下にある
- HTTPSを使用している

### 無限リダイレクトループ

**原因**: 認証確認エンドポイントがループしている

**解決**:
- `/auth/verify`に`internal;`ディレクティブを設定
- `/auth/login-redirect`は認証不要にする

### 認証後に元のURLに戻らない

**原因**: セッションに保存されていない

**解決**:
- `session['redirect_after_login']`が正しく保存・取得されているか確認
- ログイン成功後のリダイレクト処理を確認

---

## セキュリティ考慮事項

1. **HTTPS必須**: すべてのサイトでHTTPSを使用
2. **Cookie設定**: `Secure`, `HttpOnly`, `SameSite=Lax`
3. **CSRFトークン**: ログインフォームにCSRF保護
4. **リダイレクト検証**: `redirect_after_login`のURL検証（オープンリダイレクト対策）
5. **レート制限**: Nginxでログイン試行回数を制限

---

## まとめ

この構成により、PyAuthを使って複数のNginxサイトに対して統一された認証を提供できます。ユーザーは一度ログインすれば、すべての保護されたサイトにアクセスできるようになります（SSO: Single Sign-On）。
