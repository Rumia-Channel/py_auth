#!/usr/bin/env python3

from src.py_auth import create_app
import os
import logging

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = create_app()

if __name__ == '__main__':
    # 開発サーバーの設定
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    # SSL設定: FLASK_USE_SSL環境変数で制御
    # True: 強制的にHTTPS（証明書が必要）
    # False: 強制的にHTTP（Nginxリバースプロキシ用）
    # 未設定: 証明書があればHTTPS、なければHTTP（自動判定）
    use_ssl = os.getenv('FLASK_USE_SSL', '').lower()
    ssl_context = None
    cert_file = "certs/cert.pem"
    key_file = "certs/key.pem"
    
    if use_ssl == 'true':
        # 強制HTTPS
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = (cert_file, key_file)
            protocol = "https"
            print("HTTPSモードで起動します（FLASK_USE_SSL=True）")
        else:
            print("エラー: FLASK_USE_SSL=True ですが、証明書が見つかりません")
            print(f"証明書を生成してください: python generate_cert.py")
            exit(1)
    elif use_ssl == 'false':
        # 強制HTTP（Nginxリバースプロキシ用）
        protocol = "http"
        print("HTTPモードで起動します（FLASK_USE_SSL=False）")
        print("注意: Nginxなどのリバースプロキシ経由でHTTPS化してください")
    else:
        # 自動判定（デフォルト）
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = (cert_file, key_file)
            protocol = "https"
            print("HTTPSモードで起動します（証明書を検出）")
        else:
            protocol = "http"
            print("HTTPモードで起動します（証明書なし）")
            print("注意: WebAuthn/Passkeyを使用するにはHTTPSが必要です")
    
    print(f"PyAuth認証サービスを開始します...")
    print(f"URL: {protocol}://{host}:{port}")
    print(f"管理者アカウント: {os.getenv('INITIAL_USERNAME', 'admin')}")
    print(f"初期パスワード: {os.getenv('INITIAL_PASSWORD', 'admin123')}")
    print("初回ログイン時にパスワード変更、2FA、Passkey登録が必要です。")
    print("-" * 60)
    print("TOTP認証のデバッグログが有効です")
    print("ログでNTP時刻とコード生成状況を確認できます")
    print("-" * 60)
    
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)