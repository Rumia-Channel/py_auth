#!/usr/bin/env python3
"""
自己署名証明書を生成してHTTPSサーバーを起動するスクリプト
"""
import os
import ssl
import subprocess
from pathlib import Path

def generate_self_signed_cert():
    """自己署名証明書を生成"""
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)
    
    cert_file = cert_dir / "cert.pem"
    key_file = cert_dir / "key.pem"
    
    if cert_file.exists() and key_file.exists():
        print("証明書が既に存在します")
        return str(cert_file), str(key_file)
    
    # OpenSSLコマンドで自己署名証明書を生成
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(key_file),
        "-out", str(cert_file),
        "-days", "365",
        "-nodes",
        "-subj", "/C=JP/ST=Tokyo/L=Tokyo/O=Test/OU=Test/CN=localhost"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"証明書を生成しました: {cert_file}")
        print(f"秘密鍵を生成しました: {key_file}")
        return str(cert_file), str(key_file)
    except subprocess.CalledProcessError:
        print("OpenSSLが見つかりません。手動で証明書を作成してください。")
        return None, None
    except FileNotFoundError:
        print("OpenSSLが見つかりません。手動で証明書を作成してください。")
        return None, None

if __name__ == "__main__":
    cert_file, key_file = generate_self_signed_cert()
    if cert_file and key_file:
        print("\n次の手順でHTTPSサーバーを起動してください:")
        print("1. .envファイルでHTTPS設定を有効化")
        print("2. python app.py でサーバー起動")
        print("3. https://localhost:5008 でアクセス")
        print("4. ブラウザで「詳細設定」→「安全でないサイトにアクセス」を選択")