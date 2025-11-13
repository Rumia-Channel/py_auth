#!/usr/bin/env python3
"""
自己署名証明書を生成してHTTPSサーバーを起動するスクリプト
"""
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_self_signed_cert():
    """自己署名証明書を生成"""
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)
    
    cert_file = cert_dir / "cert.pem"
    key_file = cert_dir / "key.pem"
    
    if cert_file.exists() and key_file.exists():
        print("証明書が既に存在します")
        return str(cert_file), str(key_file)
    
    print("自己署名証明書を生成しています...")
    
    # 秘密鍵を生成
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # 証明書の主体と発行者を設定
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Tokyo"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyAuth"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    # 証明書を作成
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
            x509.IPAddress(IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # 秘密鍵をファイルに書き込み
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 証明書をファイルに書き込み
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"証明書を生成しました: {cert_file}")
    print(f"秘密鍵を生成しました: {key_file}")
    return str(cert_file), str(key_file)

if __name__ == "__main__":
    cert_file, key_file = generate_self_signed_cert()
    if cert_file and key_file:
        print("\n次の手順でHTTPSサーバーを起動してください:")
        print("1. python app.py でサーバー起動（自動的にHTTPSで起動します）")
        print("2. https://localhost:5000 でアクセス")
        print("3. ブラウザで「詳細設定」→「安全でないサイトにアクセス」を選択")
        print("   （自己署名証明書の警告が表示されます）")