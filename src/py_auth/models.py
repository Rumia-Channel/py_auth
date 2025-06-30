from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
import pyotp
import json
from datetime import datetime
import os

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_first_login = db.Column(db.Boolean, default=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_totp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # リレーション
    passkeys = db.relationship('Passkey', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_totp_secret(self):
        """TOTP秘密鍵を生成"""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        """TOTP QRコード用URIを取得"""
        if not self.totp_secret:
            return None
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name=current_app.config.get('RP_NAME', 'PyAuth')
        )
    
    def verify_totp(self, token):
        """TOTPトークンを検証"""
        if not self.totp_secret or not self.is_totp_enabled:
            return False
        
        # NTP同期された時刻を使用
        from .time_sync import get_current_time, get_time_debug_info
        import time
        from datetime import datetime, timezone
        
        current_time = get_current_time()
        local_time = time.time()
        totp = pyotp.TOTP(self.totp_secret)
        
        # デバッグ情報をログ出力
        import logging
        logger = logging.getLogger(__name__)
        
        # 時刻情報の詳細デバッグ
        time_debug = get_time_debug_info()
        
        # 現在の時刻ステップ計算
        time_step = 30  # TOTP標準は30秒
        current_step = int(current_time // time_step)
        step_start_time = current_step * time_step
        step_end_time = (current_step + 1) * time_step
        remaining_seconds = int(step_end_time - current_time)
        
        # 現在のコード
        current_code = totp.at(current_time)
        
        # 前後のコードも生成（デバッグ用）
        prev_code = totp.at(current_time - 30)
        next_code = totp.at(current_time + 30)
        
        # より広い検証ウィンドウを使用（前後3つのコード = ±90秒）
        is_valid = totp.verify(token, for_time=current_time, valid_window=3)
        
        # 結果のみログ出力（セキュリティ情報は非表示）
        logger.info(f"TOTP認証結果: ユーザー={self.username}, 成功={is_valid}")
        
        return is_valid
    
    def can_modify_admin_privileges(self, target_user):
        """管理者権限を変更できるかチェック"""
        if not self.is_super_admin:
            return False
        if target_user.is_super_admin:
            return False
        return True
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'is_super_admin': self.is_super_admin,
            'is_first_login': self.is_first_login,
            'is_totp_enabled': self.is_totp_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'passkeys_count': len(self.passkeys)
        }

class Passkey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    name = db.Column(db.String(100), nullable=False, default='Passkey')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='sessions')

def init_admin_user():
    """初期管理者ユーザーを作成"""
    admin_username = current_app.config.get('INITIAL_USERNAME', 'admin')
    admin_password = current_app.config.get('INITIAL_PASSWORD', 'admin123')
    
    # 既存の管理者をチェック
    existing_admin = User.query.filter_by(username=admin_username).first()
    if existing_admin:
        return existing_admin
    
    # 新しいスーパー管理者を作成
    admin_user = User(
        username=admin_username,
        is_admin=True,
        is_super_admin=True,
        is_first_login=True
    )
    admin_user.set_password(admin_password)
    
    db.session.add(admin_user)
    db.session.commit()
    
    print(f"初期管理者ユーザーを作成しました: {admin_username}")
    print(f"初期パスワード: {admin_password}")
    print("初回ログイン時にパスワード変更、2FA、Passkey登録が必要です。")
    
    return admin_user