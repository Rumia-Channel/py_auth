from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from werkzeug.security import check_password_hash
from .models import User, db
from .forms import LoginForm, PasswordChangeForm, TOTPSetupForm, TOTPVerifyForm
from functools import wraps
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def first_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 初回ログイン中は temp_user_id を使用
        user_id = session.get('temp_user_id') or session.get('user_id')
        
        if not user_id or not session.get('password_verified'):
            return redirect(url_for('auth.login'))
        
        user = User.query.get(user_id)
        if not user or not user.is_first_login:
            return redirect(url_for('auth.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_first_login:
            return redirect(url_for('auth.first_login_setup'))
        return redirect(url_for('auth.dashboard'))
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('auth.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            # パスワード認証成功
            session['temp_user_id'] = user.id
            session['password_verified'] = True
            
            # 初回ログインの場合
            if user.is_first_login:
                return redirect(url_for('auth.first_login_setup'))
            
            # 2FAが有効な場合
            if user.is_totp_enabled:
                return redirect(url_for('auth.verify_2fa'))
            
            # 2FAが無効な場合は直接ログイン
            session['user_id'] = user.id
            session.pop('temp_user_id', None)
            session.pop('password_verified', None)
            
            # リダイレクト先を決定（優先順位: next_url > next パラメータ > dashboard）
            next_page = session.pop('next_url', None) or request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('auth.dashboard'))
        
        flash('ユーザー名またはパスワードが間違っています', 'error')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user_id' not in session or not session.get('password_verified'):
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user or not user.is_totp_enabled:
        return redirect(url_for('auth.login'))
    
    form = TOTPVerifyForm()
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            # 2FA認証成功
            session['user_id'] = user.id
            session.pop('temp_user_id', None)
            session.pop('password_verified', None)
            
            # リダイレクト先を決定（優先順位: next_url > next パラメータ > dashboard）
            next_page = session.pop('next_url', None) or request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('auth.dashboard'))
        
        flash('認証コードが間違っています', 'error')
    
    return render_template('auth/verify_2fa.html', form=form)

@auth_bp.route('/first-login-setup')
def first_login_setup():
    if 'temp_user_id' not in session or not session.get('password_verified'):
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user or not user.is_first_login:
        return redirect(url_for('auth.dashboard'))
    
    return render_template('auth/first_login_setup.html')

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@first_login_required
def change_password():
    user_id = session.get('temp_user_id') or session.get('user_id')
    user = User.query.get(user_id)
    form = PasswordChangeForm()
    
    if form.validate_on_submit():
        if user.check_password(form.current_password.data):
            user.set_password(form.new_password.data)
            db.session.commit()
            
            session['password_changed'] = True
            flash('パスワードが変更されました', 'success')
            return redirect(url_for('auth.setup_2fa'))
        
        flash('現在のパスワードが間違っています', 'error')
    
    return render_template('auth/change_password.html', form=form)

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@first_login_required
def setup_2fa():
    if not session.get('password_changed'):
        return redirect(url_for('auth.change_password'))
    
    user_id = session.get('temp_user_id') or session.get('user_id')
    user = User.query.get(user_id)
    form = TOTPSetupForm()
    
    # TOTP秘密鍵を生成（まだ生成されていない場合）
    if not user.totp_secret:
        user.generate_totp_secret()
        db.session.commit()
    
    # QRコード生成
    qr_uri = user.get_totp_uri()
    qr_code = qrcode.make(qr_uri)
    qr_buffer = io.BytesIO()
    qr_code.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    qr_code_data = base64.b64encode(qr_buffer.getvalue()).decode()
    
    if form.validate_on_submit():
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"2FA設定開始: ユーザー={user.username}")
        
        # 2FA設定時は is_totp_enabled=False でも検証できるように一時的に設定
        original_totp_enabled = user.is_totp_enabled
        user.is_totp_enabled = True
        
        if user.verify_totp(form.token.data):
            # 検証成功、2FAを正式に有効化
            db.session.commit()
            
            session['totp_setup'] = True
            flash('2要素認証が有効化されました', 'success')
            logger.info(f"2FA設定成功: ユーザー={user.username}")
            return redirect(url_for('auth.setup_passkey'))
        else:
            # 検証失敗、元の状態に戻す
            user.is_totp_enabled = original_totp_enabled
            flash('認証コードが間違っています', 'error')
            logger.warning(f"2FA設定失敗: ユーザー={user.username}")
    
    return render_template('auth/setup_2fa.html', form=form, qr_code=qr_code_data, secret=user.totp_secret)

@auth_bp.route('/setup-passkey')
@first_login_required
def setup_passkey():
    if not session.get('password_changed') or not session.get('totp_setup'):
        return redirect(url_for('auth.change_password'))
    
    return render_template('auth/setup_passkey.html')

@auth_bp.route('/complete-setup', methods=['POST'])
@first_login_required
def complete_setup():
    if not session.get('password_changed') or not session.get('totp_setup'):
        return redirect(url_for('auth.change_password'))
    
    user_id = session.get('temp_user_id') or session.get('user_id')
    user = User.query.get(user_id)
    user.is_first_login = False
    db.session.commit()
    
    # セッションクリーンアップ
    session.pop('password_changed', None)
    session.pop('totp_setup', None)
    session.pop('temp_user_id', None)
    session.pop('password_verified', None)
    
    # 正式にログイン
    session['user_id'] = user.id
    
    flash('初期設定が完了しました', 'success')
    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('auth/dashboard.html', user=user)

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('ログアウトしました', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/auth')
def auth_check():
    """認証チェック用エンドポイント（nginx auth_request用）"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and not user.is_first_login:
            return jsonify({'authenticated': True, 'user': user.to_dict()}), 200
    
    # 認証失敗時：元のURLを保存してログインページにリダイレクト
    original_url = request.headers.get('X-Original-URI', '/')
    original_host = request.headers.get('X-Original-Host', request.headers.get('Host', ''))
    
    # 完全なURLを構築
    if original_host and original_url:
        full_original_url = f"https://{original_host}{original_url}"
        # セッションに保存
        session['next_url'] = full_original_url
    
    return jsonify({'authenticated': False}), 401