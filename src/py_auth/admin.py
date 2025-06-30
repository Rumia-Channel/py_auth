from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from .models import User, db
from .forms import UserCreateForm
from .auth import login_required
from functools import wraps

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('管理者権限が必要です', 'error')
            return redirect(url_for('auth.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@admin_required
def dashboard():
    """管理者ダッシュボード"""
    users = User.query.all()
    user_count = len(users)
    admin_count = len([u for u in users if u.is_admin])
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         user_count=user_count, 
                         admin_count=admin_count)

@admin_bp.route('/users')
@admin_required
def users():
    """ユーザー一覧"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    """新規ユーザー作成"""
    form = UserCreateForm()
    
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            is_admin=form.is_admin.data,
            is_first_login=True
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'ユーザー「{user.username}」を作成しました', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/create_user.html', form=form)

@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    """ユーザー詳細"""
    user = User.query.get_or_404(user_id)
    return render_template('admin/user_detail.html', user=user)

@admin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    """ユーザーパスワードリセット"""
    user = User.query.get_or_404(user_id)
    
    # 管理者自身の場合は拒否
    if user.id == session.get('user_id'):
        return jsonify({'success': False, 'error': '自分のパスワードはリセットできません'}), 400
    
    # 新しい仮パスワード生成
    import secrets
    import string
    
    chars = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(chars) for _ in range(12))
    
    user.set_password(new_password)
    user.is_first_login = True
    user.is_totp_enabled = False
    user.totp_secret = None
    
    # すべてのPasskeyを削除
    from .models import Passkey
    Passkey.query.filter_by(user_id=user.id).delete()
    
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'パスワードをリセットしました',
        'new_password': new_password
    })

@admin_bp.route('/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_user_admin(user_id):
    """ユーザーの管理者権限切り替え"""
    current_user = User.query.get(session['user_id'])
    target_user = User.query.get_or_404(user_id)
    
    # 自分自身の権限は変更不可
    if target_user.id == current_user.id:
        return jsonify({'success': False, 'error': '自分の管理者権限は変更できません'}), 400
    
    # スーパー管理者のみが他のユーザーの管理者権限を変更可能
    if not current_user.can_modify_admin_privileges(target_user):
        return jsonify({'success': False, 'error': 'スーパー管理者のみが管理者権限を変更できます'}), 403
    
    target_user.is_admin = not target_user.is_admin
    db.session.commit()
    
    status = '付与' if target_user.is_admin else '削除'
    return jsonify({
        'success': True, 
        'message': f'ユーザー「{target_user.username}」の管理者権限を{status}しました',
        'is_admin': target_user.is_admin
    })

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """ユーザー削除"""
    current_user = User.query.get(session['user_id'])
    target_user = User.query.get_or_404(user_id)
    
    # 自分自身は削除不可
    if target_user.id == current_user.id:
        return jsonify({'success': False, 'error': '自分のアカウントは削除できません'}), 400
    
    # スーパー管理者は削除不可
    if target_user.is_super_admin:
        return jsonify({'success': False, 'error': 'スーパー管理者は削除できません'}), 400
    
    username = target_user.username
    db.session.delete(target_user)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'ユーザー「{username}」を削除しました'
    })