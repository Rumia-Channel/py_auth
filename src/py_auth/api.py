from flask import Blueprint, request, jsonify, session
from .models import User, Passkey, db
from .webauthn import start_registration, complete_registration, start_authentication, complete_authentication, delete_passkey
from .auth import login_required
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    """Passkey登録開始"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        user_id = session.get('user_id') or session.get('temp_user_id')
        logger.info(f"Passkey登録開始: user_id={user_id}")
        
        if not user_id:
            logger.error("Passkey登録: ユーザーIDが見つかりません")
            return jsonify({'error': 'ユーザーIDが見つかりません'}), 401
        
        registration_data = start_registration(user_id)
        
        if registration_data is None:
            logger.error(f"Passkey登録: ユーザーが見つかりません (user_id={user_id})")
            return jsonify({'error': 'ユーザーが見つかりません'}), 404
        
        # CredentialCreationOptionsをdict化してJSON化
        # fido2ライブラリが自動的にWebAuthn標準形式に変換
        options_dict = dict(registration_data)
        
        logger.info("Passkey登録データ生成成功")
        logger.info(f"Options keys: {list(options_dict.keys())}")
        
        return jsonify(options_dict)
        
    except Exception as e:
        logger.error(f"Passkey登録開始エラー: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    """Passkey登録完了"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # リクエストボディを確認
        raw_data = request.get_data()
        content_type = request.content_type
        
        logger.info(f"Passkey登録完了: Content-Type={content_type}")
        logger.info(f"Raw data length: {len(raw_data)}")
        
        if not raw_data:
            logger.error("Passkey登録完了: リクエストボディが空です")
            return jsonify({'success': False, 'error': 'リクエストボディが空です'}), 400
        
        try:
            credential_data = request.get_json()
            if credential_data is None:
                logger.error("Passkey登録完了: JSONパースに失敗")
                return jsonify({'success': False, 'error': 'JSONパースに失敗しました'}), 400
            
            # クライアントデータの詳細デバッグ（セキュリティ上後で削除）
            logger.info(f"受信したクレデンシャルデータキー: {list(credential_data.keys())}")
            logger.info(f"credential_data['id']: {credential_data.get('id', 'なし')}")
            logger.info(f"credential_data['type']: {credential_data.get('type', 'なし')}")
            if 'response' in credential_data:
                response_keys = list(credential_data['response'].keys())
                logger.info(f"response内のキー: {response_keys}")
            
            # 生のJSONデータも確認
            logger.info(f"生のリクエストデータ（最初の200文字）: {raw_data[:200].decode('utf-8', errors='ignore')}")
            
        except Exception as json_error:
            logger.error(f"Passkey登録完了: JSON例外 - {json_error}")
            logger.error(f"生のリクエストデータ: {raw_data.decode('utf-8', errors='ignore')}")
            return jsonify({'success': False, 'error': f'JSON例外: {str(json_error)}'}), 400
        
        success, message = complete_registration(credential_data)
        
        if success:
            logger.info("Passkey登録完了成功")
            return jsonify({'success': True, 'message': message})
        else:
            logger.warning(f"Passkey登録完了失敗: {message}")
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        logger.error(f"Passkey登録完了エラー: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():
    """Passkey認証開始"""
    try:
        auth_data = start_authentication()
        
        # バイナリデータをBase64でエンコードし、WebAuthn標準のプロパティ名に変換
        def encode_binary_and_normalize(obj):
            if isinstance(obj, bytes):
                import base64
                return base64.urlsafe_b64encode(obj).decode('ascii').rstrip('=')
            elif hasattr(obj, '__dict__'):
                # オブジェクトの属性を辞書として処理
                result = {}
                for key, value in obj.__dict__.items():
                    if not key.startswith('_'):
                        # プロパティ名をWebAuthn標準に変換
                        normalized_key = normalize_property_name(key)
                        result[normalized_key] = encode_binary_and_normalize(value)
                return result
            elif isinstance(obj, dict):
                normalized_dict = {}
                for k, v in obj.items():
                    normalized_key = normalize_property_name(k)
                    normalized_dict[normalized_key] = encode_binary_and_normalize(v)
                return normalized_dict
            elif isinstance(obj, list):
                return [encode_binary_and_normalize(item) for item in obj]
            elif isinstance(obj, tuple):
                return tuple(encode_binary_and_normalize(item) for item in obj)
            return obj
        
        def normalize_property_name(key):
            """プロパティ名をWebAuthn標準に変換"""
            property_mapping = {
                'allow_credentials': 'allowCredentials',
                'user_verification': 'userVerification'
            }
            return property_mapping.get(key, key)
        
        encoded_data = encode_binary_and_normalize(auth_data)
        return jsonify(encoded_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():
    """Passkey認証完了"""
    try:
        credential_data = request.get_json()
        success, user, message = complete_authentication(credential_data)
        
        if success and user:
            # ログインセッションを設定
            session['user_id'] = user.id
            
            # 初回ログインかチェック
            if user.is_first_login:
                session['temp_user_id'] = user.id
                session['password_verified'] = True
                return jsonify({
                    'success': True, 
                    'message': message,
                    'redirect': '/first-login-setup'
                })
            
            # リダイレクト先を決定
            redirect_url = session.pop('next_url', None) or '/dashboard'
            
            return jsonify({
                'success': True, 
                'message': message,
                'redirect': redirect_url
            })
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/passkeys', methods=['GET'])
@login_required
def list_passkeys():
    """ユーザーのPasskey一覧を取得"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    passkeys = [passkey.to_dict() for passkey in user.passkeys]
    return jsonify({'passkeys': passkeys})

@api_bp.route('/passkeys/<int:passkey_id>', methods=['DELETE'])
@login_required
def remove_passkey(passkey_id):
    """Passkeyを削除"""
    user_id = session.get('user_id')
    success, message = delete_passkey(passkey_id, user_id)
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

@api_bp.route('/user/profile', methods=['GET'])
@login_required
def get_user_profile():
    """ユーザープロフィールを取得"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    return jsonify({'user': user.to_dict()})

@api_bp.route('/time-debug', methods=['GET'])
@login_required
def get_time_debug():
    """時刻デバッグ情報を取得"""
    from .time_sync import get_time_debug_info
    return jsonify(get_time_debug_info())

@api_bp.route('/ntp-sync', methods=['POST'])
@login_required
def manual_ntp_sync():
    """手動でNTP同期を実行"""
    try:
        from .time_sync import ntp_client
        success = ntp_client.sync_time()
        
        if success:
            return jsonify({'success': True, 'message': 'NTP同期が完了しました'})
        else:
            return jsonify({'success': False, 'error': 'NTP同期に失敗しました'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/totp-current', methods=['GET'])
@login_required
def get_current_totp():
    """現在のTOTPコードを取得"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user or not user.totp_secret:
        return jsonify({'error': '2FAが設定されていません'}), 400
    
    import pyotp
    from .time_sync import get_current_time
    
    current_time = get_current_time()
    totp = pyotp.TOTP(user.totp_secret)
    
    # 現在のコード
    current_code = totp.at(current_time)
    
    # 残り時間計算
    time_step = 30
    current_step = int(current_time // time_step)
    next_step_time = (current_step + 1) * time_step
    remaining = int(next_step_time - current_time)
    
    return jsonify({
        'code': current_code,
        'remaining': remaining,
        'next_code': totp.at(current_time + 30)
    })

@api_bp.route('/user/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """2FAを無効化"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    data = request.get_json()
    password = data.get('password')
    
    if not user.check_password(password):
        return jsonify({'success': False, 'error': 'パスワードが間違っています'}), 400
    
    user.is_totp_enabled = False
    user.totp_secret = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': '2FAが無効化されました'})