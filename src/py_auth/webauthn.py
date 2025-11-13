from flask import current_app, session, request
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement, ResidentKeyRequirement, RegistrationResponse
from fido2 import cbor
from .models import User, Passkey, db
import secrets
import base64

def get_webauthn_server():
    """WebAuthnサーバーインスタンスを取得"""
    # リクエストのHostヘッダーからRP_IDを動的に決定
    host = request.headers.get('Host', current_app.config['RP_ID'])
    rp_id = host.split(':')[0]  # ポート番号を除去
    
    # デバッグログ（セキュリティ上後で削除）
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"WebAuthn設定 - Host: {host}, RP_ID: {rp_id}, Config RP_ID: {current_app.config['RP_ID']}")
    
    rp = PublicKeyCredentialRpEntity(
        id=rp_id,
        name=current_app.config['RP_NAME'],
    )
    return Fido2Server(rp)

def start_registration(user_id):
    """Passkey登録を開始"""
    user = User.query.get(user_id)
    if not user:
        return None
    
    server = get_webauthn_server()
    
    user_handle = str(user.id).encode('utf-8')
    
    # 既存のcredentialを取得
    existing_credentials = []
    for passkey in user.passkeys:
        existing_credentials.append({
            'type': 'public-key',
            'id': passkey.credential_id
        })
    
    registration_data, state = server.register_begin(
        user={
            'id': user_handle,
            'name': user.username,
            'displayName': user.username,
        },
        credentials=existing_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
        resident_key_requirement=ResidentKeyRequirement.PREFERRED,
    )
    
    # セッションにstateを保存
    session['webauthn_state'] = state
    session['registering_user_id'] = user_id
    
    return registration_data

def complete_registration(credential_data):
    """Passkey登録を完了"""
    if 'webauthn_state' not in session or 'registering_user_id' not in session:
        return False, 'セッションが無効です'
    
    user_id = session['registering_user_id']
    state = session['webauthn_state']
    
    user = User.query.get(user_id)
    if not user:
        return False, 'ユーザーが見つかりません'
    
    server = get_webauthn_server()
    
    try:
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"webauthn.py - 受信データ構造: {list(credential_data.keys())}")
        
        # WebAuthn JSON形式からfido2が期待する形式に変換
        # transports, authenticatorAttachmentなどの追加フィールドを除去
        cleaned_data = {
            'id': credential_data.get('id'),
            'rawId': credential_data.get('rawId'),
            'response': credential_data.get('response'),
            'type': credential_data.get('type', 'public-key')
        }
        
        logger.info(f"クリーニング後のデータ: {list(cleaned_data.keys())}")
        
        # RegistrationResponseオブジェクトに変換
        registration_response = RegistrationResponse.from_dict(cleaned_data)
        
        logger.info("RegistrationResponse変換成功")
        logger.info("server.register_complete呼び出し直前")
        
        # register_completeを呼び出し
        auth_data = server.register_complete(state, registration_response)
        
        logger.info("server.register_complete呼び出し成功")
        
        # Passkeyをデータベースに保存
        passkey = Passkey(
            user_id=user_id,
            credential_id=auth_data.credential_data.credential_id,
            public_key=cbor.encode(auth_data.credential_data.public_key),
            name=f'Passkey {len(user.passkeys) + 1}'
        )
        
        db.session.add(passkey)
        db.session.commit()
        
        # セッションクリーンアップ
        session.pop('webauthn_state', None)
        session.pop('registering_user_id', None)
        
        return True, 'Passkeyが登録されました'
        
    except Exception as e:
        logger.error(f"登録エラー詳細: {e}", exc_info=True)
        return False, f'登録に失敗しました: {str(e)}'

def start_authentication():
    """Passkey認証を開始"""
    server = get_webauthn_server()
    
    # すべてのcredentialを取得
    credentials = []
    for passkey in Passkey.query.all():
        credentials.append({
            'type': 'public-key',
            'id': passkey.credential_id
        })
    
    auth_data, state = server.authenticate_begin(
        credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    # セッションにstateを保存
    session['webauthn_auth_state'] = state
    
    return auth_data

def complete_authentication(credential_data):
    """Passkey認証を完了"""
    if 'webauthn_auth_state' not in session:
        return False, None, 'セッションが無効です'
    
    state = session['webauthn_auth_state']
    server = get_webauthn_server()
    
    try:
        # credential IDを取得
        credential_id = credential_data['id']
        if isinstance(credential_id, str):
            credential_id = base64.urlsafe_b64decode(credential_id + '==')
        
        # Passkeyを検索
        passkey = Passkey.query.filter_by(credential_id=credential_id).first()
        if not passkey:
            return False, None, 'Passkeyが見つかりません'
        
        # 公開鍵をデコード
        public_key = cbor.decode(passkey.public_key)
        
        # 認証を完了
        server.authenticate_complete(
            state,
            [public_key],
            credential_data
        )
        
        # 使用回数を更新
        passkey.sign_count += 1
        passkey.last_used = db.func.now()
        db.session.commit()
        
        # セッションクリーンアップ
        session.pop('webauthn_auth_state', None)
        
        return True, passkey.user, '認証に成功しました'
        
    except Exception as e:
        return False, None, f'認証に失敗しました: {str(e)}'

def delete_passkey(passkey_id, user_id):
    """Passkeyを削除"""
    passkey = Passkey.query.filter_by(id=passkey_id, user_id=user_id).first()
    if not passkey:
        return False, 'Passkeyが見つかりません'
    
    db.session.delete(passkey)
    db.session.commit()
    
    return True, 'Passkeyが削除されました'