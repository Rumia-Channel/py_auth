// Base64URL encoding/decoding utilities for WebAuthn

function base64urlToArrayBuffer(base64url) {
    // パディングを追加
    const padding = 4 - (base64url.length % 4);
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padding % 4);
    
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    return bytes.buffer;
}

function arrayBufferToBase64url(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binaryString = '';
    
    for (let i = 0; i < bytes.length; i++) {
        binaryString += String.fromCharCode(bytes[i]);
    }
    
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// WebAuthn サポート確認
function isWebAuthnSupported() {
    return typeof PublicKeyCredential !== 'undefined' && typeof navigator.credentials !== 'undefined';
}

// WebAuthn が利用可能かチェック
document.addEventListener('DOMContentLoaded', function() {
    if (!isWebAuthnSupported()) {
        console.warn('WebAuthn is not supported in this browser');
        
        // Passkeyボタンを無効化
        const passkeyButtons = document.querySelectorAll('[onclick*="passkey"]');
        passkeyButtons.forEach(button => {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-exclamation-triangle"></i> ブラウザ未対応';
            button.title = 'このブラウザはWebAuthn/Passkeyに対応していません';
        });
    }
});

// CSRF トークン取得
function getCSRFToken() {
    const token = document.querySelector('meta[name=csrf-token]');
    return token ? token.getAttribute('content') : '';
}

// エラーハンドリング
function handleWebAuthnError(error) {
    console.error('WebAuthn Error:', error);
    
    if (error.name === 'NotAllowedError') {
        return 'Passkey登録がキャンセルされたか、タイムアウトしました。再度お試しください。';
    } else if (error.name === 'InvalidStateError') {
        return 'この認証器は既に登録されています';
    } else if (error.name === 'NotSupportedError') {
        return 'このブラウザまたはデバイスではPasskeyがサポートされていません';
    } else if (error.name === 'SecurityError') {
        return 'セキュリティエラーが発生しました。HTTPSでアクセスしてください。';
    } else if (error.name === 'AbortError') {
        return '操作がタイムアウトしました';
    } else {
        return 'WebAuthn エラー: ' + error.message;
    }
}

// レスポンスデータの正規化と詳細デバッグ
function processRegistrationResponse(responseData) {
    console.log('Registration response:', responseData);
    
    // public_keyプロパティからオプションを取得
    // サーバーは {publicKey: {...}} 形式で返すので publicKey を取り出す
    const options = responseData.publicKey || responseData;
    console.log('Actual options:', options);
    
    // userオブジェクトの詳細確認
    if (options.user) {
        console.log('User object:', options.user);
        console.log('User keys:', Object.keys(options.user));
    }
    
    // WebAuthn設定の詳細確認
    console.log('RP object:', options.rp);
    console.log('Current origin:', window.location.origin);
    console.log('Is HTTPS:', window.location.protocol === 'https:');
    console.log('Is localhost:', window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
    
    // WebAuthnサポートの詳細チェック
    console.log('PublicKeyCredential available:', typeof PublicKeyCredential !== 'undefined');
    console.log('navigator.credentials available:', typeof navigator.credentials !== 'undefined');
    console.log('navigator.credentials.create available:', typeof navigator.credentials.create !== 'undefined');
    
    if (typeof PublicKeyCredential !== 'undefined') {
        console.log('PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable:', 
                   typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'undefined');
        
        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'undefined') {
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then(available => console.log('Platform authenticator available:', available))
                .catch(err => console.log('Platform authenticator check failed:', err));
        }
    }
    
    // Base64デコード
    if (options.challenge) {
        options.challenge = base64urlToArrayBuffer(options.challenge);
    }
    if (options.user && options.user.id) {
        options.user.id = base64urlToArrayBuffer(options.user.id);
    }
    if (options.excludeCredentials) {
        options.excludeCredentials.forEach(cred => {
            if (cred.id) {
                cred.id = base64urlToArrayBuffer(cred.id);
            }
        });
    }
    
    // タイムアウトを設定（ミリ秒）
    options.timeout = 60000; // 60秒
    
    // WebAuthn仕様に適合しない値を削除またはデフォルト値を設定
    if (options.hints === null || options.hints === undefined) {
        delete options.hints; // nullの場合は削除
    }
    if (options.attestationFormats === null || options.attestationFormats === undefined) {
        delete options.attestationFormats;
    }
    if (options.attestation === null || options.attestation === undefined) {
        options.attestation = 'none'; // デフォルト値を設定
    }
    if (options.extensions === null || options.extensions === undefined) {
        delete options.extensions;
    }
    
    return options;
}

// 認証レスポンスデータの正規化
function processAuthenticationResponse(responseData) {
    console.log('Authentication response:', responseData);
    
    // publicKeyプロパティからオプションを取得
    const options = responseData.publicKey || responseData;
    console.log('Auth options:', options);
    
    // Base64デコード
    if (options.challenge) {
        options.challenge = base64urlToArrayBuffer(options.challenge);
    }
    if (options.allowCredentials) {
        options.allowCredentials.forEach(cred => {
            if (cred.id) {
                cred.id = base64urlToArrayBuffer(cred.id);
            }
        });
    }
    
    return options;
}

// Passkey登録関数
async function performPasskeyRegistration(csrfToken) {
    try {
        // 登録開始
        const response = await fetch('/api/webauthn/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });
        
        if (!response.ok) {
            throw new Error('登録開始に失敗しました');
        }
        
        const responseData = await response.json();
        const options = processRegistrationResponse(responseData);
        
        // WebAuthn登録
        console.log('navigator.credentials.create呼び出し直前, options:', options);
        const credential = await navigator.credentials.create({ publicKey: options });
        console.log('navigator.credentials.create成功, credential:', credential);
        
        // レスポンス準備（WebAuthn JSON形式）
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64url(credential.rawId),
            response: {
                attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON)
            },
            type: credential.type
        };
        
        // transportsが利用可能な場合は追加（パスワードマネージャー対応）
        if (credential.response.getTransports) {
            credentialResponse.transports = credential.response.getTransports();
        }
        
        // authenticatorAttachmentが利用可能な場合は追加
        if (credential.authenticatorAttachment) {
            credentialResponse.authenticatorAttachment = credential.authenticatorAttachment;
        }
        
        // 登録完了
        console.log('送信するcredentialResponse:', credentialResponse);
        const completeResponse = await fetch('/api/webauthn/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(credentialResponse)
        });
        
        console.log('completeResponse status:', completeResponse.status);
        const result = await completeResponse.json();
        console.log('completeResponse result:', result);
        
        return result;
        
    } catch (error) {
        console.error('Passkey登録エラー:', error);
        throw error;
    }
}

// Passkey認証関数
async function performPasskeyAuthentication(csrfToken) {
    try {
        // 認証開始
        const response = await fetch('/api/webauthn/authenticate/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });
        
        if (!response.ok) {
            throw new Error('認証開始に失敗しました');
        }
        
        const responseData = await response.json();
        const options = processAuthenticationResponse(responseData);
        
        // WebAuthn認証
        const credential = await navigator.credentials.get({ publicKey: options });
        
        // レスポンス準備
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64url(credential.rawId),
            response: {
                authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                signature: arrayBufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle ? arrayBufferToBase64url(credential.response.userHandle) : null
            },
            type: credential.type
        };
        
        // 認証完了
        const completeResponse = await fetch('/api/webauthn/authenticate/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(credentialResponse)
        });
        
        const result = await completeResponse.json();
        return result;
        
    } catch (error) {
        console.error('Passkey認証エラー:', error);
        throw error;
    }
}