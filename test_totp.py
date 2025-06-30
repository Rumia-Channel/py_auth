#!/usr/bin/env python3
"""
TOTP動作テストスクリプト
"""

import pyotp
import time
from datetime import datetime

def test_totp():
    print("=" * 60)
    print("TOTP動作テスト")
    print("=" * 60)
    
    # 秘密鍵を生成
    secret = pyotp.random_base32()
    print(f"生成された秘密鍵: {secret}")
    
    # TOTPオブジェクトを作成
    totp = pyotp.TOTP(secret)
    
    # QRコード用URIを生成
    provisioning_uri = totp.provisioning_uri(
        name="testuser",
        issuer_name="PyAuth Test"
    )
    print(f"QRコード用URI: {provisioning_uri}")
    
    print("-" * 60)
    print("コード生成テスト:")
    
    current_time = time.time()
    print(f"現在時刻: {datetime.fromtimestamp(current_time).isoformat()}")
    
    # 現在のコード
    current_code = totp.at(current_time)
    print(f"現在のコード: {current_code}")
    
    # 前後のコード
    prev_code = totp.at(current_time - 30)
    next_code = totp.at(current_time + 30)
    print(f"前のコード(-30秒): {prev_code}")
    print(f"次のコード(+30秒): {next_code}")
    
    print("-" * 60)
    print("検証テスト:")
    
    # 現在のコードで検証
    is_valid_current = totp.verify(current_code)
    print(f"現在のコード検証: {current_code} -> {is_valid_current}")
    
    # for_timeパラメータを使用した検証
    is_valid_for_time = totp.verify(current_code, for_time=current_time)
    print(f"for_time指定検証: {current_code} -> {is_valid_for_time}")
    
    # valid_windowを使用した検証
    is_valid_window = totp.verify(current_code, for_time=current_time, valid_window=1)
    print(f"valid_window=1検証: {current_code} -> {is_valid_window}")
    
    # 前のコードでも検証
    is_valid_prev = totp.verify(prev_code, for_time=current_time, valid_window=1)
    print(f"前のコード検証: {prev_code} -> {is_valid_prev}")
    
    print("-" * 60)
    print("時刻ステップ情報:")
    
    time_step = 30
    current_step = int(current_time // time_step)
    step_start = current_step * time_step
    step_end = (current_step + 1) * time_step
    remaining = int(step_end - current_time)
    
    print(f"時刻ステップ: {current_step}")
    print(f"ステップ開始: {datetime.fromtimestamp(step_start).isoformat()}")
    print(f"ステップ終了: {datetime.fromtimestamp(step_end).isoformat()}")
    print(f"残り時間: {remaining}秒")
    
    print("=" * 60)
    print("手動テスト用情報:")
    print(f"秘密鍵をGoogle Authenticatorに登録: {secret}")
    print(f"現在のコード: {current_code}")
    print("Google Authenticatorと一致するか確認してください")
    print("=" * 60)
    
    return secret, current_code

if __name__ == "__main__":
    test_totp()