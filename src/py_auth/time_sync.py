import socket
import struct
import time
import threading
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class NTPClient:
    """NTP時刻同期クライアント"""
    
    def __init__(self, ntp_servers=None):
        self.ntp_servers = ntp_servers or [
            'ntp.nict.jp',      # 日本標準時グループ
            'time.nist.gov',    # NIST
            'pool.ntp.org',     # NTP Pool
        ]
        self.time_offset = 0.0
        self.last_sync = None
        self.sync_interval = 3600  # 1時間ごとに同期
        self._sync_thread = None
        self._running = False
    
    def get_ntp_time(self, server, timeout=5):
        """指定されたNTPサーバーから時刻を取得"""
        try:
            # NTPパケット構築
            ntp_packet = b'\x1b' + 47 * b'\0'
            
            # UDPソケット作成
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                
                # NTPサーバーへ送信
                sock.sendto(ntp_packet, (server, 123))
                
                # 送信時刻記録
                sent_time = time.time()
                
                # レスポンス受信
                response, _ = sock.recvfrom(1024)
                
                # 受信時刻記録
                received_time = time.time()
                
                # NTPタイムスタンプ解析
                # オフセット: 40バイト目から8バイト（Transmit Timestamp）
                timestamp_bytes = response[40:48]
                timestamp = struct.unpack('!II', timestamp_bytes)
                
                # NTP時刻を Unix時刻に変換
                # NTP epoch: 1900年1月1日、Unix epoch: 1970年1月1日
                ntp_time = timestamp[0] + timestamp[1] / (2**32)
                unix_time = ntp_time - 2208988800  # NTP to Unix conversion
                
                # ネットワーク遅延補正
                network_delay = (received_time - sent_time) / 2
                corrected_time = unix_time + network_delay
                
                return corrected_time
                
        except Exception as e:
            logger.warning(f"NTPサーバー {server} からの時刻取得に失敗: {e}")
            return None
    
    def sync_time(self):
        """複数のNTPサーバーから時刻を取得して同期"""
        times = []
        
        for server in self.ntp_servers:
            ntp_time = self.get_ntp_time(server)
            if ntp_time:
                times.append(ntp_time)
                logger.info(f"NTPサーバー {server} から時刻取得成功")
            
            # 1つでも成功したら使用
            if times:
                break
        
        if not times:
            logger.error("すべてのNTPサーバーからの時刻取得に失敗")
            return False
        
        # 平均時刻を計算（複数取得した場合）
        avg_time = sum(times) / len(times)
        local_time = time.time()
        
        # オフセット計算
        self.time_offset = avg_time - local_time
        self.last_sync = datetime.now(timezone.utc)
        
        logger.info(f"時刻同期完了: オフセット {self.time_offset:.3f}秒")
        return True
    
    def get_synchronized_time(self):
        """同期された時刻を取得"""
        if self.last_sync is None:
            # 初回同期
            if not self.sync_time():
                logger.warning("NTP同期に失敗、ローカル時刻を使用")
                return time.time()
        
        # 同期から1時間以上経過していたら再同期
        if self.last_sync and (datetime.now(timezone.utc) - self.last_sync).seconds > self.sync_interval:
            self.sync_time()
        
        return time.time() + self.time_offset
    
    def start_background_sync(self):
        """バックグラウンドで定期的に時刻同期"""
        if self._running:
            return
        
        self._running = True
        
        def sync_worker():
            while self._running:
                try:
                    self.sync_time()
                    time.sleep(self.sync_interval)
                except Exception as e:
                    logger.error(f"バックグラウンド時刻同期エラー: {e}")
                    time.sleep(60)  # エラー時は1分後にリトライ
        
        self._sync_thread = threading.Thread(target=sync_worker, daemon=True)
        self._sync_thread.start()
        logger.info("バックグラウンド時刻同期を開始")
    
    def stop_background_sync(self):
        """バックグラウンド時刻同期を停止"""
        self._running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5)
        logger.info("バックグラウンド時刻同期を停止")
    
    def get_time_info(self):
        """時刻情報を取得（デバッグ用）"""
        local_time = time.time()
        sync_time = self.get_synchronized_time()
        
        return {
            'local_time': datetime.fromtimestamp(local_time).isoformat(),
            'sync_time': datetime.fromtimestamp(sync_time).isoformat(),
            'offset': self.time_offset,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'difference': sync_time - local_time
        }

# グローバルNTPクライアントインスタンス
ntp_client = NTPClient()

def get_current_time():
    """現在の同期された時刻を取得"""
    return ntp_client.get_synchronized_time()

def start_ntp_sync():
    """NTP同期を開始"""
    ntp_client.start_background_sync()

def stop_ntp_sync():
    """NTP同期を停止"""
    ntp_client.stop_background_sync()

def get_time_debug_info():
    """時刻デバッグ情報を取得"""
    return ntp_client.get_time_info()