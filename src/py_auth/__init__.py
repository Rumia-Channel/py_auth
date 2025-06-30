from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import os
import mimetypes
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    
    # プロキシ対応（Nginx経由の場合）
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(
        app.wsgi_app, 
        x_for=1,      # X-Forwarded-For
        x_proto=1,    # X-Forwarded-Proto 
        x_host=1,     # X-Forwarded-Host
        x_prefix=1    # X-Forwarded-Prefix
    )
    
    # MIMEタイプを明示的に設定
    @app.after_request
    def set_mime_types(response):
        if response.headers.get('Content-Type') == 'text/plain; charset=utf-8':
            # URLから拡張子を判定してMIMEタイプを設定
            if request.path.endswith('.js'):
                response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
            elif request.path.endswith('.css'):
                response.headers['Content-Type'] = 'text/css; charset=utf-8'
            elif request.path.endswith('.svg'):
                response.headers['Content-Type'] = 'image/svg+xml; charset=utf-8'
        return response
    
    # データベース設定
    db_dir = os.getenv('DATABASE_DIR', './data')
    db_name = os.getenv('DATABASE_NAME', 'auth.db')
    
    # 相対パスを絶対パスに変換
    if not os.path.isabs(db_dir):
        db_dir = os.path.abspath(db_dir)
    
    # データベースディレクトリを作成
    os.makedirs(db_dir, exist_ok=True)
    
    # データベースURLを構築
    db_path = os.path.join(db_dir, db_name)
    # Windowsパスの場合、スラッシュに変換
    db_path = db_path.replace('\\', '/')
    database_uri = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    
    # SECRET_KEY設定（セキュリティ重要）
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        if app.debug:
            # 開発環境：警告付きでデフォルトキー使用
            secret_key = 'dev-secret-key-change-in-production'
            print("警告: SECRET_KEYが設定されていません。開発用のデフォルトキーを使用します。")
            print("本番環境では必ず.envファイルでSECRET_KEYを設定してください。")
        else:
            # 本番環境：ランダムキー生成（再起動で変わる）
            import secrets
            secret_key = secrets.token_hex(32)
            print("警告: SECRET_KEYが設定されていません。ランダムキーを生成しました。")
            print("アプリ再起動時に全セッションが無効化されます。")
            print("本番環境では必ず固定のSECRET_KEYを設定してください。")
    
    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = True
    
    # WebAuthn設定
    rp_id = os.getenv('RP_ID', 'localhost')
    rp_name = os.getenv('RP_NAME', 'PyAuth Service')
    
    # 本番環境でのRP_ID警告
    if not app.debug and rp_id == 'localhost':
        print("警告: RP_IDがlocalhostのままです。本番環境では実際のドメインを設定してください。")
        print("例: RP_ID=your-machine-name.your-tailnet.ts.net")
    
    app.config['RP_ID'] = rp_id
    app.config['RP_NAME'] = rp_name
    
    # ORIGIN設定（.envから取得、なければ環境に応じたデフォルト）
    origin = os.getenv('ORIGIN')
    if not origin:
        # .envで設定されていない場合のデフォルト値
        if app.debug:
            origin = 'http://localhost:5008'
        else:
            # 本番環境では警告表示
            origin = 'https://localhost'
            print("警告: ORIGINが設定されていません。.envファイルでORIGINを設定してください。")
            print("例: ORIGIN=https://your-machine-name.your-tailnet.ts.net")
    
    app.config['ORIGIN'] = origin
    
    # 初期ユーザー設定
    app.config['INITIAL_USERNAME'] = os.getenv('INITIAL_USERNAME', 'admin')
    app.config['INITIAL_PASSWORD'] = os.getenv('INITIAL_PASSWORD', 'admin123')
    
    # 拡張機能の初期化
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # テンプレートグローバル変数を登録
    @app.context_processor
    def inject_globals():
        return {
            'current_app': app
        }
    
    # ブループリントの登録
    from .auth import auth_bp
    from .admin import admin_bp
    from .api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # NTP時刻同期を開始
    from .time_sync import start_ntp_sync
    start_ntp_sync()
    
    # データベースの作成
    with app.app_context():
        db.create_all()
        from .models import init_admin_user
        init_admin_user()
    
    return app
