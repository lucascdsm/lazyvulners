from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from pathlib import Path
import os

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

def create_app():
    # Point Flask to the root-level 'templates' (and optionally 'static') directories
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder='../templates',
        static_folder='../static'
    )
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    
    db_path = Path(app.instance_path) / 'app.sqlite'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    

    from .auth import auth_bp
    from .views import main_bp
    from .users import users_bp
    from .backup import backup_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(users_bp, url_prefix='/users')
    app.register_blueprint(backup_bp)

    with app.app_context():
        from .models import User, Vulnerability, Company, AIConfig
        db.create_all()
        # Migração leve para SQLite: adiciona colunas se não existirem
        try:
            from sqlalchemy import inspect, text
            engine = db.get_engine()
            insp = inspect(engine)
            cols = {c['name'] for c in insp.get_columns('vulnerability')}
            with engine.begin() as conn:
                if 'company' not in cols:
                    conn.execute(text('ALTER TABLE vulnerability ADD COLUMN company VARCHAR(100)'))
                # Campo pentest_type removido - não é mais necessário
            cols_u = {c['name'] for c in insp.get_columns('user')}
            with engine.begin() as conn:
                if 'company' not in cols_u:
                    conn.execute(text('ALTER TABLE user ADD COLUMN company VARCHAR(100)'))
            # ensure usercompany table exists
            if 'user_company' not in insp.get_table_names():
                UserCompany.__table__.create(bind=engine)
        except Exception:
            pass
        # Criar usuário padrão apenas se não existir
        try:
            # Verificar se já existe um usuário admin
            existing_admin = User.query.filter_by(role='admin').first()
            if not existing_admin:
                default_user = User(
                    username='LazyVuln',
                    role='admin',
                    company='Empresa A'
                )
                default_user.set_password('lazyvuln_for_pentesters2k25')
                db.session.add(default_user)
                db.session.commit()
                
                print("Usuario admin criado: LazyVuln")
            else:
                print("Usuario admin ja existe, mantendo dados existentes")
        except Exception as e:
            print(f"Erro ao verificar/criar usuario padrao: {e}")
            pass

    return app