from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db, login_manager

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    company = db.Column(db.String(100), nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def can_create_admin():
        """Verificar se pode criar um novo admin (apenas 1 admin permitido)"""
        return User.query.filter_by(role='admin').count() == 0

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Open')
    cvss = db.Column(db.Float, nullable=True)
    company = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    impact = db.Column(db.Text, nullable=True)
    likelihood = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    references = db.Column(db.Text, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    
    # Campos específicos para freelancers
    client_name = db.Column(db.String(200), nullable=True)
    project_name = db.Column(db.String(200), nullable=True)
    test_type = db.Column(db.String(50), nullable=True)  # Web, Network, Mobile, etc.
    test_date = db.Column(db.Date, nullable=True)
    tester_name = db.Column(db.String(100), nullable=True)
    client_contact = db.Column(db.String(200), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VulnerabilityAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    vulnerability = db.relationship('Vulnerability', backref=db.backref('access_list', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User')




class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    vulnerability = db.relationship('Vulnerability', backref=db.backref('comment_items', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User')


class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    comment = db.relationship('Comment', backref=db.backref('likes', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User')


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    contact_email = db.Column(db.String(120), nullable=True)
    contact_phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Company {self.name}>'


class ReportConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Escopo por empresa (isolar configurações)
    company = db.Column(db.String(100), nullable=False, index=True)
    # Nome do template (ex.: classic, executive, technical)
    template_name = db.Column(db.String(50), nullable=False, default='classic')
    # URLs de mídia (armazenamos caminho/URL; upload em /upload/image)
    cover_background_url = db.Column(db.String(500), nullable=True)
    page_background_url = db.Column(db.String(500), nullable=True)
    header_logo_url = db.Column(db.String(500), nullable=True)
    primary_color = db.Column(db.String(10), nullable=True, default='#01317d')
    secondary_color = db.Column(db.String(10), nullable=True, default='#3b82f6')
    include_executive = db.Column(db.Boolean, default=True)
    include_technical = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ReportConfig {self.company}:{self.template_name}>'


class AIConfig(db.Model):
    """Configurações do AI Vulnerability Assistant"""
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False, index=True)
    gemini_api_key = db.Column(db.String(500), nullable=True)
    ai_enabled = db.Column(db.Boolean, default=False)
    auto_suggest_severity = db.Column(db.Boolean, default=True)
    auto_suggest_cvss = db.Column(db.Boolean, default=True)
    auto_suggest_remediation = db.Column(db.Boolean, default=True)
    auto_detect_similar = db.Column(db.Boolean, default=True)
    auto_generate_summary = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AIConfig {self.company}:{"enabled" if self.ai_enabled else "disabled"}>'

