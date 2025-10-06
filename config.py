"""
Configurações do LazyVulners
"""

import os
from pathlib import Path

class Config:
    """Configuração base"""
    
    # Configurações básicas
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Banco de dados
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configurações de segurança
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hora
    
    # Configurações de sessão
    SESSION_COOKIE_SECURE = False  # True para HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hora
    
    # Configurações de upload
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # Configurações de PDF
    PDF_FONT_SIZE = 12
    PDF_PAGE_SIZE = 'A4'
    
    # Configurações de backup
    BACKUP_FOLDER = 'backups'
    
    # Configurações de logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'lazyvulners.log'

class DevelopmentConfig(Config):
    """Configuração para desenvolvimento"""
    
    DEBUG = True
    TESTING = False
    
    # Configurações de segurança mais relaxadas para desenvolvimento
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    
    # Logging mais detalhado
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Configuração para produção"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Configuração para testes"""
    
    DEBUG = True
    TESTING = True
    
    # Banco de dados em memória para testes
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Desabilitar CSRF para testes
    WTF_CSRF_ENABLED = False
    
    # Configurações de sessão para testes
    SESSION_COOKIE_SECURE = False

# Mapeamento de configurações
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
