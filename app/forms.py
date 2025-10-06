from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, FloatField, BooleanField
from wtforms.validators import DataRequired, Length, Optional, NumberRange, ValidationError, EqualTo
import re

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=3, max=128)])
    submit = SubmitField('Entrar')

class VulnerabilityForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired(), Length(max=200)])
    severity = SelectField('Severidade', choices=[('Informative','Informative'),('Low','Low'),('Medium','Medium'),('High','High'),('Critical','Critical')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('Open','Open'),('In Progress','In Progress'),('Closed','Closed')], validators=[DataRequired()])
    cvss = FloatField('CVSS', validators=[Optional(), NumberRange(min=0, max=10)])
    company = SelectField('Empresa', choices=[], validators=[DataRequired()])
    description = TextAreaField('Descrição', validators=[Optional()])
    impact = TextAreaField('Impacto', validators=[Optional()])
    likelihood = TextAreaField('Probabilidade', validators=[Optional()])
    remediation = TextAreaField('Remediação', validators=[Optional()])
    references = TextAreaField('Referências', validators=[Optional()])
    
    # Campos específicos para freelancers
    client_name = StringField('Nome do Cliente', validators=[Optional(), Length(max=200)])
    project_name = StringField('Nome do Projeto', validators=[Optional(), Length(max=200)])
    test_type = SelectField('Tipo de Teste', choices=[
        ('Web Application', 'Web Application'),
        ('Network', 'Network'),
        ('Mobile', 'Mobile'),
        ('API', 'API'),
        ('Infrastructure', 'Infrastructure'),
        ('Social Engineering', 'Social Engineering'),
        ('Physical', 'Physical'),
        ('Wireless', 'Wireless')
    ], validators=[Optional()])
    test_date = StringField('Data do Teste (DD/MM/AAAA)', validators=[Optional()])
    tester_name = StringField('Nome do Pentester', validators=[Optional(), Length(max=100)])
    client_contact = StringField('Contato do Cliente', validators=[Optional(), Length(max=200)])
    
    submit = SubmitField('Salvar')


def validate_strong_password(form, field):
    password = field.data or ''
    if len(password) < 12:
        raise ValidationError('Senha deve ter no mínimo 12 caracteres.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Senha deve conter ao menos 1 letra maiúscula.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Senha deve conter ao menos 1 letra minúscula.')
    if not re.search(r'\d', password):
        raise ValidationError('Senha deve conter ao menos 1 número.')
    if not re.search(r'[^\w\s]', password):
        raise ValidationError('Senha deve conter ao menos 1 caractere especial.')


class UserCreateForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    role = SelectField('Papel', choices=[('editor','Editor'),('viewer','Viewer')], validators=[DataRequired()])
    company = SelectField('Empresa', choices=[], validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired(), validate_strong_password])
    password_confirm = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password', message='Senhas não coincidem')])
    submit = SubmitField('Criar usuário')
    
    def __init__(self, *args, **kwargs):
        super(UserCreateForm, self).__init__(*args, **kwargs)
        # Apenas admins podem ver todas as empresas
        from flask_login import current_user
        if getattr(current_user, 'role', '') == 'admin':
            from .models import Company
            companies = Company.query.order_by(Company.name.asc()).all()
            self.company.choices = [('', '(selecione uma empresa)')] + [(c.name, c.name) for c in companies]
        else:
            # Usuários normais só veem sua própria empresa
            user_company = getattr(current_user, 'company', None)
            if user_company:
                self.company.choices = [(user_company, user_company)]
            else:
                self.company.choices = [('', '(nenhuma empresa)')]


class UserEditForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    role = SelectField('Papel', choices=[('editor','Editor'),('viewer','Viewer')], validators=[DataRequired()])
    company = SelectField('Empresa', choices=[], validators=[DataRequired()])
    submit = SubmitField('Salvar alterações')
    
    def __init__(self, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        # Apenas admins podem ver todas as empresas
        from flask_login import current_user
        if getattr(current_user, 'role', '') == 'admin':
            from .models import Company
            companies = Company.query.order_by(Company.name.asc()).all()
            self.company.choices = [('', '(selecione uma empresa)')] + [(c.name, c.name) for c in companies]
        else:
            # Usuários normais só veem sua própria empresa
            user_company = getattr(current_user, 'company', None)
            if user_company:
                self.company.choices = [(user_company, user_company)]
            else:
                self.company.choices = [('', '(nenhuma empresa)')]


class PasswordChangeForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired(), validate_strong_password])
    password_confirm = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password', message='Senhas não coincidem')])
    submit = SubmitField('Alterar senha')

class UserProfileForm(FlaskForm):
    """Formulário para o usuário alterar sua própria senha"""
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired(), validate_strong_password])
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('new_password', message='Senhas não coincidem')])
    submit = SubmitField('Alterar Senha')


class CommentForm(FlaskForm):
    body = TextAreaField('Comentário', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField('Comentar')


class AIConfigForm(FlaskForm):
    gemini_api_key = PasswordField('Gemini API Key', validators=[DataRequired()], 
                                  render_kw={'placeholder': 'Cole sua API Key do Google AI Studio aqui'})
    ai_enabled = BooleanField('Ativar AI Assistant', default=True)
    auto_suggest_severity = BooleanField('Sugerir Severidade Automaticamente', default=True)
    auto_suggest_cvss = BooleanField('Sugerir CVSS Automaticamente', default=True)
    auto_suggest_remediation = BooleanField('Sugerir Remediação Automaticamente', default=True)
    auto_detect_similar = BooleanField('Detectar Vulnerabilidades Similares', default=True)
    auto_generate_summary = BooleanField('Gerar Resumos Executivos Automaticamente', default=True)
    submit = SubmitField('Salvar Configurações AI')


class CompanyForm(FlaskForm):
    name = StringField('Nome da Empresa', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descrição', validators=[Optional()])
    contact_email = StringField('Email de Contato', validators=[Optional(), Length(max=120)])
    contact_phone = StringField('Telefone de Contato', validators=[Optional(), Length(max=20)])
    address = TextAreaField('Endereço', validators=[Optional()])
    submit = SubmitField('Salvar Empresa')


class ReportConfigForm(FlaskForm):
    template_name = SelectField(
        'Template',
        choices=[('classic','Clássico'),('executive','Executivo'),('technical','Técnico')],
        validators=[DataRequired()]
    )
    primary_color = StringField('Cor Primária', validators=[Optional(), Length(max=10)])
    secondary_color = StringField('Cor Secundária', validators=[Optional(), Length(max=10)])
    cover_background_url = StringField('Fundo da Capa (URL)', validators=[Optional(), Length(max=500)])
    page_background_url = StringField('Fundo das Páginas (URL)', validators=[Optional(), Length(max=500)])
    header_logo_url = StringField('Logo no Cabeçalho (URL)', validators=[Optional(), Length(max=500)])
    include_executive = BooleanField('Incluir Seção Executiva')
    include_technical = BooleanField('Incluir Seção Técnica')
    submit = SubmitField('Salvar Configurações')

