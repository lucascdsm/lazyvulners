from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from . import db
from .models import User
from .forms import UserCreateForm, UserEditForm, PasswordChangeForm, UserProfileForm

users_bp = Blueprint('users', __name__)


def require_roles(*roles):
    def decorator(func):
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            if getattr(current_user, 'role', None) not in roles:
                flash('Acesso negado.', 'warning')
                return redirect(url_for('main.dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


@users_bp.route('/')
@login_required
@require_roles('admin')
def index():
    q = request.args.get('q', '').strip()
    query = User.query
    
    # Filtrar usuários por empresa se não for admin global
    if getattr(current_user, 'role', '') == 'admin':
        # Admin pode ver todos os usuários
        pass
    else:
        # Usuários normais só veem usuários da mesma empresa
        user_company = getattr(current_user, 'company', None)
        if user_company:
            query = query.filter(User.company == user_company)
        else:
            query = query.filter(False)  # Não mostra nenhum usuário se não tem empresa
    
    if q:
        like = f"%{q}%"
        query = query.filter(User.username.ilike(like))
    users = query.order_by(User.username.asc()).all()
    return render_template('users/index.html', users=users, q=q)


@users_bp.route('/new', methods=['GET','POST'])
@login_required
@require_roles('admin')
def create():
    form = UserCreateForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Usuário já existe.', 'warning')
            return render_template('users/form.html', form=form, mode='create')
        
        # Verificar se está tentando criar admin (não permitido)
        if form.role.data == 'admin':
            flash('Não é possível criar usuários administradores. Apenas 1 admin é permitido no sistema.', 'error')
            return render_template('users/form.html', form=form, mode='create')
        
        # Verificar se está criando usuário para empresa diferente (não permitido para não-admins)
        if getattr(current_user, 'role', '') != 'admin':
            user_company = getattr(current_user, 'company', None)
            if not user_company or form.company.data != user_company:
                flash('Acesso negado. Você só pode criar usuários para sua empresa.', 'warning')
                return render_template('users/form.html', form=form, mode='create')
        
        u = User(username=form.username.data, role=form.role.data, company=form.company.data or None)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        flash('Usuário criado.', 'success')
        return redirect(url_for('users.index'))
    return render_template('users/form.html', form=form, mode='create')


@users_bp.route('/<int:user_id>/edit', methods=['GET','POST'])
@login_required
@require_roles('admin')
def edit(user_id):
    u = User.query.get_or_404(user_id)
    
    # Verificar se o usuário pode editar este usuário (mesma empresa)
    if getattr(current_user, 'role', '') != 'admin':
        user_company = getattr(current_user, 'company', None)
        if not user_company or u.company != user_company:
            flash('Acesso negado. Você só pode editar usuários da sua empresa.', 'warning')
            return redirect(url_for('users.index'))
    
    form = UserEditForm(obj=u)
    if form.validate_on_submit():
        if User.query.filter(User.username==form.username.data, User.id!=u.id).first():
            flash('Nome de usuário já em uso.', 'warning')
            return render_template('users/form.html', form=form, mode='edit', user=u)
        u.username = form.username.data
        u.role = form.role.data
        u.company = form.company.data or None
        db.session.commit()
        flash('Usuário atualizado.', 'success')
        return redirect(url_for('users.index'))
    return render_template('users/form.html', form=form, mode='edit', user=u)


@users_bp.route('/<int:user_id>/password', methods=['GET','POST'])
@login_required
def change_password(user_id):
    # Admin pode trocar a senha de qualquer usuário; usuário pode trocar a própria
    if not (current_user.role == 'admin' or current_user.id == user_id):
        flash('Acesso negado.', 'warning')
        return redirect(url_for('main.dashboard'))
    u = User.query.get_or_404(user_id)
    form = PasswordChangeForm()
    if form.validate_on_submit():
        u.set_password(form.password.data)
        db.session.commit()
        flash('Senha alterada com sucesso.', 'success')
        return redirect(url_for('users.index') if current_user.role=='admin' else url_for('main.dashboard'))
    return render_template('users/password.html', form=form, user=u)


@users_bp.route('/<int:user_id>/delete', methods=['POST'])
@login_required
@require_roles('admin')
def delete(user_id):
    if current_user.id == user_id:
        flash('Você não pode remover seu próprio usuário.', 'warning')
        return redirect(url_for('users.index'))
    
    u = User.query.get_or_404(user_id)
    
    # Verificar se o usuário pode deletar este usuário (mesma empresa)
    if getattr(current_user, 'role', '') != 'admin':
        user_company = getattr(current_user, 'company', None)
        if not user_company or u.company != user_company:
            flash('Acesso negado. Você só pode remover usuários da sua empresa.', 'warning')
            return redirect(url_for('users.index'))
    
    db.session.delete(u)
    db.session.commit()
    flash('Usuário removido.', 'info')
    return redirect(url_for('users.index'))


@users_bp.route('/profile')
@login_required
def profile():
    """Página de perfil do usuário"""
    return render_template('users/profile.html', user=current_user)


@users_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_user_password():
    """Alterar senha do próprio usuário"""
    form = UserProfileForm()
    
    if form.validate_on_submit():
        # Verificar senha atual
        if not current_user.check_password(form.current_password.data):
            flash('Senha atual incorreta.', 'error')
            return render_template('users/change_password.html', form=form)
        
        # Alterar senha
        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('users.profile'))
    
    return render_template('users/change_password.html', form=form)



