from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, jsonify, Response, session
from flask_login import login_required, current_user
from io import BytesIO
from . import db
from .models import Vulnerability, Comment, CommentLike, VulnerabilityAccess, User, Company, ReportConfig, AIConfig
from .forms import VulnerabilityForm, CommentForm, CompanyForm, ReportConfigForm, AIConfigForm
from .utils import build_vuln_pdf, build_full_report, save_uploaded_image, build_executive_report, build_technical_report
import math

main_bp = Blueprint('main', __name__)

def require_role(*roles):
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

@main_bp.route('/')
@login_required
def dashboard():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    company = request.args.get('company', selected_company).strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    if getattr(current_user, 'role', '') == 'admin':
        # Admin pode ver todas as vulnerabilidades, mas filtra pela empresa selecionada na sessão
        query = Vulnerability.query.filter(Vulnerability.company.ilike(selected_company))
    else:
        # Usuários não-admin só veem vulnerabilidades da empresa selecionada na sessão
        query = Vulnerability.query.filter(Vulnerability.company.ilike(selected_company))
    if q:
        like = f"%{q}%"
        query = query.filter(Vulnerability.title.ilike(like))
    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))
    if status:
        query = query.filter(Vulnerability.status.ilike(status))
    if company:
        query = query.filter(Vulnerability.company.ilike(company))

    # ordenação fixa por severidade (Crítica → Informativa)
    from sqlalchemy import case, func
    sev_norm = func.lower(Vulnerability.severity)
    sev_order = case(
        (sev_norm == 'critical', 1),
        (sev_norm == 'alta', 2),  # caso houvesse PT-BR
        (sev_norm == 'high', 2),
        (sev_norm == 'média', 3),
        (sev_norm == 'media', 3),
        (sev_norm == 'medium', 3),
        (sev_norm == 'baixa', 4),
        (sev_norm == 'low', 4),
        (sev_norm == 'informativa', 5),
        (sev_norm == 'informative', 5),
        (sev_norm == 'info', 5),
        else_=6
    )
    query = query.order_by(sev_order, Vulnerability.created_at.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    vulns = pagination.items
    total_open = query.filter(Vulnerability.status.ilike('Open')).count()
    total_inprogress = query.filter(Vulnerability.status.ilike('In Progress')).count()
    total_closed = query.filter(Vulnerability.status.ilike('Closed')).count()
    # contagem por severidade (inclui Informativa)
    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informative': 0}
    for v in query.all():
        sev_raw = (v.severity or '').strip().lower()
        if sev_raw in ['informativa', 'informative', 'info']:
            sev_key = 'Informative'
        elif sev_raw == 'critical':
            sev_key = 'Critical'
        elif sev_raw == 'high':
            sev_key = 'High'
        elif sev_raw == 'medium':
            sev_key = 'Medium'
        elif sev_raw == 'low':
            sev_key = 'Low'
        else:
            continue
        sev_counts[sev_key] += 1
    
    # Obter empresas do banco de dados
    companies_from_db = Company.query.order_by(Company.name.asc()).all()
    company_names = [c.name for c in companies_from_db]
    
    return render_template('dashboard.html', vulns=vulns, q=q, severity=severity, status=status, company=company, pagination=None, per_page=per_page, total_open=total_open, total_inprogress=total_inprogress, total_closed=total_closed, company_names=company_names, sev_counts=sev_counts, selected_company=selected_company)


@main_bp.route('/dashboard/')
@login_required
def dashboard_alt():
    """Rota alternativa para /dashboard/"""
    return redirect(url_for('main.dashboard'))


@main_bp.route('/company-selection')
@login_required
def company_selection():
    """Tela de seleção de empresas após login"""
    # Admin pode ver todas as empresas, usuários normais só veem sua empresa
    if getattr(current_user, 'role', '') == 'admin':
        companies = Company.query.order_by(Company.name.asc()).all()
    else:
        # Usuários não-admin só veem sua empresa
        if getattr(current_user, 'company', None):
            companies = Company.query.filter(Company.name.ilike(current_user.company)).all()
        else:
            companies = []
    
    return render_template('company_selection.html', companies=companies)


@main_bp.route('/select-company', methods=['POST'])
@login_required
def select_company():
    """Selecionar empresa e redirecionar para dashboard"""
    company_id = request.form.get('company_id', type=int)
    if company_id:
        company = Company.query.get_or_404(company_id)
        
        # Verificar permissão: admin pode selecionar qualquer empresa, usuários normais só sua empresa
        if getattr(current_user, 'role', '') != 'admin':
            if not getattr(current_user, 'company', None) or current_user.company != company.name:
                flash('Acesso negado. Você só pode acessar sua empresa.', 'warning')
                return redirect(url_for('main.company_selection'))
        
        session['selected_company'] = company.name
        flash(f'Empresa "{company.name}" selecionada com sucesso!', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/change-company')
@login_required
def change_company():
    """Trocar empresa atual"""
    # Usuários não-admin não podem trocar de empresa
    if getattr(current_user, 'role', '') != 'admin':
        flash('Acesso negado. Apenas administradores podem trocar de empresa.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    session.pop('selected_company', None)
    return redirect(url_for('main.company_selection'))


@main_bp.route('/charts/severity_donut.png')
@login_required
def severity_donut_png():
    # aplica o mesmo escopo/filtro do dashboard
    company = request.args.get('company', '').strip()
    if getattr(current_user, 'role', '') == 'admin':
        query = Vulnerability.query
    else:
        allowed = []
        if getattr(current_user, 'company', None):
            allowed.append(current_user.company)
        try:
            allowed.extend([uc.company for uc in current_user.companies])
        except Exception:
            pass
        allowed = list({c for c in allowed if c})
        query = Vulnerability.query
        if allowed:
            query = query.filter(Vulnerability.company.in_(allowed))
        else:
            query = query.filter(False)
    if company:
        query = query.filter(Vulnerability.company.ilike(company))
    # conta severidades (inclui categoria Informativa)
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informative': 0}
    for v in query.all():
        sev_raw = (v.severity or '').strip()
        sev = sev_raw.capitalize()
        # Mapeia possíveis variações para "Informative"
        if sev_raw.lower() in ['informativa', 'informative', 'info']:
            sev = 'Informative'
        if sev in counts:
            counts[sev] += 1

    # desenha PNG em alta resolução e reduz para melhor nitidez
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return Response(status=500)
    # canvas interno de alta resolução (ainda menor)
    scale = 2.0
    base_w, base_h = 240, 140
    width, height = int(base_w * scale), int(base_h * scale)
    # fundo transparente
    img = Image.new('RGBA', (width, height), (255,255,255,0))
    draw = ImageDraw.Draw(img)
    # paleta por severidade: Crítica(Vermelho), Alta(Laranja), Média(Amarela), Baixa(Verde), Informativa(Azul)
    palette = [
        (220, 53, 69, 255),    # Critical - red (#dc3545)
        (253, 126, 20, 255),   # High - orange (#fd7e14)
        (255, 193, 7, 255),    # Medium - yellow (#ffc107)
        (40, 167, 69, 255),    # Low - green (#28a745)
        (13, 110, 253, 255)    # Informative - blue (#0d6efd)
    ]
    data = [counts['Critical'], counts['High'], counts['Medium'], counts['Low'], counts['Informative']]
    total = sum(data)
    # área do donut
    margin = int(12 * scale)
    size = int(110 * scale)
    left = margin
    # centraliza verticalmente o donut
    top = max(margin, (height - size) // 2)
    bbox = (left, top, left + size, top + size)
    start = -90.0
    if total == 0:
        # círculo vazio
        draw.ellipse(bbox, outline=(200,210,230,255), width=int(2*scale))
    else:
        for idx, val in enumerate(data):
            if val <= 0: continue
            extent = (val/total)*360.0
            draw.pieslice(bbox, start, start+extent, fill=palette[idx])
            start += extent
    # furo central branco (proporcional ao novo tamanho)
    inner_pad = int(22 * scale)
    inner_bbox = (left + inner_pad, top + inner_pad, left + size - inner_pad, top + size - inner_pad)
    draw.ellipse(inner_bbox, fill=(255,255,255,255))

    # legenda
    labels = ['Crítica','Alta','Média','Baixa','Informativa']
    text_color = (255, 255, 255, 255)
    leg_x = left + size + int(12 * scale)
    box_w = int(10 * scale)
    box_h = int(10 * scale)
    gap = int(6 * scale)
    # centraliza verticalmente a legenda ao lado do donut
    total_legend_h = 5 * box_h + 4 * gap
    leg_y = top + max(0, (size - total_legend_h) // 2)
    try:
        font = ImageFont.truetype("arial.ttf", int(7 * scale))
    except Exception:
        try:
            font = ImageFont.truetype("segoeui.ttf", int(7 * scale))
        except Exception:
            font = None
    for i, lab in enumerate(labels):
        draw.rectangle((leg_x, leg_y + i*(box_h + gap), leg_x + box_w, leg_y + box_h + i*(box_h + gap)), fill=palette[i])
        text_pos = (leg_x + box_w + int(8 * scale), leg_y - int(2 * scale) + i*(box_h + gap))
        draw.text(text_pos, f"{lab}: {data[i]}", fill=text_color, font=font)

    # redimensiona para exibição menor mantendo nitidez (2x pixel density)
    target_w = 460
    target_h = 220
    try:
        img = img.resize((target_w, target_h), resample=Image.LANCZOS)
    except Exception:
        img = img.resize((target_w, target_h))

    # output sem cache
    from io import BytesIO
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    resp = send_file(buf, mimetype='image/png')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@main_bp.route('/charts/severity_donut.svg')
@login_required
def severity_donut_svg():
    # mesmo escopo do dashboard
    company = request.args.get('company', '').strip()
    if getattr(current_user, 'role', '') == 'admin':
        query = Vulnerability.query
    else:
        allowed = []
        if getattr(current_user, 'company', None):
            allowed.append(current_user.company)
        try:
            allowed.extend([uc.company for uc in current_user.companies])
        except Exception:
            pass
        allowed = list({c for c in allowed if c})
        query = Vulnerability.query
        if allowed:
            query = query.filter(Vulnerability.company.in_(allowed))
        else:
            query = query.filter(False)
    if company:
        query = query.filter(Vulnerability.company.ilike(company))

    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informative': 0}
    for v in query.all():
        sev_raw = (v.severity or '').strip()
        sev = sev_raw.capitalize()
        if sev_raw.lower() in ['informativa', 'informative', 'info']:
            sev = 'Informative'
        if sev in counts:
            counts[sev] += 1

    data = [counts['Critical'], counts['High'], counts['Medium'], counts['Low'], counts['Informative']]
    # Texto PT-BR padronizado (plural)
    labels_pt = ['Críticas','Altas','Médias','Baixas','Informativas']
    # Cores por severidade solicitadas
    palette = ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#0d6efd']
    total = sum(data) or 1

    # dimensões exatas do SVG (ainda menor)
    w, h = 240, 150
    cx, cy = 75, 75
    outer_r = 54
    inner_r = 34

    def polar_to_cart(center_x, center_y, radius, angle_deg):
        rad = math.radians(angle_deg)
        return (center_x + radius * math.cos(rad), center_y + radius * math.sin(rad))

    def donut_slice(cx, cy, r_outer, r_inner, start_angle, extent):
        # limita extent a <= 359.999 para evitar artefatos
        extent = min(extent, 359.999)
        end_angle = start_angle + extent
        x0, y0 = polar_to_cart(cx, cy, r_outer, start_angle)
        x1, y1 = polar_to_cart(cx, cy, r_outer, end_angle)
        x2, y2 = polar_to_cart(cx, cy, r_inner, end_angle)
        x3, y3 = polar_to_cart(cx, cy, r_inner, start_angle)
        large_arc = 1 if extent > 180 else 0
        path = (
            f"M {x0:.3f} {y0:.3f} "
            f"A {r_outer} {r_outer} 0 {large_arc} 1 {x1:.3f} {y1:.3f} "
            f"L {x2:.3f} {y2:.3f} "
            f"A {r_inner} {r_inner} 0 {large_arc} 0 {x3:.3f} {y3:.3f} Z"
        )
        return path

    start = -90.0
    slices = []
    for i, val in enumerate(data):
        if val <= 0: continue
        extent = (val/total) * 360.0
        d = donut_slice(cx, cy, outer_r, inner_r, start, extent)
        slices.append((d, palette[i]))
        start += extent

    # legenda
    box = 9
    gap = 5
    # centraliza verticalmente a legenda ao lado do donut
    legend_x = cx + outer_r + 16
    total_legend_h = 5 * box + 4 * gap
    legend_y = cy - total_legend_h // 2

    # constrói SVG
    parts = []
    parts.append(f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' viewBox='0 0 {w} {h}'>")
    parts.append("<rect width='100%' height='100%' fill='none'/>")
    for d, color in slices:
        parts.append(f"<path d='{d}' fill='{color}' stroke='none' />")
    # círculo central para garantirmos o furo perfeito
    parts.append(f"<circle cx='{cx}' cy='{cy}' r='{inner_r}' fill='none' />")

    # legenda sempre com todas as categorias
    for i, lab in enumerate(labels_pt):
        y = legend_y + i*(box + gap)
        parts.append(f"<rect x='{legend_x}' y='{y}' width='{box}' height='{box}' fill='{palette[i]}' />")
        parts.append(f"<text x='{legend_x + box + 8}' y='{y + box - 2}' font-family='Segoe UI, Arial, sans-serif' font-size='12' fill='#ffffff'>{lab}: {data[i]}</text>")

    parts.append("</svg>")
    svg = "".join(parts)
    resp = Response(svg, mimetype='image/svg+xml')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

@main_bp.route('/vulnerabilities/new', methods=['GET','POST'])
@login_required
@require_role('admin')
def vuln_create():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    form = VulnerabilityForm()
    # Usuários só podem criar vulnerabilidades para a empresa selecionada
    form.company.choices = [(selected_company, selected_company)]
    form.company.data = selected_company
    
    if form.validate_on_submit():
        # Processar data do teste
        test_date = None
        if form.test_date.data:
            try:
                from datetime import datetime
                test_date = datetime.strptime(form.test_date.data, '%d/%m/%Y').date()
            except ValueError:
                flash('Formato de data inválido. Use DD/MM/AAAA.', 'warning')
                return render_template('vulnerabilities/form.html', form=form, mode='create')
        
        v = Vulnerability(**{
            'title': form.title.data,
            'severity': form.severity.data,
            'status': form.status.data,
            'cvss': form.cvss.data,
            'company': form.company.data,
            'description': form.description.data,
            'impact': form.impact.data,
            'likelihood': form.likelihood.data,
            'remediation': form.remediation.data,
            'references': form.references.data,
            'client_name': form.client_name.data,
            'project_name': form.project_name.data,
            'test_type': form.test_type.data,
            'test_date': test_date,
            'tester_name': form.tester_name.data,
            'client_contact': form.client_contact.data,
        })
        db.session.add(v)
        db.session.commit()
        if getattr(current_user, 'role', '') != 'admin':
            db.session.add(VulnerabilityAccess(vulnerability_id=v.id, user_id=current_user.id))
        db.session.commit()
        flash('Vulnerabilidade criada.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('vulnerabilities/form.html', form=form, mode='create')

@main_bp.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vuln_detail(vuln_id):
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    v = Vulnerability.query.get_or_404(vuln_id)
    
    # Verificar se a vulnerabilidade pertence à empresa selecionada
    if v.company != selected_company:
        flash('Acesso negado. Esta vulnerabilidade não pertence à empresa selecionada.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    comments = Comment.query.filter_by(vulnerability_id=v.id).order_by(Comment.created_at.asc()).all()
    form = CommentForm()
    return render_template('vulnerabilities/detail.html', v=v, comments=comments, form=form)

@main_bp.route('/vulnerabilities/<int:vuln_id>/edit', methods=['GET','POST'])
@login_required
@require_role('admin','editor')
def vuln_edit(vuln_id):
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    v = Vulnerability.query.get_or_404(vuln_id)
    
    # Verificar se a vulnerabilidade pertence à empresa selecionada
    if v.company != selected_company:
        flash('Acesso negado. Esta vulnerabilidade não pertence à empresa selecionada.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    form = VulnerabilityForm(obj=v)
    # Usuários só podem editar vulnerabilidades da empresa selecionada
    form.company.choices = [(selected_company, selected_company)]
    
    if form.validate_on_submit():
        form.populate_obj(v)
        db.session.commit()
        flash('Vulnerabilidade atualizada.', 'success')
        return redirect(url_for('main.vuln_detail', vuln_id=v.id))
    return render_template('vulnerabilities/form.html', form=form, mode='edit')


@main_bp.route('/vulnerabilities/<int:vuln_id>/access')
@login_required
@require_role('admin')
def vuln_access(vuln_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    access = VulnerabilityAccess.query.filter_by(vulnerability_id=v.id).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template('vulnerabilities/access.html', v=v, access=access, users=users)


@main_bp.route('/vulnerabilities/<int:vuln_id>/access/add', methods=['POST'])
@login_required
@require_role('admin')
def vuln_access_add(vuln_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    user_id = request.form.get('user_id', type=int)
    if not user_id:
        flash('Usuário inválido.', 'warning')
        return redirect(url_for('main.vuln_access', vuln_id=v.id))
    exists = VulnerabilityAccess.query.filter_by(vulnerability_id=v.id, user_id=user_id).first()
    if exists:
        flash('Usuário já possui acesso.', 'info')
        return redirect(url_for('main.vuln_access', vuln_id=v.id))
    db.session.add(VulnerabilityAccess(vulnerability_id=v.id, user_id=user_id))
    db.session.commit()
    flash('Acesso concedido.', 'success')
    return redirect(url_for('main.vuln_access', vuln_id=v.id))


@main_bp.route('/vulnerabilities/<int:vuln_id>/access/<int:access_id>/remove', methods=['POST'])
@login_required
@require_role('admin')
def vuln_access_remove(vuln_id, access_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    a = VulnerabilityAccess.query.get_or_404(access_id)
    if a.vulnerability_id != v.id:
        flash('Acesso inválido.', 'warning')
        return redirect(url_for('main.vuln_access', vuln_id=v.id))
    db.session.delete(a)
    db.session.commit()
    flash('Acesso revogado.', 'info')
    return redirect(url_for('main.vuln_access', vuln_id=v.id))

@main_bp.route('/vulnerabilities/<int:vuln_id>/delete', methods=['POST'])
@login_required
@require_role('admin')
def vuln_delete(vuln_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    db.session.delete(v)
    db.session.commit()
    flash('Vulnerabilidade removida.', 'info')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/reports')
@login_required
def reports():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    # carregar configuração atual, se existir
    cfg = ReportConfig.query.filter_by(company=selected_company).first()
    return render_template('reports/index.html', selected_company=selected_company, report_config=cfg)


@main_bp.route('/reports/config', methods=['GET','POST'])
@login_required
@require_role('admin','editor')
def reports_config():
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))

    cfg = ReportConfig.query.filter_by(company=selected_company).first()
    form = ReportConfigForm(obj=cfg)
    if form.validate_on_submit():
        if not cfg:
            cfg = ReportConfig(company=selected_company)
            db.session.add(cfg)
        cfg.template_name = form.template_name.data
        cfg.primary_color = form.primary_color.data or '#01317d'
        cfg.secondary_color = form.secondary_color.data or '#3b82f6'
        cfg.cover_background_url = form.cover_background_url.data or None
        cfg.page_background_url = form.page_background_url.data or None
        cfg.header_logo_url = form.header_logo_url.data or None
        cfg.include_executive = bool(form.include_executive.data)
        cfg.include_technical = bool(form.include_technical.data)
        db.session.commit()
        flash('Configurações de relatório salvas.', 'success')
        return redirect(url_for('main.reports_config'))

    return render_template('reports/config.html', form=form, selected_company=selected_company, cfg=cfg)


@main_bp.route('/vulnerabilities')
@login_required
def vulnerabilities_list():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    # Filtrar apenas vulnerabilidades da empresa selecionada
    query = Vulnerability.query.filter(Vulnerability.company.ilike(selected_company))
    
    if q:
        like = f"%{q}%"
        query = query.filter(Vulnerability.title.ilike(like))
    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))
    if status:
        query = query.filter(Vulnerability.status.ilike(status))

    # Ordenação por severidade
    from sqlalchemy import case, func
    sev_norm = func.lower(Vulnerability.severity)
    sev_order = case(
        (sev_norm == 'critical', 1),
        (sev_norm == 'high', 2),
        (sev_norm == 'medium', 3),
        (sev_norm == 'low', 4),
        (sev_norm == 'informative', 5),
        else_=6
    )
    query = query.order_by(sev_order, Vulnerability.created_at.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    vulns = pagination.items
    
    return render_template('vulnerabilities/list.html', 
                         vulns=vulns, 
                         pagination=pagination,
                         q=q, 
                         severity=severity, 
                         status=status,
                         selected_company=selected_company)


@main_bp.route('/vulnerabilities/<int:vuln_id>/comments', methods=['POST'])
@login_required
def add_comment(vuln_id):
    v = Vulnerability.query.get_or_404(vuln_id)
    form = CommentForm()
    if form.validate_on_submit():
        c = Comment(vulnerability_id=v.id, user_id=current_user.id, body=form.body.data)
        db.session.add(c)
        db.session.commit()
        flash('Comentário adicionado.', 'success')
    else:
        flash('Comentário inválido.', 'warning')
    return redirect(url_for('main.vuln_detail', vuln_id=v.id))


@main_bp.route('/comments/<int:comment_id>/like', methods=['POST'])
@login_required
def like_comment(comment_id):
    c = Comment.query.get_or_404(comment_id)
    existing = CommentLike.query.filter_by(comment_id=c.id, user_id=current_user.id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        flash('Like removido.', 'info')
    else:
        like = CommentLike(comment_id=c.id, user_id=current_user.id)
        db.session.add(like)
        db.session.commit()
        flash('Curtido.', 'success')
    return redirect(url_for('main.vuln_detail', vuln_id=c.vulnerability_id))


@main_bp.route('/upload/image', methods=['POST'])
@login_required
@require_role('admin','editor')
def upload_image():
    """Upload seguro de imagens com validação"""
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    # Validar tipo de arquivo
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    if not file.filename or not file.filename.lower().endswith(tuple(f'.{ext}' for ext in allowed_extensions)):
        return jsonify({'error': 'Tipo de arquivo não permitido'}), 400
    
    # Validar tamanho (máximo 5MB)
    file.seek(0, 2)  # Ir para o final do arquivo
    file_size = file.tell()
    file.seek(0)  # Voltar para o início
    if file_size > 5 * 1024 * 1024:  # 5MB
        return jsonify({'error': 'Arquivo muito grande (máximo 5MB)'}), 400
    
    try:
        url = save_uploaded_image(file)
        return jsonify({'location': url})
    except Exception as e:
        return jsonify({'error': 'Erro ao processar arquivo'}), 500

@main_bp.route('/export/vulnerability/<int:vuln_id>.pdf')
@login_required
def export_vuln_pdf(vuln_id):
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        flash('Empresa não selecionada.', 'warning')
        return redirect(url_for('main.company_selection'))
    
    v = Vulnerability.query.get_or_404(vuln_id)
    
    # Verificar se a vulnerabilidade pertence à empresa selecionada
    if v.company != selected_company:
        flash('Acesso negado. Esta vulnerabilidade não pertence à empresa selecionada.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    pdf_bytes = build_vuln_pdf(v)
    return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=f'vulnerability_{v.id}_{selected_company}.pdf', mimetype='application/pdf')

@main_bp.route('/export/report.pdf')
@login_required
def export_report_pdf():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        flash('Empresa não selecionada.', 'warning')
        return redirect(url_for('main.company_selection'))
    
    # Filtrar apenas vulnerabilidades da empresa selecionada
    vulns = Vulnerability.query.filter_by(company=selected_company).order_by(Vulnerability.severity.desc()).all()
    pdf_bytes = build_full_report(vulns)
    return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=f'relatorio_vulnerabilidades_{selected_company}.pdf', mimetype='application/pdf')


@main_bp.route('/export/report-executivo.pdf')
@login_required
def export_report_executivo():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        flash('Empresa não selecionada.', 'warning')
        return redirect(url_for('main.company_selection'))
    
    # Filtrar apenas vulnerabilidades da empresa selecionada
    vulns = Vulnerability.query.filter_by(company=selected_company).order_by(Vulnerability.severity.desc()).all()
    period_start = request.args.get('start', '').strip()
    period_end = request.args.get('end', '').strip()
    period = (period_start, period_end) if (period_start or period_end) else None
    pdf_bytes = build_executive_report(vulns, period)
    return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=f'relatorio_executivo_{selected_company}.pdf', mimetype='application/pdf')


@main_bp.route('/export/report-tecnico.pdf')
@login_required
def export_report_tecnico():
    # Verificar se o usuário tem uma empresa selecionada na sessão
    selected_company = session.get('selected_company')
    if not selected_company:
        flash('Empresa não selecionada.', 'warning')
        return redirect(url_for('main.company_selection'))
    
    # Filtrar apenas vulnerabilidades da empresa selecionada
    vulns = Vulnerability.query.filter_by(company=selected_company).order_by(Vulnerability.severity.desc()).all()
    period_start = request.args.get('start', '').strip()
    period_end = request.args.get('end', '').strip()
    period = (period_start, period_end) if (period_start or period_end) else None
    pdf_bytes = build_technical_report(vulns, period)
    return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=f'relatorio_tecnico_{selected_company}.pdf', mimetype='application/pdf')


# Rotas para gerenciamento de empresas
@main_bp.route('/companies')
@login_required
@require_role('admin','editor')
def companies_list():
    companies = Company.query.order_by(Company.name.asc()).all()
    return render_template('companies/list.html', companies=companies)


@main_bp.route('/companies/new', methods=['GET','POST'])
@login_required
@require_role('admin','editor')
def company_create():
    form = CompanyForm()
    if form.validate_on_submit():
        company = Company(
            name=form.name.data,
            description=form.description.data,
            contact_email=form.contact_email.data,
            contact_phone=form.contact_phone.data,
            address=form.address.data
        )
        db.session.add(company)
        db.session.commit()
        flash('Empresa criada com sucesso.', 'success')
        return redirect(url_for('main.companies_list'))
    return render_template('companies/form.html', form=form, mode='create')


@main_bp.route('/companies/<int:company_id>/edit', methods=['GET','POST'])
@login_required
@require_role('admin','editor')
def company_edit(company_id):
    company = Company.query.get_or_404(company_id)
    form = CompanyForm(obj=company)
    if form.validate_on_submit():
        form.populate_obj(company)
        db.session.commit()
        flash('Empresa atualizada com sucesso.', 'success')
        return redirect(url_for('main.companies_list'))
    return render_template('companies/form.html', form=form, mode='edit', company=company)


@main_bp.route('/companies/<int:company_id>/delete', methods=['POST'])
@login_required
@require_role('admin')
def company_delete(company_id):
    company = Company.query.get_or_404(company_id)
    db.session.delete(company)
    db.session.commit()
    flash('Empresa removida com sucesso.', 'info')
    return redirect(url_for('main.companies_list'))


@main_bp.route('/companies/<int:company_id>/rename', methods=['POST'])
@login_required
@require_role('admin','editor')
def company_rename(company_id):
    company = Company.query.get_or_404(company_id)
    new_name = request.form.get('name', '').strip()
    
    if not new_name:
        flash('Nome da empresa não pode estar vazio.', 'warning')
        return redirect(url_for('main.companies_list'))
    
    # Verificar se já existe uma empresa com esse nome
    existing = Company.query.filter(Company.name == new_name, Company.id != company_id).first()
    if existing:
        flash('Já existe uma empresa com esse nome.', 'warning')
        return redirect(url_for('main.companies_list'))
    
    old_name = company.name
    company.name = new_name
    db.session.commit()
    
    # Atualizar a sessão se a empresa renomeada for a selecionada
    if session.get('selected_company') == old_name:
        session['selected_company'] = new_name
    
    flash(f'Empresa renomeada de "{old_name}" para "{new_name}" com sucesso.', 'success')
    return redirect(url_for('main.companies_list'))



@main_bp.route('/backup')
@login_required
def backup_page():
    """Página de backup e export para freelancers"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    return render_template('backup.html', selected_company=selected_company)


# ==================== AI ASSISTANT ROUTES ====================

@main_bp.route('/ai-config')
@login_required
@require_role('admin')
def ai_config():
    """Página de configuração do AI Assistant"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    # Buscar configuração existente
    ai_config = AIConfig.query.filter_by(company=selected_company).first()
    if not ai_config:
        ai_config = AIConfig(company=selected_company)
        db.session.add(ai_config)
        db.session.commit()
    
    form = AIConfigForm(obj=ai_config)
    # Não mostrar a API key atual por segurança
    form.gemini_api_key.data = ""
    
    return render_template('ai/config.html', form=form, ai_config=ai_config, selected_company=selected_company)


@main_bp.route('/ai-config', methods=['POST'])
@login_required
@require_role('admin')
def ai_config_save():
    """Salvar configurações do AI Assistant"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    form = AIConfigForm()
    if form.validate_on_submit():
        ai_config = AIConfig.query.filter_by(company=selected_company).first()
        if not ai_config:
            ai_config = AIConfig(company=selected_company)
            db.session.add(ai_config)
        
        # Atualizar configurações
        ai_config.gemini_api_key = form.gemini_api_key.data
        ai_config.ai_enabled = form.ai_enabled.data
        ai_config.auto_suggest_severity = form.auto_suggest_severity.data
        ai_config.auto_suggest_cvss = form.auto_suggest_cvss.data
        ai_config.auto_suggest_remediation = form.auto_suggest_remediation.data
        ai_config.auto_detect_similar = form.auto_detect_similar.data
        ai_config.auto_generate_summary = form.auto_generate_summary.data
        
        db.session.commit()
        flash('Configurações do AI Assistant salvas com sucesso!', 'success')
        return redirect(url_for('main.ai_config'))
    
    return render_template('ai/config.html', form=form, selected_company=selected_company)


@main_bp.route('/ai-analyze', methods=['POST'])
@login_required
def ai_analyze():
    """Analisar vulnerabilidade com AI"""
    from .ai_assistant import get_ai_assistant
    
    selected_company = session.get('selected_company')
    if not selected_company:
        return jsonify({'success': False, 'error': 'Empresa não selecionada'})
    
    data = request.get_json()
    description = data.get('description', '')
    title = data.get('title', '')
    
    if not description:
        return jsonify({'success': False, 'error': 'Descrição é obrigatória'})
    
    ai_assistant = get_ai_assistant(selected_company)
    if not ai_assistant:
        return jsonify({'success': False, 'error': 'AI Assistant não configurado'})
    
    result = ai_assistant.analyze_vulnerability(description, title)
    return jsonify(result)


@main_bp.route('/ai-similar', methods=['POST'])
@login_required
def ai_detect_similar():
    """Detectar vulnerabilidades similares"""
    from .ai_assistant import get_ai_assistant
    
    selected_company = session.get('selected_company')
    if not selected_company:
        return jsonify({'success': False, 'error': 'Empresa não selecionada'})
    
    data = request.get_json()
    description = data.get('description', '')
    
    if not description:
        return jsonify({'success': False, 'error': 'Descrição é obrigatória'})
    
    ai_assistant = get_ai_assistant(selected_company)
    if not ai_assistant:
        return jsonify({'success': False, 'error': 'AI Assistant não configurado'})
    
    similar = ai_assistant.detect_similar_vulnerabilities(description, selected_company)
    return jsonify({'success': True, 'similar': similar})


@main_bp.route('/ai-tutorial')
@login_required
@require_role('admin')
def ai_tutorial():
    """Tutorial do AI Assistant"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    return render_template('ai/tutorial.html', selected_company=selected_company)


@main_bp.route('/ai-quota-info')
@login_required
@require_role('admin')
def ai_quota_info():
    """Informações sobre limites de cota"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return redirect(url_for('main.company_selection'))
    
    return render_template('ai/quota_info.html', selected_company=selected_company)


@main_bp.route('/ai-test', methods=['POST'])
@login_required
@require_role('admin')
def ai_test_connection():
    """Testar conexão com a API do Gemini"""
    from .ai_assistant import test_ai_connection
    
    data = request.get_json()
    api_key = data.get('api_key', '')
    
    if not api_key:
        return jsonify({'success': False, 'error': 'API Key é obrigatória'})
    
    result = test_ai_connection(api_key)
    return jsonify(result)


@main_bp.route('/ai-models', methods=['GET'])
@login_required
@require_role('admin')
def ai_list_models():
    """Listar modelos disponíveis"""
    try:
        import google.generativeai as genai
        from .models import AIConfig
        
        selected_company = session.get('selected_company')
        if not selected_company:
            return jsonify({'success': False, 'error': 'Empresa não selecionada'})
        
        ai_config = AIConfig.query.filter_by(company=selected_company).first()
        if not ai_config or not ai_config.gemini_api_key:
            return jsonify({'success': False, 'error': 'API Key não configurada'})
        
        genai.configure(api_key=ai_config.gemini_api_key)
        models = genai.list_models()
        
        available_models = []
        for model in models:
            if 'generateContent' in model.supported_generation_methods:
                available_models.append({
                    'name': model.name,
                    'display_name': model.display_name,
                    'description': model.description
                })
        
        return jsonify({
            'success': True,
            'models': available_models
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Erro ao listar modelos: {str(e)}'
        })





