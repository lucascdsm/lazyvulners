from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF
import os
from flask import current_app
from pathlib import Path
from werkzeug.utils import secure_filename
import uuid
import re
from datetime import datetime
# Import será feito dentro da função para evitar importação circular

def _ensure_ptbr_font():
    """Registra uma fonte que suporte caracteres UTF-8"""
    try:
        pdfmetrics.getFont('DejaVuSans')
        return 'DejaVuSans'
    except:
        pass
    
    # Tenta fontes do sistema Windows
    font_paths = [
        'C:/Windows/Fonts/arial.ttf',
        'C:/Windows/Fonts/calibri.ttf', 
        'C:/Windows/Fonts/segoeui.ttf'
    ]
    
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('SystemFont', font_path))
                return 'SystemFont'
            except:
                continue
    
    # Fallback para fonte padrão
    return 'Helvetica'

def build_vuln_pdf(vuln):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    font_name = _ensure_ptbr_font()
    
    # Aplica a fonte a todos os estilos
    for style_name, style in styles.byName.items():
        style.fontName = font_name
    elements = []
    title = f"{vuln.title} (Severidade: {vuln.severity})"
    elements.append(Paragraph(title, styles['Title']))
    meta = [["Status", vuln.status], ["CVSS", str(vuln.cvss or '')]]
    table = Table(meta, hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(1,0),colors.lightgrey),('BOX',(0,0),(-1,-1),1,colors.black),('INNERGRID',(0,0),(-1,-1),0.5,colors.grey)]))
    elements.extend([Spacer(1, 12), table, Spacer(1,12)])
    for label, text in [("Descrição", vuln.description),("Impacto", vuln.impact),("Probabilidade", vuln.likelihood),("Remediação", vuln.remediation),("Referências", vuln.references),("Comentários", vuln.comments)]:
        if text:
            elements.append(Paragraph(label, styles['Heading3']))
            elements.extend(_flowables_from_html(text, styles))
            elements.append(Spacer(1, 8))
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

def build_full_report(vulns):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*inch, bottomMargin=1*inch)
    styles = getSampleStyleSheet()
    font_name = _ensure_ptbr_font()
    
    # Aplica a fonte a todos os estilos
    for style_name, style in styles.byName.items():
        style.fontName = font_name
    
    elements = []
    
    # Página de Capa
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph('RELATÓRIO DE VULNERABILIDADES', styles['Title']))
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph('Análise de Segurança', styles['Heading2']))
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(f'Data: {datetime.now().strftime("%d/%m/%Y")}', styles['Normal']))
    elements.append(Paragraph(f'Total de Vulnerabilidades: {len(vulns)}', styles['Normal']))
    
    # Contagem por severidade
    severity_count = {}
    for v in vulns:
        severity_count[v.severity] = severity_count.get(v.severity, 0) + 1
    
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph('Resumo por Severidade:', styles['Heading3']))
    for severity, count in severity_count.items():
        elements.append(Paragraph(f'• {severity}: {count}', styles['Normal']))
    
    elements.append(PageBreak())
    
    # Sumário
    elements.append(Paragraph('SUMÁRIO', styles['Title']))
    elements.append(Spacer(1, 0.3*inch))
    
    for i, v in enumerate(vulns, 1):
        elements.append(Paragraph(f'{i}. {v.title} - {v.severity}', styles['Normal']))
    
    elements.append(PageBreak())
    
    # Detalhes das Vulnerabilidades
    elements.append(Paragraph('DETALHES DAS VULNERABILIDADES', styles['Title']))
    elements.append(Spacer(1, 0.3*inch))
    
    for i, v in enumerate(vulns, 1):
        elements.append(Paragraph(f'{i}. {v.title}', styles['Heading2']))
        meta = [["Severidade", v.severity], ["Status", v.status], ["CVSS", str(v.cvss or 'N/A')]]
        table = Table(meta, hAlign='LEFT')
        table.setStyle(TableStyle([('BOX',(0,0),(-1,-1),1,colors.black),('INNERGRID',(0,0),(-1,-1),0.5,colors.grey)]))
        elements.extend([table, Spacer(1,8)])
        
        for label, text in [("Descrição", v.description),("Impacto", v.impact),("Probabilidade", v.likelihood),("Remediação", v.remediation),("Referências", v.references),("Comentários", v.comments)]:
            if text:
                elements.append(Paragraph(f"<b>{label}</b>", styles['BodyText']))
                elements.extend(_flowables_from_html(text, styles))
                elements.append(Spacer(1,6))

        if i < len(vulns):  # Não adiciona quebra de página na última vulnerabilidade
            elements.append(PageBreak())
    
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def save_uploaded_image(file_storage):
    """Save an uploaded image with a unique filename, preserving extension.
    Avoids overwriting when clients use generic names like 'pasted.png'.
    """
    orig = secure_filename(file_storage.filename or '')
    ext = ''
    if '.' in orig:
        ext = '.' + orig.rsplit('.', 1)[-1].lower()
    if not ext:
        ext = '.png'
    upload_dir = Path(current_app.static_folder) / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    # always generate a unique name
    for _ in range(5):
        unique_name = f"img-{uuid.uuid4().hex}{ext}"
        path = upload_dir / unique_name
        if not path.exists():
            file_storage.save(path)
            return f"/static/uploads/{unique_name}"
    # fallback (extremely unlikely)
    fallback_name = f"img-{uuid.uuid4().hex}{ext}"
    file_storage.save(upload_dir / fallback_name)
    return f"/static/uploads/{fallback_name}"


def _flowables_from_html(html_text, styles):
    """Converte HTML simples com <img> em Flowables (Paragraph e Image)."""
    parts = []
    # quebra por <img ...>
    pattern = re.compile(r"(<img[^>]*src=\"[^\"]+\"[^>]*>)", re.IGNORECASE)
    tokens = pattern.split((html_text or '').replace('\n', '<br/>'))
    for token in tokens:
        if token.lower().startswith('<img'):
            m = re.search(r'src=\"([^\"]+)\"', token, re.IGNORECASE)
            if not m:
                continue
            src = m.group(1)
            # Resolve caminho local somente para /static/...; ignora URLs externas
            if src.startswith('/static/'):
                static_root = Path(current_app.root_path).parent / 'static'
                rel = src.replace('/static/', '')
                file_path = static_root / rel
                if file_path.exists():
                    try:
                        img = RLImage(str(file_path))
                        # Redimensiona para caber na largura da página (~6.5in)
                        max_width = 6.0 * inch
                        if img.drawWidth > max_width:
                            ratio = max_width / float(img.drawWidth)
                            img.drawWidth *= ratio
                            img.drawHeight *= ratio
                        parts.append(img)
                        parts.append(Spacer(1, 6))
                    except Exception:
                        # Se falhar, coloca como texto
                        parts.append(Paragraph(f"[imagem: {src}]", styles['BodyText']))
                else:
                    parts.append(Paragraph(f"[imagem não encontrada: {src}]", styles['BodyText']))
            else:
                parts.append(Paragraph(f"[imagem externa: {src}]", styles['BodyText']))
        else:
            text = token.strip()
            if text:
                parts.append(Paragraph(text, styles['BodyText']))
    return parts


# ================== NOVO PADRÃO DE RELATÓRIO ==================

NAVY = colors.HexColor('#001f3f')
WHITE = colors.white


def _get_logo_path():
    static_root = Path(current_app.root_path).parent / 'static'
    # padrão esperado: static/img/logo.png
    for rel in ['img/logo.png', 'img/logo.jpg', 'logo.png', 'logo.jpg']:
        p = static_root / rel
        if p.exists():
            return str(p)
    return None


def _get_company_label(vulns):
    companies = sorted({(v.company or '').strip() for v in vulns if (v.company or '').strip()})
    if not companies:
        return 'Unidade: (não especificada)'
    if len(companies) == 1:
        return f'Unidade: {companies[0]}'
    return 'Unidades: ' + ', '.join(companies)


def _header_footer(canvas, doc, title_left='Uso Interno', color=NAVY):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(color)
    canvas.rect(0, height-28, width, 28, fill=True, stroke=False)
    canvas.setFillColor(WHITE)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(18, height-18, title_left)
    # footer
    canvas.setFillColor(color)
    canvas.rect(0, 0, width, 24, fill=True, stroke=False)
    canvas.setFillColor(WHITE)
    canvas.setFont('Helvetica', 9)
    page_txt = f"Página {doc.page}"
    canvas.drawRightString(width-18, 10, page_txt)
    canvas.restoreState()


def build_executive_report(vulns, period=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=48, bottomMargin=36, leftMargin=42, rightMargin=42)
    styles = getSampleStyleSheet()
    font_name = _ensure_ptbr_font()
    for _, s in styles.byName.items():
        s.fontName = font_name

    elements = []

    # CAPA
    logo_path = _get_logo_path()
    elements.append(Spacer(1, 1.5*inch))
    if logo_path:
        try:
            img = RLImage(logo_path, width=2.2*inch, height=2.2*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.3*inch))
        except Exception:
            pass
    elements.append(Paragraph('Relatório de Pentest — Executivo', styles['Title']))
    # empresa/unidade sob o título
    elements.append(Spacer(1, 0.15*inch))
    elements.append(Paragraph(_get_company_label(vulns), styles['Heading2']))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph(datetime.now().strftime('%d/%m/%Y'), styles['Normal']))
    if period:
        start, end = period
        period_txt = f"Período: {start or 'N/A'} a {end or 'N/A'}"
        elements.append(Paragraph(period_txt, styles['Normal']))
    elements.append(PageBreak())

    # 1) AVISO LEGAL (nova página)
    elements.append(Paragraph('1. Aviso Legal', styles['Heading2']))
    elements.extend(_long_text_blocks([
        '1.1 Aviso de Limitação de Responsabilidade',
        'É importante destacar que não existe a possibilidade de avaliar redes, sistemas, serviços ou aplicações frente a todas as vulnerabilidades de segurança possíveis. Assim, este relatório não deve ser interpretado como uma garantia absoluta de proteção contra todas as ameaças conhecidas ou futuras.',
        'Os testes aqui documentados representam a análise realizada dentro do escopo acordado, refletindo exclusivamente as condições observadas no momento da execução. Logo, não é viável assegurar que os ativos avaliados estejam imunes a todos os vetores de ataque.',
        'Dada a constante evolução do cenário de tecnologia da informação, reconhece-se que falhas ainda não documentadas ou divulgadas no momento do teste podem não ter sido detectadas durante a atividade.',
        '1.2 Termo de Confidencialidade',
        'Este relatório contém informações confidenciais e de propriedade da empresa, sendo vedada sua reprodução, distribuição ou utilização, integral ou parcial, sem autorização formal expressa por escrito.',
        'É autorizado o cliente disponibilizar este documento a auditores, órgãos reguladores ou parceiros de negócio, exclusivamente para fins de comprovação da execução do teste de intrusão. Essa permissão é restrita a contextos de auditoria, conformidade normativa ou processos que exijam tal evidência.'
    ], styles))
    elements.append(PageBreak())

    # 2) INTRODUÇÃO (nova página)
    elements.append(Paragraph('2. Introdução', styles['Heading2']))
    intro_period = ''
    if period:
        start, end = period
        intro_period = f"entre o período de {start or 'N/A'} a {end or 'N/A'}, "
    elements.extend(_long_text_blocks([
        f'Foi realizado um teste de intrusão {intro_period}com o objetivo de identificar vulnerabilidades que possam afetar dados, sistemas e reputação da empresa.',
        'O teste simulou ataques reais de forma controlada, seguindo etapas de mapeamento do ambiente, priorização de ativos críticos, exploração de falhas e registro das evidências encontradas.',
        'Com este relatório, a empresa contratante dispõe de uma visão clara sobre os riscos identificados e recebe recomendações para fortalecer suas defesas, priorizando correções conforme a gravidade de cada vulnerabilidade.'
    ], styles))
    elements.append(PageBreak())

    # 3) SUMÁRIO + GRÁFICO (nova página)
    elements.append(Paragraph('3. Sumário', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Foi realizada uma análise de segurança com foco na exploração prática das vulnerabilidades, buscando validar acessos indevidos e expor riscos reais dentro do prazo definido. Diferente de um levantamento superficial, a abordagem priorizou profundidade, obtendo evidências concretas para apoiar decisões de mitigação.',
        'Os objetivos do trabalho foram:',
        '• Mapear vetores de ataque;',
        '• Identificar riscos reais;',
        '• Apresentar recomendações de correção.'
    ], styles))

    sev_count = _severity_count(vulns)
    total = sum(sev_count.values()) or 0
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Como resultado, foram detectadas {total} vulnerabilidades, classificadas em: {sev_count.get('Critical',0)} crítica(s), {sev_count.get('High',0)} alta(s), {sev_count.get('Medium',0)} média(s), {sev_count.get('Low',0)} baixa(s), {sev_count.get('Informative',0)} informativa(s).", styles['BodyText']))
    # espaço extra (~3 br)
    elements.append(Spacer(1, 24))
    elements.append(_severity_donut(sev_count))
    elements.append(PageBreak())

    # 4) ESCOPO (após Sumário)
    elements.append(Paragraph('4. Escopo', styles['Heading2']))
    types = ['Penetration Test']  # Tipo fixo já que não temos o campo pentest_type
    elements.append(Paragraph('Categoria(s) de Pentest:', styles['BodyText']))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph('• ' + ', '.join(types), styles['BodyText']))
    elements.append(Spacer(1, 10))

    # 5) METODOLOGIA
    elements.append(Paragraph('5. Metodologia', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Durante os testes, foram abrangidas centenas de possibilidades para encontrar ou provocar vulnerabilidades, além de coletar o máximo de informações possíveis sobre a aplicação, e assim analisar os riscos que essas informações poderão trazer ao negócio.',
        'Nos testes de intrusão, foram utilizados os principais guias e padrões do mercado para sucesso da tarefa, que podem ser citados: NIST, CWE, OWASP TOP 10, PTES e OSSTMM.'
    ], styles))
    elements.append(PageBreak())

    # 6) CLASSIFICAÇÃO DE RISCOS (nova página)
    elements.append(Paragraph('Classificação de Riscos', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Foi adotado um modelo simplificado de categorização de risco para cada vulnerabilidade identificada, com o objetivo de priorizar a triagem nos problemas que representam maior impacto.',
        'Para referência, utiliza-se o Common Vulnerability Scoring System (CVSS), um padrão amplamente aceito no mercado, que atribui notas de 0,0 a 10,0 conforme a gravidade da falha.',
        'A tabela a seguir apresenta as categorias de risco adotadas e sua relação aproximada com as faixas de pontuação do CVSS.'
    ], styles))
    # tenta incluir imagem da tabela se existir
    try:
        static_root = Path(current_app.root_path).parent / 'static'
        for rel in ['img/cvss_tabela.png', 'img/cvss.png', 'uploads/pasted.png']:
            p = static_root / rel
            if p.exists():
                img = RLImage(str(p))
                max_w = 6.0 * inch
                if img.drawWidth > max_w:
                    ratio = max_w / float(img.drawWidth)
                    img.drawWidth *= ratio
                    img.drawHeight *= ratio
                elements.append(img)
                break
    except Exception:
        pass
    elements.extend(_long_text_blocks([
        'O CVSS não é aplicável a todos os tipos de riscos. Por essa razão, o leitor pode encontrar vulnerabilidades sem classificação CVSS em nossos relatórios.'
    ], styles))
    elements.append(PageBreak())

    # 7) DETALHES RESUMIDOS (cada vulnerabilidade em nova página)
    for idx, v in enumerate(vulns, 1):
        elements.append(Paragraph('Detalhes Resumidos', styles['Heading2']))
        elements.append(Paragraph(f'{idx}. {v.title} — {v.severity}', styles['Heading3']))
        elements.extend(_flowables_from_html(v.description or '', styles))
        elements.append(Spacer(1, 6))
        if idx < len(vulns):
            elements.append(PageBreak())

    doc.build(elements, onFirstPage=lambda c, d: _header_footer(c, d), onLaterPages=lambda c, d: _header_footer(c, d))
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def build_technical_report(vulns, period=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=48, bottomMargin=36, leftMargin=42, rightMargin=42)
    styles = getSampleStyleSheet()
    font_name = _ensure_ptbr_font()
    for _, s in styles.byName.items():
        s.fontName = font_name

    elements = []

    # CAPA
    logo_path = _get_logo_path()
    elements.append(Spacer(1, 1.2*inch))
    if logo_path:
        try:
            img = RLImage(logo_path, width=2.0*inch, height=2.0*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.2*inch))
        except Exception:
            pass
    elements.append(Paragraph('Relatório de Pentest — Técnico', styles['Title']))
    elements.append(Spacer(1, 0.15*inch))
    elements.append(Paragraph(_get_company_label(vulns), styles['Heading2']))
    elements.append(Paragraph(datetime.now().strftime('%d/%m/%Y'), styles['Normal']))
    if period:
        start, end = period
        period_txt = f"Período: {start or 'N/A'} a {end or 'N/A'}"
        elements.append(Paragraph(period_txt, styles['Normal']))
    elements.append(PageBreak())

    # 1) AVISO LEGAL (nova página)
    elements.append(Paragraph('1. Aviso Legal', styles['Heading2']))
    elements.extend(_long_text_blocks([
        '1.1 Aviso de Limitação de Responsabilidade',
        'É importante destacar que não existe a possibilidade de avaliar redes, sistemas, serviços ou aplicações frente a todas as vulnerabilidades de segurança possíveis. Assim, este relatório não deve ser interpretado como uma garantia absoluta de proteção contra todas as ameaças conhecidas ou futuras.',
        'Os testes aqui documentados representam a análise realizada dentro do escopo acordado, refletindo exclusivamente as condições observadas no momento da execução. Logo, não é viável assegurar que os ativos avaliados estejam imunes a todos os vetores de ataque.',
        'Dada a constante evolução do cenário de tecnologia da informação, reconhece-se que falhas ainda não documentadas ou divulgadas no momento do teste podem não ter sido detectadas durante a atividade.',
        '1.2 Termo de Confidencialidade',
        'Este relatório contém informações confidenciais e de propriedade da empresa, sendo vedada sua reprodução, distribuição ou utilização, integral ou parcial, sem autorização formal expressa por escrito.',
        'É autorizado o cliente disponibilizar este documento a auditores, órgãos reguladores ou parceiros de negócio, exclusivamente para fins de comprovação da execução do teste de intrusão. Essa permissão é restrita a contextos de auditoria, conformidade normativa ou processos que exijam tal evidência.'
    ], styles))
    elements.append(PageBreak())

    # 2) INTRODUÇÃO (nova página)
    elements.append(Paragraph('2. Introdução', styles['Heading2']))
    intro_period = ''
    if period:
        start, end = period
        intro_period = f"entre o período de {start or 'N/A'} a {end or 'N/A'}, "
    elements.extend(_long_text_blocks([
        f'Foi realizado um teste de intrusão {intro_period}com o objetivo de identificar vulnerabilidades que possam afetar dados, sistemas e reputação da empresa.',
        'O teste simulou ataques reais de forma controlada, seguindo etapas de mapeamento do ambiente, priorização de ativos críticos, exploração de falhas e registro das evidências encontradas.',
        'Com este relatório, a empresa contratante dispõe de uma visão clara sobre os riscos identificados e recebe recomendações para fortalecer suas defesas, priorizando correções conforme a gravidade de cada vulnerabilidade.'
    ], styles))
    elements.append(PageBreak())

    # 3) SUMÁRIO + GRÁFICO (nova página)
    elements.append(Paragraph('3. Sumário', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Foi realizada uma análise de segurança com foco na exploração prática das vulnerabilidades, buscando validar acessos indevidos e expor riscos reais dentro do prazo definido. Diferente de um levantamento superficial, a abordagem priorizou profundidade, obtendo evidências concretas para apoiar decisões de mitigação.',
        'Os objetivos do trabalho foram:',
        '• Mapear vetores de ataque;',
        '• Identificar riscos reais;',
        '• Apresentar recomendações de correção.'
    ], styles))
    sev_count = _severity_count(vulns)
    total = sum(sev_count.values()) or 0
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Como resultado, foram detectadas {total} vulnerabilidades, classificadas em: {sev_count.get('Critical',0)} crítica(s), {sev_count.get('High',0)} alta(s), {sev_count.get('Medium',0)} média(s), {sev_count.get('Low',0)} baixa(s), {sev_count.get('Informative',0)} informativa(s).", styles['BodyText']))
    elements.append(Spacer(1, 24))
    elements.append(_severity_donut(sev_count))
    elements.append(PageBreak())

    # ESCOPO
    elements.append(Paragraph('Escopo', styles['Heading2']))
    types_t = ['Penetration Test']  # Tipo fixo já que não temos o campo pentest_type
    elements.append(Paragraph('Categoria(s) de Pentest:', styles['BodyText']))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph('• ' + ', '.join(types_t), styles['BodyText']))
    elements.append(Spacer(1, 10))

    # METODOLOGIA
    elements.append(Paragraph('Metodologia', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Durante os testes, foram abrangidas centenas de possibilidades para encontrar ou provocar vulnerabilidades, além de coletar o máximo de informações possíveis sobre a aplicação, e assim analisar os riscos que essas informações poderão trazer ao negócio.',
        'Nos testes de intrusão, foram utilizados os principais guias e padrões do mercado para sucesso da tarefa, que podem ser citados: NIST, CWE, OWASP TOP 10, PTES e OSSTMM.'
    ], styles))
    elements.append(PageBreak())

    # CLASSIFICAÇÃO DE RISCOS
    elements.append(Paragraph('Classificação de Riscos', styles['Heading2']))
    elements.extend(_long_text_blocks([
        'Foi adotado um modelo simplificado de categorização de risco para cada vulnerabilidade identificada, com o objetivo de priorizar a triagem nos problemas que representam maior impacto.',
        'Para referência, utiliza-se o Common Vulnerability Scoring System (CVSS), um padrão amplamente aceito no mercado, que atribui notas de 0,0 a 10,0 conforme a gravidade da falha.',
        'A tabela a seguir apresenta as categorias de risco adotadas e sua relação aproximada com as faixas de pontuação do CVSS.'
    ], styles))
    try:
        static_root = Path(current_app.root_path).parent / 'static'
        for rel in ['img/cvss_tabela.png', 'img/cvss.png', 'uploads/pasted.png']:
            p = static_root / rel
            if p.exists():
                img = RLImage(str(p))
                max_w = 6.0 * inch
                if img.drawWidth > max_w:
                    ratio = max_w / float(img.drawWidth)
                    img.drawWidth *= ratio
                    img.drawHeight *= ratio
                elements.append(img)
                break
    except Exception:
        pass
    elements.extend(_long_text_blocks([
        'O CVSS não é aplicável a todos os tipos de riscos. Por essa razão, o leitor pode encontrar vulnerabilidades sem classificação CVSS em nossos relatórios.'
    ], styles))
    elements.append(PageBreak())

    # DETALHES TÉCNICOS COMPLETOS
    for i, v in enumerate(vulns, 1):
        elements.append(Paragraph(f'{i}. {v.title}', styles['Heading2']))
        meta = [["Severidade", v.severity], ["Status", v.status], ["CVSS", str(v.cvss or 'N/A')]]
        table = Table(meta, hAlign='LEFT')
        table.setStyle(TableStyle([('BOX',(0,0),(-1,-1),1,colors.black),('INNERGRID',(0,0),(-1,-1),0.5,colors.grey)]))
        elements.extend([table, Spacer(1,8)])

        for label, text in [("Descrição", v.description),("Impacto", v.impact),("Probabilidade", v.likelihood),("Remediação", v.remediation),("Referências", v.references)]:
            if text:
                elements.append(Paragraph(f"<b>{label}</b>", styles['BodyText']))
                elements.extend(_flowables_from_html(text, styles))
                elements.append(Spacer(1,6))
        elements.append(PageBreak())

    doc.build(elements, onFirstPage=lambda c, d: _header_footer(c, d), onLaterPages=lambda c, d: _header_footer(c, d))
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def _severity_count(vulns):
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informative': 0}
    for v in vulns:
        sev_raw = (v.severity or '').strip().lower()
        if sev_raw in ['informativa', 'informative', 'info']:
            sev = 'Informative'
        else:
            sev = (v.severity or '').capitalize()
        if sev in counts:
            counts[sev] += 1
    return counts


def _severity_donut(counts):
    data = [counts.get('Critical',0), counts.get('High',0), counts.get('Medium',0), counts.get('Low',0), counts.get('Informative',0)]
    labels = ['Crítica', 'Alta', 'Média', 'Baixa', 'Informativa']
    # Cores alinhadas ao padrão (vermelho, laranja, amarelo, verde, azul)
    palette = [colors.HexColor('#dc3545'), colors.HexColor('#fd7e14'), colors.HexColor('#ffc107'), colors.HexColor('#28a745'), colors.HexColor('#0d6efd')]
    total = sum(data)
    if total == 0:
        total = 1
    d = Drawing(400, 250)
    pie = Pie()
    pie.x = 80
    pie.y = 20
    pie.width = 240
    pie.height = 240
    pie.data = data
    pie.labels = [f"{labels[i]} ({data[i]})" for i in range(len(data))]
    pie.slices.strokeWidth = 0.5
    for i, col in enumerate(palette):
        if i < len(pie.slices):
            pie.slices[i].fillColor = col
    # efeito rosca: desenha um círculo branco central
    # (na integração como Flowable, vamos sobrepor com um Paragraph central)
    d.add(pie)
    return d


def _long_text_blocks(paragraphs, styles):
    blocks = []
    for t in paragraphs:
        if t.startswith('1.1') or t.startswith('1.2'):
            blocks.append(Paragraph(f'<b>{t}</b>', styles['BodyText']))
        elif t.startswith('•') or t.startswith('- '):
            blocks.append(Paragraph(t, styles['BodyText']))
        else:
            blocks.append(Paragraph(t, styles['BodyText']))
        blocks.append(Spacer(1, 6))
    return blocks


def _clean_text(text):
    """Limpa texto para evitar problemas de encoding"""
    if not text:
        return ""
    try:
        # Limpar caracteres problemáticos
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        # Remover caracteres de controle
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        return text
    except:
        return str(text) if text else ""

# Função removida - templates customizáveis não são mais suportados
def _removed_build_custom_report_pdf(vulns, template_id, company_name):
    """Gera PDF customizável baseado no template"""
    # ReportTemplate removido - templates customizáveis não são mais suportados
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    font_name = _ensure_ptbr_font()
    
    # Buscar template
    # ReportTemplate removido - templates customizáveis não são mais suportados
    raise ValueError("Templates customizáveis não são mais suportados")
    if not template:
        raise ValueError("Template não encontrado")
    
    # Configurar cores
    try:
        primary_color = colors.HexColor(template.primary_color or '#01317d')
    except:
        primary_color = colors.HexColor('#01317d')
    
    try:
        secondary_color = colors.HexColor(template.secondary_color or '#3b82f6')
    except:
        secondary_color = colors.HexColor('#3b82f6')
    
    # Configurar fonte
    font_size = template.font_size or 12
    # Usar fonte segura do sistema
    font_family = _ensure_ptbr_font()
    
    # Estilos customizados
    custom_styles = {
        'Title': styles['Title'],
        'Heading1': styles['Heading1'],
        'Heading2': styles['Heading2'],
        'BodyText': styles['BodyText'],
        'Normal': styles['Normal']
    }
    
    # Aplicar fonte customizada
    for style in custom_styles.values():
        style.fontName = font_family
        style.fontSize = font_size
        # Garantir que a fonte seja válida
        try:
            # Testar se a fonte é válida
            if hasattr(style, 'fontName'):
                style.fontName = font_family
        except:
            # Fallback para fonte padrão
            style.fontName = 'Helvetica'
    
    custom_styles['Title'].textColor = primary_color
    custom_styles['Heading1'].textColor = primary_color
    custom_styles['Heading2'].textColor = primary_color
    
    blocks = []
    
    # Capa
    if template.include_cover:
        # Título da capa
        if template.cover_title:
            title_text = _clean_text(template.cover_title.replace('{{ empresa }}', company_name))
            blocks.append(Paragraph(title_text, custom_styles['Title']))
            blocks.append(Spacer(1, 20))
        
        # Subtítulo
        if template.cover_subtitle:
            subtitle_text = _clean_text(template.cover_subtitle.replace('{{ empresa }}', company_name))
            blocks.append(Paragraph(subtitle_text, custom_styles['Heading2']))
            blocks.append(Spacer(1, 30))
        
        # Empresa
        if template.cover_company:
            company_text = _clean_text(template.cover_company.replace('{{ empresa }}', company_name))
            blocks.append(Paragraph(company_text, custom_styles['Heading2']))
            blocks.append(Spacer(1, 20))
        
        # Data
        if template.cover_date:
            date_text = _clean_text(template.cover_date.replace('{{ data_atual }}', datetime.now().strftime('%d/%m/%Y')))
            blocks.append(Paragraph(date_text, custom_styles['Normal']))
        
        blocks.append(PageBreak())
    
    # Aviso Legal
    if template.include_legal and template.legal_notice:
        blocks.append(Paragraph("Aviso Legal", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        legal_text = _clean_text(template.legal_notice.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(legal_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Introdução
    if template.include_introduction and template.introduction:
        blocks.append(Paragraph("Introdução", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        intro_text = _clean_text(template.introduction.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(intro_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Sumário Executivo
    if template.include_executive_summary and template.executive_summary:
        blocks.append(Paragraph("Sumário Executivo", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        summary_text = _clean_text(template.executive_summary.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(summary_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Escopo
    if template.include_scope and template.scope:
        blocks.append(Paragraph("Escopo", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        scope_text = _clean_text(template.scope.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(scope_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Metodologia
    if template.include_methodology and template.methodology:
        blocks.append(Paragraph("Metodologia", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        method_text = _clean_text(template.methodology.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(method_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Classificação de Riscos
    if template.include_risk_classification and template.risk_classification:
        blocks.append(Paragraph("Classificação de Riscos", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        risk_text = _clean_text(template.risk_classification.replace('{{ empresa }}', company_name))
        blocks.append(Paragraph(risk_text, custom_styles['BodyText']))
        blocks.append(PageBreak())
    
    # Tabela de Vulnerabilidades
    if template.include_vulnerabilities_table and vulns:
        blocks.append(Paragraph("Tabela de Vulnerabilidades", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        
        # Dados da tabela
        table_data = [['Título', 'Severidade', 'Status', 'CVSS', 'Data']]
        for vuln in vulns:
            table_data.append([
                _clean_text(vuln.title),
                _clean_text(vuln.severity),
                _clean_text(vuln.status),
                str(vuln.cvss) if vuln.cvss else '-',
                vuln.created_at.strftime('%d/%m/%Y')
            ])
        
        # Criar tabela
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), font_family),
            ('FONTSIZE', (0, 0), (-1, 0), font_size),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        blocks.append(table)
        blocks.append(PageBreak())
    
    # Detalhes das Vulnerabilidades
    if template.include_vulnerability_details and vulns:
        blocks.append(Paragraph("Detalhes das Vulnerabilidades", custom_styles['Heading1']))
        blocks.append(Spacer(1, 12))
        
        for vuln in vulns:
            # Título da vulnerabilidade
            blocks.append(Paragraph(_clean_text(vuln.title), custom_styles['Heading2']))
            blocks.append(Spacer(1, 6))
            
            # Informações básicas
            info_data = [
                ['Severidade', _clean_text(vuln.severity)],
                ['Status', _clean_text(vuln.status)],
                ['CVSS', str(vuln.cvss) if vuln.cvss else 'N/A'],
                ['Data', vuln.created_at.strftime('%d/%m/%Y')]
            ]
            
            info_table = Table(info_data)
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), font_family),
                ('FONTSIZE', (0, 0), (-1, -1), font_size - 1),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
            ]))
            
            blocks.append(info_table)
            blocks.append(Spacer(1, 12))
            
            # Descrição
            if vuln.description:
                blocks.append(Paragraph("<b>Descrição:</b>", custom_styles['BodyText']))
                blocks.append(Paragraph(_clean_text(vuln.description), custom_styles['BodyText']))
                blocks.append(Spacer(1, 12))
            
            # Impacto
            if vuln.impact:
                blocks.append(Paragraph("<b>Impacto:</b>", custom_styles['BodyText']))
                blocks.append(Paragraph(_clean_text(vuln.impact), custom_styles['BodyText']))
                blocks.append(Spacer(1, 12))
            
            # Remediação
            if vuln.remediation:
                blocks.append(Paragraph("<b>Remediação:</b>", custom_styles['BodyText']))
                blocks.append(Paragraph(_clean_text(vuln.remediation), custom_styles['BodyText']))
                blocks.append(Spacer(1, 12))
            
            # Referências
            if vuln.references:
                blocks.append(Paragraph("<b>Referências:</b>", custom_styles['BodyText']))
                blocks.append(Paragraph(_clean_text(vuln.references), custom_styles['BodyText']))
            
            blocks.append(PageBreak())
    
    # Construir PDF
    try:
        doc.build(blocks)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        # Se houver erro, criar um PDF simples com erro
        error_buffer = BytesIO()
        error_doc = SimpleDocTemplate(error_buffer, pagesize=A4)
        error_styles = getSampleStyleSheet()
        error_blocks = [
            Paragraph("Erro ao Gerar Relatório", error_styles['Title']),
            Spacer(1, 20),
            Paragraph(f"Erro: {str(e)}", error_styles['BodyText']),
            Spacer(1, 20),
            Paragraph("Por favor, verifique as configurações do template.", error_styles['BodyText'])
        ]
        error_doc.build(error_blocks)
        error_buffer.seek(0)
        return error_buffer.getvalue()