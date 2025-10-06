"""
Sistema de backup e export para freelancers
"""

import json
import csv
from datetime import datetime
from flask import Blueprint, jsonify, send_file, request, session
from flask_login import login_required, current_user
from io import StringIO, BytesIO
from . import db
from .models import Vulnerability, Company

backup_bp = Blueprint('backup', __name__)

@backup_bp.route('/backup/vulnerabilities.json')
@login_required
def export_vulnerabilities_json():
    """Exportar vulnerabilidades em formato JSON"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return jsonify({'error': 'Empresa não especificada'}), 400
    
    # Buscar vulnerabilidades da empresa
    vulns = Vulnerability.query.filter_by(company=selected_company).all()
    
    # Converter para JSON
    data = {
        'company': selected_company,
        'export_date': datetime.now().isoformat(),
        'vulnerabilities': []
    }
    
    for vuln in vulns:
        vuln_data = {
            'id': vuln.id,
            'title': vuln.title,
            'severity': vuln.severity,
            'status': vuln.status,
            'cvss': vuln.cvss,
            'description': vuln.description,
            'impact': vuln.impact,
            'likelihood': vuln.likelihood,
            'remediation': vuln.remediation,
            'references': vuln.references,
            'comments': vuln.comments,
            'client_name': vuln.client_name,
            'project_name': vuln.project_name,
            'test_type': vuln.test_type,
            'test_date': vuln.test_date.isoformat() if vuln.test_date else None,
            'tester_name': vuln.tester_name,
            'client_contact': vuln.client_contact,
            'created_at': vuln.created_at.isoformat(),
            'updated_at': vuln.updated_at.isoformat()
        }
        data['vulnerabilities'].append(vuln_data)
    
    # Criar arquivo JSON
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    json_bytes = json_str.encode('utf-8')
    
    return send_file(
        BytesIO(json_bytes),
        as_attachment=True,
        download_name=f'vulnerabilities_{selected_company}_{datetime.now().strftime("%Y%m%d")}.json',
        mimetype='application/json'
    )

@backup_bp.route('/backup/vulnerabilities.csv')
@login_required
def export_vulnerabilities_csv():
    """Exportar vulnerabilidades em formato CSV"""
    selected_company = session.get('selected_company')
    if not selected_company:
        return jsonify({'error': 'Empresa não especificada'}), 400
    
    # Buscar vulnerabilidades da empresa
    vulns = Vulnerability.query.filter_by(company=selected_company).all()
    
    # Criar CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Cabeçalhos
    headers = [
        'ID', 'Título', 'Severidade', 'Status', 'CVSS', 'Descrição',
        'Impacto', 'Probabilidade', 'Remediação', 'Referências', 'Comentários',
        'Cliente', 'Projeto', 'Tipo de Teste', 'Data do Teste',
        'Pentester', 'Contato do Cliente', 'Criado em', 'Atualizado em'
    ]
    writer.writerow(headers)
    
    # Dados
    for vuln in vulns:
        row = [
            vuln.id,
            vuln.title,
            vuln.severity,
            vuln.status,
            vuln.cvss or '',
            vuln.description or '',
            vuln.impact or '',
            vuln.likelihood or '',
            vuln.remediation or '',
            vuln.references or '',
            vuln.comments or '',
            vuln.client_name or '',
            vuln.project_name or '',
            vuln.test_type or '',
            vuln.test_date.strftime('%d/%m/%Y') if vuln.test_date else '',
            vuln.tester_name or '',
            vuln.client_contact or '',
            vuln.created_at.strftime('%d/%m/%Y %H:%M'),
            vuln.updated_at.strftime('%d/%m/%Y %H:%M')
        ]
        writer.writerow(row)
    
    # Converter para bytes
    csv_str = output.getvalue()
    csv_bytes = csv_str.encode('utf-8-sig')  # BOM para Excel
    
    return send_file(
        BytesIO(csv_bytes),
        as_attachment=True,
        download_name=f'vulnerabilities_{selected_company}_{datetime.now().strftime("%Y%m%d")}.csv',
        mimetype='text/csv'
    )

