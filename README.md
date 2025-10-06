# 🛡️ LazyVulners - Sistema de Gerenciamento de Vulnerabilidades

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![SQLite](https://img.shields.io/badge/SQLite-3+-lightblue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

<p align="center">
  <img width="763" height="1083" alt="image" src="https://github.com/user-attachments/assets/8145ccdd-54a7-4862-8d9b-66741e1980b3" />
</p>

## 📋 Visão Geral

O **LazyVulners** é um sistema completo de gerenciamento de vulnerabilidades desenvolvido especificamente para **freelancers de pentest** e **equipes de segurança**. O sistema oferece uma interface intuitiva para gerenciar vulnerabilidades, gerar relatórios personalizados e manter um controle eficiente de projetos de segurança.

### 🎯 Características Principais

- **🔐 Sistema de Autenticação Seguro**: Login com controle de acesso por roles
- **📊 Dashboard Interativo**: Visualização de vulnerabilidades com gráficos e estatísticas
- **📝 Gerenciamento de Vulnerabilidades**: CRUD completo com campos específicos para freelancers
- **📄 Relatórios Personalizáveis**: Templates customizáveis para diferentes tipos de pentest
- **💾 Sistema de Backup**: Export de dados em JSON e CSV
- **🏢 Multi-empresa**: Suporte a múltiplas empresas com isolamento de dados
- **👥 Controle de Usuários**: Sistema de roles (Admin, Editor, Visualizador)
- **🔒 Segurança Robusta**: CSRF protection, validação de senhas, controle de acesso

## 🚀 Instalação e Configuração

### Pré-requisitos

- Python 3.11 ou superior
- pip (gerenciador de pacotes Python)
- Git (opcional, para clonagem)

### 1. Clone o Repositório

```bash
git clone https://github.com/lucascdsm/lazyvulners.git
cd lazyvulners
```

### 2. Criação do Ambiente Virtual

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalação das Dependências

```bash
pip install -r requirements.txt
```

### 4. Execução da Aplicação

```bash
python run.py
```

### 5. Acesso ao Sistema

Abra seu navegador e acesse: `http://localhost:5000`

**Credenciais Padrão:**
- **Usuário**: `LazyVuln`
- **Senha**: `lazyvuln_for_pentesters2k25`

## 📁 Estrutura do Projeto

```
lazyvulners/
├── app/                          # Aplicação principal
│   ├── __init__.py              # Configuração da aplicação
│   ├── models.py                # Modelos de dados (SQLAlchemy)
│   ├── views.py                 # Rotas e lógica de negócio
│   ├── forms.py                 # Formulários (WTForms)
│   ├── auth.py                  # Autenticação e login
│   ├── users.py                 # Gerenciamento de usuários
│   ├── backup.py                # Sistema de backup e export
│   └── utils.py                 # Utilitários (geração de PDF)
├── templates/                    # Templates HTML
│   ├── base.html               # Template base
│   ├── dashboard_base.html      # Template do dashboard
│   ├── login.html              # Página de login
│   ├── dashboard.html          # Dashboard principal
│   ├── vulnerabilities/        # Templates de vulnerabilidades
│   ├── reports/                # Templates de relatórios
│   └── users/                  # Templates de usuários
├── static/                      # Arquivos estáticos
│   ├── css/                   # Estilos CSS
│   ├── js/                    # JavaScript
│   └── images/                # Imagens
├── instance/                   # Banco de dados SQLite
├── run.py                     # Arquivo de execução
├── requirements.txt           # Dependências Python
└── README.md                  # Este arquivo
```

## 🎨 Funcionalidades Detalhadas

### 🔐 Sistema de Autenticação

- **Login Seguro**: Autenticação com hash de senha (scrypt)
- **Controle de Acesso**: Sistema de roles (Admin, Editor, Visualizador)
- **Sessões Seguras**: Cookies seguros com CSRF protection
- **Alteração de Senha**: Usuários podem alterar suas próprias senhas

### 📊 Dashboard

- **Visão Geral**: Estatísticas de vulnerabilidades por severidade
- **Filtros Avançados**: Por empresa, severidade, status e data
- **Gráficos Interativos**: Visualização de dados com gráficos
- **Busca Inteligente**: Pesquisa por título, descrição e outros campos

### 🛡️ Gerenciamento de Vulnerabilidades

#### Campos Básicos
- **Título**: Nome da vulnerabilidade
- **Severidade**: Critical, High, Medium, Low, Informative
- **Status**: Open, In Progress, Closed
- **CVSS**: Score de 0.0 a 10.0
- **Descrição**: Detalhes técnicos
- **Impacto**: Análise de impacto
- **Probabilidade**: Análise de probabilidade
- **Remediação**: Passos para correção
- **Referências**: Links e documentos

#### Campos Específicos para Freelancers
- **Cliente**: Nome do cliente
- **Projeto**: Nome do projeto
- **Tipo de Teste**: Web, Network, Mobile, API, Infrastructure, etc.
- **Data do Teste**: Data da execução
- **Pentester**: Nome do profissional
- **Contato do Cliente**: Informações de contato

### 📄 Sistema de Relatórios

#### Relatórios Padrão
- **Relatório Completo**: PDF com todas as vulnerabilidades
- **Relatório Executivo**: Resumo para gestores
- **Relatório Técnico**: Detalhes técnicos para equipe

#### Templates Personalizáveis
- **Web Application Pentest**: Otimizado para aplicações web
- **Network Infrastructure Pentest**: Para infraestrutura de rede
- **Mobile Application Pentest**: Para aplicações móveis
- **Templates Customizáveis**: Criação de templates personalizados

#### Seções Customizáveis
- **Capa**: Título, subtítulo, empresa, data, logo
- **Aviso Legal**: Texto de confidencialidade
- **Introdução**: Contexto do teste
- **Sumário Executivo**: Resumo para gestores
- **Escopo**: Definição do escopo do teste
- **Metodologia**: Técnicas utilizadas
- **Classificação de Riscos**: Critérios de classificação
- **Tabela de Vulnerabilidades**: Lista resumida
- **Detalhes das Vulnerabilidades**: Descrição completa

### 💾 Sistema de Backup

- **Export JSON**: Backup completo em formato JSON
- **Export CSV**: Para análise em Excel
- **Templates JSON**: Export de templates personalizados
- **Backup Completo**: Download de todos os dados

### 🏢 Multi-empresa

- **Isolamento de Dados**: Cada empresa vê apenas seus dados
- **Seleção de Empresa**: Interface para troca de contexto
- **Controle de Acesso**: Admins podem acessar todas as empresas

### 👥 Gerenciamento de Usuários

- **Admin Único**: Apenas 1 administrador no sistema
- **Roles Limitadas**: Apenas Editor e Visualizador para novos usuários
- **Perfil do Usuário**: Interface para alterar senha
- **Controle de Acesso**: Permissões adequadas por role

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👥 Autores

- **Desenvolvedor Principal**: [Seu Nome](https://github.com/lucascdsm)

## 📞 Suporte

- **Issues**: [GitHub Issues](https://github.com/lucascdsm/lazyvulners/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lucascdsm/lazyvulners/discussions)
- **Email**: lucascm1358@gmail.com

## 🙏 Agradecimentos

- **Flask**: Framework web Python
- **SQLAlchemy**: ORM para Python
- **Bootstrap**: Framework CSS
- **ReportLab**: Geração de PDFs
- **Comunidade Python**: Suporte e contribuições

---

**LazyVulners** - Simplificando o gerenciamento de vulnerabilidades para profissionais de segurança! 🛡️✨
