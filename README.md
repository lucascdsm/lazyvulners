# 🛡️ LazyVulners - Sistema de Gerenciamento de Vulnerabilidades

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![SQLite](https://img.shields.io/badge/SQLite-3+-lightblue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

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

## 🔧 Configuração Avançada

### Variáveis de Ambiente

```bash
# Chave secreta para sessões (obrigatório em produção)
export SECRET_KEY="sua-chave-secreta-aqui"

# Configurações de banco de dados (opcional)
export DATABASE_URL="sqlite:///app.sqlite"
```

### Configurações de Segurança

O sistema inclui várias camadas de segurança:

- **CSRF Protection**: Proteção contra ataques CSRF
- **Validação de Senhas**: Senhas fortes obrigatórias
- **Controle de Acesso**: Permissões por role e empresa
- **Sessões Seguras**: Cookies seguros e HTTPOnly
- **Upload Seguro**: Validação de tipos e tamanhos de arquivo

### Personalização de Templates

Os templates de relatório podem ser completamente personalizados:

1. **Acesse**: Relatórios → Templates Customizáveis
2. **Crie um novo template** ou edite existente
3. **Configure seções**: Escolha quais seções incluir
4. **Personalize conteúdo**: Texto, cores, fontes
5. **Teste o template**: Visualize antes de usar

## 📊 Banco de Dados

### Modelos Principais

#### User (Usuário)
- `id`: Identificador único
- `username`: Nome de usuário
- `password_hash`: Hash da senha
- `role`: Papel (admin, editor, viewer)
- `company`: Empresa do usuário
- `created_at`: Data de criação

#### Vulnerability (Vulnerabilidade)
- `id`: Identificador único
- `title`: Título da vulnerabilidade
- `severity`: Severidade (Critical, High, Medium, Low, Informative)
- `status`: Status (Open, In Progress, Closed)
- `cvss`: Score CVSS
- `company`: Empresa
- `description`: Descrição técnica
- `impact`: Análise de impacto
- `likelihood`: Análise de probabilidade
- `remediation`: Passos de remediação
- `references`: Referências
- `comments`: Comentários
- `client_name`: Nome do cliente (freelancer)
- `project_name`: Nome do projeto (freelancer)
- `test_type`: Tipo de teste (freelancer)
- `test_date`: Data do teste (freelancer)
- `tester_name`: Nome do pentester (freelancer)
- `client_contact`: Contato do cliente (freelancer)
- `created_at`: Data de criação
- `updated_at`: Data de atualização

#### ReportTemplate (Template de Relatório)
- `id`: Identificador único
- `company`: Empresa
- `name`: Nome do template
- `description`: Descrição
- `cover_title`: Título da capa
- `cover_subtitle`: Subtítulo da capa
- `cover_company`: Empresa na capa
- `cover_date`: Data na capa
- `cover_logo_url`: URL do logo
- `legal_notice`: Aviso legal
- `introduction`: Introdução
- `executive_summary`: Sumário executivo
- `scope`: Escopo
- `methodology`: Metodologia
- `risk_classification`: Classificação de riscos
- `primary_color`: Cor primária
- `secondary_color`: Cor secundária
- `font_family`: Família da fonte
- `font_size`: Tamanho da fonte
- `include_*`: Flags para incluir seções
- `is_default`: Template padrão
- `created_at`: Data de criação
- `updated_at`: Data de atualização

## 🚀 Deploy em Produção

### 1. Configuração do Servidor

```bash
# Instalar dependências do sistema
sudo apt update
sudo apt install python3 python3-pip python3-venv nginx

# Configurar aplicação
git clone https://github.com/seu-usuario/lazyvulners.git
cd lazyvulners
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configuração do Nginx

```nginx
server {
    listen 80;
    server_name seu-dominio.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Configuração do Systemd

```ini
[Unit]
Description=LazyVulners Web Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/lazyvulners
Environment=PATH=/path/to/lazyvulners/venv/bin
ExecStart=/path/to/lazyvulners/venv/bin/python run.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### 4. Configurações de Segurança

```bash
# Configurar HTTPS
sudo certbot --nginx -d seu-dominio.com

# Configurar firewall
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

## 🔧 Desenvolvimento

### Estrutura de Desenvolvimento

```bash
# Clonar repositório
git clone https://github.com/seu-usuario/lazyvulners.git
cd lazyvulners

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r requirements.txt

# Executar em modo desenvolvimento
python run.py
```

### Adicionando Novas Funcionalidades

1. **Modelos**: Adicione novos modelos em `app/models.py`
2. **Rotas**: Crie novas rotas em `app/views.py`
3. **Formulários**: Adicione formulários em `app/forms.py`
4. **Templates**: Crie templates em `templates/`
5. **Estilos**: Adicione CSS em `static/css/`

### Testes

```bash
# Executar testes (quando implementados)
python -m pytest tests/

# Teste de integração
python test_integration.py
```

## 📈 Melhorias Futuras

### Funcionalidades Planejadas

- **🔔 Notificações**: Sistema de alertas por email
- **📊 Analytics**: Dashboard avançado com métricas
- **🔗 Integrações**: APIs para ferramentas externas
- **📱 Mobile**: Aplicativo móvel
- **🌐 Multi-idioma**: Suporte a múltiplos idiomas
- **🤖 IA**: Sugestões automáticas de remediação
- **📈 Relatórios**: Mais tipos de relatórios
- **🔒 2FA**: Autenticação de dois fatores
- **📊 Métricas**: KPIs e dashboards avançados

### Melhorias Técnicas

- **⚡ Performance**: Otimização de consultas
- **🔒 Segurança**: Auditoria de segurança
- **📱 Responsivo**: Interface mobile-first
- **🧪 Testes**: Cobertura de testes completa
- **📚 Documentação**: Documentação da API
- **🐳 Docker**: Containerização
- **☁️ Cloud**: Deploy em nuvem

## 🤝 Contribuição

### Como Contribuir

1. **Fork** o repositório
2. **Crie** uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. **Push** para a branch (`git push origin feature/nova-funcionalidade`)
5. **Abra** um Pull Request

### Padrões de Código

- **Python**: PEP 8
- **HTML**: HTML5 semântico
- **CSS**: BEM methodology
- **JavaScript**: ES6+
- **Commits**: Conventional Commits

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👥 Autores

- **Desenvolvedor Principal**: [Seu Nome](https://github.com/seu-usuario)
- **Contribuidores**: Veja [CONTRIBUTORS.md](CONTRIBUTORS.md)

## 📞 Suporte

- **Issues**: [GitHub Issues](https://github.com/seu-usuario/lazyvulners/issues)
- **Discussions**: [GitHub Discussions](https://github.com/seu-usuario/lazyvulners/discussions)
- **Email**: suporte@lazyvulners.com

## 🙏 Agradecimentos

- **Flask**: Framework web Python
- **SQLAlchemy**: ORM para Python
- **Bootstrap**: Framework CSS
- **ReportLab**: Geração de PDFs
- **Comunidade Python**: Suporte e contribuições

---

**LazyVulners** - Simplificando o gerenciamento de vulnerabilidades para profissionais de segurança! 🛡️✨