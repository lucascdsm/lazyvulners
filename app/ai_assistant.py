"""
AI Vulnerability Assistant
Sistema inteligente para análise automática de vulnerabilidades
"""

import google.generativeai as genai
from flask import current_app
import json
import re
from typing import Dict, List, Optional, Tuple
from .models import AIConfig, Vulnerability


class AIAssistant:
    """AI Vulnerability Assistant usando Google Gemini"""
    
    def __init__(self, api_key: str):
        """Inicializa o AI Assistant com a API key do Gemini"""
        genai.configure(api_key=api_key)
        
        # Listar modelos disponíveis e escolher o melhor
        try:
            models = genai.list_models()
            available_models = []
            
            for model in models:
                if 'generateContent' in model.supported_generation_methods:
                    # Evitar modelos experimentais que podem ter quotas restritivas
                    if not any(exp in model.name.lower() for exp in ['exp', 'experimental', 'beta', 'preview']):
                        available_models.append(model.name)
            
            # Priorizar modelos estáveis com boa quota gratuita
            preferred_models = [
                'models/gemini-1.5-flash',  # Modelo mais eficiente para quota gratuita
                'models/gemini-1.5-pro',    # Modelo robusto com boa quota
                'models/gemini-pro',        # Modelo estável
                'models/gemini-1.0-pro'     # Fallback estável
            ]
            
            # Encontrar o primeiro modelo preferido que está disponível
            selected_model = None
            for preferred in preferred_models:
                if preferred in available_models:
                    selected_model = preferred
                    break
            
            if not selected_model and available_models:
                # Se nenhum modelo preferido estiver disponível, usar o primeiro disponível
                selected_model = available_models[0]
            
            if selected_model:
                self.model = genai.GenerativeModel(selected_model)
                print(f"AI Assistant usando modelo: {selected_model}")
            else:
                raise Exception("Nenhum modelo disponível encontrado")
                
        except Exception as e:
            print(f"Erro ao listar modelos: {e}")
            # Fallback para modelo padrão
            try:
                self.model = genai.GenerativeModel('gemini-pro')
                print("AI Assistant usando modelo padrão: gemini-pro")
            except Exception:
                raise Exception("Não foi possível inicializar nenhum modelo do Gemini")
    
    def analyze_vulnerability(self, description: str, title: str = "") -> Dict:
        """
        Analisa uma vulnerabilidade e retorna sugestões automáticas
        """
        try:
            prompt = f"""
            Você é um especialista em segurança da informação. Analise a seguinte vulnerabilidade e forneça:

            TÍTULO: {title}
            DESCRIÇÃO: {description}

            Retorne APENAS um JSON com as seguintes informações:
            {{
                "title": "Título técnico e descritivo da vulnerabilidade",
                "improved_description": "Descrição melhorada com linguagem técnica e detalhes",
                "severity": "Critical|High|Medium|Low|Informative",
                "cvss_score": "0.0-10.0",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "remediation": "Sugestão detalhada de remediação",
                "impact": "Descrição do impacto da vulnerabilidade",
                "likelihood": "Descrição da probabilidade de exploração",
                "similar_vulns": ["Lista de vulnerabilidades similares conhecidas"],
                "executive_summary": "Resumo executivo para gestores",
                "references": "Referências técnicas (CVE, OWASP, NIST, etc.)"
            }}

            IMPORTANTE: 
            - Use apenas texto simples, SEM formatação markdown (**, *, etc.)
            - Para CVSS: Critical=9.0-10.0, High=7.0-8.9, Medium=4.0-6.9, Low=0.1-3.9, Informative=0.0
            - Seja preciso e técnico. Use padrões OWASP e NIST quando aplicável.
            - Inclua referências técnicas relevantes (CVE, OWASP Top 10, etc.)
            - O título deve ser conciso, técnico e descritivo (máximo 200 caracteres)
            """
            
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                raise Exception("Resposta vazia do modelo")
                
            result = self._parse_json_response(response.text)
            
            return {
                'success': True,
                'data': result
            }
            
        except Exception as e:
            # Log do erro para debug
            error_msg = str(e)
            print(f"Erro na análise AI: {error_msg}")
            
            # Tratar erros específicos
            if "404" in error_msg and "models" in error_msg:
                return {
                    'success': False,
                    'error': 'Modelo não disponível. Verifique sua API Key e tente novamente.'
                }
            elif "403" in error_msg:
                return {
                    'success': False,
                    'error': 'API Key inválida ou sem permissões. Verifique sua configuração.'
                }
            elif "quota" in error_msg.lower() or "429" in error_msg:
                # Extrair tempo de retry se disponível
                retry_seconds = 0
                if "retry in" in error_msg.lower():
                    try:
                        import re
                        match = re.search(r'retry in (\d+\.?\d*)s', error_msg.lower())
                        if match:
                            retry_seconds = int(float(match.group(1)))
                    except:
                        pass
                
                if retry_seconds > 0:
                    return {
                        'success': False,
                        'error': f'Limite de cota excedido. Tente novamente em {retry_seconds} segundos.',
                        'retry_after': retry_seconds
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Limite de cota gratuita excedido. Aguarde algumas horas ou considere fazer upgrade do plano. Dica: Use o modelo gemini-1.5-flash para melhor eficiência de quota.'
                    }
            else:
                return {
                    'success': False,
                    'error': f"Erro na análise: {error_msg}"
                }
    
    def detect_similar_vulnerabilities(self, description: str, company: str) -> List[Dict]:
        """
        Detecta vulnerabilidades similares no banco de dados
        """
        try:
            # Buscar vulnerabilidades da mesma empresa
            existing_vulns = Vulnerability.query.filter_by(company=company).all()
            
            if not existing_vulns:
                return []
            
            # Criar prompt para comparação
            vuln_titles = [f"- {v.title}" for v in existing_vulns[:10]]  # Limitar a 10 para não sobrecarregar
            vuln_list = "\n".join(vuln_titles)
            
            prompt = f"""
            Analise a seguinte vulnerabilidade e compare com a lista de vulnerabilidades existentes.
            
            NOVA VULNERABILIDADE:
            {description}
            
            VULNERABILIDADES EXISTENTES:
            {vuln_list}
            
            Retorne APENAS um JSON com vulnerabilidades similares:
            {{
                "similar_vulnerabilities": [
                    {{
                        "title": "Título da vulnerabilidade similar",
                        "similarity_score": "0.0-1.0",
                        "reason": "Motivo da similaridade"
                    }}
                ]
            }}
            """
            
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            
            return result.get('similar_vulnerabilities', [])
            
        except Exception as e:
            return []
    
    def generate_executive_summary(self, vulnerabilities: List[Dict]) -> str:
        """
        Gera um resumo executivo das vulnerabilidades
        """
        try:
            # Preparar dados das vulnerabilidades
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append({
                    'title': vuln.get('title', ''),
                    'severity': vuln.get('severity', ''),
                    'description': vuln.get('description', '')[:200] + '...' if len(vuln.get('description', '')) > 200 else vuln.get('description', '')
                })
            
            prompt = f"""
            Gere um resumo executivo para gestores sobre as seguintes vulnerabilidades de segurança:
            
            {json.dumps(vuln_data, indent=2, ensure_ascii=False)}
            
            O resumo deve:
            - Ser claro e direto para executivos
            - Destacar os riscos principais
            - Incluir recomendações de ação
            - Ter no máximo 300 palavras
            - Usar linguagem profissional mas acessível
            
            Retorne APENAS o texto do resumo executivo.
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            return f"Erro ao gerar resumo executivo: {str(e)}"
    
    def suggest_remediation(self, vulnerability_type: str, description: str) -> str:
        """
        Sugere remediação específica para um tipo de vulnerabilidade
        """
        try:
            prompt = f"""
            Como especialista em segurança, forneça uma remediação detalhada para:
            
            TIPO: {vulnerability_type}
            DESCRIÇÃO: {description}
            
            A remediação deve incluir:
            - Passos técnicos específicos
            - Melhores práticas de segurança
            - Verificações pós-implementação
            - Referências a padrões (OWASP, NIST, etc.)
            
            Seja técnico mas prático. Máximo 500 palavras.
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            return f"Erro ao gerar sugestão de remediação: {str(e)}"
    
    def improve_description(self, description: str) -> str:
        """
        Melhora a descrição de uma vulnerabilidade
        """
        try:
            prompt = f"""
            Como especialista em segurança da informação, melhore a seguinte descrição de vulnerabilidade:
            
            DESCRIÇÃO ORIGINAL: {description}
            
            Retorne APENAS a descrição melhorada com:
            - Linguagem técnica e precisa
            - Detalhes técnicos relevantes
            - Contexto de segurança
            - Informações sobre o impacto
            - Máximo 1000 palavras
            - Use apenas texto simples, SEM formatação markdown
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            return f"Erro ao melhorar descrição: {str(e)}"
    
    def generate_title(self, description: str) -> str:
        """
        Gera um título técnico para uma vulnerabilidade baseado na descrição
        """
        try:
            prompt = f"""
            Como especialista em segurança da informação, gere um título técnico e descritivo para a seguinte vulnerabilidade:
            
            DESCRIÇÃO: {description}
            
            O título deve:
            - Ser conciso e técnico (máximo 200 caracteres)
            - Descrever claramente a vulnerabilidade
            - Usar terminologia de segurança padrão
            - Ser específico sobre o tipo de falha
            - Não usar formatação markdown
            
            Retorne APENAS o título.
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            return f"Erro ao gerar título: {str(e)}"
    
    def _parse_json_response(self, text: str) -> Dict:
        """
        Extrai JSON da resposta do modelo
        """
        try:
            # Tentar encontrar JSON na resposta
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                # Se não encontrar JSON, tentar parsear toda a resposta
                result = json.loads(text)
            
            # Limpar formatação markdown de todos os campos de texto
            return self._clean_markdown_formatting(result)
            
        except json.JSONDecodeError:
            # Se falhar, retornar estrutura padrão
            return {
                "title": "Vulnerabilidade de Segurança",
                "improved_description": description,  # Manter descrição original se não conseguir melhorar
                "severity": "Medium",
                "cvss_score": "5.0",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "remediation": "Analise a vulnerabilidade e implemente as correções necessárias.",
                "impact": "Impacto a ser avaliado",
                "likelihood": "Probabilidade a ser avaliada",
                "similar_vulns": [],
                "executive_summary": "Resumo executivo a ser gerado",
                "references": "Referências a serem adicionadas"
            }
    
    def _clean_markdown_formatting(self, data: Dict) -> Dict:
        """
        Remove formatação markdown dos textos
        """
        cleaned_data = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # Remover formatação markdown comum
                cleaned_value = value
                cleaned_value = re.sub(r'\*\*(.*?)\*\*', r'\1', cleaned_value)  # **texto** -> texto
                cleaned_value = re.sub(r'\*(.*?)\*', r'\1', cleaned_value)      # *texto* -> texto
                cleaned_value = re.sub(r'__(.*?)__', r'\1', cleaned_value)      # __texto__ -> texto
                cleaned_value = re.sub(r'_(.*?)_', r'\1', cleaned_value)        # _texto_ -> texto
                cleaned_value = re.sub(r'`(.*?)`', r'\1', cleaned_value)        # `texto` -> texto
                cleaned_value = re.sub(r'#{1,6}\s*', '', cleaned_value)         # Remove headers
                cleaned_value = re.sub(r'^\s*[-*+]\s*', '', cleaned_value, flags=re.MULTILINE)  # Remove list markers
                cleaned_value = re.sub(r'\n\s*\n', '\n\n', cleaned_value)       # Normalize line breaks
                cleaned_value = cleaned_value.strip()
                cleaned_data[key] = cleaned_value
            elif isinstance(value, list):
                # Limpar formatação de listas também
                cleaned_list = []
                for item in value:
                    if isinstance(item, str):
                        cleaned_item = re.sub(r'\*\*(.*?)\*\*', r'\1', item)
                        cleaned_item = re.sub(r'\*(.*?)\*', r'\1', cleaned_item)
                        cleaned_item = cleaned_item.strip()
                        cleaned_list.append(cleaned_item)
                    else:
                        cleaned_list.append(item)
                cleaned_data[key] = cleaned_list
            else:
                cleaned_data[key] = value
        
        return cleaned_data


def get_ai_assistant(company: str) -> Optional[AIAssistant]:
    """
    Obtém instância do AI Assistant para uma empresa
    """
    try:
        ai_config = AIConfig.query.filter_by(company=company, ai_enabled=True).first()
        if not ai_config or not ai_config.gemini_api_key:
            return None
        
        return AIAssistant(ai_config.gemini_api_key)
    except Exception as e:
        print(f"Erro ao criar AI Assistant: {str(e)}")
        return None


def test_ai_connection(api_key: str) -> Dict:
    """
    Testa a conexão com a API do Gemini
    """
    try:
        genai.configure(api_key=api_key)
        
        # Listar modelos disponíveis
        models = genai.list_models()
        available_models = []
        
        for model in models:
            if 'generateContent' in model.supported_generation_methods:
                # Evitar modelos experimentais que podem ter quotas restritivas
                if not any(exp in model.name.lower() for exp in ['exp', 'experimental', 'beta', 'preview']):
                    available_models.append(model.name)
        
        if not available_models:
            return {
                'success': False,
                'error': 'Nenhum modelo disponível encontrado'
            }
        
        # Priorizar modelos estáveis com boa quota gratuita
        preferred_models = [
            'models/gemini-1.5-flash',  # Modelo mais eficiente para quota gratuita
            'models/gemini-1.5-pro',    # Modelo robusto com boa quota
            'models/gemini-pro',        # Modelo estável
            'models/gemini-1.0-pro'     # Fallback estável
        ]
        
        # Encontrar o primeiro modelo preferido que está disponível
        selected_model = None
        for preferred in preferred_models:
            if preferred in available_models:
                selected_model = preferred
                break
        
        if not selected_model:
            selected_model = available_models[0]
        
        # Testar o modelo selecionado
        model = genai.GenerativeModel(selected_model)
        response = model.generate_content("Teste de conectividade")
        
        if response and response.text:
            return {
                'success': True,
                'model': selected_model,
                'message': f'Conexão bem-sucedida com {selected_model}',
                'available_models': len(available_models)
            }
        else:
            return {
                'success': False,
                'error': 'Resposta vazia do modelo'
            }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Erro de configuração: {str(e)}'
        }


def is_ai_enabled(company: str) -> bool:
    """
    Verifica se o AI Assistant está habilitado para uma empresa
    """
    try:
        ai_config = AIConfig.query.filter_by(company=company).first()
        return ai_config and ai_config.ai_enabled and ai_config.gemini_api_key
    except Exception:
        return False
