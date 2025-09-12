# Security Examples

## Visão Geral

Este documento contém exemplos práticos de implementação de recursos de segurança no SentinelIQ SDK, incluindo gerenciamento seguro de credenciais, validação de entrada e controles de acesso.

## Exemplo 1: Analyzer Seguro Básico

### Implementação Completa

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata
import requests
import re
from typing import Dict, Any

class SecureVirusTotalAnalyzer(Analyzer):
    """Analyzer VirusTotal com implementação de segurança completa."""
    
    METADATA = ModuleMetadata(
        name="Secure VirusTotal Analyzer",
        description="Análise segura de IPs usando VirusTotal API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/secure_virustotal/",
        version_stage="TESTING",
    )
    
    BASE_URL = "https://www.virustotal.com/vtapi/v2"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SentinelIQ-SDK/1.0'
        })
    
    def validate_secrets(self) -> bool:
        """Valida se todos os secrets necessários estão presentes."""
        try:
            api_key = self.get_secret("virustotal.api_key", "VirusTotal API key obrigatória")
            
            # Validar formato da API key
            if not re.match(r'^[a-f0-9]{64}$', api_key):
                self.logger.error("Formato de API key inválido")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro na validação de secrets: {e}")
            return False
    
    def validate_input(self, ip: str) -> bool:
        """Valida entrada de IP."""
        from ipaddress import ip_address, AddressValueError
        
        try:
            # Validar formato de IP
            ip_obj = ip_address(ip)
            
            # Verificar se não é IP privado (opcional)
            if ip_obj.is_private:
                self.logger.warning(f"IP privado detectado: {ip}")
            
            return True
            
        except AddressValueError:
            self.logger.error(f"IP inválido: {ip}")
            return False
    
    def sanitize_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove dados sensíveis dos logs."""
        sanitized = data.copy()
        
        # Remover API key se presente
        if 'apikey' in sanitized:
            sanitized['apikey'] = '***REDACTED***'
        
        # Limitar tamanho de campos grandes
        for key, value in sanitized.items():
            if isinstance(value, str) and len(value) > 100:
                sanitized[key] = value[:100] + '...'
        
        return sanitized
    
    def make_secure_request(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Faz requisição segura para a API."""
        # Log sanitizado da requisição
        safe_params = self.sanitize_log_data(params)
        self.logger.info(f"Fazendo requisição para {endpoint} com params: {safe_params}")
        
        try:
            # Configurar timeout
            timeout = self.get_config("virustotal.timeout", 30)
            
            # Fazer requisição
            response = self.session.get(
                endpoint,
                params=params,
                timeout=timeout,
                verify=True  # Sempre verificar SSL
            )
            
            # Verificar status
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.Timeout:
            raise Exception("Timeout na requisição para VirusTotal")
        except requests.exceptions.SSLError:
            raise Exception("Erro de SSL na conexão com VirusTotal")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                raise Exception("API key inválida ou sem permissão")
            elif e.response.status_code == 429:
                raise Exception("Rate limit excedido")
            else:
                raise Exception(f"Erro HTTP: {e.response.status_code}")
    
    def execute(self) -> AnalyzerReport:
        # Validar secrets
        if not self.validate_secrets():
            return self.report({
                "error": "invalid_secrets",
                "message": "Credenciais inválidas ou ausentes",
                "metadata": self.METADATA.to_dict()
            })
        
        # Obter e validar dados
        ip = self.get_data()
        if not self.validate_input(ip):
            return self.report({
                "error": "invalid_input",
                "message": "IP inválido",
                "observable": ip,
                "metadata": self.METADATA.to_dict()
            })
        
        # Verificar controles TLP/PAP
        input_tlp = self.get_tlp()
        max_tlp = self.get_config("security.max_tlp", 2)
        
        if input_tlp > max_tlp:
            return self.report({
                "error": "tlp_violation",
                "message": f"TLP {input_tlp} excede máximo permitido {max_tlp}",
                "observable": ip,
                "metadata": self.METADATA.to_dict()
            })
        
        try:
            # Obter API key
            api_key = self.get_secret("virustotal.api_key")
            
            # Fazer requisição segura
            endpoint = f"{self.BASE_URL}/ip-address/report"
            params = {
                "apikey": api_key,
                "ip": ip
            }
            
            data = self.make_secure_request(endpoint, params)
            
            # Processar resposta
            if data.get("response_code") == 1:
                detected_urls = len(data.get("detected_urls", []))
                detected_samples = len(data.get("detected_downloaded_samples", []))
                
                # Calcular score de ameaça
                threat_score = min(100, detected_urls * 10 + detected_samples * 5)
                
                # Determinar veredito
                if threat_score >= 70:
                    verdict = "malicious"
                elif threat_score >= 30:
                    verdict = "suspicious"
                else:
                    verdict = "safe"
                
                # Construir taxonomia
                taxonomy = self.build_taxonomy(
                    level=verdict,
                    namespace="virustotal",
                    predicate="ip-reputation",
                    value=ip
                )
                
                result = {
                    "observable": ip,
                    "verdict": verdict,
                    "taxonomy": [taxonomy.to_dict()],
                    "threat_score": threat_score,
                    "details": {
                        "detected_urls": detected_urls,
                        "detected_samples": detected_samples,
                        "country": data.get("country"),
                        "asn": data.get("asn")
                    },
                    "tlp": max(input_tlp, 1),  # Mínimo GREEN para resultados
                    "metadata": self.METADATA.to_dict()
                }
            else:
                result = {
                    "observable": ip,
                    "verdict": "info",
                    "message": "IP não encontrado no VirusTotal",
                    "tlp": input_tlp,
                    "metadata": self.METADATA.to_dict()
                }
            
            return self.report(result)
            
        except Exception as e:
            self.logger.error(f"Erro na análise: {e}")
            return self.report({
                "error": "analysis_failed",
                "message": str(e),
                "observable": ip,
                "metadata": self.METADATA.to_dict()
            })

# Exemplo de uso
if __name__ == "__main__":
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description="Secure VirusTotal Analyzer Example")
    parser.add_argument("--ip", required=True, help="IP para analisar")
    parser.add_argument("--api-key", help="VirusTotal API key (ou use VT_API_KEY env var)")
    parser.add_argument("--execute", action="store_true", help="Executar análise real")
    
    args = parser.parse_args()
    
    if not args.execute:
        print("Modo dry-run. Use --execute para análise real.")
        exit(0)
    
    # Configurar credenciais
    api_key = args.api_key or os.getenv("VT_API_KEY")
    if not api_key:
        print("Erro: API key não fornecida")
        exit(1)
    
    # Criar configuração
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        secrets={
            "virustotal": {
                "api_key": api_key
            },
            "security": {
                "max_tlp": 2
            }
        }
    )
    
    # Criar input
    worker_input = WorkerInput(
        data_type="ip",
        data=args.ip,
        tlp=1,  # GREEN
        pap=1,  # GREEN
        config=config
    )
    
    # Executar analyzer
    analyzer = SecureVirusTotalAnalyzer(worker_input)
    result = analyzer.run()
    
    print(f"Resultado: {result.to_dict()}")
```

## Exemplo 2: Validação Avançada de Entrada

### Validator Personalizado

```python
from __future__ import annotations

import re
import hashlib
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network, AddressValueError
from typing import Dict, List, Optional, Tuple

class AdvancedInputValidator:
    """Validador avançado de entrada com múltiplas verificações."""
    
    # Padrões de validação
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # Subdomínios
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'        # Domínio principal
    )
    
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
    }
    
    # Listas de bloqueio
    PRIVATE_IP_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '::1/128',
        'fc00::/7',
        'fe80::/10'
    ]
    
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',  # URL shorteners
        'tempmail.org', '10minutemail.com',         # Temp email
    ]
    
    @classmethod
    def validate_ip(cls, ip: str) -> Tuple[bool, Optional[str], Dict[str, any]]:
        """Valida IP com verificações avançadas."""
        try:
            ip_obj = ip_address(ip)
            
            metadata = {
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback
            }
            
            # Verificações de segurança
            if ip_obj.is_private:
                return False, "IP privado não permitido", metadata
            
            if ip_obj.is_multicast:
                return False, "IP multicast não permitido", metadata
            
            if ip_obj.is_reserved:
                return False, "IP reservado não permitido", metadata
            
            if ip_obj.is_loopback:
                return False, "IP loopback não permitido", metadata
            
            return True, None, metadata
            
        except AddressValueError as e:
            return False, f"Formato de IP inválido: {e}", {}
    
    @classmethod
    def validate_domain(cls, domain: str) -> Tuple[bool, Optional[str], Dict[str, any]]:
        """Valida domínio com verificações avançadas."""
        # Verificações básicas
        if not domain or len(domain) > 253:
            return False, "Domínio muito longo", {}
        
        if not cls.DOMAIN_PATTERN.match(domain):
            return False, "Formato de domínio inválido", {}
        
        # Verificar caracteres suspeitos
        if any(char in domain for char in ['..', '--', '__']):
            return False, "Caracteres suspeitos no domínio", {}
        
        # Verificar domínios suspeitos
        domain_lower = domain.lower()
        for suspicious in cls.SUSPICIOUS_DOMAINS:
            if suspicious in domain_lower:
                return False, f"Domínio suspeito detectado: {suspicious}", {
                    'suspicious_match': suspicious
                }
        
        # Verificar IDN (Internationalized Domain Names)
        try:
            ascii_domain = domain.encode('ascii')
        except UnicodeEncodeError:
            return False, "Domínio contém caracteres não-ASCII", {
                'contains_unicode': True
            }
        
        metadata = {
            'length': len(domain),
            'labels': domain.count('.') + 1,
            'tld': domain.split('.')[-1] if '.' in domain else None
        }
        
        return True, None, metadata
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, Optional[str], Dict[str, any]]:
        """Valida URL com verificações avançadas."""
        try:
            parsed = urlparse(url)
            
            # Verificações básicas
            if not all([parsed.scheme, parsed.netloc]):
                return False, "URL incompleta", {}
            
            # Verificar esquemas permitidos
            allowed_schemes = ['http', 'https', 'ftp', 'ftps']
            if parsed.scheme.lower() not in allowed_schemes:
                return False, f"Esquema não permitido: {parsed.scheme}", {
                    'scheme': parsed.scheme
                }
            
            # Validar domínio da URL
            domain_valid, domain_error, domain_meta = cls.validate_domain(parsed.netloc)
            if not domain_valid:
                return False, f"Domínio inválido na URL: {domain_error}", domain_meta
            
            # Verificar caracteres suspeitos no path
            suspicious_patterns = [
                r'\.\./',  # Directory traversal
                r'%2e%2e%2f',  # Encoded directory traversal
                r'<script',  # XSS
                r'javascript:',  # JavaScript URLs
            ]
            
            full_url = url.lower()
            for pattern in suspicious_patterns:
                if re.search(pattern, full_url):
                    return False, f"Padrão suspeito detectado: {pattern}", {
                        'suspicious_pattern': pattern
                    }
            
            metadata = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path_length': len(parsed.path),
                'has_query': bool(parsed.query),
                'has_fragment': bool(parsed.fragment)
            }
            
            return True, None, metadata
            
        except Exception as e:
            return False, f"Erro ao analisar URL: {e}", {}
    
    @classmethod
    def validate_hash(cls, hash_value: str, expected_type: str = None) -> Tuple[bool, Optional[str], Dict[str, any]]:
        """Valida hash com verificações avançadas."""
        if not hash_value:
            return False, "Hash vazio", {}
        
        # Verificar caracteres válidos
        if not re.match(r'^[a-fA-F0-9]+$', hash_value):
            return False, "Hash contém caracteres inválidos", {}
        
        # Detectar tipo de hash
        detected_types = []
        for hash_type, pattern in cls.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                detected_types.append(hash_type)
        
        if not detected_types:
            return False, "Tipo de hash não reconhecido", {
                'length': len(hash_value)
            }
        
        # Verificar tipo esperado
        if expected_type and expected_type.lower() not in detected_types:
            return False, f"Hash não é do tipo esperado {expected_type}", {
                'detected_types': detected_types,
                'expected_type': expected_type
            }
        
        metadata = {
            'detected_types': detected_types,
            'length': len(hash_value),
            'uppercase': hash_value.isupper(),
            'lowercase': hash_value.islower()
        }
        
        return True, None, metadata
    
    @classmethod
    def validate_email(cls, email: str) -> Tuple[bool, Optional[str], Dict[str, any]]:
        """Valida email com verificações avançadas."""
        if not email or len(email) > 254:
            return False, "Email muito longo", {}
        
        if not cls.EMAIL_PATTERN.match(email):
            return False, "Formato de email inválido", {}
        
        # Separar local e domínio
        local, domain = email.rsplit('@', 1)
        
        # Validar parte local
        if len(local) > 64:
            return False, "Parte local do email muito longa", {}
        
        # Validar domínio
        domain_valid, domain_error, domain_meta = cls.validate_domain(domain)
        if not domain_valid:
            return False, f"Domínio inválido no email: {domain_error}", domain_meta
        
        # Verificar domínios de email temporário
        temp_domains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com']
        if domain.lower() in temp_domains:
            return False, "Domínio de email temporário detectado", {
                'temp_domain': domain
            }
        
        metadata = {
            'local_part': local,
            'domain_part': domain,
            'local_length': len(local),
            'total_length': len(email)
        }
        
        return True, None, metadata

# Analyzer usando validação avançada
class ValidatedAnalyzer(Analyzer):
    """Analyzer com validação avançada de entrada."""
    
    METADATA = ModuleMetadata(
        name="Validated Analyzer",
        description="Analyzer com validação avançada de entrada",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="validation",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/validated/",
        version_stage="TESTING",
    )
    
    def execute(self) -> AnalyzerReport:
        data = self.get_data()
        data_type = self.get_data_type()
        
        # Validar baseado no tipo
        validation_methods = {
            'ip': AdvancedInputValidator.validate_ip,
            'domain': AdvancedInputValidator.validate_domain,
            'url': AdvancedInputValidator.validate_url,
            'hash': AdvancedInputValidator.validate_hash,
            'mail': AdvancedInputValidator.validate_email
        }
        
        validator = validation_methods.get(data_type)
        if not validator:
            return self.report({
                "error": "unsupported_type",
                "message": f"Tipo de dados não suportado: {data_type}",
                "observable": data,
                "metadata": self.METADATA.to_dict()
            })
        
        # Executar validação
        is_valid, error_message, validation_metadata = validator(data)
        
        if not is_valid:
            taxonomy = self.build_taxonomy(
                level="malicious",
                namespace="validation",
                predicate="invalid-input",
                value=data
            )
            
            return self.report({
                "observable": data,
                "verdict": "malicious",
                "taxonomy": [taxonomy.to_dict()],
                "validation": {
                    "status": "failed",
                    "error": error_message,
                    "metadata": validation_metadata
                },
                "metadata": self.METADATA.to_dict()
            })
        
        # Dados válidos - continuar com análise
        taxonomy = self.build_taxonomy(
            level="safe",
            namespace="validation",
            predicate="valid-input",
            value=data
        )
        
        return self.report({
            "observable": data,
            "verdict": "safe",
            "taxonomy": [taxonomy.to_dict()],
            "validation": {
                "status": "passed",
                "metadata": validation_metadata
            },
            "metadata": self.METADATA.to_dict()
        })
```

## Exemplo 3: Criptografia e Armazenamento Seguro

### Sistema de Criptografia

```python
from __future__ import annotations

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from typing import Dict, Any, Optional

class SecureStorage:
    """Sistema de armazenamento seguro com criptografia."""
    
    def __init__(self, master_password: str, salt: Optional[bytes] = None):
        self.salt = salt or os.urandom(16)
        self.key = self._derive_key(master_password.encode(), self.salt)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Deriva chave de criptografia usando PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_data(self, data: Dict[str, Any]) -> str:
        """Criptografa dados em formato JSON."""
        json_data = json.dumps(data, sort_keys=True)
        encrypted = self.cipher.encrypt(json_data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Descriptografa dados JSON."""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return json.loads(decrypted.decode())
    
    def encrypt_string(self, text: str) -> str:
        """Criptografa string simples."""
        encrypted = self.cipher.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """Descriptografa string simples."""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()

# Analyzer com armazenamento seguro
class SecureStorageAnalyzer(Analyzer):
    """Analyzer que usa armazenamento seguro para cache."""
    
    METADATA = ModuleMetadata(
        name="Secure Storage Analyzer",
        description="Analyzer com armazenamento seguro de cache",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="secure-storage",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/secure_storage/",
        version_stage="TESTING",
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Inicializar armazenamento seguro
        master_key = self.get_secret("encryption.master_key", "Chave de criptografia obrigatória")
        salt = self.get_secret("encryption.salt", "Salt de criptografia obrigatório")
        
        self.secure_storage = SecureStorage(master_key, salt.encode())
        self.cache_file = self.get_config("cache.file_path", "/tmp/secure_cache.enc")
    
    def load_cache(self) -> Dict[str, Any]:
        """Carrega cache criptografado."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    encrypted_data = f.read()
                return self.secure_storage.decrypt_data(encrypted_data)
            return {}
        except Exception as e:
            self.logger.warning(f"Erro ao carregar cache: {e}")
            return {}
    
    def save_cache(self, cache_data: Dict[str, Any]):
        """Salva cache criptografado."""
        try:
            encrypted_data = self.secure_storage.encrypt_data(cache_data)
            
            # Criar diretório se não existir
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            
            # Salvar com permissões restritas
            with open(self.cache_file, 'w') as f:
                f.write(encrypted_data)
            
            # Definir permissões apenas para o proprietário
            os.chmod(self.cache_file, 0o600)
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar cache: {e}")
    
    def get_cached_result(self, observable: str) -> Optional[Dict[str, Any]]:
        """Obtém resultado do cache seguro."""
        cache = self.load_cache()
        
        # Usar hash do observable como chave
        cache_key = hashlib.sha256(observable.encode()).hexdigest()
        
        cached_entry = cache.get(cache_key)
        if cached_entry:
            # Verificar se não expirou
            from datetime import datetime, timedelta
            
            cached_time = datetime.fromisoformat(cached_entry['timestamp'])
            cache_ttl = self.get_config("cache.ttl_hours", 24)
            
            if datetime.utcnow() - cached_time < timedelta(hours=cache_ttl):
                self.logger.info(f"Cache hit para {observable[:10]}...")
                return cached_entry['result']
            else:
                self.logger.info(f"Cache expirado para {observable[:10]}...")
        
        return None
    
    def cache_result(self, observable: str, result: Dict[str, Any]):
        """Armazena resultado no cache seguro."""
        cache = self.load_cache()
        
        cache_key = hashlib.sha256(observable.encode()).hexdigest()
        
        cache[cache_key] = {
            'timestamp': datetime.utcnow().isoformat(),
            'result': result
        }
        
        # Limitar tamanho do cache
        max_entries = self.get_config("cache.max_entries", 1000)
        if len(cache) > max_entries:
            # Remover entradas mais antigas
            sorted_entries = sorted(
                cache.items(),
                key=lambda x: x[1]['timestamp']
            )
            
            # Manter apenas as mais recentes
            cache = dict(sorted_entries[-max_entries:])
        
        self.save_cache(cache)
    
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        
        # Tentar cache primeiro
        cached_result = self.get_cached_result(observable)
        if cached_result:
            return self.report(cached_result)
        
        # Executar análise
        result = self.perform_analysis(observable)
        
        # Armazenar no cache
        self.cache_result(observable, result)
        
        return self.report(result)
    
    def perform_analysis(self, observable: str) -> Dict[str, Any]:
        """Executa análise real (implementar conforme necessário)."""
        # Simular análise
        taxonomy = self.build_taxonomy(
            level="safe",
            namespace="secure-storage",
            predicate="cached-analysis",
            value=observable
        )
        
        return {
            "observable": observable,
            "verdict": "safe",
            "taxonomy": [taxonomy.to_dict()],
            "analysis_time": datetime.utcnow().isoformat(),
            "metadata": self.METADATA.to_dict()
        }
```

## Exemplo 4: Auditoria e Monitoramento

### Sistema de Auditoria Completo

```python
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

class SecurityAuditor:
    """Sistema de auditoria de segurança."""
    
    def __init__(self, log_file: str = "/var/log/sentineliq/security.log"):
        self.log_file = Path(log_file)
        self.setup_logging()
    
    def setup_logging(self):
        """Configura logging de auditoria."""
        # Criar diretório se não existir
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configurar logger
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(logging.INFO)
        
        # Handler para arquivo
        handler = logging.FileHandler(self.log_file)
        handler.setLevel(logging.INFO)
        
        # Formato estruturado
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          severity: str = "INFO", user_id: Optional[str] = None):
        """Registra evento de segurança."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "details": self._sanitize_details(details),
            "session_id": self._get_session_id()
        }
        
        # Log estruturado
        log_message = f"SECURITY_EVENT: {json.dumps(event)}"
        
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "ERROR":
            self.logger.error(log_message)
        elif severity == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Remove dados sensíveis dos detalhes."""
        sanitized = {}
        
        for key, value in details.items():
            # Chaves sensíveis
            if any(sensitive in key.lower() for sensitive in 
                   ['password', 'key', 'token', 'secret', 'credential']):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + "..."
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _get_session_id(self) -> str:
        """Obtém ID da sessão atual."""
        # Implementar lógica de sessão
        return "session_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")

# Analyzer com auditoria completa
class AuditedAnalyzer(Analyzer):
    """Analyzer com auditoria completa de segurança."""
    
    METADATA = ModuleMetadata(
        name="Audited Analyzer",
        description="Analyzer com auditoria completa de segurança",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="audited",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/audited/",
        version_stage="TESTING",
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Inicializar auditor
        audit_log_path = self.get_config("audit.log_path", "/var/log/sentineliq/security.log")
        self.auditor = SecurityAuditor(audit_log_path)
        
        # Log início da sessão
        self.auditor.log_security_event(
            "analyzer_initialized",
            {
                "analyzer_name": self.__class__.__name__,
                "data_type": self.get_data_type(),
                "tlp": self.get_tlp(),
                "pap": self.get_pap()
            }
        )
    
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        
        # Log início da análise
        self.auditor.log_security_event(
            "analysis_started",
            {
                "observable_hash": hashlib.sha256(observable.encode()).hexdigest(),
                "observable_type": self.get_data_type(),
                "tlp": self.get_tlp(),
                "pap": self.get_pap()
            }
        )
        
        try:
            # Verificar permissões
            if not self._check_permissions():
                self.auditor.log_security_event(
                    "permission_denied",
                    {
                        "analyzer": self.__class__.__name__,
                        "reason": "insufficient_permissions"
                    },
                    severity="WARNING"
                )
                
                return self.report({
                    "error": "permission_denied",
                    "message": "Permissões insuficientes",
                    "metadata": self.METADATA.to_dict()
                })
            
            # Executar análise
            result = self._perform_secure_analysis(observable)
            
            # Log sucesso
            self.auditor.log_security_event(
                "analysis_completed",
                {
                    "verdict": result.get("verdict"),
                    "threat_score": result.get("threat_score", 0),
                    "execution_time_ms": result.get("execution_time_ms", 0)
                }
            )
            
            return self.report(result)
            
        except Exception as e:
            # Log erro
            self.auditor.log_security_event(
                "analysis_failed",
                {
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "observable_hash": hashlib.sha256(observable.encode()).hexdigest()
                },
                severity="ERROR"
            )
            
            # Re-raise para tratamento normal
            raise
    
    def _check_permissions(self) -> bool:
        """Verifica permissões de execução."""
        # Verificar TLP/PAP
        input_tlp = self.get_tlp()
        input_pap = self.get_pap()
        
        max_tlp = self.get_config("security.max_tlp", 2)
        max_pap = self.get_config("security.max_pap", 2)
        
        if input_tlp > max_tlp or input_pap > max_pap:
            return False
        
        # Verificar outras permissões conforme necessário
        return True
    
    def _perform_secure_analysis(self, observable: str) -> Dict[str, Any]:
        """Executa análise com medidas de segurança."""
        start_time = datetime.utcnow()
        
        # Simular análise
        import time
        time.sleep(0.1)  # Simular processamento
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds() * 1000
        
        # Log acesso a recursos externos (se houver)
        self.auditor.log_security_event(
            "external_api_access",
            {
                "api_endpoint": "example.com/api",
                "response_code": 200,
                "response_time_ms": execution_time
            }
        )
        
        taxonomy = self.build_taxonomy(
            level="safe",
            namespace="audited",
            predicate="secure-analysis",
            value=observable
        )
        
        return {
            "observable": observable,
            "verdict": "safe",
            "taxonomy": [taxonomy.to_dict()],
            "threat_score": 10,
            "execution_time_ms": execution_time,
            "analysis_timestamp": end_time.isoformat(),
            "metadata": self.METADATA.to_dict()
        }
```

## Veja Também

- [Security Guide](../guides/security.md)
- [WorkerConfig](../core/worker-config.md)
- [Secrets Management](../core/secrets.md)
- [Building Analyzers](../tutorials/building-analyzers.md)
- [Threat Intelligence](../guides/threat-intelligence.md)