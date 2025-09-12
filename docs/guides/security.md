# Security Guide

## Visão Geral

Este guia aborda as melhores práticas de segurança para desenvolvimento e uso do SentinelIQ SDK, incluindo gerenciamento seguro de credenciais, proteção de dados sensíveis e implementação de controles de segurança.

## Gerenciamento de Credenciais

### Princípios Fundamentais

#### Nunca Hardcode Credenciais
```python
# ❌ NUNCA faça isso
api_key = "sk-1234567890abcdef"  # Hardcoded - PERIGOSO!

# ✅ Use WorkerConfig.secrets
api_key = self.get_secret("service.api_key", "API key obrigatória")
```

#### Separação de Ambientes
```python
# Configuração por ambiente
class ProductionConfig:
    secrets = {
        "virustotal": {
            "api_key": "prod_vt_key_here"
        }
    }

class DevelopmentConfig:
    secrets = {
        "virustotal": {
            "api_key": "dev_vt_key_here"
        }
    }
```

### Estrutura Segura de Secrets

#### Organização Hierárquica
```python
secrets = {
    "database": {
        "host": "db.example.com",
        "username": "app_user",
        "password": "secure_password",
        "ssl_cert": "/path/to/cert.pem"
    },
    "apis": {
        "virustotal": {
            "api_key": "vt_api_key",
            "rate_limit": 4  # requests per minute
        },
        "shodan": {
            "api_key": "shodan_api_key",
            "timeout": 30
        }
    },
    "encryption": {
        "master_key": "encryption_master_key",
        "salt": "random_salt_value"
    }
}
```

#### Validação de Secrets
```python
class SecureAnalyzer(Analyzer):
    def validate_secrets(self):
        """Valida se todos os secrets necessários estão presentes."""
        required_secrets = [
            "service.api_key",
            "service.username",
            "service.password"
        ]
        
        for secret_path in required_secrets:
            try:
                value = self.get_secret(secret_path)
                if not value or len(value.strip()) == 0:
                    raise ValueError(f"Secret vazio: {secret_path}")
            except KeyError:
                raise ValueError(f"Secret obrigatório não encontrado: {secret_path}")
    
    def execute(self) -> AnalyzerReport:
        # Validar secrets antes de executar
        self.validate_secrets()
        
        # Continuar com a execução...
        return self.report({"status": "success"})
```

## Proteção de Dados Sensíveis

### Sanitização de Logs

#### Implementação de Log Sanitizer
```python
import re
from typing import Any, Dict

class LogSanitizer:
    """Sanitiza dados sensíveis em logs."""
    
    SENSITIVE_PATTERNS = {
        'api_key': re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\s]+)', re.IGNORECASE),
        'password': re.compile(r'(password["\']?\s*[:=]\s*["\']?)([^"\s]+)', re.IGNORECASE),
        'token': re.compile(r'(token["\']?\s*[:=]\s*["\']?)([^"\s]+)', re.IGNORECASE),
        'secret': re.compile(r'(secret["\']?\s*[:=]\s*["\']?)([^"\s]+)', re.IGNORECASE),
        'authorization': re.compile(r'(authorization["\']?\s*[:=]\s*["\']?)([^"\s]+)', re.IGNORECASE)
    }
    
    @classmethod
    def sanitize(cls, data: Any) -> Any:
        """Sanitiza dados sensíveis."""
        if isinstance(data, str):
            return cls._sanitize_string(data)
        elif isinstance(data, dict):
            return cls._sanitize_dict(data)
        elif isinstance(data, list):
            return [cls.sanitize(item) for item in data]
        else:
            return data
    
    @classmethod
    def _sanitize_string(cls, text: str) -> str:
        """Sanitiza string removendo dados sensíveis."""
        for pattern_name, pattern in cls.SENSITIVE_PATTERNS.items():
            text = pattern.sub(r'\1***REDACTED***', text)
        return text
    
    @classmethod
    def _sanitize_dict(cls, data: Dict) -> Dict:
        """Sanitiza dicionário recursivamente."""
        sanitized = {}
        
        for key, value in data.items():
            # Chaves sensíveis
            if any(sensitive in key.lower() for sensitive in ['key', 'password', 'token', 'secret']):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = cls.sanitize(value)
        
        return sanitized

# Uso em analyzers
class SecureAnalyzer(Analyzer):
    def log_safe(self, message: str, data: Any = None):
        """Log seguro que sanitiza dados sensíveis."""
        safe_message = LogSanitizer.sanitize(message)
        
        if data:
            safe_data = LogSanitizer.sanitize(data)
            self.logger.info(f"{safe_message}: {safe_data}")
        else:
            self.logger.info(safe_message)
    
    def execute(self) -> AnalyzerReport:
        api_key = self.get_secret("service.api_key")
        
        # ❌ NUNCA faça isso
        # self.logger.info(f"Using API key: {api_key}")
        
        # ✅ Use log seguro
        self.log_safe("Iniciando análise com credenciais configuradas")
        
        return self.report({"status": "success"})
```

### Criptografia de Dados

#### Implementação de Encryption Helper
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class EncryptionHelper:
    """Helper para criptografia de dados sensíveis."""
    
    def __init__(self, master_key: str, salt: str = None):
        self.salt = salt.encode() if salt else os.urandom(16)
        self.key = self._derive_key(master_key.encode(), self.salt)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Deriva chave de criptografia a partir de senha."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt(self, data: str) -> str:
        """Criptografa dados."""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Descriptografa dados."""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()

# Uso em analyzers
class EncryptedAnalyzer(Analyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Obter chave de criptografia dos secrets
        master_key = self.get_secret("encryption.master_key")
        salt = self.get_secret("encryption.salt")
        
        self.encryption = EncryptionHelper(master_key, salt)
    
    def store_sensitive_data(self, data: str) -> str:
        """Armazena dados sensíveis criptografados."""
        return self.encryption.encrypt(data)
    
    def retrieve_sensitive_data(self, encrypted_data: str) -> str:
        """Recupera dados sensíveis descriptografados."""
        return self.encryption.decrypt(encrypted_data)
```

## Controles de Acesso

### Traffic Light Protocol (TLP)

#### Implementação de Verificação TLP
```python
class TLPSecureAnalyzer(Analyzer):
    """Analyzer que respeita controles TLP."""
    
    TLP_LEVELS = {
        0: "WHITE",    # Sem restrições
        1: "GREEN",    # Comunidade
        2: "AMBER",    # Organização limitada
        3: "RED"       # Pessoal/Restrito
    }
    
    def check_tlp_compliance(self, data_tlp: int, max_allowed_tlp: int) -> bool:
        """Verifica se o TLP dos dados está dentro do permitido."""
        return data_tlp <= max_allowed_tlp
    
    def execute(self) -> AnalyzerReport:
        # Obter TLP dos dados de entrada
        input_tlp = self.get_tlp()
        
        # Obter TLP máximo permitido para este analyzer
        max_tlp = self.get_config("security.max_tlp", 2)  # Default: AMBER
        
        # Verificar compliance
        if not self.check_tlp_compliance(input_tlp, max_tlp):
            return self.report({
                "error": "TLP violation",
                "input_tlp": self.TLP_LEVELS.get(input_tlp, "UNKNOWN"),
                "max_allowed": self.TLP_LEVELS.get(max_tlp, "UNKNOWN"),
                "message": "Dados com TLP muito alto para este analyzer"
            })
        
        # Continuar com análise normal
        observable = self.get_data()
        
        # Garantir que o output tenha TLP apropriado
        output_tlp = max(input_tlp, 1)  # Mínimo GREEN para resultados
        
        result = {
            "observable": observable,
            "verdict": "safe",
            "tlp": output_tlp,
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(result)
```

### Permissible Actions Protocol (PAP)

#### Implementação de Verificação PAP
```python
class PAPSecureAnalyzer(Analyzer):
    """Analyzer que respeita controles PAP."""
    
    PAP_LEVELS = {
        0: "WHITE",    # Sem restrições
        1: "GREEN",    # Ações automáticas permitidas
        2: "AMBER",    # Ações manuais apenas
        3: "RED"       # Nenhuma ação
    }
    
    def can_perform_action(self, action_type: str, data_pap: int) -> bool:
        """Verifica se uma ação pode ser executada baseado no PAP."""
        action_requirements = {
            "automated_block": 1,     # Requer GREEN ou melhor
            "manual_review": 2,       # Requer AMBER ou melhor
            "information_only": 3     # Sempre permitido
        }
        
        required_pap = action_requirements.get(action_type, 3)
        return data_pap <= required_pap
    
    def execute(self) -> AnalyzerReport:
        input_pap = self.get_pap()
        observable = self.get_data()
        
        # Determinar ações possíveis baseado no PAP
        possible_actions = []
        
        if self.can_perform_action("information_only", input_pap):
            possible_actions.append("information_only")
        
        if self.can_perform_action("manual_review", input_pap):
            possible_actions.append("manual_review")
        
        if self.can_perform_action("automated_block", input_pap):
            possible_actions.append("automated_block")
        
        result = {
            "observable": observable,
            "verdict": "suspicious",
            "pap": input_pap,
            "possible_actions": possible_actions,
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(result)
```

## Validação de Entrada

### Sanitização de Dados

```python
import re
from urllib.parse import urlparse
from ipaddress import ip_address, AddressValueError

class InputValidator:
    """Validador de entrada para dados de observáveis."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Valida endereço IP."""
        try:
            ip_address(ip)
            return True
        except AddressValueError:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valida nome de domínio."""
        # Regex básico para domínio
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # Subdomínios
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'        # Domínio principal
        )
        return bool(pattern.match(domain)) and len(domain) <= 253
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Valida URL."""
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    @staticmethod
    def validate_hash(hash_value: str, hash_type: str = None) -> bool:
        """Valida hash criptográfico."""
        hash_patterns = {
            'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
            'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
            'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
            'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
        }
        
        if hash_type:
            pattern = hash_patterns.get(hash_type.lower())
            return bool(pattern and pattern.match(hash_value))
        
        # Tentar detectar tipo automaticamente
        for pattern in hash_patterns.values():
            if pattern.match(hash_value):
                return True
        
        return False
    
    @staticmethod
    def sanitize_input(data: str, max_length: int = 1000) -> str:
        """Sanitiza entrada removendo caracteres perigosos."""
        if not isinstance(data, str):
            raise ValueError("Input deve ser string")
        
        # Limitar comprimento
        if len(data) > max_length:
            raise ValueError(f"Input muito longo (max: {max_length})")
        
        # Remover caracteres de controle
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data)
        
        # Remover espaços extras
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized

# Uso em analyzers
class ValidatedAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        raw_data = self.get_data()
        data_type = self.get_data_type()
        
        try:
            # Sanitizar entrada
            clean_data = InputValidator.sanitize_input(raw_data)
            
            # Validar baseado no tipo
            if data_type == "ip" and not InputValidator.validate_ip(clean_data):
                raise ValueError("IP inválido")
            elif data_type == "domain" and not InputValidator.validate_domain(clean_data):
                raise ValueError("Domínio inválido")
            elif data_type == "url" and not InputValidator.validate_url(clean_data):
                raise ValueError("URL inválida")
            elif data_type == "hash" and not InputValidator.validate_hash(clean_data):
                raise ValueError("Hash inválido")
            
        except ValueError as e:
            return self.report({
                "error": "validation_failed",
                "message": str(e),
                "original_data": raw_data[:100] + "..." if len(raw_data) > 100 else raw_data
            })
        
        # Continuar com dados validados
        result = {
            "observable": clean_data,
            "verdict": "safe",
            "validation": "passed",
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(result)
```

## Auditoria e Monitoramento

### Log de Auditoria

```python
import json
from datetime import datetime
from typing import Dict, Any

class AuditLogger:
    """Logger de auditoria para ações sensíveis."""
    
    def __init__(self, analyzer_name: str):
        self.analyzer_name = analyzer_name
    
    def log_action(self, action: str, details: Dict[str, Any], user_id: str = None):
        """Registra ação para auditoria."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "analyzer": self.analyzer_name,
            "action": action,
            "user_id": user_id,
            "details": LogSanitizer.sanitize(details),
            "session_id": self._get_session_id()
        }
        
        # Log em formato estruturado
        self._write_audit_log(audit_entry)
    
    def _get_session_id(self) -> str:
        """Obtém ID da sessão atual."""
        # Implementar lógica de sessão
        return "session_123"
    
    def _write_audit_log(self, entry: Dict):
        """Escreve entrada de auditoria."""
        # Implementar escrita segura (arquivo, syslog, etc.)
        print(f"AUDIT: {json.dumps(entry)}")

# Uso em analyzers
class AuditedAnalyzer(Analyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit = AuditLogger(self.__class__.__name__)
    
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        
        # Log início da análise
        self.audit.log_action("analysis_started", {
            "observable_type": self.get_data_type(),
            "observable_hash": hash(observable)  # Hash para não expor dados
        })
        
        try:
            # Executar análise
            result = self.perform_analysis(observable)
            
            # Log sucesso
            self.audit.log_action("analysis_completed", {
                "verdict": result.get("verdict"),
                "threat_score": result.get("threat_score")
            })
            
            return self.report(result)
            
        except Exception as e:
            # Log erro
            self.audit.log_action("analysis_failed", {
                "error_type": type(e).__name__,
                "error_message": str(e)
            })
            raise
```

## Boas Práticas de Segurança

### Checklist de Segurança

#### Para Desenvolvimento
- [ ] Nunca hardcodar credenciais no código
- [ ] Usar `WorkerConfig.secrets` para todas as credenciais
- [ ] Implementar validação de entrada
- [ ] Sanitizar logs para remover dados sensíveis
- [ ] Respeitar controles TLP/PAP
- [ ] Implementar tratamento seguro de erros
- [ ] Usar HTTPS para todas as comunicações externas
- [ ] Implementar timeouts apropriados
- [ ] Validar certificados SSL
- [ ] Implementar rate limiting

#### Para Deployment
- [ ] Configurar secrets de forma segura
- [ ] Usar `WorkerConfig` para configurações (e `WorkerConfig.secrets` para credenciais); evitar variáveis de ambiente para configs específicas de módulos
- [ ] Implementar rotação de credenciais
- [ ] Configurar logs de auditoria
- [ ] Implementar monitoramento de segurança
- [ ] Configurar alertas para atividades suspeitas
- [ ] Implementar backup seguro de configurações
- [ ] Testar recuperação de desastres

#### Para Operação
- [ ] Monitorar uso de APIs
- [ ] Revisar logs de auditoria regularmente
- [ ] Atualizar credenciais periodicamente
- [ ] Monitorar tentativas de acesso não autorizado
- [ ] Implementar alertas para falhas de segurança
- [ ] Manter inventário de credenciais
- [ ] Documentar procedimentos de resposta a incidentes

### Configuração Segura de Exemplo

```python
# ✅ Exemplo de configuração segura seguindo as regras do SDK
secure_config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,  # Máximo AMBER
    check_pap=True,
    max_pap=2,  # Máximo AMBER
    auto_extract=True,
    secrets={
        "virustotal": {
            "api_key": "sua_vt_api_key_aqui",  # Obtenha via get_secret()
            "rate_limit": 4
        },
        "shodan": {
            "api_key": "sua_shodan_api_key_aqui",  # Obtenha via get_secret()
            "timeout": 30
        },
        "database": {
            "host": "db.exemplo.com",  # Obtenha via get_secret()
            "username": "usuario_db",  # Obtenha via get_secret()
            "password": "senha_segura",  # Obtenha via get_secret()
            "ssl_mode": "require"
        },
        "encryption": {
            "master_key": "chave_mestre_criptografia",  # Obtenha via get_secret()
            "salt": "salt_aleatorio"  # Obtenha via get_secret()
        }
    }
)
```

## Veja Também

- [WorkerConfig](../core/worker-config.md)
- [Secrets Management](../core/secrets.md)
- [Building Analyzers](../tutorials/building-analyzers.md)
- [Threat Intelligence](threat-intelligence.md)
- [Examples](../examples/security.md)