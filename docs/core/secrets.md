# Secrets Management

## Visão Geral

O SentinelIQ SDK implementa um sistema robusto de gerenciamento de secrets para proteger credenciais, API keys e outras informações sensíveis.

## Princípios de Segurança

### ❌ Práticas Proibidas

- **Nunca** hardcode credenciais no código fonte
- **Nunca** use `os.environ` diretamente em módulos
- **Nunca** commite secrets no repositório
- **Nunca** logue credenciais em logs

### ✅ Práticas Recomendadas

- **Sempre** use `WorkerConfig.secrets` para credenciais
- **Sempre** use métodos `get_secret()` e `get_config()`
- **Sempre** valide secrets antes do uso
- **Sempre** use mensagens descritivas para secrets obrigatórios

## Estrutura de Secrets

### Organização Hierárquica

```python
secrets = {
    "modulo_nome": {
        "api_key": "valor_da_api_key",
        "username": "nome_usuario",
        "password": "senha_segura",
        "token": "bearer_token",
        "endpoint": "https://api.exemplo.com"
    },
    "outro_modulo": {
        "credentials": "base64_encoded_creds",
        "certificate": "-----BEGIN CERTIFICATE-----..."
    }
}
```

### Convenção de Nomenclatura

Use a convenção `modulo.secret_name` para organizar secrets:

```python
# Exemplos de nomenclatura
"shodan_analyzer.api_key"
"virustotal_analyzer.api_key"
"smtp_responder.password"
"webhook_responder.auth_token"
"database_client.connection_string"
```

## Acesso a Secrets

### Método get_secret()

```python
class MeuAnalyzer(Analyzer):
    def execute(self):
        # Secret obrigatório com mensagem de erro
        api_key = self.get_secret(
            "meu_analyzer.api_key", 
            "API key é obrigatória para análise"
        )
        
        # Secret opcional
        username = self.get_secret("meu_analyzer.username")
        
        # Verificar se secret existe
        if username:
            # Usar username se disponível
            pass
```

### Tratamento de Secrets Ausentes

```python
try:
    api_key = self.get_secret("analyzer.api_key", "API key obrigatória")
except ValueError as e:
    self.logger.error(f"Configuração inválida: {e}")
    # Retornar erro ou usar fallback
    return self.report({"error": "API key não configurada"})
```

## Tipos de Secrets

### API Keys
```python
# Chaves de API para serviços externos
api_key = self.get_secret("virustotal.api_key")
shodan_key = self.get_secret("shodan.api_key")
```

### Credenciais de Autenticação
```python
# Username/Password
username = self.get_secret("service.username")
password = self.get_secret("service.password")

# Bearer Tokens
token = self.get_secret("api.bearer_token")
```

### Certificados e Chaves
```python
# Certificados SSL/TLS
cert = self.get_secret("tls.certificate")
key = self.get_secret("tls.private_key")

# Chaves de assinatura
signing_key = self.get_secret("jwt.signing_key")
```

### Strings de Conexão
```python
# Database connections
db_url = self.get_secret("database.connection_string")
redis_url = self.get_secret("redis.url")
```

## Configuração vs Secrets

### Quando Usar Secrets
- API keys, tokens, senhas
- Certificados e chaves privadas
- Strings de conexão com credenciais
- Qualquer informação sensível

### Quando Usar Config
- Timeouts, limites, portas
- URLs públicas, endpoints
- Flags de habilitação/desabilitação
- Configurações não sensíveis

```python
class ExemploAnalyzer(Analyzer):
    def execute(self):
        # ✅ Secret: Informação sensível
        api_key = self.get_secret("exemplo.api_key")
        
        # ✅ Config: Configuração não sensível
        timeout = self.get_config("exemplo.timeout", 30)
        endpoint = self.get_config("exemplo.endpoint", "https://api.exemplo.com")
```

## Validação de Secrets

### Validação Básica
```python
def validate_api_key(self, api_key: str) -> bool:
    """Valida formato da API key."""
    if not api_key:
        return False
    
    if len(api_key) < 32:
        self.logger.warning("API key parece muito curta")
        return False
    
    return True

def execute(self):
    api_key = self.get_secret("analyzer.api_key", "API key obrigatória")
    
    if not self.validate_api_key(api_key):
        raise ValueError("API key inválida")
```

### Teste de Conectividade
```python
def test_credentials(self) -> bool:
    """Testa se as credenciais estão válidas."""
    try:
        api_key = self.get_secret("analyzer.api_key")
        # Fazer uma chamada de teste
        response = requests.get(
            "https://api.exemplo.com/test",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        self.logger.error(f"Teste de credenciais falhou: {e}")
        return False
```

## Segurança em Logs

### Mascaramento de Secrets
```python
def safe_log_config(self):
    """Loga configuração mascarando secrets."""
    config_copy = self.config.copy()
    
    # Mascarar secrets
    if 'api_key' in config_copy:
        config_copy['api_key'] = f"{config_copy['api_key'][:4]}****"
    
    self.logger.info(f"Configuração: {config_copy}")
```

### Evitar Vazamento em Exceções
```python
try:
    api_key = self.get_secret("analyzer.api_key")
    result = external_api_call(api_key)
except requests.RequestException as e:
    # ❌ PERIGOSO: Pode vazar API key na mensagem
    # self.logger.error(f"Erro na API: {e}")
    
    # ✅ SEGURO: Log genérico
    self.logger.error("Erro na chamada da API externa")
    raise
```

## Rotação de Secrets

### Suporte a Múltiplas Keys
```python
def get_active_api_key(self):
    """Obtém API key ativa com fallback."""
    # Tentar key primária
    primary_key = self.get_secret("analyzer.api_key_primary")
    if primary_key and self.test_api_key(primary_key):
        return primary_key
    
    # Fallback para key secundária
    secondary_key = self.get_secret("analyzer.api_key_secondary")
    if secondary_key and self.test_api_key(secondary_key):
        self.logger.warning("Usando API key secundária")
        return secondary_key
    
    raise ValueError("Nenhuma API key válida disponível")
```

## Exemplo Completo

```python
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport

class SecureAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        # Obter secrets obrigatórios
        api_key = self.get_secret(
            "secure_analyzer.api_key", 
            "API key é obrigatória para análise"
        )
        
        # Obter configurações
        timeout = self.get_config("secure_analyzer.timeout", 30)
        endpoint = self.get_config(
            "secure_analyzer.endpoint", 
            "https://api.exemplo.com"
        )
        
        # Validar credenciais
        if not self.validate_api_key(api_key):
            raise ValueError("API key inválida")
        
        # Usar secrets de forma segura
        try:
            result = self.call_external_api(api_key, endpoint, timeout)
            return self.build_report(result)
        except Exception as e:
            self.logger.error("Erro na análise externa")
            raise
    
    def validate_api_key(self, api_key: str) -> bool:
        return api_key and len(api_key) >= 32
    
    def call_external_api(self, api_key: str, endpoint: str, timeout: int):
        # Implementação da chamada API
        pass
```

## Veja Também

- [WorkerConfig](worker-config.md)
- [Building Analyzers](../tutorials/building-analyzers.md)
- [Security Best Practices](../guides/security.md)
- [Configuration Guide](../guides/guide.md)