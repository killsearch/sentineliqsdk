# WorkerConfig

## Visão Geral

A classe `WorkerConfig` é o mecanismo central de configuração do SentinelIQ SDK, fornecendo acesso seguro a credenciais, configurações e parâmetros de execução.

## Estrutura da Configuração

### Inicialização

```python
from sentineliqsdk import WorkerConfig

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    secrets={
        "meu_modulo": {
            "api_key": "chave_secreta",
            "username": "usuario",
            "password": "senha"
        }
    }
)
```

## Parâmetros de Configuração

### Controle de TLP (Traffic Light Protocol)

- **`check_tlp`** (bool): Habilita verificação de TLP
- **`max_tlp`** (int): Nível máximo de TLP permitido (0-4)
  - 0: TLP:CLEAR (público)
  - 1: TLP:GREEN (comunidade)
  - 2: TLP:AMBER (limitado)
  - 3: TLP:AMBER+STRICT (muito limitado)
  - 4: TLP:RED (restrito)

### Controle de PAP (Permissible Actions Protocol)

- **`check_pap`** (bool): Habilita verificação de PAP
- **`max_pap`** (int): Nível máximo de PAP permitido (0-4)
  - 0: PAP:CLEAR (sem restrições)
  - 1: PAP:GREEN (uso passivo)
  - 2: PAP:AMBER (uso ativo limitado)
  - 3: PAP:AMBER+STRICT (uso muito limitado)
  - 4: PAP:RED (sem uso automatizado)

### Extração Automática

- **`auto_extract`** (bool): Habilita extração automática de observáveis

## Gerenciamento de Secrets

### Estrutura de Secrets

```python
secrets = {
    "modulo_nome": {
        "api_key": "valor_secreto",
        "username": "usuario",
        "password": "senha",
        "token": "bearer_token"
    },
    "outro_modulo": {
        "endpoint": "https://api.exemplo.com",
        "credentials": "base64_encoded"
    }
}
```

### Acesso a Secrets

```python
# Em um Worker/Analyzer/Responder
class MeuAnalyzer(Analyzer):
    def execute(self):
        # Obter secret obrigatório
        api_key = self.get_secret("meu_analyzer.api_key", "API key é obrigatória")
        
        # Obter secret opcional
        username = self.get_secret("meu_analyzer.username")
        
        # Obter configuração com valor padrão
        timeout = self.get_config("meu_analyzer.timeout", 30)
```

## Configurações Específicas de Módulo

### Convenção de Nomenclatura

Use a convenção `modulo.configuracao` para organizar configurações:

```python
# Exemplos de configurações
configs = {
    "shodan_analyzer.timeout": 30,
    "shodan_analyzer.max_results": 100,
    "virustotal_analyzer.api_version": "v3",
    "smtp_responder.port": 587,
    "webhook_responder.retry_count": 3
}
```

### Tipos de Configuração Suportados

- **String**: Textos, URLs, endpoints
- **Integer**: Timeouts, limites, portas
- **Boolean**: Flags de habilitação/desabilitação
- **Float**: Valores decimais, thresholds
- **List**: Arrays de valores
- **Dict**: Objetos complexos

## Segurança

### Boas Práticas

1. **Nunca hardcode secrets** no código fonte
2. **Use get_secret()** para todas as credenciais
3. **Separe configurações** de secrets
4. **Valide configurações** antes do uso
5. **Use valores padrão** sensatos

### Exemplo Seguro

```python
class SecureAnalyzer(Analyzer):
    def execute(self):
        # ✅ CORRETO: Usar get_secret()
        api_key = self.get_secret("secure_analyzer.api_key", "API key obrigatória")
        
        # ✅ CORRETO: Usar get_config() com padrão
        timeout = self.get_config("secure_analyzer.timeout", 30)
        
        # ❌ INCORRETO: Nunca fazer isso
        # api_key = "hardcoded_key_123"
        # api_key = os.environ.get("API_KEY")
```

## Validação de Configuração

### Verificação de TLP/PAP

```python
# O SDK automaticamente verifica TLP/PAP se habilitado
if config.check_tlp and input_data.tlp > config.max_tlp:
    raise ValueError(f"TLP {input_data.tlp} excede máximo permitido {config.max_tlp}")

if config.check_pap and input_data.pap > config.max_pap:
    raise ValueError(f"PAP {input_data.pap} excede máximo permitido {config.max_pap}")
```

## Integração com WorkerInput

```python
from sentineliqsdk import WorkerInput, WorkerConfig

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        secrets={
            "meu_analyzer": {
                "api_key": "secret_key"
            }
        }
    )
)
```

## Veja Também

- [Secrets Management](secrets.md)
- [Building Analyzers](../tutorials/building-analyzers.md)
- [Security Best Practices](../guides/security.md)
- [API Reference](../reference/api/worker.md)