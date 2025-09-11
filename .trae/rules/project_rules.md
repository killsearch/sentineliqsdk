# SentinelIQ SDK - Regras de Projeto

Este documento consolida todas as regras de desenvolvimento do SentinelIQ SDK baseadas nas regras do Cursor.

## 🔒 Regras Críticas de Segurança

### ❌ PROIBIÇÕES ABSOLUTAS
- **NUNCA** usar `os.environ` diretamente em módulos
- **NUNCA** hardcodar credenciais no código fonte
- **NUNCA** usar variáveis de ambiente para configuração específica de módulos
- **NUNCA** deixar commits sem realizar após modificações

### ✅ OBRIGAÇÕES FUNDAMENTAIS
- **SEMPRE** usar `WorkerConfig.secrets` para credenciais (API keys, senhas, tokens)
- **SEMPRE** usar `WorkerConfig` para configurações específicas de módulos
- **SEMPRE** usar métodos `get_secret()` e `get_config()`
- **SEMPRE** realizar commit automático após qualquer modificação

## 📁 Estrutura de Classes Base

Todos os módulos devem seguir a hierarquia:
- `Worker` (classe base)
  - `Analyzer` (para análise de dados)
  - `Responder` (para ações de resposta)
  - `Producer` (para publicação de mensagens)
  - `Consumer` (para consumo de mensagens)
  - `Pipeline` (para orquestração)

## 🏗️ Padrões de Desenvolvimento

### Convenções de Nomenclatura
- **Analyzers**: `<Nome>Analyzer`
- **Responders**: `<Nome>Responder`
- **Producers**: `<Nome>Producer`
- **Consumers**: `<Nome>Consumer`
- **Pipelines**: `<Nome>Pipeline`
- **Detectores**: `<Nome>Detector`

### Imports Obrigatórios
```python
from __future__ import annotations

# Imports do SDK
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata
```

### Formatação de Código
- Python 3.13
- Imports absolutos apenas
- Indentação de 4 espaços
- Comprimento de linha: 100 caracteres
- Sempre usar `from __future__ import annotations` primeiro

## 🔧 Configuração e Acesso a Dados

### Para Credenciais (Secrets)
```python
# CORRETO: Use get_secret() para credenciais
api_key = self.get_secret("meu_modulo.api_key", message="API key obrigatória")
username = self.get_secret("meu_modulo.username")
password = self.get_secret("meu_modulo.password")
```

### Para Configurações (Settings)
```python
# CORRETO: Use get_config() para configurações
timeout = self.get_config("meu_modulo.timeout", 30)
max_retries = self.get_config("meu_modulo.max_retries", 3)
debug_mode = self.get_config("meu_modulo.debug", False)
```

### Estrutura WorkerInput
```python
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    filename=None,  # Opcional, para tipos de arquivo
    tlp=2,
    pap=2,
    config=WorkerConfig(
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
)
```

## 📊 Metadados Obrigatórios

### Estrutura ModuleMetadata
```python
from sentineliqsdk.models import ModuleMetadata

class MeuModulo(Worker):
    METADATA = ModuleMetadata(
        name="Meu Módulo",
        description="Descrição do que o módulo faz",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",  # ou "smtp", "webhook", "kafka", etc.
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/meu_modulo/",
        version_stage="TESTING",  # ou "DEVELOPER", "STABLE"
    )
```

### Estágios de Versão
- **DEVELOPER**: Estágio de desenvolvimento/experimental
- **TESTING**: Estágio de teste, não pronto para produção
- **STABLE**: Pronto para produção, versão estável

## 🔍 Desenvolvimento de Analyzers

### Estrutura Obrigatória
```python
class MeuAnalyzer(Analyzer):
    METADATA = ModuleMetadata(...)

    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full = {
            "observable": observable, 
            "verdict": "safe", 
            "taxonomy": [taxonomy.to_dict()],
            "metadata": self.METADATA.to_dict()
        }
        return self.report(full)

    def run(self) -> AnalyzerReport:
        return self.execute()
```

### Níveis de Taxonomia
- **`info`**: Informacional
- **`safe`**: Seguro/limpo
- **`suspicious`**: Suspeito mas não malicioso
- **`malicious`**: Confirmadamente malicioso

## 🚨 Desenvolvimento de Responders

### Estrutura Obrigatória
```python
class MeuResponder(Responder):
    METADATA = ModuleMetadata(...)

    def execute(self) -> ResponderReport:
        target = self.get_data()
        ops = [self.build_operation("block", target=target)]
        full = {
            "action": "block", 
            "target": target,
            "metadata": self.METADATA.to_dict()
        }
        return self.report(full)

    def run(self) -> ResponderReport:
        return self.execute()
```

### Tipos de Operações Comuns
- **`block`**: Bloquear um recurso/IP/domínio
- **`allow`**: Permitir um recurso
- **`quarantine`**: Colocar em quarentena
- **`notify`**: Enviar notificação
- **`escalate`**: Escalar para análise manual
- **`remediate`**: Executar remediação automática

## 🔍 Desenvolvimento de Detectores

### Estrutura Obrigatória
```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class MeuDetector:
    name: str = "meu_tipo"

    def matches(self, value: str) -> bool:
        return value.startswith("MEU:")
```

### Registro de Detectores
```python
from sentineliqsdk.extractors import Extractor

# Registrar antes de detector existente
Extractor.register_detector(MeuDetector(), before="hash")

# Registrar depois de detector existente
Extractor.register_detector(MeuDetector(), after="ip")
```

### Ordem de Precedência
```
ip → cidr → url → domain → hash → user-agent → uri_path → registry → mail → mac → asn → cve → ip_port → fqdn
```

## 📨 Desenvolvimento de Messaging

### Estrutura de Producer
```python
class MeuProducer(Producer):
    METADATA = ModuleMetadata(...)

    def publish(self, message: Message) -> ProducerReport:
        # Implementação aqui
        pass

    def run(self) -> ProducerReport:
        # Implementação aqui
        pass
```

### Estrutura de Consumer
```python
class MeuConsumer(Consumer):
    METADATA = ModuleMetadata(...)

    def consume(self) -> list[Message]:
        # Implementação aqui
        pass

    def process_message(self, message: Message) -> dict:
        # Implementação aqui
        pass

    def run(self) -> ConsumerReport:
        # Implementação aqui
        pass
```

## 📚 Exemplos e Documentação

### Regra de Exemplos Obrigatórios
Sempre adicionar um exemplo executável em `examples/` ao introduzir um novo módulo.

### Convenção de Nomenclatura
- **Analyzers**: `examples/analyzers/<nome>_example.py`
- **Responders**: `examples/responders/<nome>_example.py`
- **Detectors**: `examples/detectors/<nome>_example.py`
- **Producers**: `examples/producers/<nome>_example.py`
- **Consumers**: `examples/consumers/<nome>_example.py`
- **Pipelines**: `examples/pipelines/<nome>_example.py`

### Argumentos Padrão Obrigatórios
```python
# Argumentos de dados
parser.add_argument("--data", help="Dados para processar")
parser.add_argument("--data-type", help="Tipo de dados")

# Portões de segurança (OBRIGATÓRIO)
parser.add_argument("--execute", action="store_true", help="Executar operações reais")
parser.add_argument("--include-dangerous", action="store_true", help="Incluir operações perigosas")
```

### Verificações de Segurança
```python
# Verificação de modo dry-run
if not args.execute:
    print("Modo dry-run. Use --execute para operações reais.")
    return

# Verificação de operações perigosas
if operacao_perigosa and not args.include_dangerous:
    print("Operação perigosa detectada. Use --include-dangerous para prosseguir.")
    return
```

## 🔄 Workflow de Desenvolvimento

### Comandos de Scaffolding
```bash
# Scaffolding genérico
poe new -- --kind <analyzer|responder|detector> --name <Nome> [--force]

# Atalhos específicos
poe new-analyzer -- --name Shodan
poe new-responder -- --name BlockIp
poe new-detector -- --name MyType
```

### Ferramentas de Qualidade
- **Linting**: `poe lint` (pre-commit com ruff/mypy)
- **Testes**: `poe test` (pytest com coverage)
- **Documentação**: `poe docs` (MkDocs)
- **Build**: `uv build`

### Checklist de Desenvolvimento
Para cada novo módulo:
- [ ] Nomenclatura e imports em conformidade
- [ ] `execute()` implementado; `run()` retorna Report apropriado
- [ ] Chama `self.report(...)` com um dict
- [ ] Taxonomia/operações incluídas conforme apropriado
- [ ] Atributo METADATA declarado e incluído no full_report
- [ ] Configuração usando `WorkerConfig.secrets` e `WorkerConfig`
- [ ] Testes adicionados com cobertura adequada (>80%)
- [ ] Exemplo executável criado
- [ ] Página MkDocs criada
- [ ] `poe lint` passa sem erros
- [ ] `poe test` passa com cobertura adequada
- [ ] **Commit automático realizado**

## 📝 Commits Automáticos

### Formato Obrigatório (Conventional Commits)
```
<tipo>(<escopo>): <descrição>

[corpo opcional]

[rodapé opcional]
```

### Tipos Permitidos
- **feat**: Nova funcionalidade
- **fix**: Correção de bug
- **docs**: Alterações na documentação
- **style**: Formatação, espaços em branco, etc.
- **refactor**: Refatoração de código
- **test**: Adição ou modificação de testes
- **chore**: Tarefas de manutenção, configuração
- **ci**: Alterações em CI/CD
- **perf**: Melhorias de performance
- **build**: Alterações no sistema de build

### Regra de Frequência
**OBRIGATÓRIO**: Realizar commit imediatamente após QUALQUER ação executada por agente, incluindo:
- ✅ Criação de novos arquivos
- ✅ Modificação de arquivos existentes
- ✅ Exclusão de arquivos
- ✅ Alterações em configurações
- ✅ Adição de dependências
- ✅ Execução de scaffolding
- ✅ Correções de bugs
- ✅ Refatorações
- ✅ Atualizações de documentação

### Validações Pré-Commit
```bash
# Sequência completa para commit automático
pre-commit run --all-files || true
git add .
git commit -m "<tipo>(<escopo>): <descrição>"
```

## 📂 Estrutura de Arquivos

### Organizações por Tipo
- **Analyzers**:
  - Código: `src/sentineliqsdk/analyzers/<nome>.py`
  - Exemplo: `examples/analyzers/<nome>_example.py`
  - Testes: `tests/analyzers/test_<nome>.py`

- **Responders**:
  - Código: `src/sentineliqsdk/responders/<nome>.py`
  - Exemplo: `examples/responders/<nome>_example.py`
  - Testes: `tests/responders/test_<nome>.py`

- **Detectores**:
  - Código: `src/sentineliqsdk/extractors/custom/<nome>_detector.py`
  - Exemplo: `examples/detectors/<nome>_example.py`
  - Testes: `tests/extractors/test_<nome>_detector.py`

- **Producers/Consumers/Pipelines**:
  - Código: `src/sentineliqsdk/<tipo>/<nome>.py`
  - Exemplo: `examples/<tipo>/<nome>_example.py`
  - Testes: `tests/<tipo>/test_<nome>.py`

## 🎯 Tipos de Dados Suportados

### Rede
- `ip`, `cidr`, `url`, `domain`, `fqdn`, `mac`, `ip_port`

### Segurança
- `hash`, `cve`, `asn`

### Web
- `user-agent`, `uri_path`, `registry`

### Comunicação
- `mail`

### Outros
- `file`, `other`

---

> **💡 Resumo**: Este documento consolida todas as regras essenciais do SentinelIQ SDK. Para desenvolvimento, sempre seguir os padrões de configuração segura, implementar metadados obrigatórios, criar exemplos executáveis e realizar commits automáticos após modificações.