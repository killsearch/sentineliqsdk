# SentinelIQ SDK - Migração para Dataclasses

Este documento descreve a migração da SentinelIQ SDK de retornos JSON para dataclasses, proporcionando melhor type safety e experiência de desenvolvimento.

## Visão Geral

A SDK agora utiliza dataclasses Python para estruturar dados de entrada e saída, substituindo o uso de dicionários JSON. Isso oferece:

- ✅ **Type Safety**: Verificação de tipos em tempo de desenvolvimento
- ✅ **Melhor IDE Support**: Autocomplete e detecção de erros
- ✅ **Estruturas Imutáveis**: Dados protegidos contra modificações acidentais
- ✅ **Contratos Claros**: Estruturas de dados bem definidas
- ✅ **Compatibilidade**: Suporte a entradas de dicionário para compatibilidade

## Principais Mudanças

### 1. WorkerInput - Entrada de Dados

**Antes (JSON):**
```python
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,
    "pap": 2,
    "config": {
        "check_tlp": True,
        "max_tlp": 2,
        "auto_extract": True,
        "proxy": {
            "http": "http://proxy:8080",
            "https": "https://proxy:8080"
        }
    }
}
```

**Agora (Dataclass):**
```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        auto_extract=True,
        proxy=ProxyConfig(
            http="http://proxy:8080",
            https="https://proxy:8080"
        )
    )
)
```

### 2. TaxonomyEntry - Entradas de Taxonomia

**Antes (JSON):**
```python
taxonomy = {
    "level": "malicious",
    "namespace": "reputation",
    "predicate": "static",
    "value": "1.2.3.4"
}
```

**Agora (Dataclass):**
```python
from sentineliqsdk import TaxonomyEntry

taxonomy = TaxonomyEntry(
    level="malicious",
    namespace="reputation",
    predicate="static",
    value="1.2.3.4"
)
```

### 3. Artifact - Artefatos

**Antes (JSON):**
```python
artifact = {
    "dataType": "ip",
    "data": "8.8.8.8",
    "tlp": 2,
    "pap": 2
}
```

**Agora (Dataclass):**
```python
from sentineliqsdk import Artifact

artifact = Artifact(
    data_type="ip",
    data="8.8.8.8",
    tlp=2,
    pap=2,
    extra={"confidence": 0.9}
)
```

### 4. Operation - Operações

**Antes (JSON):**
```python
operation = {
    "type": "hunt",
    "target": "1.2.3.4",
    "priority": "high"
}
```

**Agora (Dataclass):**
```python
from sentineliqsdk import Operation

operation = Operation(
    operation_type="hunt",
    parameters={"target": "1.2.3.4", "priority": "high"}
)
```

## Dataclasses Disponíveis

### Core Models

- **`WorkerInput`**: Dados de entrada para workers
- **`WorkerConfig`**: Configuração de workers (TLP/PAP, proxy, etc.)
- **`ProxyConfig`**: Configuração de proxy HTTP/HTTPS

### Analysis Models

- **`TaxonomyEntry`**: Entrada de taxonomia para analyzers
- **`Artifact`**: Artefato extraído da análise
- **`Operation`**: Operação de follow-up

### Report Models

- **`AnalyzerReport`**: Relatório completo de analyzer
- **`ResponderReport`**: Relatório completo de responder
- **`WorkerError`**: Resposta de erro

### Extraction Models

- **`ExtractorResult`**: Resultado individual de extração
- **`ExtractorResults`**: Coleção de resultados de extração

## Exemplos de Uso

### Analyzer com Dataclasses

```python
from sentineliqsdk import Analyzer, WorkerInput, TaxonomyLevel

class MyAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        
        # Build taxonomy using dataclass
        taxonomy = self.build_taxonomy(
            level="malicious",
            namespace="reputation",
            predicate="static",
            value=str(observable)
        )
        
        # Build artifacts using dataclass
        artifacts = [
            self.build_artifact("ip", "8.8.8.8", tlp=2),
            self.build_artifact("domain", "example.com")
        ]
        
        full_report = {
            "observable": observable,
            "verdict": "malicious",
            "taxonomy": [taxonomy.to_dict()],
            "artifacts": [artifact.to_dict() for artifact in artifacts]
        }
        
        self.report(full_report)

# Usage
input_data = WorkerInput(data_type="ip", data="1.2.3.4")
analyzer = MyAnalyzer(input_data)
analyzer.run()
```

### Responder com Dataclasses

```python
from sentineliqsdk import Responder, WorkerInput

class MyResponder(Responder):
    def run(self) -> None:
        ip = self.get_data()
        
        # Build operations using dataclass
        operations = [
            self.build_operation("block", target=ip, duration="24h"),
            self.build_operation("alert", severity="high")
        ]
        
        result = {
            "action": "block",
            "target": ip,
            "operations": [operation.to_dict() for operation in operations]
        }
        
        self.report(result)

# Usage
input_data = WorkerInput(data_type="ip", data="1.2.3.4")
responder = MyResponder(input_data)
responder.run()
```

## Compatibilidade com Versões Anteriores

A SDK mantém compatibilidade com entradas de dicionário para facilitar a migração:

```python
# Ambos funcionam
dict_input = {"dataType": "ip", "data": "1.2.3.4"}
dataclass_input = WorkerInput(data_type="ip", data="1.2.3.4")

analyzer = MyAnalyzer(dict_input)  # ✅ Funciona
analyzer = MyAnalyzer(dataclass_input)  # ✅ Funciona
```

## Conversão para JSON

Todas as dataclasses possuem método `to_dict()` para conversão para dicionário JSON:

```python
from sentineliqsdk import WorkerInput

input_data = WorkerInput(data_type="ip", data="1.2.3.4")
json_data = input_data.to_dict()
# Resultado: {"dataType": "ip", "data": "1.2.3.4", "tlp": 2, "pap": 2, "config": {...}}
```

## Benefícios da Migração

### 1. Type Safety
```python
# Antes: Sem verificação de tipos
input_data["dataType"] = 123  # ❌ Erro só em runtime

# Agora: Verificação em tempo de desenvolvimento
input_data = WorkerInput(data_type=123)  # ❌ Erro de tipo imediatamente
```

### 2. Melhor IDE Support
```python
# Autocomplete para propriedades
input_data.data_type  # ✅ IDE sugere: "ip", "url", "domain", etc.
input_data.config.check_tlp  # ✅ IDE sugere: True/False
```

### 3. Estruturas Imutáveis
```python
input_data = WorkerInput(data_type="ip", data="1.2.3.4")
# input_data.data_type = "url"  # ❌ AttributeError - dataclass é frozen
```

### 4. Contratos Claros
```python
# Estrutura bem definida
@dataclass(frozen=True)
class WorkerInput:
    data_type: str
    data: str
    filename: Optional[str] = None
    tlp: int = 2
    pap: int = 2
    config: WorkerConfig = field(default_factory=WorkerConfig)
```

## Migração Gradual

Para migrar código existente:

1. **Identifique entradas JSON**: Substitua dicionários por `WorkerInput`
2. **Atualize builders**: Use métodos que retornam dataclasses
3. **Converta saídas**: Use `to_dict()` quando necessário para JSON
4. **Teste gradualmente**: Mantenha compatibilidade com dicionários

## Exemplos Completos

Veja os exemplos atualizados em:
- `examples/simple_programmatic.py` - Uso básico com dataclasses
- `examples/programmatic_usage.py` - Exemplos avançados
- `examples/dataclass_usage.py` - Demonstração completa das dataclasses

## Testes

Os testes foram atualizados para usar dataclasses:
- `tests/test_dataclasses.py` - Testes específicos para dataclasses
- Testes existentes mantêm compatibilidade com dicionários

## Conclusão

A migração para dataclasses representa um grande avanço na qualidade e segurança da SDK, proporcionando:

- Melhor experiência de desenvolvimento
- Menos erros em runtime
- Código mais limpo e maintível
- Compatibilidade com código existente

A SDK agora oferece o melhor dos dois mundos: type safety moderno com compatibilidade total com código legado.
