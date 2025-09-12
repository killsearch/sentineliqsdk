# Analyzer Base

## Visão Geral

Todos os analyzers do SentinelIQ SDK herdam da classe base `Analyzer`, que fornece funcionalidades comuns para análise de dados de threat intelligence.

## Classe Base Analyzer

### Herança

```python
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

class MeuAnalyzer(Analyzer):
    METADATA = ModuleMetadata(
        name="Meu Analyzer",
        description="Descrição do analyzer",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/meu_analyzer/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        # Implementação específica do analyzer
        pass

    def run(self) -> AnalyzerReport:
        return self.execute()
```

### Métodos Principais

#### `execute()`
Método principal que deve ser implementado por cada analyzer. Contém a lógica específica de análise.

#### `run()`
Método de entrada que chama `execute()`. Geralmente não precisa ser modificado.

#### `get_data()`
Retorna os dados a serem analisados do `WorkerInput`.

#### `get_secret(key, message=None)`
Obtém credenciais seguras da configuração.

#### `get_config(key, default=None)`
Obtém configurações específicas do módulo.

#### `build_taxonomy(level, namespace, predicate, value)`
Constrói taxonomia padronizada para o relatório.

#### `report(data)`
Gera o relatório final do analyzer.

## Estrutura do Relatório

Todos os analyzers devem retornar um `AnalyzerReport` com a seguinte estrutura:

```python
full_report = {
    "observable": self.get_data(),
    "verdict": "safe|suspicious|malicious|info",
    "taxonomy": [taxonomy.to_dict()],
    "metadata": self.METADATA.to_dict(),
    # Dados específicos do analyzer
}

return self.report(full_report)
```

## Níveis de Taxonomia

- **`info`**: Informacional, sem implicações de segurança
- **`safe`**: Confirmadamente seguro/limpo
- **`suspicious`**: Suspeito, requer investigação adicional
- **`malicious`**: Confirmadamente malicioso

## Configuração e Segurança

### Uso de Secrets
```python
# CORRETO: Use get_secret() para credenciais
api_key = self.get_secret("meu_analyzer.api_key", "API key obrigatória")
```

### Uso de Configurações
```python
# CORRETO: Use get_config() para configurações
timeout = self.get_config("meu_analyzer.timeout", 30)
```

## Tratamento de Erros

Todos os analyzers devem implementar tratamento adequado de erros:

```python
try:
    # Lógica do analyzer
    result = self.analyze_data()
except Exception as e:
    self.logger.error(f"Erro na análise: {e}")
    # Retornar relatório com erro ou re-raise conforme apropriado
```

## Veja Também

- [Building Analyzers](../tutorials/building-analyzers.md)
- [WorkerConfig](../core/worker-config.md)
- [Taxonomy](../core/taxonomy.md)
- [API Reference](../reference/api/analyzer.md)