# SentinelIQ SDK — Guia do Agente

Esta é a fonte única de verdade para construir analisadores, respondedores e detectores com
o SentinelIQ SDK em `src/sentineliqsdk`. Reflete a implementação atual neste
repositório.

**Requisitos**: Python 3.13, imports absolutos, indentação de 4 espaços, comprimento de linha 100.

## Metadados do Módulo (Novo)

- Todo Analyzer/Responder deve declarar um atributo `METADATA` usando
  `sentineliqsdk.models.ModuleMetadata` e incluí-lo no `full_report` sob a
  chave `metadata`.
- **Campos obrigatórios** (chaves quando serializadas via `to_dict()`):
  - `Name`, `Description`, `Author` (lista de "Nome <email>"), `License`
  - `pattern` (ex.: "smtp", "webhook", "kafka", "threat-intel")
  - `doc_pattern` (descrição curta do formato da documentação)
  - `doc` (URL pública da documentação do módulo — site do SentinelIQ)
  - `VERSION` (um de: `DEVELOPER`, `TESTING`, `STABLE`)

**Exemplo**:

```python
from sentineliqsdk.models import ModuleMetadata

class MyResponder(Responder):
    METADATA = ModuleMetadata(
        name="My Responder",
        description="Does something useful",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="webhook",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/my_responder/",
        version_stage="TESTING",
    )

    def execute(self) -> ResponderReport:
        full = {"action": "noop", "metadata": self.METADATA.to_dict()}
        return self.report(full)
```

## Exemplos Obrigatórios (Regra do Agente)

- Sempre adicione um exemplo executável em `examples/` quando introduzir um novo Analyzer, Responder
  ou Detector.
- **Nomenclatura**: `examples/<kind>/<name>_example.py` onde `<kind>` ∈ {`analyzers`, `responders`,
  `detectors`}.
- **O exemplo deve**:
  - Usar entrada dataclass (`WorkerInput`) e chamar `.run()` (ou `.execute()` quando fornecido).
  - Ser executável localmente apenas com stdlib + SDK.
  - Imprimir um resultado compacto para STDOUT. Chamadas de rede padrão para dry-run e requerem `--execute`.
    Operações impactantes (ex.: scans) devem ser protegidas por `--include-dangerous`.
- Referencie seu exemplo no README ou documentação quando útil.

## Atualizações de Documentação (Sempre)

Mantenha a documentação sincronizada sempre que adicionar ou alterar comportamento:

- Atualize páginas em `docs/` (Guias, Tutoriais, Exemplos, Referência) para refletir o
  comportamento atual, flags e portões de segurança (`--execute`, `--include-dangerous`).
- Vincule novos exemplos nas páginas relevantes (`docs/examples/*.md`) e, quando útil, no README.
- Adicione uma página de uso programático para cada módulo em `docs/modulos/<kind>/<name>.md`.
  A página deve mostrar entrada dataclass (`WorkerInput`) e chamar `.execute()` (ou `.run()`),
  usando apenas stdlib + SDK. Atualize a navegação em `mkdocs.yml` na seção "Modules".
- Se adicionar nova API pública ou módulos, garante que páginas mkdocstrings existam e a navegação em
  `mkdocs.yml` seja atualizada.
- Valide localmente com `poe docs` (ou pré-visualize com `poe docs-serve`).

## Scaffolding (Tarefas Poe)

- **Genérico**: `poe new -- --kind <analyzer|responder|detector> --name <Nome> [--force]`
- **Atalhos**:
  - Analyzer: `poe new-analyzer -- --name Shodan`
  - Responder: `poe new-responder -- --name BlockIp`
  - Detector: `poe new-detector -- --name MyType`

**Saídas (código + exemplo)**:
- Analyzer: `src/sentineliqsdk/analyzers/<snake>.py` e `examples/analyzers/<snake>_example.py`
- Responder: `src/sentineliqsdk/responders/<snake>.py` e
  `examples/responders/<snake>_example.py`
- Detector: `src/sentineliqsdk/extractors/custom/<snake>_detector.py` e
  `examples/detectors/<snake>_example.py`

## Início Rápido

Analyzer mínimo usando dataclasses:

```python
from __future__ import annotations

import json

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class ReputationAnalyzer(Analyzer):
    """Marca 1.2.3.4 como malicioso, outros como seguros."""

    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(level=verdict, namespace="reputation", predicate="static",
                                  value=str(observable))
        return self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    report = ReputationAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4")).run()
    print(json.dumps(report.full_report, ensure_ascii=False))
```

Execute exemplos diretamente, ex.: `python examples/analyzers/shodan_analyzer_all_methods.py --help`.

## Regras de Desenvolvimento — Criando Novo Analyzer/Responder/Detector

Siga estas regras para componentes consistentes. Cada receita lista o layout de arquivos, nomenclatura de classes
e um esqueleto mínimo alinhado com este SDK.

### Analyzer

- **Arquivos**:
  - Código: `src/sentineliqsdk/analyzers/<name>.py`
  - Exemplo: `examples/analyzers/<name>_example.py`
  - Testes: `tests/analyzers/test_<name>.py`
- **Nome da classe**: `<Nome>Analyzer` estendendo `sentineliqsdk.analyzers.Analyzer`.
- **Imports**: absolutos; sempre `from __future__ import annotations` primeiro.
- **Implementar** `execute() -> AnalyzerReport` e fazer `run()` retornar `self.execute()`.
- **Construir taxonomia** via `self.build_taxonomy(...)`; incluir `taxonomy.to_dict()` no seu payload.
- **Usar apenas dataclasses** (`WorkerInput` é obrigatório). TLP/PAP e proxies são aplicados pelo `Worker`.
- **Exemplos** devem ser dry-run por padrão e suportar `--execute` para chamadas reais.

**Esqueleto**:

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full = {"observable": observable, "verdict": "safe", "taxonomy": [taxonomy.to_dict()]}
        return self.report(full)

    def run(self) -> AnalyzerReport:
        return self.execute()
```

**Checklist**:

- Nomenclatura e imports em conformidade; classe termina com `Analyzer`.
- `execute()` implementado; `run()` retorna `AnalyzerReport`.
- Chama `self.report(...)` com um dict; taxonomia incluída.
- Exemplo em `examples/analyzers/` executável e imprime resultado compacto.
- Testes adicionados; `poe lint` e `poe test` passam.
- Documentação atualizada (Guia/Tutoriais/Exemplos/Referência), links adicionados, `mkdocs.yml` atualizado se necessário;
  `poe docs` passa localmente.
- Página de documentação programática adicionada: `docs/modulos/analyzers/<name>.md`.

### Responder

- **Arquivos**:
  - Código: `src/sentineliqsdk/responders/<name>.py`
  - Exemplo: `examples/responders/<name>_example.py`
  - Testes: `tests/responders/test_<name>.py`
- **Nome da classe**: `<Nome>Responder` estendendo `sentineliqsdk.responders.Responder`.
- **Implementar** `execute() -> ResponderReport` e fazer `run()` retornar `self.execute()`.
- **Construir operações** via `self.build_operation(...)` e chamar `self.report(full_report)`.

**Esqueleto**:

```python
from __future__ import annotations

from sentineliqsdk import Responder
from sentineliqsdk.models import ResponderReport


class MyResponder(Responder):
    def execute(self) -> ResponderReport:
        target = self.get_data()
        ops = [self.build_operation("block", target=target)]
        full = {"action": "block", "target": target}
        return self.report(full)

    def run(self) -> ResponderReport:
        return self.execute()
```

**Checklist**:

- Nomenclatura e caminhos corretos; imports absolutos.
- `execute()` e `run()` retornam `ResponderReport`.
- Operações criadas via `build_operation` e reportadas.
- Exemplo em `examples/responders/` executável e imprime resultado compacto.
- Documentação atualizada (Guia/Tutoriais/Exemplos/Referência), links adicionados, `mkdocs.yml` atualizado se necessário;
  `poe docs` passa localmente.
- Página de documentação programática adicionada: `docs/modulos/responders/<name>.md`.

### Detector

- **Arquivos**:
  - Principal: estender `src/sentineliqsdk/extractors/detectors.py` (preferido para tipos oficiais), ou
    criar um detector customizado em `src/sentineliqsdk/extractors/custom/<name>_detector.py` e
    registrá-lo via `Extractor.register_detector(...)` no seu analyzer.
  - Exemplo: `examples/detectors/<name>_example.py`
  - Testes: `tests/extractors/test_<name>_detector.py`
- **Protocolo**: `Detector` com atributo `name: str` e método `matches(value: str) -> bool`.
- **Para incluir no core (tipo oficial)**:
  - Adicionar o literal em `sentineliqsdk.models.DataType`.
  - Importar/adicionar o detector na lista de precedência em `Extractor` (`extractors/regex.py`).
  - Considerar normalização/flags expostas por `DetectionContext` quando relevante.
- **Para uso local apenas (sem tocar no core)**:
  - Registrar via `Extractor.register_detector(MyDetector(), before="hash")`, por exemplo.

**Esqueleto** (customizado):

```python
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class MyDetector:
    name: str = "my_type"

    def matches(self, value: str) -> bool:
        return value.startswith("MY:")
```

**Checklist**:

- Tipo incluído em `DataType` (se core) e precedência ajustada em `Extractor`.
- Testes cobrem positivos/negativos; evitar falsos positivos óbvios.
- Exemplo em `examples/detectors/` demonstrando `Extractor.check_string/iterable`.
- Documentação atualizada (Guia/Tutoriais/Exemplos/Referência), links adicionados, `mkdocs.yml` atualizado se necessário;
  `poe docs` passa localmente.
- Página de documentação programática adicionada: `docs/modulos/detectors/<name>.md`.

## Visão Geral dos Módulos

- `sentineliqsdk.Worker`: base comum para analyzers/responders (config, env, hooks de relatório).
- `sentineliqsdk.Analyzer`: classe base para analyzers; inclui helpers de auto-extração.
- `sentineliqsdk.Responder`: classe base para responders; envelope mais simples.
- `sentineliqsdk.Extractor`: extrator de IOC guiado por stdlib (ip/url/domain/hash/...).
- `sentineliqsdk.runner(worker_cls, input_data)`: conveniência para instanciar e executar.
- `sentineliqsdk.models`: dataclasses para estruturas type-safe.

Layout interno (para mantenedores):
- `src/sentineliqsdk/core/worker.py` implementa `Worker`.
- `src/sentineliqsdk/analyzers/base.py` implementa `Analyzer`.
- `src/sentineliqsdk/responders/base.py` implementa `Responder`.
- `src/sentineliqsdk/extractors/regex.py` implementa `Extractor`.
- `src/sentineliqsdk/core/config/proxy.py` define proxies de env (`EnvProxyConfigurator`).
- `src/sentineliqsdk/core/config/secrets.py` sanitiza config de payload de erro.

## Contrato de Entrada/Saída

Workers recebem dados de entrada como dataclasses e retornam resultados na memória. Este SDK removeu
a entrada de dicionário legada da API pública neste repositório.

- Entrada: passe um dataclass `WorkerInput` para o construtor do worker.
- Saída: `Analyzer.report(...)` retorna `AnalyzerReport`; `Responder.report(...)` retorna
  `ResponderReport`. Exemplos podem imprimir JSON compacto para STDOUT explicitamente.

### Entrada (Dataclasses)

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    filename=None,  # Optional, for file datatypes
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        proxy=ProxyConfig(
            http="http://proxy:8080",
            https="https://proxy:8080"
        )
    )
)
```

Campos de entrada comuns:

- `data_type`: um de `ip`, `url`, `domain`, `fqdn`, `hash`, `mail`, `user-agent`,
  `uri_path`, `registry`, `file`, `other`, `asn`, `cve`, `ip_port`, `mac`, `cidr`.
- `data` ou `filename`: valor observável ou nome do arquivo para `data_type == "file"`.
- `tlp` e `pap`: números aplicados via config quando habilitado.
- `config.*` inclui:
  - `config.check_tlp` / `config.max_tlp`
  - `config.check_pap` / `config.max_pap`
  - `config.proxy.http` / `config.proxy.https` (exportado internamente para clientes stdlib)
  - `config.auto_extract` para analyzers
  - `config.params` (dict/mapping): parâmetros programáticos por módulo
  - `config.secrets` (dict/mapping): segredos/credenciais por módulo

Em caso de erro, chaves sensíveis em `config` contendo qualquer um de `key`, `password`, `secret`, `token`
são substituídas por `"REMOVED"` no payload de erro.

## Conceitos Principais: Worker

Assinatura: `Worker(input_data: WorkerInput, secret_phrases: tuple[str, ...] | None)`

- `get_param(name, default=None, message=None)`: não usado neste repositório (apenas dataclasses).
- `get_env(key, default=None, message=None)`: lê variáveis de ambiente, use apenas para configurações gerais de ambiente (nunca para segredos nem config específica de módulos).
- `get_config(path, default=None)`: lê de `WorkerConfig.params` via caminho pontuado
  (ex.: `"shodan.method"`, `"webhook.headers"`).
- `get_secret(path, default=None, message=None)`: lê de `WorkerConfig.secrets` via
  caminho pontuado (ex.: `"shodan.api_key"`, `"smtp.password"`).
- `get_data() -> Any`: retorna o valor observável (sobrescrito em subclasses).
- `build_operation(op_type: str, **parameters) -> Operation`: descreve operações de acompanhamento.
- `operations(raw) -> list[Operation]`: hook para trabalho de acompanhamento; padrão `[]`.
- `summary(raw) -> dict`: resumo curto; padrão `{}`.
- `artifacts(raw) -> list[Artifact]`: override do analyzer executa auto-extração quando habilitada.
- `report(output: dict) -> dict | AnalyzerReport | ResponderReport`: retorna resultado na memória.
- `error(message: str, ensure_ascii: bool = False) -> NoReturn`: imprime JSON de erro e exit(1).
- `run() -> None`: sua lógica principal (sobrescreva em subclasses).

Aplicação TLP/PAP:

- Habilite com `config.check_tlp`/`config.check_pap`; defina `config.max_tlp`/`config.max_pap`.
- Se excedido, o worker chama `error("TLP is higher than allowed.")` ou o equivalente PAP.

## Analyzer

`Analyzer` estende `Worker` com comportamento específico de analyzer:

- `get_data()`: retorna `filename` quando `data_type == "file"`, caso contrário o campo `data`.
- `auto_extract`: habilitado por padrão a menos que `config.auto_extract` seja `False`.
- `artifacts(raw)`: quando habilitado, usa `Extractor(ignore=self.get_data())` e retorna uma
  coleção de dataclass `list[Artifact]` para o relatório completo.
- `build_taxonomy(level, namespace, predicate, value) -> TaxonomyEntry`: helper para entradas
  de taxonomia onde `level` é um de `info|safe|suspicious|malicious`.
- `build_artifact(data_type, data, **kwargs) -> Artifact`: constrói um dataclass artifact.
- `report(full_report: dict) -> AnalyzerReport`: retorna um envelope com
  `success/summary/artifacts/operations/full_report`.

Notas:
- Helpers legados como `getData`/`checkTlp` foram removidos; use apenas a API moderna.
- Verificações TLP/PAP executam automaticamente em `Worker.__init__`.

## Responder

`Responder` espelha `Analyzer` com um envelope mais simples:

- `get_data()`: retorna o campo `data`.
- `report(full_report) -> ResponderReport` com `success/full_report/operations`.

## Extractor

Extrator de IOC usando helpers da stdlib do Python (ex.: `ipaddress`, `urllib.parse`, `email.utils`)
em vez de regexes complexas. Tipos típicos detectados incluem:

- `ip` (IPv4 e IPv6), `cidr`, `url`, `domain`, `fqdn`, `hash` (MD5/SHA1/SHA256), `mail`,
  `user-agent`, `uri_path`, `registry`, `mac`, `asn`, `cve`, `ip_port`.

API:

- `Extractor(ignore: str | None = None, strict_dns: bool = False, normalize_domains: bool = False,
  normalize_urls: bool = False, support_mailto: bool = False, max_string_length: int = 10000,
  max_iterable_depth: int = 100)`
- `check_string(value: str) -> str`: retorna um nome de tipo de dados ou string vazia.
- `check_iterable(iterable: list | dict | str | tuple | set) -> list[ExtractorResult]`:
  retorna uma lista de-duplicada de resultados dataclass.

Ordem de precedência (primeira correspondência ganha): ip → cidr → url → domain → hash → user-agent → uri_path →
registry → mail → mac → asn → cve → ip_port → fqdn.
Use `Extractor.register_detector(detector, before=..., after=...)` para customizar.

## Exemplo de Analyzer Mínimo

### Dataclasses

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput


class ReputationAnalyzer(Analyzer):
    """Analyzer de exemplo que marca "1.2.3.4" como malicioso e outros como seguros."""

    def run(self) -> None:
        observable = self.get_data()

        verdict = "malicious" if observable == "1.2.3.4" else "safe"

        # Construir taxonomia usando dataclass
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="reputation",
            predicate="static",
            value=str(observable),
        )

        full = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
        }

        self.report(full)


if __name__ == "__main__":
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    ReputationAnalyzer(input_data).run()
```

## Exemplo de Responder Mínimo

### Dataclasses

```python
from __future__ import annotations

from sentineliqsdk import Responder, WorkerInput


class BlockIpResponder(Responder):
    def run(self) -> None:
        ip = self.get_data()

        result = {
            "action": "block",
            "target": ip,
            "status": "ok",
        }
        self.report(result)


if __name__ == "__main__":
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    BlockIpResponder(input_data).run()
```

## Exemplo de Entrada e Saída

Entrada (programática): `WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)`

Resultado programático do Analyzer (dataclass `AnalyzerReport`):

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "verdict": "malicious",
    "taxonomy": [
      {"level": "malicious", "namespace": "reputation", "predicate": "static", "value": "1.2.3.4"}
    ]
  }
}
```

Em caso de erro, o worker imprime para STDOUT e sai com código 1:

```json
{ "success": false, "input": { ... }, "errorMessage": "<reason>" }
```

## Operações e Artefatos

- Use `build_operation("<type>", **params)` e retorne uma lista de `operations(full_report)` para
  disparar trabalho de acompanhamento.
- Construa artefatos em analyzers com `build_artifact("file", "/path/to/file")` ou com
  tipos não-arquivo: `build_artifact("ip", "8.8.8.8", tlp=2)`.
- Quando `auto_extract` está habilitado (padrão), `artifacts(full_report)` usa `Extractor` para detectar
  IOCs no relatório, excluindo o valor observável original.

## Execução e Depuração

- Execute exemplos diretamente em `examples/` com `python ...`.
- Use `--execute` para chamadas de rede reais; caso contrário permaneça em dry‑run.
- Use `--include-dangerous` para habilitar ações impactantes quando aplicável.
- Proxies: defina `WorkerInput.config.proxy.http` / `.https`.

## Uso Programático (Sem I/O de Arquivo)

Use o SDK diretamente passando `WorkerInput` para o construtor e imprimindo conforme necessário.

### Dataclasses

```python
from sentineliqsdk import Analyzer, WorkerInput


class MyAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        # Your analysis logic here
        result = {"observable": observable, "verdict": "safe"}
        self.report(result)


# Criar dados de entrada usando dataclass
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
)

analyzer = MyAnalyzer(input_data=input_data)
analyzer.run()
```

### Resultados em Memória

Para obter resultados em memória, chame `execute()` (ou `run()` se sua classe retorna o relatório):

```python
report = analyzer.execute()  # or analyzer.run() if run() returns the report
print(report.full_report)
```

### Processamento em Lote

Processe múltiplos observáveis sem I/O de arquivo:

```python
from sentineliqsdk import WorkerInput

observables = ["1.2.3.4", "8.8.8.8", "5.6.7.8"]
results = []

for obs in observables:
    input_data = WorkerInput(
        data_type="ip",
        data=obs,
        tlp=2,
        pap=2,
    )

    analyzer = MyAnalyzer(input_data=input_data)
    # Processar e obter resultado em memória
    result = analyzer.execute()
    results.append(result)
```

## Dataclasses e Segurança de Tipos

O SDK fornece dataclasses para melhor segurança de tipos e experiência do desenvolvedor:

- `WorkerInput`: Input data for workers
- `WorkerConfig`: Worker configuration (TLP/PAP, proxy, etc.)
- `ProxyConfig`: HTTP/HTTPS proxy configuration
- `TaxonomyEntry`: Taxonomy entries for analyzers
- `Artifact`: Extracted artifacts
- `Operation`: Follow‑up operations
- `AnalyzerReport`: Complete analyzer report
- `ResponderReport`: Complete responder report
- `WorkerError`: Error responses
- `ExtractorResult`: Individual extraction results
- `ExtractorResults`: Collection of extraction results

### Example Usage

```python
from sentineliqsdk import (
    WorkerInput, WorkerConfig, ProxyConfig,
    TaxonomyEntry, Artifact, Operation,
)

# Criar entrada estruturada
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        proxy=ProxyConfig(http="http://proxy:8080"),
    ),
)

# Criar entrada de taxonomia
taxonomy = TaxonomyEntry(
    level="malicious",
    namespace="reputation",
    predicate="static",
    value="1.2.3.4",
)

# Criar artefato
artifact = Artifact(
    data_type="ip",
    data="8.8.8.8",
    tlp=2,
    extra={"confidence": 0.9},
)

# Criar operação
operation = Operation(
    operation_type="hunt",
    parameters={"target": "1.2.3.4", "priority": "high"},
)

# Converter para dict para serialização JSON
# Nota: use dataclasses.asdict para dataclasses sem to_dict() customizado
from dataclasses import asdict
json_data = {
    "taxonomy": [taxonomy.to_dict()],
    "artifacts": [asdict(artifact)],
    "operations": [asdict(operation)],
}
```

## Dicas de Projeto e CI

- Lint e verificação de tipos: `poe lint` (pre-commit com ruff/mypy configurado).
- Testes: `poe test` (pytest com cobertura para `reports/`).
- Docs: `poe docs` constrói site MkDocs para `docs/` (veja `.github/workflows/docs.yml`).
- Build: `uv build`; publica via CI no release do GitHub.

## Releases (CI/CD)

Este repositório publica no PyPI via GitHub Actions quando você cria um GitHub Release.

- Workflow: veja `.github/workflows/publish.yml` (executa `uv build` então `uv publish`).
- Auth: GitHub OIDC (`permissions: id-token: write`) com um PyPI Trusted Publisher.
- Trigger: GitHub Release para uma tag como `vX.Y.Z`.

Checklist de release (mantenedores):

1. Garantir que `main` está verde
   - Abrir um PR e aguardar o workflow "Test" passar.
   - Fazer merge para `main` quando lint, tipos e testes passarem.
2. Atualizar versão e changelog com Commitizen
   - Recomendado (usa o env do projeto): `uv run cz bump`
   - Exemplos não-interativos:
     - Patch: `uv run cz bump --increment patch`
     - Minor: `uv run cz bump --increment minor`
     - Major: `uv run cz bump --increment major`
   - Pré-releases:
     - Primeiro RC: `uv run cz bump --prerelease rc`
     - Próximo RC: `uv run cz bump --prerelease rc`
     - RC para próximo minor: `uv run cz bump --increment minor --prerelease rc`
   - Commitizen atualiza `[project].version` em `pyproject.toml`, atualiza `CHANGELOG.md`, cria
     a tag `vX.Y.Z` e faz commit da mudança (conforme `[tool.commitizen]`).
3. Push do branch e tags
   - `git push origin main --follow-tags`
   - Se seu branch local estiver atrasado: `git pull --rebase origin main` então push novamente.
4. Criar um GitHub Release para a nova tag
   - UI: Releases → New release → Escolher tag `vX.Y.Z` → Publish.
   - CLI: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file CHANGELOG.md --latest`
5. CI publica no PyPI
   - O workflow "Publish" executa e chama `uv publish` usando OIDC.
   - Acompanhar em Actions → Publish (ou `gh run list --workflow=Publish`).
6. Verificar o release
   - `pip install sentineliqsdk==X.Y.Z`
   - `python -c "import importlib.metadata as m; print(m.version('sentineliqsdk'))"`

Pré-requisitos (uma vez, org/mantenedores):

- Configurar um PyPI Trusted Publisher para este repo:
  - PyPI: Project → Settings → Collaboration → Trusted Publishers → Add → GitHub
    - Repository: `killsearch/sentineliqsdk`
    - Workflows: permitir `.github/workflows/publish.yml`
  - Sem tokens de API clássicos; OIDC é concedido por `id-token: write`.
- Opcional: proteger o ambiente `pypi` no GitHub com revisores obrigatórios.

Notas e dicas:

- Formato da tag é `v$version` (config Commitizen); deve corresponder ao `pyproject.toml`.
- Marcar GitHub Releases como "Pre-release" ao publicar RCs (`X.Y.Z-rc.N`).
- Se o job Publish falhar com erro de permissão PyPI, revisar as configurações do Trusted Publisher
  e as `permissions` do workflow.
