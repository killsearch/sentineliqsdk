# SentinelIQ SDK — Regras de Desenvolvimento

Este documento define regras, padrões e convenções de desenvolvimento para o SentinelIQ SDK,
em alinhamento com o AGENTS.md e o código atual em `src/sentineliqsdk`.

## Índice

1. Visão Geral
2. Ambiente
3. Padrões de Código
4. Estrutura do Projeto
5. Componentes (Analyzer/Responder/Detector)
6. Exemplos Obrigatórios
7. Qualidade: Lint, Tipos e Testes
8. Docs e Build
9. Releases (CI/CD)
10. Segurança e Privacidade
11. Checklist de PR

---

## Visão Geral

- Python: 3.13 (mínimo)
- Imports absolutos; sempre `from __future__ import annotations` no topo
- Indentação de 4 espaços; largura de linha 100
- API moderna baseada em dataclasses (sem dicionários legados neste repositório)

Princípios SOLID no design:
- SRP: classes focadas (Worker/Analyzer/Responder/Extractor)
- OCP: hooks (`summary`, `artifacts`, `operations`, `run`) para extensão
- LSP/ISP/DIP: contratos claros; dependências externas encapsuladas

---

## Ambiente

Ambientes suportados:
- GitHub Codespaces (recomendado)
- VS Code Dev Container (recomendado)
- Local com `uv`

Comandos úteis:
```bash
# Criar ambiente (com dependências de desenvolvimento)
uv sync --python 3.13 --group dev --all-extras

# Ativar o ambiente virtual
# - macOS/Linux (bash/zsh):
source .venv/bin/activate
# - Windows (PowerShell):
. .\.venv\Scripts\Activate.ps1

# Instalar hooks do pre-commit (alternativa sem ativar: `uv run pre-commit install --install-hooks`)
pre-commit install --install-hooks

# Tarefas principais (sempre via uv)
uv run poe lint
uv run poe test
uv run poe docs
uv run poe docs-serve   # servidor local de docs (http://localhost:8000)
```

---

## Padrões de Código

Diretrizes gerais:
- `from __future__ import annotations` em primeiro lugar
- Imports absolutos, ordenados (stdlib → terceiros → locais)
- Sem imports relativos (ver Ruff: `ban-relative-imports = "all"`)
- Type hints nas APIs públicas; evitar `Any` quando viável
- Docstrings sucintas e úteis; evite comentários redundantes

Convenções de nomenclatura:
- Arquivos Python: `snake_case.py`
- Classes: `PascalCase`
- Funções/métodos/variáveis: `snake_case`
- Constantes: `UPPER_SNAKE_CASE`

Assinaturas corretas (exemplos):
```python
from __future__ import annotations
from sentineliqsdk.models import WorkerInput

class Worker:
    def __init__(self, input_data: WorkerInput, secret_phrases: tuple[str, ...] | None = None) -> None:
        ...

class Analyzer(Worker):
    def build_taxonomy(self, level: str, namespace: str, predicate: str, value: str):
        ...
```

---

## Estrutura do Projeto

```
src/sentineliqsdk/
  __init__.py                # API pública (+ runner)
  constants.py               # Constantes (TLP/PAP, HASH_LENGTHS, etc.)
  models.py                  # Dataclasses (WorkerInput, Reports, etc.)
  core/
    worker.py                # Base Worker (TLP/PAP, proxies, erros)
    config/
      proxy.py               # EnvProxyConfigurator
      secrets.py             # sanitize_config
  analyzers/
    base.py                  # Analyzer base
    shodan.py                # Exemplo
    axur.py                  # Exemplo
  responders/
    base.py                  # Responder base
  extractors/
    regex.py                 # Extractor (ordem, normalização, limites)
    detectors.py             # Detectores (ip, url, domain, ...)
    custom/                  # Detectores locais opcionais
examples/
  _templates/                # Templates de scaffolding
  analyzers/                 # Exemplos de analyzers
tests/
  ...                        # Testes unitários
```

---

## Componentes (Analyzer/Responder/Detector)

Regras comuns:
- Use dataclasses (`WorkerInput`) na construção
- `run()` pode retornar o relatório chamando `execute()` internamente (recomendado)
- Utilize `self.report(...)` para obter `AnalyzerReport`/`ResponderReport`

Analyzer (esqueleto mínimo):
```python
from __future__ import annotations
from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport

class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        obs = self.get_data()
        tax = self.build_taxonomy("safe", "example", "static", str(obs))
        return self.report({"observable": obs, "verdict": "safe", "taxonomy": [tax.to_dict()]})

    def run(self) -> AnalyzerReport:
        return self.execute()
```

Responder (esqueleto mínimo):
```python
from __future__ import annotations
from sentineliqsdk import Responder
from sentineliqsdk.models import ResponderReport

class MyResponder(Responder):
    def execute(self) -> ResponderReport:
        target = self.get_data()
        return self.report({"action": "noop", "target": target})

    def run(self) -> ResponderReport:
        return self.execute()
```

Extractor:
- Usa stdlib (e.g., `ipaddress`, `urllib.parse`, `email.utils`)
- Tipos: `ip`, `cidr`, `url`, `domain`, `fqdn`, `hash`, `mail`, `user-agent`, `uri_path`,
  `registry`, `mac`, `asn`, `cve`, `ip_port`
- Precedência: `ip → cidr → url → domain → hash → user-agent → uri_path → registry → mail → mac → asn → cve → ip_port → fqdn`
- Customização: `Extractor.register_detector(det, before=..., after=...)`

Detector (custom):
```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class MyDetector:
    name: str = "my_type"
    def matches(self, value: str) -> bool:
        return value.startswith("MY:")
```

---

## Exemplos Obrigatórios

Para cada novo Analyzer/Responder/Detector, inclua um exemplo executável:
- Caminho: `examples/<kind>/<name>_example.py`
- Use `WorkerInput` e chame `.run()` (ou `.execute()` quando necessário)
- Imprima resultado compacto no STDOUT
- Por padrão, chamadas de rede ficam em dry‑run; habilite com `--execute`
- Operações impactantes exigem `--include-dangerous`

Scaffolding com Poe:
```bash
uv run poe new -- --kind analyzer  --name Shodan
uv run poe new -- --kind responder --name BlockIp
uv run poe new -- --kind detector  --name MyType

# Atalhos:
uv run poe new-analyzer  -- --name Shodan
uv run poe new-responder -- --name BlockIp
uv run poe new-detector  -- --name MyType
```

---

## Qualidade: Lint, Tipos e Testes

Lint/Tipos:
- `uv run poe lint` executa pre-commit (Ruff + Mypy)
- Regras principais: largura 100, imports absolutos, sem relativos

Testes:
- `uv run poe test` executa pytest com cobertura gerando relatórios em `reports/`
- Escreva testes focados no escopo alterado; evite corrigir falhas não relacionadas

Práticas de validação:
- Comece do específico (unidade alterada) para o mais amplo
- Após confiança, rode a suíte completa

---

## Docs e Build

- Docs: `uv run poe docs` (MkDocs) gera o site em `site/` e usa fontes em `docs/`
- Servir docs localmente: `uv run poe docs-serve` (http://localhost:8000)
- CI de docs publica no GitHub Pages automaticamente em pushes para main e em Releases
- Build do pacote: `uv build`

---

## Releases (CI/CD)

Workflows:
- `.github/workflows/test.yml` — Lint e testes (uv)
- `.github/workflows/docs.yml` — Build e deploy de documentação (GitHub Pages)
- `.github/workflows/publish.yml` — Publicação PyPI via GitHub Release (OIDC Trusted Publisher)

Fluxo recomendado:
1. Garantir que `main` está verde (CI “CI” passou)
2. Rodar bump de versão e changelog: `uv run cz bump` (ou `--increment patch|minor|major`, `--prerelease rc`)
3. Enviar commits e tags: `git push origin main --follow-tags`
4. Criar Release para a tag `vX.Y.Z` no GitHub
5. Acompanhar workflows:
   - “Publish”: valida tag == versão do pyproject, builda e publica no PyPI
   - “Docs”: publica documentação no GitHub Pages
6. Validar publicação: `pip install sentineliqsdk==X.Y.Z`

Notas:
- A tag `v$version` deve casar com a versão em `pyproject.toml` (checado no CI)
- Releases RC: marcar como “Pre-release”

---

## Segurança e Privacidade

- `Worker.error(...)` emite JSON com `input` sanitizado via `sanitize_config` substituindo
  valores de chaves contendo: `key`, `password`, `secret`, `token`
- `secret_phrases` no construtor de `Worker` permite estender a lista
- Proxies: `WorkerInput.config.proxy.http/https` e variáveis `http_proxy`/`https_proxy`

---

## Checklist de PR

Antes de abrir o PR:
- [ ] Código segue padrões (imports absolutos, hints, 100 colunas)
- [ ] Exemplos atualizados/adicionados em `examples/`
- [ ] Testes cobrindo a mudança (`uv run poe test` OK)
- [ ] Lint/tipos passam (`uv run poe lint` OK)
- [ ] Documentação/AGENTS.md/README atualizados quando necessário

Após review:
- [ ] Mensagens no padrão Conventional Commits / Commitizen
- [ ] CHANGELOG/versão atualizados quando aplicável

---

Para dúvidas ou propostas, abra uma Issue/Discussion no GitHub.

