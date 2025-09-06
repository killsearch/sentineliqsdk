# SentinelIQ SDK — Regras de Desenvolvimento e Manutenção

Este documento estabelece todas as regras, padrões e convenções para desenvolvimento e manutenção do projeto SentinelIQ SDK.

## 📋 Índice

1. [Visão Geral do Projeto](#visão-geral-do-projeto)
2. [Configuração do Ambiente](#configuração-do-ambiente)
3. [Padrões de Código](#padrões-de-código)
4. [Estrutura de Arquivos](#estrutura-de-arquivos)
5. [Convenções de Nomenclatura](#convenções-de-nomenclatura)
6. [Testes](#testes)
7. [Qualidade de Código](#qualidade-de-código)
8. [Documentação](#documentação)
9. [Versionamento e Releases](#versionamento-e-releases)
10. [CI/CD](#cicd)
11. [Segurança](#segurança)
12. [Contribuição](#contribuição)

---

## 🎯 Visão Geral do Projeto

### Propósito
O SentinelIQ SDK é uma biblioteca Python moderna que fornece classes utilitárias para construir analisadores e respondedores para a plataforma SentinelIQ.

### Requisitos Técnicos
- **Python**: >=3.13, <4.0
- **Indentação**: 4 espaços
- **Comprimento de linha**: 100 caracteres
- **Imports**: Absolutos (sem imports relativos)

### Arquitetura
O projeto segue princípios SOLID:
- **SRP**: Classes focadas em responsabilidades específicas
- **OCP**: Hooks para extensão sem modificação
- **LSP**: Subclasses podem sobrescrever comportamentos sem quebrar contratos
- **ISP**: Interfaces mínimas e coesas
- **DIP**: Dependências externas encapsuladas

---

## ⚙️ Configuração do Ambiente

### Ambientes de Desenvolvimento Suportados

1. **GitHub Codespaces** (Recomendado)
   - Clique em "Open in GitHub Codespaces"
   - Desenvolvimento direto no navegador

2. **VS Code Dev Container** (Recomendado)
   - Clique em "Open in Dev Containers"
   - Clone em volume de container

3. **uv** (Local)
   ```bash
   # Criar e instalar ambiente virtual
   uv sync --python 3.13 --all-extras
   
   # Ativar ambiente virtual
   source .venv/bin/activate
   
   # Instalar hooks pre-commit
   pre-commit install --install-hooks
   ```

### Pré-requisitos
- Docker Desktop
- VS Code com extensão Dev Containers
- Chave SSH configurada no GitHub
- Fonte Nerd Font (opcional, para melhor experiência)

---

## 📝 Padrões de Código

### Estrutura de Classes

#### Worker (Classe Base)
```python
from __future__ import annotations
from abc import ABC, abstractmethod

class Worker(ABC):
    """Funcionalidade comum para analisadores e respondedores."""
    
    def __init__(
        self,
        job_directory: str | None = None,
        secret_phrases: tuple[str, ...] | None = None,
    ) -> None:
        # Implementação...
    
    @abstractmethod
    def run(self) -> None:
        """Lógica principal - deve ser sobrescrita em subclasses."""
        ...
```

#### Analyzer
```python
class Analyzer(Worker):
    """Classe base para analisadores com suporte a auto-extração."""
    
    def get_data(self) -> Any:
        """Retorna filename quando dataType == 'file', senão o campo data."""
        ...
    
    def build_taxonomy(
        self, 
        level: str, 
        namespace: str, 
        predicate: str, 
        value: str
    ) -> dict:
        """Helper para entradas de taxonomia."""
        ...
```

#### Responder
```python
class Responder(Worker):
    """Classe base para respondedores com formato de relatório simplificado."""
    
    def get_data(self) -> Any:
        """Retorna o campo data."""
        ...
```

### Imports

#### Estrutura de Imports
```python
from __future__ import annotations

# Imports da biblioteca padrão
import json
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, NoReturn

# Imports locais (absolutos)
from sentineliqsdk.core.worker import Worker
from sentineliqsdk.analyzers.base import Analyzer
```

#### Regras de Import
- **Sempre** usar `from __future__ import annotations` no topo
- **Nunca** usar imports relativos (ex: `from .worker import Worker`)
- **Sempre** usar imports absolutos (ex: `from sentineliqsdk.core.worker import Worker`)
- Ordenar imports: stdlib, third-party, local
- Uma linha por import

### Type Hints

#### Obrigatórios
```python
def get_param(
    self, 
    name: str, 
    default: Any = None, 
    message: str | None = None
) -> Any:
    """Método com type hints completos."""
    ...

def report(self, output: dict, ensure_ascii: bool = False) -> None:
    """Método com parâmetros tipados."""
    ...
```

#### Convenções
- **Sempre** usar type hints em métodos públicos
- **Sempre** usar `|` para union types (Python 3.10+)
- **Sempre** usar `None` em vez de `type(None)`
- **Sempre** documentar tipos complexos

---

## 📚 Exemplos Obrigatórios (Regra do Agente)

- Sempre que criar um novo Analyzer, Responder ou Detector, adicione um exemplo executável em
  `examples/`.
- Estrutura sugerida: `examples/<tipo>/<nome>_example.py` onde `<tipo>` ∈ {`analyzers`,
  `responders`, `detectors`}.
- O exemplo deve:
  - Usar dataclasses (`WorkerInput`) e chamar `.run()` (ou `.execute()` quando existir).
  - Imprimir um resultado compacto no STDOUT (JSON resumido).
  - Por padrão, ser “dry‑run” para chamadas de rede; habilitar execução real com `--execute`.
  - Operações potencialmente impactantes (e.g., scans) exigem `--include-dangerous`.
- Evite criar pastas alternativas (ex.: `exemplo/`); padronize em `examples/`.
- Atualize README/docs para referenciar o novo exemplo quando aplicável.

---

## 📁 Estrutura de Arquivos

### Organização do Projeto
```
sentineliqsdk/
├── src/sentineliqsdk/           # Código fonte principal
│   ├── __init__.py             # API pública
│   ├── core/                   # Funcionalidades centrais
│   │   ├── worker.py           # Classe base Worker
│   │   ├── config/             # Configurações
│   │   ├── io/                 # Input/Output
│   │   └── runtime/            # Runtime utilities
│   ├── analyzers/              # Classes de analisadores
│   │   └── base.py             # Classe base Analyzer
│   ├── responders/             # Classes de respondedores
│   │   └── base.py             # Classe base Responder
│   └── extractors/             # Extratores de IOCs
│       └── regex.py            # Extrator baseado em regex
├── tests/                      # Testes
│   ├── fixtures/               # Dados de teste
│   └── test_*.py               # Arquivos de teste
├── docs/                       # Documentação
├── .github/                    # Configurações GitHub
│   └── workflows/              # CI/CD
├── pyproject.toml              # Configuração do projeto
├── .pre-commit-config.yaml     # Hooks pre-commit
└── README.md                   # Documentação principal
```

### Convenções de Arquivos

#### Nomenclatura
- **Arquivos Python**: `snake_case.py`
- **Classes**: `PascalCase`
- **Métodos/Funções**: `snake_case`
- **Constantes**: `UPPER_SNAKE_CASE`
- **Variáveis**: `snake_case`

#### Estrutura de Módulos
```python
"""Docstring do módulo explicando seu propósito."""

from __future__ import annotations

# Imports...

# Constantes do módulo
DEFAULT_SECRET_PHRASES = ("key", "password", "secret", "token")

# Classes e funções...

# Código de execução (se aplicável)
if __name__ == "__main__":
    # ...
```

---

## 🧪 Testes

### Estrutura de Testes

#### Organização
```
tests/
├── __init__.py
├── fixtures/                   # Dados de teste
│   ├── test-minimal-config.json
│   └── test-proxy-config.json
├── test_import.py              # Testes de importação
├── test_suite_analyzer.py      # Testes de analisadores
├── test_suite_extractor.py     # Testes de extratores
├── test_suite_files.py         # Testes de arquivos
└── test_suite_integration.py   # Testes de integração
```

#### Padrões de Teste

##### Nomenclatura
```python
def test_method_name_scenario() -> None:
    """Testa comportamento específico do método."""
    # Arrange
    # Act
    # Assert
```

##### Fixtures
```python
def _set_stdin_from_fixture(
    monkeypatch: pytest.MonkeyPatch, 
    fixture_path: str
) -> None:
    """Helper para configurar STDIN com dados de fixture."""
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, fixture_path)) as fh:
        content = fh.read()
    monkeypatch.setattr(sys, "stdin", StringIO(content))
```

##### Testes de Integração
```python
def test_output(
    monkeypatch: pytest.MonkeyPatch, 
    capsys: pytest.CaptureFixture[str]
) -> None:
    """Testa saída completa do analisador."""
    monkeypatch.setattr(
        sys, 
        "stdin", 
        StringIO(json.dumps({"data": "8.8.8.8", "dataType": "ip"}))
    )
    analyzer = Analyzer()
    analyzer.report({"result": "1.2.3.4"})
    
    output = capsys.readouterr().out.strip()
    json_output = json.loads(output)
    assert analyzer.get_data() not in output
    assert json_output["artifacts"][0]["data"] == "1.2.3.4"
```

### Execução de Testes

#### Comandos
```bash
# Executar todos os testes
poe test

# Executar testes com coverage
pytest --cov=src/sentineliqsdk --cov-report=term-missing

# Executar testes específicos
pytest tests/test_suite_analyzer.py::test_default_config
```

#### Configuração
- **Framework**: pytest
- **Coverage**: pytest-cov
- **Paralelização**: pytest-xdist (auto)
- **Relatórios**: XML em `reports/`
- **Fixtures**: pytest fixtures para setup/teardown

---

## 🔍 Qualidade de Código

### Ferramentas de Linting

#### Ruff (Linter e Formatter)
```toml
[tool.ruff]
line-length = 100
target-version = "py313"
src = ["src", "tests"]

[tool.ruff.lint]
select = [
    "A", "ASYNC", "B", "C4", "C90", "D", "DTZ", "E", "F", 
    "FLY", "FURB", "I", "ISC", "LOG", "N", "NPY", "PERF", 
    "PGH", "PIE", "PL", "PT", "Q", "RET", "RUF", "RSE", 
    "SIM", "TID", "UP", "W", "YTT"
]
ignore = ["D203", "D213", "E501", "PGH002", "PGH003", "RET504", "S101", "S307"]
```

#### MyPy (Type Checker)
```toml
[tool.mypy]
ignore_missing_imports = true
pretty = true
show_column_numbers = true
show_error_codes = true
warn_unreachable = true
```

### Pre-commit Hooks

#### Configuração
```yaml
repos:
  - repo: local
    hooks:
      - id: ruff-check
        name: ruff check
        entry: ruff check
        args: ["--force-exclude", "--extend-fixable=F401,F841", "--fix-only"]
      
      - id: ruff-format
        name: ruff format
        entry: ruff format
        args: [--force-exclude]
      
      - id: mypy
        name: mypy
        entry: mypy
```

#### Execução
```bash
# Instalar hooks
pre-commit install --install-hooks

# Executar em todos os arquivos
poe lint

# Executar manualmente
pre-commit run --all-files
```

### Regras de Qualidade

#### Código
- **Máximo 100 caracteres por linha**
- **4 espaços de indentação** (nunca tabs)
- **Docstrings obrigatórias** em classes e métodos públicos
- **Type hints obrigatórios** em assinaturas públicas
- **Imports absolutos** sempre

#### Documentação
- **Docstrings**: Formato NumPy
- **Comentários**: Explicar "por que", não "o que"
- **README**: Sempre atualizado
- **CHANGELOG**: Seguir Keep a Changelog

---

## 📚 Documentação

### Estrutura de Documentação

#### Arquivos Principais
- `README.md`: Visão geral e instalação
- `AGENTS.md`: Guia para desenvolvedores de agentes
- `CHANGELOG.md`: Histórico de mudanças
- `docs/`: Documentação técnica (MkDocs)

#### Docstrings

##### Formato NumPy
```python
def build_taxonomy(
    self, 
    level: str, 
    namespace: str, 
    predicate: str, 
    value: str
) -> dict:
    """Constrói entrada de taxonomia para relatórios.
    
    Parameters
    ----------
    level : str
        Nível de severidade: 'info', 'safe', 'suspicious', 'malicious'
    namespace : str
        Namespace da taxonomia
    predicate : str
        Predicado da entrada
    value : str
        Valor da entrada
        
    Returns
    -------
    dict
        Dicionário com estrutura de taxonomia
        
    Examples
    --------
    >>> analyzer = Analyzer()
    >>> taxonomy = analyzer.build_taxonomy(
    ...     level="malicious",
    ...     namespace="reputation", 
    ...     predicate="static",
    ...     value="1.2.3.4"
    ... )
    """
```

### Geração de Documentação

#### Comandos
```bash
# Construir documentação
poe docs

# Servir localmente
poe docs-serve
```

#### Configuração MkDocs
```yaml
site_name: SentinelIQ SDK
theme:
  name: material
  features:
    - navigation.tabs
    - navigation.sections
    - navigation.expand
    - navigation.top
    - search.highlight
    - search.share
```

---

## 🏷️ Versionamento e Releases

### Convenção de Commits

#### Conventional Commits
```bash
# Formato
<type>[optional scope]: <description>

# Exemplos
feat: add support for file artifacts
fix: resolve TLP validation issue
docs: update API documentation
test: add integration tests for extractor
```

#### Tipos Permitidos
- `feat`: Nova funcionalidade
- `fix`: Correção de bug
- `docs`: Mudanças na documentação
- `style`: Formatação, sem mudança de código
- `refactor`: Refatoração de código
- `test`: Adição ou correção de testes
- `chore`: Mudanças em build, dependências, etc.

### Versionamento Semântico

#### Estrutura
```
MAJOR.MINOR.PATCH[-prerelease]

# Exemplos
1.0.0        # Release inicial
1.1.0        # Nova funcionalidade
1.1.1        # Correção de bug
1.2.0-rc.1   # Release candidate
```

#### Regras
- **MAJOR**: Mudanças incompatíveis na API
- **MINOR**: Funcionalidades compatíveis
- **PATCH**: Correções compatíveis

### Processo de Release

#### Com Commitizen
```bash
# Bump automático
uv run cz bump

# Bump específico
uv run cz bump --increment patch
uv run cz bump --increment minor
uv run cz bump --increment major

# Pre-release
uv run cz bump --prerelease rc
```

#### Checklist de Release
1. ✅ Branch `main` está verde
2. ✅ Todos os testes passando
3. ✅ Linting sem erros
4. ✅ Documentação atualizada
5. ✅ CHANGELOG atualizado
6. ✅ Version bump executado
7. ✅ Tag criada e pushada
8. ✅ GitHub Release criado
9. ✅ CI/CD publicou no PyPI

---

## 🚀 CI/CD

### Workflows GitHub Actions

#### Test Workflow
```yaml
name: Test
on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.13"]
        resolution-strategy: ["highest", "lowest-direct"]
    
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      
      - name: Start Dev Container
        run: devcontainer up --workspace-folder .
      
      - name: Lint package
        run: devcontainer exec --workspace-folder . poe lint
      
      - name: Test package
        run: devcontainer exec --workspace-folder . poe test
```

#### Publish Workflow
```yaml
name: Publish
on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      
      - name: Install uv
        uses: astral-sh/setup-uv@v6
      
      - name: Publish package
        run: |
          uv build
          uv publish
```

### Configuração PyPI

#### Trusted Publishers
- **Repository**: `killsearch/sentineliqsdk`
- **Workflow**: `.github/workflows/publish.yml`
- **Environment**: `pypi` (com reviewers opcionais)

#### Autenticação
- **Método**: GitHub OIDC
- **Permissões**: `id-token: write`
- **Sem tokens clássicos** necessários

---

## 🔒 Segurança

### Sanitização de Dados

#### Frases Secretas Padrão
```python
DEFAULT_SECRET_PHRASES = ("key", "password", "secret", "token")
```

#### Sanitização Automática
- Chaves de configuração contendo frases secretas são substituídas por `"REMOVED"`
- Aplicado em payloads de erro
- Customizável via parâmetro `secret_phrases`

### Validação TLP/PAP

#### Configuração
```json
{
  "config": {
    "check_tlp": true,
    "max_tlp": 2,
    "check_pap": true,
    "max_pap": 2
  }
}
```

#### Comportamento
- Validação automática se habilitada
- Erro se TLP/PAP exceder limites
- Mensagens de erro padronizadas

### Dependências

#### Auditoria
```bash
# Verificar vulnerabilidades
uv audit

# Atualizar dependências
uv sync --upgrade
```

#### Políticas
- **Dependências mínimas**: Apenas stdlib
- **Dev dependencies**: Ferramentas de desenvolvimento
- **Updates regulares**: Via Dependabot

---

## 🤝 Contribuição

### Processo de Contribuição

#### 1. Setup
```bash
# Fork do repositório
# Clone local
git clone https://github.com/seu-usuario/sentineliqsdk.git
cd sentineliqsdk

# Setup ambiente
uv sync --python 3.13 --all-extras
pre-commit install --install-hooks
```

#### 2. Desenvolvimento
```bash
# Criar branch
git checkout -b feat/nova-funcionalidade

# Desenvolver
# ... código ...

# Testar
poe test
poe lint

# Commit
git add .
git commit -m "feat: add nova funcionalidade"
```

#### 3. Pull Request
- **Título**: Descritivo e claro
- **Descrição**: Explicar mudanças e motivação
- **Testes**: Incluir testes para novas funcionalidades
- **Documentação**: Atualizar se necessário

### Code Review

#### Critérios
- ✅ Código segue padrões estabelecidos
- ✅ Testes passam e coverage adequado
- ✅ Linting sem erros
- ✅ Documentação atualizada
- ✅ Commits seguem conventional commits
- ✅ Mudanças são backwards compatible

#### Checklist do Reviewer
- [ ] Funcionalidade implementada corretamente
- [ ] Testes adequados e passando
- [ ] Performance não degradada
- [ ] Segurança mantida
- [ ] Documentação clara
- [ ] Exemplos funcionais

### Comunicação

#### Canais
- **Issues**: Bug reports e feature requests
- **Discussions**: Perguntas e discussões gerais
- **Pull Requests**: Code review e discussão técnica

#### Etiqueta
- **Respeitoso**: Comunicação profissional
- **Construtivo**: Feedback útil e específico
- **Responsivo**: Respostas em tempo hábil
- **Colaborativo**: Foco em melhorar o projeto

---

## 📋 Checklist de Desenvolvimento

### Antes de Começar
- [ ] Ambiente configurado corretamente
- [ ] Pre-commit hooks instalados
- [ ] Branch atualizada com `main`
- [ ] Issue/feature request criado

### Durante o Desenvolvimento
- [ ] Código segue padrões estabelecidos
- [ ] Type hints em métodos públicos
- [ ] Docstrings em classes/métodos públicos
- [ ] Testes para nova funcionalidade
- [ ] Exemplo adicionado em `examples/` (Analyzer/Responder/Detector)
- [ ] Imports absolutos
- [ ] Linting sem erros

### Antes do Commit
- [ ] `poe test` passando
- [ ] `poe lint` sem erros
- [ ] Coverage adequado
- [ ] Commit message segue conventional commits
- [ ] Arquivos desnecessários não commitados

### Antes do PR
- [ ] Branch atualizada com `main`
- [ ] Todos os testes passando
- [ ] Documentação atualizada
- [ ] CHANGELOG atualizado (se aplicável)
- [ ] PR description completa
- [ ] Screenshots/demos (se aplicável)

### Após Merge
- [ ] Branch deletada
- [ ] Issue fechada
- [ ] Release notes atualizadas
- [ ] Documentação publicada

---

## 🆘 Troubleshooting

### Problemas Comuns

#### Ambiente
```bash
# Problema: uv não encontrado
# Solução: Instalar uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Problema: Python 3.13 não encontrado
# Solução: Instalar Python 3.13
uv python install 3.13
```

#### Testes
```bash
# Problema: Testes falhando
# Solução: Verificar ambiente
poe test --verbose

# Problema: Coverage baixo
# Solução: Adicionar testes
pytest --cov=src/sentineliqsdk --cov-report=html
```

#### Linting
```bash
# Problema: Ruff errors
# Solução: Auto-fix
ruff check --fix

# Problema: MyPy errors
# Solução: Verificar type hints
mypy src/sentineliqsdk
```

### Recursos de Ajuda

#### Documentação
- [Python 3.13 Docs](https://docs.python.org/3.13/)
- [pytest Docs](https://docs.pytest.org/)
- [Ruff Docs](https://docs.astral.sh/ruff/)
- [MyPy Docs](https://mypy.readthedocs.io/)

#### Comunidade
- [GitHub Issues](https://github.com/killsearch/sentineliqsdk/issues)
- [GitHub Discussions](https://github.com/killsearch/sentineliqsdk/discussions)

---

## 📝 Changelog

### v0.1.1 (2025-09-05)
- **Feat**: Melhorias no tratamento de arquivos e configuração de coverage
- **Perf**: Micro-otimizações no extrator e suporte a iteráveis

### v0.1.0 (2025-09-05)
- **Added**: Release inicial do SentinelIQ SDK
- **Added**: Classes base Worker, Analyzer, Responder
- **Added**: Extrator de IOCs baseado em stdlib
- **Added**: CI/CD com GitHub Actions
- **Added**: Documentação e exemplos

---

*Este documento é mantido atualizado com as práticas e convenções do projeto SentinelIQ SDK. Para sugestões ou melhorias, abra uma issue no repositório.*
