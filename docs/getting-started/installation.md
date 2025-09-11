# Instalação

Este guia detalha como instalar o SentinelIQ SDK e configurar seu ambiente de desenvolvimento.

## Pré-requisitos

Certifique-se de ter os seguintes pré-requisitos instalados em seu sistema:

- **Python 3.13**: A versão recomendada para o desenvolvimento com o SDK.
- **Ambiente Virtual**: Altamente recomendado para gerenciar as dependências do projeto de forma isolada.

## Instalação via PyPI

Para instalar a versão mais recente do SentinelIQ SDK diretamente do PyPI, siga os passos abaixo:

```bash
pip install --upgrade pip
pip install sentineliqsdk
```

### Verificação da Instalação

Após a instalação, você pode verificar se o SDK foi instalado corretamente executando o seguinte comando:

```bash
python -c "import importlib.metadata as m; print(m.version('sentineliqsdk'))"
```

## Configuração Opcional para Desenvolvedores

Se você pretende contribuir com o desenvolvimento do SDK ou executar tarefas como testes e geração de documentação, configure o ambiente de desenvolvimento com as dependências extras:

```bash
# Instale as dependências de desenvolvimento usando uv (recomendado) ou pip
uv sync --all-extras --dev  # se uv estiver disponível

# Ou com pip
pip install -e .[dev]
```

## Construindo a Documentação Localmente

Para gerar e visualizar a documentação do projeto localmente, utilize os seguintes comandos:

```bash
poe docs
# Para servir a documentação localmente em seu navegador
poe docs-serve
```
