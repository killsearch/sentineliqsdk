[![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI2ZmZiIgZD0iTTE3IDE2VjdsLTYgNU0yIDlWOGwxLTFoMWw0IDMgOC04aDFsNCAyIDEgMXYxNGwtMSAxLTQgMmgtMWwtOC04LTQgM0gzbC0xLTF2LTFsMy0zIi8+PC9zdmc+)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/killsearch/sentineliqsdk) [![Open in GitHub Codespaces](https://img.shields.io/static/v1?label=GitHub%20Codespaces&message=Open&color=blue&logo=github)](https://github.com/codespaces/new/killsearch/sentineliqsdk)

# Sentineliqsdk

Modern Python library of utility classes for SentinelIQ analyzers and responders.

Note: This SDK now exposes only the modern API (Python 3.13). Legacy helper aliases
such as `getData`, `getParam`, `checkTlp`, and `notSupported` were removed. Migrate to
`get_data`, `get_param`, and rely on automatic TLP/PAP enforcement in `Worker`.

## Installing

To install this package, run:

```sh
pip install sentineliqsdk
```

## Using

Example usage:

```python
from sentineliqsdk import Analyzer, Responder, Worker, Extractor, runner


class EchoAnalyzer(Analyzer):
    def run(self) -> None:
        data = self.get_data()
        self.report({"echo": data})


if __name__ == "__main__":
    runner(EchoAnalyzer)
```

Internal structure (for maintainers):
- `src/sentineliqsdk/core/worker.py`
- `src/sentineliqsdk/analyzers/base.py`
- `src/sentineliqsdk/responders/base.py`
- `src/sentineliqsdk/extractors/regex.py` (Extractor uses stdlib validators: ipaddress, urlparse)

### Extractor

The `Extractor` detects common IOC types using Python's standard library instead of
complex regular expressions:

- ip: `ipaddress.ip_address`
- url/uri: `urllib.parse.urlparse`
- mail: `email.utils.parseaddr`
- hash: length + hex digits check
- domain/fqdn/registry/user‑agent: simple heuristics aligned with the test suite

## Migration (Breaking Changes)

- Import from the top-level package only:
  - Before: `from sentineliqsdk.analyzer import Analyzer`
  - After: `from sentineliqsdk import Analyzer`
- Removed legacy helpers: `getData`, `getParam`, `checkTlp`, `notSupported`, `unexpectedError`.
- Removed legacy config key: `config.auto_extract_artifacts` (use `config.auto_extract`).
- Removed legacy module paths: `sentineliqsdk.analyzer`, `sentineliqsdk.responder`,
  `sentineliqsdk.worker`, `sentineliqsdk.extractor` (all exported at top-level instead).

## Contributing

<details>
<summary>Prerequisites</summary>

1. [Generate an SSH key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent#generating-a-new-ssh-key) and [add the SSH key to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).
1. Configure SSH to automatically load your SSH keys:

    ```sh
    cat << EOF >> ~/.ssh/config
    
    Host *
      AddKeysToAgent yes
      IgnoreUnknown UseKeychain
      UseKeychain yes
      ForwardAgent yes
    EOF
    ```

1. [Install Docker Desktop](https://www.docker.com/get-started).
1. [Install VS Code](https://code.visualstudio.com/) and [VS Code's Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers). Alternatively, install [PyCharm](https://www.jetbrains.com/pycharm/download/).
1. _Optional:_ install a [Nerd Font](https://www.nerdfonts.com/font-downloads) such as [FiraCode Nerd Font](https://github.com/ryanoasis/nerd-fonts/tree/master/patched-fonts/FiraCode) and [configure VS Code](https://github.com/tonsky/FiraCode/wiki/VS-Code-Instructions) or [PyCharm](https://github.com/tonsky/FiraCode/wiki/Intellij-products-instructions) to use it.

</details>

<details open>
<summary>Development environments</summary>

The following development environments are supported:

1. ⭐️ _GitHub Codespaces_: click on [Open in GitHub Codespaces](https://github.com/codespaces/new/killsearch/sentineliqsdk) to start developing in your browser.
1. ⭐️ _VS Code Dev Container (with container volume)_: click on [Open in Dev Containers](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/killsearch/sentineliqsdk) to clone this repository in a container volume and create a Dev Container with VS Code.
1. ⭐️ _uv_: clone this repository and run the following from root of the repository:

    ```sh
    # Create and install a virtual environment
    uv sync --python 3.13 --all-extras

    # Activate the virtual environment
    source .venv/bin/activate

    # Install the pre-commit hooks
    pre-commit install --install-hooks
    ```

1. _VS Code Dev Container_: clone this repository, open it with VS Code, and run <kbd>Ctrl/⌘</kbd> + <kbd>⇧</kbd> + <kbd>P</kbd> → _Dev Containers: Reopen in Container_.
1. _PyCharm Dev Container_: clone this repository, open it with PyCharm, [create a Dev Container with Mount Sources](https://www.jetbrains.com/help/pycharm/start-dev-container-inside-ide.html), and [configure an existing Python interpreter](https://www.jetbrains.com/help/pycharm/configuring-python-interpreter.html#widget) at `/opt/venv/bin/python`.

</details>

<details open>
<summary>Developing</summary>

- This project follows the [Conventional Commits](https://www.conventionalcommits.org/) standard to automate [Semantic Versioning](https://semver.org/) and [Keep A Changelog](https://keepachangelog.com/) with [Commitizen](https://github.com/commitizen-tools/commitizen).
- Run `poe` from within the development environment to print a list of [Poe the Poet](https://github.com/nat-n/poethepoet) tasks available to run on this project.
- Run tests with coverage: `poe test` (writes `reports/coverage.xml` and shows a summary).
- Run `uv add {package}` from within the development environment to install a run time dependency and add it to `pyproject.toml` and `uv.lock`. Add `--dev` to install a development dependency.
- Run `uv sync --upgrade` from within the development environment to upgrade all dependencies to the latest versions allowed by `pyproject.toml`. Add `--only-dev` to upgrade the development dependencies only.
- Run `cz bump` to bump the package's version, update the `CHANGELOG.md`, and create a git tag. Then push the changes and the git tag with `git push origin main --tags`.

</details>

<details>
<summary>Security and privacy</summary>

- Error payloads sanitize config keys containing any of: `key`, `password`, `secret`, `token`.
- You can override or extend this list via the `secret_phrases` parameter to `Worker(...)`.

</details>
