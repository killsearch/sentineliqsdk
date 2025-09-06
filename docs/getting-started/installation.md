# Installation

Prerequisites:

- Python 3.13
- A virtual environment (recommended)

Install from PyPI:

```bash
pip install --upgrade pip
pip install sentineliqsdk
```

Verify the installation:

```bash
python -c "import importlib.metadata as m; print(m.version('sentineliqsdk'))"
```

Optional developer setup (tasks, docs, tests):

```bash
# Install dev extras using uv (recommended) or pip
uv sync --all-extras --dev  # if uv is available

# Or with pip
pip install -e .[dev]
```

Build docs locally:

```bash
poe docs
# Serve locally
poe docs-serve
```
