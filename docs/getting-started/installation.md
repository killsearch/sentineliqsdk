---
title: Installation
---

# Installation

The SentinelIQ SDK is a Python library that requires Python 3.13 or higher. This guide covers different installation methods and environment setup.

## Prerequisites

- **Python 3.13+**: The SDK requires Python 3.13 or higher
- **pip**: Python package installer (usually included with Python)
- **Virtual Environment** (recommended): For isolated dependency management

## Installation Methods

### Method 1: Using pip (Recommended)

Install the latest stable version from PyPI:

```bash
pip install sentineliqsdk
```

### Method 2: Install Specific Version

Install a specific version:

```bash
pip install sentineliqsdk==0.1.2
```

### Method 3: Install from Source

For development or to get the latest features:

```bash
# Clone the repository
git clone https://github.com/killsearch/sentineliqsdk.git
cd sentineliqsdk

# Install in development mode
pip install -e .
```

### Method 4: Using uv (Modern Python Package Manager)

If you're using `uv` for Python package management:

```bash
# Add to your project
uv add sentineliqsdk

# Or install globally
uv tool install sentineliqsdk
```

## Virtual Environment Setup

We strongly recommend using a virtual environment to avoid dependency conflicts:

### Using venv (Built-in)

```bash
# Create virtual environment
python -m venv sentineliq-env

# Activate (Linux/macOS)
source sentineliq-env/bin/activate

# Activate (Windows)
sentineliq-env\Scripts\activate

# Install SDK
pip install sentineliqsdk
```

### Using conda

```bash
# Create conda environment
conda create -n sentineliq python=3.13

# Activate environment
conda activate sentineliq

# Install SDK
pip install sentineliqsdk
```

### Using uv

```bash
# Create project with uv
uv init my-sentineliq-project
cd my-sentineliq-project

# Add SDK dependency
uv add sentineliqsdk

# Install dependencies
uv sync
```

## Verify Installation

Test your installation with a simple script:

```python
# test_installation.py
from sentineliqsdk import Worker, Analyzer, Responder, Extractor

print("✅ SentinelIQ SDK installed successfully!")
print(f"Available classes: Worker, Analyzer, Responder, Extractor")

# Test basic functionality
extractor = Extractor()
result = extractor.check_string("192.168.1.1")
print(f"IP detection test: {result}")  # Should print "ip"
```

Run the test:

```bash
python test_installation.py
```

Expected output:
```
✅ SentinelIQ SDK installed successfully!
Available classes: Worker, Analyzer, Responder, Extractor
IP detection test: ip
```

## Development Installation

For contributing to the SDK or running tests:

```bash
# Clone repository
git clone https://github.com/killsearch/sentineliqsdk.git
cd sentineliqsdk

# Install with development dependencies
pip install -e ".[dev]"

# Or using uv
uv sync --all-extras
```

## Troubleshooting

### Common Issues

**Python Version Error:**
```
ERROR: Package 'sentineliqsdk' requires a different Python: 3.12.0 not in '>=3.13,<4.0'
```
**Solution:** Upgrade to Python 3.13 or higher.

**Permission Denied:**
```
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```
**Solution:** Use a virtual environment or install with `--user` flag:
```bash
pip install --user sentineliqsdk
```

**Import Error:**
```
ModuleNotFoundError: No module named 'sentineliqsdk'
```
**Solution:** Ensure you're in the correct virtual environment and the package is installed.

### Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](../troubleshooting/common-issues.md)
2. Search [GitHub Issues](https://github.com/killsearch/sentineliqsdk/issues)
3. Create a new issue with:
   - Python version (`python --version`)
   - Installation method used
   - Complete error message
   - Operating system

## Next Steps

Once installed, proceed to:

- [Quick Start Guide](quick-start.md) - Get up and running in 5 minutes
- [First Analyzer](first-analyzer.md) - Build your first analyzer
- [API Reference](../reference/api/worker.md) - Explore the full API
