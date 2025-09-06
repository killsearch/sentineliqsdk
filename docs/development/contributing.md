---
title: Contributing
---

# Contributing to SentinelIQ SDK

Thank you for your interest in contributing to the SentinelIQ SDK! This guide will help you get started with contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Getting Started

### Prerequisites

- Python 3.13 or higher
- Git
- Docker (optional, for containerized development)
- VS Code or PyCharm (recommended)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/your-username/sentineliqsdk.git
cd sentineliqsdk
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/killsearch/sentineliqsdk.git
```

## Development Setup

### Option 1: Local Development

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install development dependencies:

```bash
pip install -e ".[dev]"
```

3. Install pre-commit hooks:

```bash
pre-commit install --install-hooks
```

### Option 2: Dev Container

1. Open the project in VS Code
2. Install the Dev Containers extension
3. Press `Ctrl+Shift+P` and select "Dev Containers: Reopen in Container"

### Option 3: GitHub Codespaces

1. Click "Code" on the repository page
2. Select "Codespaces" tab
3. Click "Create codespace on main"

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

1. **Bug Fixes**: Fix bugs and issues
2. **Features**: Add new functionality
3. **Documentation**: Improve documentation
4. **Tests**: Add or improve tests
5. **Examples**: Add usage examples
6. **Performance**: Optimize performance
7. **Security**: Improve security

### Before You Start

1. **Check existing issues**: Look for existing issues or discussions
2. **Create an issue**: For significant changes, create an issue first
3. **Discuss changes**: For major features, discuss the approach first
4. **Check the roadmap**: See if your contribution aligns with project goals

### Development Workflow

1. **Create a branch**:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number
```

2. **Make your changes**:

```bash
# Make your code changes
# Add tests
# Update documentation
```

3. **Test your changes**:

```bash
# Run tests
poe test

# Run linting
poe lint

# Check type hints
mypy src/
```

4. **Commit your changes**:

```bash
git add .
git commit -m "feat: add new feature"
```

5. **Push and create PR**:

```bash
git push origin feature/your-feature-name
# Create PR on GitHub
```

## Code Style

### Python Style

We follow PEP 8 with some modifications:

- **Line length**: 100 characters
- **Indentation**: 4 spaces
- **String quotes**: Double quotes for strings, single quotes for docstrings
- **Import order**: Standard library, third-party, local imports

### Code Formatting

We use `ruff` for code formatting and linting:

```bash
# Format code
ruff format src/ tests/

# Lint code
ruff check src/ tests/
```

### Type Hints

All public functions and methods should have type hints:

```python
def process_data(self, data: str, config: dict[str, Any]) -> ProcessResult:
    """Process data with configuration."""
    pass
```

### Docstrings

Use NumPy-style docstrings:

```python
def analyze_threat(self, observable: str) -> ThreatAnalysis:
    """
    Analyze observable for threat indicators.
    
    Parameters
    ----------
    observable : str
        The observable to analyze (IP, URL, domain, etc.)
    
    Returns
    -------
    ThreatAnalysis
        Analysis results with verdict and confidence
    
    Raises
    ------
    ValidationError
        If observable format is invalid
    AnalysisError
        If analysis fails
    """
    pass
```

### Error Handling

Use specific exception types:

```python
class ValidationError(Exception):
    """Raised when input validation fails."""
    pass

class AnalysisError(Exception):
    """Raised when analysis fails."""
    pass

# Usage
if not self._is_valid_ip(ip):
    raise ValidationError(f"Invalid IP address: {ip}")
```

## Testing

### Test Structure

Tests should be organized in the `tests/` directory:

```
tests/
├── test_core/
│   ├── test_worker.py
│   └── test_contracts.py
├── test_analyzers/
│   └── test_base.py
├── test_responders/
│   └── test_base.py
├── test_extractors/
│   └── test_regex.py
└── test_integration/
    └── test_full_workflow.py
```

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch
from sentineliqsdk import Worker, WorkerInput

class TestWorker:
    def test_worker_initialization(self):
        """Test worker initialization with valid input."""
        input_data = WorkerInput(
            data_type="ip",
            data="1.2.3.4",
            tlp=2,
            pap=2
        )
        
        worker = Worker(input_data)
        assert worker.data_type == "ip"
        assert worker.tlp == 2
        assert worker.pap == 2
    
    def test_get_data(self):
        """Test getting data from input."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = Worker(input_data)
        
        assert worker.get_data() == "1.2.3.4"
    
    def test_error_handling(self):
        """Test error handling."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = Worker(input_data)
        
        with pytest.raises(SystemExit):
            worker.error("Test error")
    
    @patch('sentineliqsdk.Worker.get_param')
    def test_configuration_access(self, mock_get_param):
        """Test configuration parameter access."""
        mock_get_param.return_value = "test_value"
        
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = Worker(input_data)
        
        result = worker.get_param("config.test_param")
        assert result == "test_value"
        mock_get_param.assert_called_once_with("config.test_param")
```

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test performance characteristics
5. **Security Tests**: Test security features

### Running Tests

```bash
# Run all tests
poe test

# Run specific test file
pytest tests/test_core/test_worker.py

# Run with coverage
pytest --cov=src/sentineliqsdk --cov-report=html

# Run specific test
pytest tests/test_core/test_worker.py::TestWorker::test_worker_initialization
```

### Test Coverage

Maintain high test coverage:

```bash
# Check coverage
pytest --cov=src/sentineliqsdk --cov-report=term-missing

# Generate HTML report
pytest --cov=src/sentineliqsdk --cov-report=html
open htmlcov/index.html
```

## Documentation

### Code Documentation

- Document all public functions and classes
- Use clear, concise docstrings
- Include examples where helpful
- Document parameters and return values
- Include type hints

### User Documentation

- Update relevant documentation files
- Add examples for new features
- Update API reference if needed
- Include migration guides for breaking changes

### Documentation Structure

```
docs/
├── getting-started/
├── tutorials/
├── examples/
├── guides/
├── reference/
├── troubleshooting/
└── architecture/
```

### Building Documentation

```bash
# Build documentation
poe docs

# Serve documentation locally
poe docs-serve
```

## Pull Request Process

### Before Submitting

1. **Run all checks**:

```bash
# Format code
ruff format src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/

# Run tests
poe test

# Build documentation
poe docs
```

2. **Update CHANGELOG.md**:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description
```

3. **Update version** (if needed):

```bash
# For new features
uv run cz bump --increment minor

# For bug fixes
uv run cz bump --increment patch
```

### PR Description

Include:

1. **Summary**: Brief description of changes
2. **Type**: Bug fix, feature, documentation, etc.
3. **Breaking Changes**: List any breaking changes
4. **Testing**: How you tested the changes
5. **Screenshots**: For UI changes
6. **Related Issues**: Link to related issues

### PR Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Code Review**: Maintainers review the code
3. **Testing**: Additional testing if needed
4. **Approval**: At least one maintainer approval required
5. **Merge**: Squash and merge to main branch

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. **Update version**:

```bash
# For patch release
uv run cz bump --increment patch

# For minor release
uv run cz bump --increment minor

# For major release
uv run cz bump --increment major
```

2. **Push changes**:

```bash
git push origin main --follow-tags
```

3. **Create GitHub Release**:

```bash
gh release create v1.2.3 --title "v1.2.3" --notes-file CHANGELOG.md
```

4. **Verify release**:

```bash
pip install sentineliqsdk==1.2.3
python -c "import sentineliqsdk; print(sentineliqsdk.__version__)"
```

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors.

### Expected Behavior

- Be respectful and inclusive
- Focus on what's best for the community
- Accept constructive criticism gracefully
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or inflammatory comments
- Personal attacks or political discussions
- Spam or off-topic discussions

### Enforcement

Violations will be addressed by project maintainers and may result in temporary or permanent bans.

## Getting Help

### Questions

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Email**: team@sentineliq.com.br for sensitive issues

### Resources

- [Documentation](https://killsearch.github.io/sentineliqsdk/)
- [API Reference](https://killsearch.github.io/sentineliqsdk/reference/)
- [Examples](https://killsearch.github.io/sentineliqsdk/examples/)

## Recognition

Contributors will be recognized in:

- **CHANGELOG.md**: For significant contributions
- **README.md**: For major contributors
- **Release Notes**: For each release
- **GitHub**: Contributor statistics

## Thank You

Thank you for contributing to the SentinelIQ SDK! Your contributions help make the project better for everyone.

If you have any questions about contributing, please don't hesitate to ask. We're here to help!
