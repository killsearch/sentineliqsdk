# SentinelIQ SDK Rules

This directory contains development rules and patterns for the SentinelIQ SDK.

## Rule Files

### Core Development Rules
- **`worker-core-concepts.mdc`** - Core worker concepts and base class patterns
- **`configuration-patterns.mdc`** - Configuration patterns and requirements (MANDATORY)
- **`input-output-patterns.mdc`** - Input/output patterns and dataclass usage
- **`module-metadata.mdc`** - Module metadata requirements for analyzers and responders

### Module Development Rules
- **`analyzer-development.mdc`** - Analyzer development patterns and requirements
- **`responder-development.mdc`** - Responder development patterns and requirements
- **`detector-development.mdc`** - Detector development patterns and requirements

### Documentation and Examples
- **`examples-and-docs.mdc`** - Mandatory examples and documentation requirements
- **`extractor-usage.mdc`** - Extractor usage patterns and IOC detection

### Project Management
- **`development-workflow.mdc`** - Development workflow and tooling requirements
- **`project-structure.mdc`** - Project structure and file organization

## Key Configuration Rules (CRITICAL)

### PROHIBITED
- **NEVER** use `os.environ` directly in modules
- **NEVER** hardcode credentials in source code

### REQUIRED
- **ALWAYS** use `WorkerConfig.secrets` for credentials
- **ALWAYS** use `get_secret()` and `get_config()` methods
- **ALWAYS** follow the configuration patterns in `configuration-patterns.mdc`

## Quick Reference

### For Analyzers
1. Read `analyzer-development.mdc`
2. Follow `configuration-patterns.mdc` for credentials
3. Include `module-metadata.mdc` requirements
4. Create examples per `examples-and-docs.mdc`

### For Responders
1. Read `responder-development.mdc`
2. Follow `configuration-patterns.mdc` for credentials
3. Include `module-metadata.mdc` requirements
4. Create examples per `examples-and-docs.mdc`

### For Detectors
1. Read `detector-development.mdc`
2. Follow `extractor-usage.mdc` patterns
3. Create examples per `examples-and-docs.mdc`

## Configuration Examples

### Correct Configuration Usage
```python
# CORRECT: Use WorkerConfig.secrets
secrets = {
    "my_module": {
        "api_key": "secret_key",
        "username": "user",
        "password": "pass"
    }
}
input_data = WorkerInput(..., config=WorkerConfig(secrets=secrets))

# In module:
api_key = self.get_secret("my_module.api_key")
```

### Incorrect Configuration Usage
```python
# INCORRECT: Direct os.environ usage (PROHIBITED)
import os
api_key = os.environ["API_KEY"]  # DON'T DO THIS
```

## Enforcement

These rules are enforced through:
- Code review processes
- Linting and type checking
- Documentation validation
- Example testing

All modules must follow these patterns for consistency and security.
