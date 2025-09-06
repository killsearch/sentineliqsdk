# Contributing

Welcome! This SDK follows clear conventions to keep contributions consistent and safe.

Key references:

- Agent Guide: `docs/guides/guide.md` (full conventions for analyzers/responders/detectors)
- Development Rules: `DEVELOPMENT_RULES.md` (detailed coding standards and workflow)

Setup:

```bash
uv sync --all-extras --dev  # or: pip install -e .[dev]
pre-commit install --install-hooks
```

Common tasks:

- Lint/Types: `poe lint`
- Tests: `poe test`
- Docs: `poe docs` (and `poe docs-serve` to preview)

Scaffolding:

```bash
poe new-analyzer  -- --name Shodan
poe new-responder -- --name BlockIp
poe new-detector  -- --name MyType
```

Checklist (PR):

- Code style: absolute imports, 4 spaces, line length ≤ 100
- Examples under `examples/` (dry‑run by default; `--execute` for network)
- Tests added/updated when applicable
- `poe lint` and `poe test` pass
- Documentation updated where helpful (Guides/Reference/Examples)

Releases:

- Bump with Commitizen: `uv run cz bump` (or `--increment patch|minor|major`)
- Push with tags: `git push origin main --follow-tags`
- Create a GitHub Release for tag `vX.Y.Z` to publish to PyPI via OIDC
