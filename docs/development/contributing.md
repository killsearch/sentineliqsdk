# Contribuindo

Bem-vindo(a)! Este SDK segue convenções claras para manter as contribuições consistentes e seguras.

**Referências principais:**

- Guia do Agente: `docs/guides/guide.md` (convenções completas para analisadores/respondedores/detectores)
- Regras de Desenvolvimento: `DEVELOPMENT_RULES.md` (padrões de codificação e fluxo de trabalho detalhados)

**Configuração:**

```bash
uv sync --all-extras --dev  # ou: pip install -e .[dev]
pre-commit install --install-hooks
```

**Tarefas comuns:**

- Lint/Tipos: `poe lint`
- Testes: `poe test`
- Documentação: `poe docs` (e `poe docs-serve` para pré-visualizar)

**Scaffolding:**

```bash
poe new-analyzer  -- --name Shodan
poe new-responder -- --name BlockIp
poe new-detector  -- --name MyType
```

**Checklist (PR):**

- Estilo de código: imports absolutos, 4 espaços, comprimento da linha ≤ 100
- Exemplos em `examples/` (dry-run por padrão; `--execute` para rede)
- Testes adicionados/atualizados quando aplicável
- `poe lint` e `poe test` passam
- Documentação atualizada onde for útil (Guias/Referência/Exemplos)

**Lançamentos:**

- Bump com Commitizen: `uv run cz bump` (ou `--increment patch|minor|major`)
- Push com tags: `git push origin main --follow-tags`
- Crie um GitHub Release para a tag `vX.Y.Z` para publicar no PyPI via OIDC
