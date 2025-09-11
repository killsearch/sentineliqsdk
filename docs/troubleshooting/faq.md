# Perguntas Frequentes

- **Como executo um exemplo?**
  - Execute `python examples/.../example.py --help` para ver as flags. Por padrão, os exemplos são executados em modo dry-run; adicione `--execute` para realizar chamadas de rede. Algumas ações também exigem `--include-dangerous`.

- **Por que dataclasses em vez de entrada de dicionário?**
  - A API pública usa dataclasses para segurança de tipo e clareza. Passe um `WorkerInput` para o construtor do worker; a entrada de dicionário legada foi removida neste repositório.

- **Como obtenho resultados na memória?**
  - Implemente `execute()` retornando `AnalyzerReport`/`ResponderReport` e faça com que `run()` retorne `self.execute()`. Em seguida, chame `.execute()` ou `.run()` diretamente e leia `.full_report`.

- **De onde vêm os artefatos?**
  - Quando `auto_extract` está habilitado (padrão), o Analyzer usa o Extractor para encontrar IOCs em seu `full_report`, excluindo o observável original. Você também pode adicionar artefatos manualmente via `self.build_artifact(...)`.

- **Como adiciono um novo detector?**
  - Para uso local, crie um `@dataclass` com `name` e `matches()` e registre-o com `Extractor.register_detector(...)`. Para tipos principais, atualize `models.DataType` e a lista de precedência em `extractors/regex.py`.

- **Estou atrás de um proxy corporativo. Como o configuro?**
  - Use `WorkerInput.config.proxy` (preferencial). O Worker exporta essas configurações para o ambiente do processo na inicialização para que os clientes HTTP da stdlib as respeitem.
