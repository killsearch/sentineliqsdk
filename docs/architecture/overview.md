# Visão Geral da Arquitetura

**Princípios de Design:**

- **SOLID**: classes pequenas e compostas, com pontos de extensão claros.
- **Dataclasses**: envelopes fortemente tipados para entrada/saída.
- **Stdlib-first**: Extractor prefere `ipaddress`, `urllib.parse`, `email.utils` em vez de regexes complexas.

**Módulos e Responsabilidades:**

- **Worker Core**: `src/sentineliqsdk/core/worker.py`
  - Aplicação de TLP/PAP, configuração de ambiente proxy, relatório de erros com configuração sanitizada.
  - Hooks: `summary`, `artifacts`, `operations`, `run`.
- **Base do Analisador**: `src/sentineliqsdk/analyzers/base.py`
  - Autoextração de IOCs em artefatos, helpers de taxonomia, manipulação de arquivos via `get_data()`.
- **Base do Respondedor**: `src/sentineliqsdk/responders/base.py`
  - Envelope de ação simples, helpers de operação.
- **Extrator**: `src/sentineliqsdk/extractors/regex.py`
  - Registro e precedência de detectores, flags de normalização, verificação iterável.
- **Modelos**: `src/sentineliqsdk/models.py`
  - Dataclasses: `WorkerInput`, `WorkerConfig`, `ProxyConfig`, `TaxonomyEntry`, `Artifact`,
    `Operation`, `AnalyzerReport`, `ResponderReport`, `WorkerError`, `ExtractorResult(s)`.

**Fluxo de Dados (Analisador):**

1. Construção com `WorkerInput`.
2. `__init__` aplica TLP/PAP e configura proxies.
3. `execute()` constrói o relatório completo e chama `self.report(...)`.
4. O envelope adiciona os hooks `summary`, `artifacts` (autoextração) e `operations`.

**Precedência do Extrator (primeira correspondência vence):**

`ip` → `cidr` → `url` → `domain` → `hash` → `user-agent` → `uri_path` → `registry` → `mail` →
`mac` → `asn` → `cve` → `ip_port` → `fqdn`

**Customização:**

- Registre detectores dinamicamente com `Extractor.register_detector(detector, before=..., after=...)`.
- Inclua novos tipos de núcleo atualizando `models.DataType` e a lista de precedência do Extrator.
