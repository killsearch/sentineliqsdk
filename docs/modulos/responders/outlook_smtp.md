# Outlook SMTP Responder

Envia e‑mail via Outlook/Office365 SMTP (smtp.office365.com:587) com STARTTLS. Por padrão,
executa em dry‑run; o envio real requer portas de segurança habilitadas.

## Visão Geral

- Destinatário: `WorkerInput.data` (`data_type == "mail"`).
- Conteúdo: `email.subject` e `email.body`.
- Remetente: `email.from` (padrão: `outlook.username`).
- Autenticação: `outlook.username` / `outlook.password`.
- Portas de segurança: `config.params.execute=True` e `config.params.include_dangerous=True`.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.smtp_outlook import OutlookSmtpResponder

inp = WorkerInput(data_type="mail", data="destinatario@example.com")
report = OutlookSmtpResponder(inp).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Configuração

Preferencial (programática):

- `WorkerConfig.secrets`:
  - `outlook.username` (ou `smtp.username`)
  - `outlook.password` (ou `smtp.password`)
- `WorkerConfig.params`:
  - `email.from` (opcional)
  - `email.subject`
  - `email.body`
  - `execute` (bool) e `include_dangerous` (bool)

Sem suporte por variáveis de ambiente.

## Uso Correto

- Defina os dois sinalizadores de segurança para envio real.

## Retorno

- `ResponderReport` com `action`, `provider`, `server`, `port`, `from`, `to`, `subject`,
  `dry_run` e, em envio real, `status`.

## Metadata

O responder inclui `full_report.metadata` com:

```json
{
  "Name": "Outlook SMTP Responder",
  "Description": "Send an email via Outlook/Office365 SMTP with STARTTLS",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "smtp",
  "doc_pattern": "MkDocs module page; customer-facing usage and API",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/responders/outlook_smtp/",
  "VERSION": "STABLE"
}
```
