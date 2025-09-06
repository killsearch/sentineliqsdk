# Gmail SMTP Responder

Envia e‑mail via Gmail SMTP (smtp.gmail.com:587) usando STARTTLS. Por padrão, roda em dry‑run;
o envio real exige habilitar as portas de segurança.

## Visão Geral

- Destinatário: `WorkerInput.data` (`data_type == "mail"`).
- Conteúdo: `config.params['email'].subject` e `config.params['email'].body`.
- Remetente: `config.params['email'].from` (padrão: `gmail.username`).
- Autenticação: `config.secrets['gmail'].username` / `config.secrets['gmail'].password`.
- Portas de segurança: `config.params.execute=True` e `config.params.include_dangerous=True`.

## Como Funciona

- Monta `EmailMessage` e envia via `smtplib.SMTP` com STARTTLS; em dry‑run, apenas retorna o plano.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.smtp_gmail import GmailSmtpResponder

inp = WorkerInput(data_type="mail", data="destinatario@example.com")
report = GmailSmtpResponder(inp).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Configuração

Preferencial (programática):

- `WorkerConfig.secrets`:
  - `gmail.username` (ou `smtp.username`)
  - `gmail.password` (ou `smtp.password`)
- `WorkerConfig.params`:
  - `email.from` (opcional)
  - `email.subject`
  - `email.body`
  - `execute` (bool) e `include_dangerous` (bool)

Sem suporte por variáveis de ambiente.

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig

inp = WorkerInput(
    data_type="mail",
    data="destinatario@example.com",
    config=WorkerConfig(
        secrets={"gmail": {"username": "user@gmail.com", "password": "APP-PASS"}},
        params={
            "email": {"from": "user@gmail.com", "subject": "Oi", "body": "Olá"},
            "execute": True,
            "include_dangerous": True,
        },
    ),
)
```

## Uso Correto

- Use App Passwords no Gmail.
- Defina os dois sinalizadores de segurança para envio real.

## Retorno

- `ResponderReport` com `action`, `provider`, `server`, `port`, `from`, `to`, `subject`,
  `dry_run` e, em envio real, `status`.

## Metadata

O responder inclui `full_report.metadata` com:

```json
{
  "Name": "Gmail SMTP Responder",
  "Description": "Send an email via Gmail SMTP with STARTTLS",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "smtp",
  "doc_pattern": "MkDocs module page; customer-facing usage and API",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/responders/gmail_smtp/",
  "VERSION": "STABLE"
}
```
