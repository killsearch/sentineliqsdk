## Automation & Responders Examples

Responders perform actions such as sending notifications or publishing messages. Examples
default to dry-run. Use `--execute` to perform network calls, and `--include-dangerous` to
explicitly acknowledge impactful actions.

### Gmail SMTP

- Run help:
  - `python examples/responders/gmail_smtp_example.py --help`
- Dry-run:
  - `python examples/responders/gmail_smtp_example.py --to someone@example.com`
- Execute (pass creds via flags or pre-config):
  - `python examples/responders/gmail_smtp_example.py --to someone@example.com --username user --password APPPASS --execute --include-dangerous`

### Outlook/Office365 SMTP

- Dry-run:
  - `python examples/responders/outlook_smtp_example.py --to someone@example.com`
- Execute (pass creds via flags or pre-config):
  - `python examples/responders/outlook_smtp_example.py --to someone@example.com --username user --password PASS --execute --include-dangerous`

### Webhook

- POST to a webhook URL with optional headers/body (string or JSON):
  - `python examples/responders/webhook_example.py --url https://httpbin.org/post --headers '{"X-Test":"1"}' --body '{"ok":true}'`
- Execute:
  - `python examples/responders/webhook_example.py --url https://httpbin.org/post --execute --include-dangerous`

### Kafka via REST Proxy

- Publish to a Kafka topic using Confluent REST Proxy:
  - `python examples/responders/kafka_rest_example.py --rest-url http://localhost:8082 --topic demo --message "hello"`
- With headers and basic auth:
  - `python examples/responders/kafka_rest_example.py --rest-url http://localhost:8082 --topic demo --message "hello" --headers '{"X-Trace":"1"}' --auth user:pass --execute --include-dangerous`

### RabbitMQ via HTTP API

- Publish to an exchange:
  - `python examples/responders/rabbitmq_http_example.py --api-url http://localhost:15672 --exchange my-ex --routing-key test --message "hello"`
- Execute with auth and properties:
  - `python examples/responders/rabbitmq_http_example.py --api-url http://localhost:15672 --exchange my-ex --routing-key test --message "hello" --username guest --password guest --properties '{"delivery_mode":2}' --execute --include-dangerous`

Notes:
- All examples are stdlib-only (no extra dependencies). Network calls require `--execute`.
- Impactful operations are gated by `--include-dangerous`.
- Configure programaticamente via `WorkerConfig.params` e `WorkerConfig.secrets`; não há suporte
  por variáveis de ambiente para estes módulos.
