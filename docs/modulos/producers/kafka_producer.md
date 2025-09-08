# Kafka Producer

O Kafka Producer é uma implementação de produtor de mensagens para Apache Kafka integrada ao SentinelIQ SDK.

## Características

- **Delivery Confirmation**: Confirmação de entrega das mensagens
- **Error Handling**: Tratamento robusto de erros
- **Configuration**: Configuração flexível via secrets
- **Security**: Suporte a SSL/TLS e autenticação SASL
- **Metadata**: Rastreamento completo de metadados das mensagens

## Uso Básico

```python
from __future__ import annotations

from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import QueueConfig, MessageConfig
from sentineliqsdk.producers import KafkaProducer

# Configurar entrada
input_data = WorkerInput(
    data_type="other",
    data="Hello from SentinelIQ!",
    config=WorkerConfig(
        secrets={
            "kafka.bootstrap_servers": "localhost:9092",
            "kafka.security_protocol": "PLAINTEXT",
        }
    ),
)

# Criar producer
producer = KafkaProducer(input_data)

# Configurar fila
queue_config = QueueConfig(
    queue_name="sentineliq-events",
    durable=True,
    auto_delete=False,
)
producer.configure_queue(queue_config)

# Configurar mensagens
message_config = MessageConfig(
    delivery_mode="persistent",
    mandatory=True,
)
producer.configure_messaging(message_config)

# Publicar mensagem
report = producer.run()
print(f"Message published: {report.message_id}")
```

## Configuração

### Secrets (WorkerConfig.secrets)

- `kafka.bootstrap_servers`: Servidores Kafka (padrão: "localhost:9092")
- `kafka.security_protocol`: Protocolo de segurança (PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL)
- `kafka.sasl_mechanism`: Mecanismo SASL (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)
- `kafka.sasl_username`: Usuário SASL
- `kafka.sasl_password`: Senha SASL
- `kafka.ssl_cafile`: Arquivo CA SSL
- `kafka.ssl_certfile`: Arquivo certificado SSL
- `kafka.ssl_keyfile`: Arquivo chave SSL

### Parâmetros (WorkerConfig.params)

- `correlation_id`: ID de correlação para rastreamento

## Exemplo Completo

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import QueueConfig, MessageConfig
from sentineliqsdk.producers import KafkaProducer

def publish_event(data: str, topic: str) -> dict:
    """Publica um evento no Kafka."""
    
    input_data = WorkerInput(
        data_type="other",
        data=data,
        config=WorkerConfig(
            params={"correlation_id": "event-123"},
            secrets={
                "kafka.bootstrap_servers": "kafka1:9092,kafka2:9092",
                "kafka.security_protocol": "SASL_SSL",
                "kafka.sasl_mechanism": "PLAIN",
                "kafka.sasl_username": "user",
                "kafka.sasl_password": "password",
            }
        ),
    )
    
    producer = KafkaProducer(input_data)
    
    # Configurar fila
    queue_config = QueueConfig(
        queue_name=topic,
        durable=True,
    )
    producer.configure_queue(queue_config)
    
    # Publicar
    report = producer.run()
    
    return {
        "success": report.success,
        "message_id": report.message_id,
        "topic": report.queue_name,
        "delivery_confirmed": report.delivery_confirmed,
    }

# Uso
result = publish_event("Security alert detected", "security-events")
print(json.dumps(result, indent=2))
```

## Tratamento de Erros

O Kafka Producer trata automaticamente:

- **Conexão**: Falhas de conexão com o broker
- **Serialização**: Erros de serialização de mensagens
- **Timeout**: Timeouts de entrega
- **Retry**: Tentativas automáticas de reenvio

```python
try:
    report = producer.run()
    if not report.success:
        print(f"Failed to publish: {report.error_message}")
except Exception as e:
    print(f"Producer error: {e}")
finally:
    producer.close()
```

## Dependências

- `kafka-python`: Cliente Python para Apache Kafka

Instalar com:
```bash
pip install kafka-python
```
