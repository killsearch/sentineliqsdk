# Kafka Consumer

O Kafka Consumer é uma implementação de consumidor de mensagens para Apache Kafka integrada ao SentinelIQ SDK.

## Características

- **Auto Processing**: Processamento automático de mensagens
- **Error Handling**: Tratamento robusto de erros com retry
- **Configuration**: Configuração flexível via secrets
- **Security**: Suporte a SSL/TLS e autenticação SASL
- **Statistics**: Estatísticas de processamento em tempo real

## Uso Básico

```python
from __future__ import annotations

from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import QueueConfig, MessageConfig
from sentineliqsdk.consumers import KafkaConsumer

# Configurar entrada
input_data = WorkerInput(
    data_type="other",
    data="consumer_data",
    config=WorkerConfig(
        params={
            "max_messages": 10,
            "timeout_ms": 5000,
        },
        secrets={
            "kafka.bootstrap_servers": "localhost:9092",
            "kafka.security_protocol": "PLAINTEXT",
            "kafka.group_id": "sentineliq-consumer",
        }
    ),
)

# Criar consumer
consumer = KafkaConsumer(input_data)

# Configurar fila
queue_config = QueueConfig(
    queue_name="sentineliq-events",
    durable=True,
    auto_delete=False,
)
consumer.configure_queue(queue_config)

# Configurar mensagens
message_config = MessageConfig(
    auto_ack=False,
    prefetch_count=1,
)
consumer.configure_messaging(message_config)

# Consumir mensagens
report = consumer.start_consuming()
print(f"Processed {report.messages_processed} messages")
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
- `kafka.group_id`: ID do grupo de consumidores (padrão: "sentineliq-consumer")

### Parâmetros (WorkerConfig.params)

- `max_messages`: Número máximo de mensagens a processar (padrão: 10)
- `timeout_ms`: Timeout em milissegundos (padrão: 5000)

## Exemplo Completo

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import QueueConfig, MessageConfig
from sentineliqsdk.consumers import KafkaConsumer

def consume_events(topic: str, group_id: str) -> dict:
    """Consome eventos do Kafka."""
    
    input_data = WorkerInput(
        data_type="other",
        data="consumer_data",
        config=WorkerConfig(
            params={
                "max_messages": 50,
                "timeout_ms": 10000,
            },
            secrets={
                "kafka.bootstrap_servers": "kafka1:9092,kafka2:9092",
                "kafka.security_protocol": "SASL_SSL",
                "kafka.sasl_mechanism": "PLAIN",
                "kafka.sasl_username": "user",
                "kafka.sasl_password": "password",
                "kafka.group_id": group_id,
            }
        ),
    )
    
    consumer = KafkaConsumer(input_data)
    
    # Configurar fila
    queue_config = QueueConfig(
        queue_name=topic,
        durable=True,
    )
    consumer.configure_queue(queue_config)
    
    # Consumir
    report = consumer.start_consuming()
    
    return {
        "success": report.success,
        "messages_processed": report.messages_processed,
        "messages_failed": report.messages_failed,
        "processing_time": report.processing_time,
    }

# Uso
result = consume_events("security-events", "security-processor")
print(json.dumps(result, indent=2))
```

## Processamento Personalizado

Para implementar lógica de processamento personalizada, estenda a classe `KafkaConsumer`:

```python
from __future__ import annotations

from sentineliqsdk.consumers import KafkaConsumer
from sentineliqsdk.messaging import Message

class SecurityEventConsumer(KafkaConsumer):
    """Consumer especializado para eventos de segurança."""
    
    def _process_message(self, message: Message) -> dict[str, Any]:
        """Processa eventos de segurança."""
        if message.data_type == "ip":
            return self._process_ip_event(message)
        elif message.data_type == "url":
            return self._process_url_event(message)
        else:
            return self._process_generic_event(message)
    
    def _process_ip_event(self, message: Message) -> dict[str, Any]:
        """Processa eventos relacionados a IPs."""
        return {
            "action": "analyze_ip",
            "ip": message.data,
            "severity": "high",
            "processed_at": time.time(),
        }
    
    def _process_url_event(self, message: Message) -> dict[str, Any]:
        """Processa eventos relacionados a URLs."""
        return {
            "action": "scan_url",
            "url": message.data,
            "severity": "medium",
            "processed_at": time.time(),
        }
    
    def _process_generic_event(self, message: Message) -> dict[str, Any]:
        """Processa eventos genéricos."""
        return {
            "action": "log_event",
            "data": message.data,
            "processed_at": time.time(),
        }
```

## Tratamento de Erros

O Kafka Consumer trata automaticamente:

- **Conexão**: Falhas de conexão com o broker
- **Deserialização**: Erros de deserialização de mensagens
- **Processamento**: Falhas no processamento de mensagens
- **Commit**: Falhas no commit de offsets

```python
try:
    report = consumer.start_consuming()
    if not report.success:
        print(f"Consumer failed: {report.error_message}")
    else:
        print(f"Successfully processed {report.messages_processed} messages")
except Exception as e:
    print(f"Consumer error: {e}")
finally:
    consumer.stop()
```

## Estatísticas de Processamento

O consumer mantém estatísticas em tempo real:

```python
# Durante o processamento
summary = consumer.summary({})
print(f"Processed: {summary['messages_processed']}")
print(f"Failed: {summary['messages_failed']}")
print(f"Time: {summary['processing_time']:.2f}s")
```

## Dependências

- `kafka-python`: Cliente Python para Apache Kafka

Instalar com:
```bash
pip install kafka-python
```
