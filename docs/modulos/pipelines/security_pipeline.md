# Security Pipeline

O Security Pipeline é uma implementação especializada de pipeline para detecção e resposta automática a ameaças de segurança.

## Características

- **Threat Detection**: Detecção automática de ameaças usando analyzers
- **Automated Response**: Resposta automática baseada na análise
- **Routing Rules**: Regras de roteamento baseadas em prioridade e tipo de dados
- **Integration**: Integração completa com Producers, Consumers, Analyzers e Responders

## Uso Básico

```python
from __future__ import annotations

from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import Message, MessageMetadata
from sentineliqsdk.pipelines import SecurityPipeline

# Configurar pipeline
input_data = WorkerInput(
    data_type="other",
    data="security_pipeline",
    config=WorkerConfig(
        params={
            "auto_respond": True,
            "response_threshold": "suspicious",
        },
        secrets={
            "kafka.bootstrap_servers": "localhost:9092",
            "kafka.security_protocol": "PLAINTEXT",
            "shodan.api_key": "your_shodan_api_key",
        }
    ),
)

pipeline = SecurityPipeline(input_data)

# Processar mensagem de ameaça
message = Message(
    message_type="event",
    data_type="ip",
    data="192.168.1.100",
    metadata=MessageMetadata(
        message_id="threat_001",
        priority="high",
        tags={"source": "firewall", "event_type": "threat_detected"}
    ),
    payload={"secrets": {"shodan.api_key": "your_shodan_api_key"}}
)

result = pipeline.process_message(message)
print(f"Pipeline result: {result['pipeline_status']}")
```

## Configuração

### Parâmetros (WorkerConfig.params)

- `auto_respond`: Habilitar resposta automática (padrão: True)
- `response_threshold`: Limiar para resposta ("info", "suspicious", "malicious")

### Secrets (WorkerConfig.secrets)

- `kafka.bootstrap_servers`: Servidores Kafka
- `kafka.security_protocol`: Protocolo de segurança
- `shodan.api_key`: Chave da API do Shodan
- Outros secrets específicos dos analyzers/responders

## Analyzers Registrados

O Security Pipeline registra automaticamente:

- **IP**: ShodanAnalyzer
- **Domain**: ShodanAnalyzer
- **Hash**: (quando disponível) VirusTotalAnalyzer
- **URL**: (quando disponível) VirusTotalAnalyzer

## Responders Registrados

O Security Pipeline registra automaticamente:

- **block**: BlockIPResponder (quando disponível)
- **alert**: NotifyResponder (quando disponível)
- **quarantine**: QuarantineResponder (quando disponível)

## Regras de Roteamento

O pipeline aplica regras de roteamento baseadas em:

1. **Prioridade Crítica**: `priority == "critical"` → "immediate_response"
2. **Dados de Threat Intel**: `data_type in ["ip", "domain"]` → "threat_intel"
3. **Análise Padrão**: Outros tipos → "standard_analysis"

## Determinação de Ações

O pipeline determina ações baseadas na taxonomia:

### Nível Malicious
```python
{
    "action": "block",
    "target": "192.168.1.100",
    "reason": "malicious",
    "confidence": "high",
    "source": "shodan"
}
```

### Nível Suspicious
```python
{
    "action": "alert",
    "target": "192.168.1.100", 
    "reason": "suspicious",
    "confidence": "medium",
    "source": "shodan"
}
```

### Prioridade Crítica
```python
{
    "action": "escalate",
    "target": "192.168.1.100",
    "reason": "critical_priority",
    "confidence": "high",
    "source": "security_pipeline"
}
```

## Exemplo Completo

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.messaging import Message, MessageMetadata
from sentineliqsdk.pipelines import SecurityPipeline

def process_security_threat(ip: str, source: str = "firewall") -> dict:
    """Processa uma ameaça de segurança através do pipeline."""
    
    # Configurar pipeline
    input_data = WorkerInput(
        data_type="other",
        data="security_pipeline",
        config=WorkerConfig(
            params={
                "auto_respond": True,
                "response_threshold": "suspicious",
            },
            secrets={
                "kafka.bootstrap_servers": "localhost:9092",
                "kafka.security_protocol": "PLAINTEXT",
                "shodan.api_key": "your_shodan_api_key",
            }
        ),
    )
    
    pipeline = SecurityPipeline(input_data)
    
    # Criar mensagem de ameaça
    message = Message(
        message_type="event",
        data_type="ip",
        data=ip,
        metadata=MessageMetadata(
            message_id=f"threat_{int(time.time())}",
            priority="high",
            tags={"source": source, "event_type": "threat_detected"}
        ),
        payload={"secrets": {"shodan.api_key": "your_shodan_api_key"}}
    )
    
    # Processar através do pipeline
    result = pipeline.process_message(message)
    
    return {
        "success": result.get("pipeline_status") == "completed",
        "message_id": result.get("message_id"),
        "analysis": result.get("analysis", {}),
        "actions": result.get("actions", []),
        "responder_results": result.get("responder_results", []),
    }

# Uso
threats = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]
results = []

for threat_ip in threats:
    result = process_security_threat(threat_ip, "firewall")
    results.append(result)
    print(f"Processed threat {threat_ip}: {result['success']}")

print(json.dumps(results, indent=2))
```

## Integração com Consumer

```python
from sentineliqsdk.consumers import PipelineConsumer
from sentineliqsdk.pipelines import SecurityPipeline

# Criar pipeline
pipeline = SecurityPipeline(pipeline_input)

# Criar consumer com pipeline
consumer = PipelineConsumer(consumer_input, pipeline=pipeline)

# Configurar e consumir
consumer.configure_queue(QueueConfig(queue_name="security-events"))
consumer.configure_messaging(MessageConfig(auto_ack=False))

# Processar mensagens
report = consumer.start_consuming()
print(f"Processed {report.messages_processed} security events")
```

## Monitoramento

O pipeline fornece estatísticas de processamento:

```python
# Obter estatísticas
summary = pipeline.summary({})
print(f"Messages processed: {summary['messages_processed']}")
print(f"Messages failed: {summary['messages_failed']}")
print(f"Processing time: {summary['processing_time']:.2f}s")
print(f"Registered analyzers: {summary['registered_analyzers']}")
print(f"Registered responders: {summary['registered_responders']}")
```

## Tratamento de Erros

O pipeline trata automaticamente:

- **Analyzer não encontrado**: Retorna erro para data_type não suportado
- **Falha na análise**: Registra falha e continua processamento
- **Falha no responder**: Registra erro específico do responder
- **Exceções gerais**: Captura e registra todas as exceções

## Dependências

- `kafka-python`: Para integração com Kafka
- Analyzers registrados (ex: ShodanAnalyzer)
- Responders registrados (ex: BlockIPResponder)

Instalar com:
```bash
pip install kafka-python
```


