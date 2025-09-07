# AnyRun Analyzer

O AnyRun Analyzer permite submeter arquivos e URLs para análise em sandbox usando a API do AnyRun. Este analisador suporta configurações avançadas de ambiente e opções de rede para análises personalizadas.

## Características

- **Suporte a arquivos e URLs**: Analisa tanto arquivos quanto URLs suspeitas
- **Configuração flexível**: Permite configurar ambiente, opções de rede e outros parâmetros
- **Polling inteligente**: Aguarda automaticamente a conclusão da análise
- **Taxonomia detalhada**: Gera entradas de taxonomia baseadas nos scores do AnyRun
- **Limpeza de relatórios**: Remove campos grandes para otimizar o uso de memória

## Configuração

### Parâmetros Obrigatórios

- **Token da API**: Token de autenticação do AnyRun
- **Tipo de privacidade**: Tipo de privacidade para a análise (ex: "public", "private")

### Parâmetros Opcionais

#### Configurações de Ambiente
- `env_bitness`: Arquitetura do ambiente (32, 64)
- `env_version`: Versão do ambiente
- `env_type`: Tipo do ambiente

#### Opções de Rede
- `opt_network_connect`: Permitir conexões de rede
- `opt_network_fakenet`: Usar rede simulada
- `opt_network_tor`: Usar rede Tor
- `opt_network_mitm`: Interceptar tráfego de rede
- `opt_network_geo`: Configurações geográficas

#### Outras Opções
- `opt_kernel_heavyevasion`: Evasão pesada do kernel
- `opt_timeout`: Timeout da análise em segundos
- `obj_ext_startfolder`: Pasta inicial para extração
- `obj_ext_browser`: Configurações do navegador
- `verify_ssl`: Verificar certificados SSL (padrão: True)

## Uso Programático

### Análise de Arquivo

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.anyrun import AnyRunAnalyzer

# Configurar entrada
input_data = WorkerInput(
    data_type="file",
    filename="/path/to/sample.exe",
    config=WorkerConfig(
        secrets={"anyrun": {"token": "YOUR_API_TOKEN"}},
        params={"anyrun": {"privacy_type": "public"}}
    ),
)

# Executar análise
analyzer = AnyRunAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultado
print(f"Veredicto: {report.full_report['verdict']}")
print(f"Task ID: {report.full_report['task_id']}")
```

### Análise de URL

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.anyrun import AnyRunAnalyzer

# Configurar entrada
input_data = WorkerInput(
    data_type="url",
    data="https://example.com/malware.exe",
    config=WorkerConfig(
        secrets={"anyrun": {"token": "YOUR_API_TOKEN"}},
        params={
            "anyrun": {
                "privacy_type": "public",
                "env_bitness": "64",
                "opt_timeout": 300
            }
        }
    ),
)

# Executar análise
analyzer = AnyRunAnalyzer(input_data)
report = analyzer.execute()
```

### Configuração Avançada

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.anyrun import AnyRunAnalyzer

# Configuração completa
config = WorkerConfig(
    secrets={"anyrun": {"token": "YOUR_API_TOKEN"}},
    params={
        "anyrun": {
            "privacy_type": "private",
            "env_bitness": "64",
            "env_version": "10",
            "env_type": "windows",
            "opt_network_connect": True,
            "opt_network_fakenet": True,
            "opt_network_tor": False,
            "opt_network_mitm": True,
            "opt_kernel_heavyevasion": True,
            "opt_timeout": 600,
            "obj_ext_startfolder": "C:\\Users\\Public",
            "obj_ext_browser": "chrome",
            "verify_ssl": True
        }
    }
)

input_data = WorkerInput(
    data_type="file",
    filename="/path/to/sample.exe",
    config=config,
)

analyzer = AnyRunAnalyzer(input_data)
report = analyzer.execute()
```

## Estrutura do Relatório

O relatório retornado contém:

```json
{
  "observable": "arquivo.exe",
  "verdict": "malicious",
  "taxonomy": [
    {
      "level": "malicious",
      "namespace": "anyrun",
      "predicate": "sandbox-score",
      "value": "100/100"
    }
  ],
  "source": "anyrun",
  "data_type": "file",
  "task_id": "12345678-1234-1234-1234-123456789012",
  "analysis": {
    "scores": {
      "verdict": {"score": 100},
      "behavior": {"score": 85},
      "network": {"score": 70}
    },
    "incidents": [...],
    "processes": [...]
  },
  "metadata": {
    "Name": "AnyRun Analyzer",
    "Description": "Submete arquivos e URLs para análise em sandbox via AnyRun API",
    "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "License": "SentinelIQ License",
    "pattern": "threat-intel",
    "doc_pattern": "MkDocs module page; programmatic usage",
    "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/anyrun/",
    "VERSION": "TESTING"
  }
}
```

## Níveis de Taxonomia

O analisador gera entradas de taxonomia baseadas nos scores do AnyRun:

- **safe**: Score 0-50
- **suspicious**: Score 51-99  
- **malicious**: Score 100

### Entradas de Taxonomia

- `anyrun/sandbox-score`: Score principal do veredicto
- `anyrun/{score_type}-score`: Scores específicos (behavior, network, etc.)

## Exemplo de Uso

Veja o arquivo de exemplo completo em `examples/analyzers/anyrun_example.py`:

```bash
# Análise de arquivo (modo dry-run)
python examples/analyzers/anyrun_example.py --file /path/to/sample.exe --include-dangerous

# Análise de URL (modo dry-run)
python examples/analyzers/anyrun_example.py --url "https://example.com/malware.exe"

# Executar análise real
python examples/analyzers/anyrun_example.py --url "https://example.com/malware.exe" --execute

# Configuração personalizada
python examples/analyzers/anyrun_example.py \
  --url "https://example.com/malware.exe" \
  --execute \
  --privacy-type private \
  --env-bitness 64 \
  --timeout 600
```

## Limitações e Considerações

1. **Rate Limiting**: A API do AnyRun tem limites de taxa. O analisador implementa retry automático com backoff.

2. **Timeout**: Análises podem levar vários minutos. O timeout padrão é de 15 minutos.

3. **Tamanho de Arquivo**: Verifique os limites de tamanho de arquivo da API do AnyRun.

4. **Privacidade**: Configure adequadamente o tipo de privacidade conforme suas necessidades.

5. **Custos**: Análises reais podem ter custos associados dependendo do plano da API.

## Tratamento de Erros

O analisador trata os seguintes cenários de erro:

- Token de API inválido ou ausente
- Tipo de privacidade não especificado
- Arquivo não encontrado
- Erros de rede e timeout
- Rate limiting da API
- Análise que excede o tempo limite

## Integração com Outros Módulos

Este analisador pode ser usado em conjunto com:

- **Extractors**: Para extrair IOCs dos relatórios de análise
- **Responders**: Para ações baseadas nos resultados da análise
- **Detectors**: Para detecção automática de tipos de arquivo suspeitos
