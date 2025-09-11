"""EclecticIQ Analyzer: busca observáveis em instância EclecticIQ configurada.

Este analisador fornece acesso à API EclecticIQ para buscar observáveis e entidades relacionadas.
Todos os tipos de dados padrão do Cortex são suportados.

Exemplo de uso:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer

    secrets = {
        "eclectiq": {
            "api_key": "sua_chave_api_aqui",
            "url": "https://sua-instancia.eclecticiq.com",
            "name": "nome_da_instancia"
        }
    }
    input_data = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(secrets=secrets)
    )
    report = EclecticIQAnalyzer(input_data).execute()

Configuração:
- Forneça credenciais da API via `WorkerConfig.secrets['eclectiq']['api_key']`
- Forneça URL da instância via `WorkerConfig.secrets['eclectiq']['url']`
- Forneça nome da instância via `WorkerConfig.secrets['eclectiq']['name']`
- Proxies HTTP são respeitados via `WorkerConfig.proxy`
"""

from __future__ import annotations

from typing import Any

import requests

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel


class EclecticIQAnalyzer(Analyzer):
    """Analisador para buscar observáveis em instância EclecticIQ configurada."""

    METADATA = ModuleMetadata(
        name="EclecticIQ Analyzer",
        description="Busca observáveis em instância EclecticIQ configurada",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático documentado",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/eclectiq/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None) -> None:
        """Inicializa o analisador EclecticIQ."""
        super().__init__(input_data, secret_phrases)

        # Configuração da sessão HTTP
        self.session = requests.Session()

        # Configurar proxies se fornecidos
        if self.http_proxy or self.https_proxy:
            proxies = {}
            if self.http_proxy:
                proxies["http"] = self.http_proxy
            if self.https_proxy:
                proxies["https"] = self.https_proxy
            self.session.proxies.update(proxies)

    def _get_client_config(self) -> dict[str, Any]:
        """Obtém configuração do cliente EclecticIQ."""
        name = self.get_secret(
            "eclectiq.name", message="Nome da instância EclecticIQ não fornecido."
        )
        url = self.get_secret("eclectiq.url", message="URL da instância EclecticIQ não fornecida.")
        api_key = self.get_secret(
            "eclectiq.api_key", message="Chave da API EclecticIQ não fornecida."
        )

        # Configurar verificação de certificado
        cert_check = self.get_config("eclectiq.cert_check", True)
        if cert_check:
            cert_path = self.get_config("eclectiq.cert_path", True)
            self.session.verify = cert_path
        else:
            self.session.verify = False

        # Configurar headers
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}
        )

        return {"name": name, "url": url, "api_key": api_key}

    def _get_source_name(self, source_url: str) -> str:
        """Obtém o nome da fonte a partir da URL."""
        try:
            response = self.session.get(source_url)
            response.raise_for_status()
            return response.json()["data"]["name"]
        except Exception as e:
            self.error(f"Erro ao obter nome da fonte: {e}")

    @staticmethod
    def _get_confidence(data: dict[str, Any]) -> Any:
        """Extrai valor de confiança dos dados."""
        confidence = data.get("confidence")
        if isinstance(confidence, dict):
            confidence = confidence.get("value")
        return confidence

    def _add_observable_info(
        self, results: dict[str, Any], observable: str, config: dict[str, Any]
    ) -> str | None:
        """Adiciona informações do observável aos resultados."""
        url = f"{config['url']}/api/v2/observables"
        params = {"filter[value]": observable}

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            response_data = response.json()

            if not response_data.get("count"):
                return None

            data = response_data["data"][0]
            results["obs_type"] = data["type"]
            results["obs_score"] = data.get("meta", {}).get("maliciousness")
            return data["id"]

        except Exception as e:
            self.error(f"Erro ao buscar informações do observável: {e}")

    def _get_entities_info(self, obs_id: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Obtém informações das entidades relacionadas ao observável."""
        url = f"{config['url']}/api/v2/entities"
        params = {"filter[observables]": obs_id}

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            response_data = response.json()

            if not response_data.get("count"):
                return None

            return response_data

        except Exception as e:
            self.error(f"Erro ao buscar informações das entidades: {e}")

    def _determine_verdict(self, results: dict[str, Any]) -> TaxonomyLevel:
        """Determina o veredito baseado nos resultados."""
        obs_score = results.get("obs_score")
        entity_count = results.get("count", 0)

        # Se há score de maliciosidade, usar para determinar veredito
        if obs_score is not None:
            if obs_score >= 70:
                return "malicious"
            if obs_score >= 30:
                return "suspicious"
            return "safe"

        # Se não há score mas há entidades, considerar suspeito
        if entity_count > 0:
            return "suspicious"

        # Caso contrário, informacional
        return "info"

    def execute(self) -> AnalyzerReport:
        """Executa a análise EclecticIQ."""
        observable = self.get_data()
        data_type = self.data_type

        # Obter configuração do cliente
        config = self._get_client_config()

        # Inicializar resultados
        results = {
            "name": config["name"],
            "url": config["url"],
            "obs_value": observable,
        }

        # Buscar informações do observável
        obs_id = self._add_observable_info(results, str(observable), config)
        if not obs_id:
            # Nenhum dado encontrado
            taxonomy = self.build_taxonomy(
                level="info", namespace="eclectiq", predicate="search", value="Não encontrado"
            )
            full_report = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "source": "eclectiq",
                "data_type": data_type,
                "details": results,
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

        # Buscar informações das entidades
        entities_info = self._get_entities_info(obs_id, config)
        if not entities_info:
            # Nenhuma entidade encontrada
            taxonomy = self.build_taxonomy(
                level="info",
                namespace="eclectiq",
                predicate="search",
                value="Observável encontrado, mas sem entidades relacionadas",
            )
            full_report = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "source": "eclectiq",
                "data_type": data_type,
                "details": results,
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

        # Processar entidades encontradas
        results["count"] = entities_info["count"]
        results["entities"] = []

        for entity in entities_info["data"]:
            try:
                source_name = (
                    self._get_source_name(entity["sources"][0])
                    if entity.get("sources")
                    else "Desconhecido"
                )
                entity_data = entity.get("data", {})

                results["entities"].append(
                    {
                        "id": entity["id"],
                        "title": entity_data.get("title"),
                        "type": entity_data.get("type"),
                        "confidence": self._get_confidence(entity_data),
                        "tags": entity.get("meta", {}).get("tags"),
                        "timestamp": entity.get("meta", {}).get("estimated_threat_start_time"),
                        "source_name": source_name,
                    }
                )
            except Exception as e:
                # Log erro mas continue processando outras entidades
                self.error(f"Erro ao processar entidade {entity.get('id', 'desconhecida')}: {e}")

        # Determinar veredito
        verdict = self._determine_verdict(results)

        # Construir taxonomia
        entity_count = results.get("count", 0)
        taxonomy_value = (
            f"Encontradas {entity_count} entidades" if entity_count > 0 else "Não encontrado"
        )
        taxonomy = self.build_taxonomy(
            level=verdict, namespace="eclectiq", predicate="reputation", value=taxonomy_value
        )

        # Construir relatório final
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "eclectiq",
            "data_type": data_type,
            "details": results,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Executa análise e retorna AnalyzerReport."""
        return self.execute()
