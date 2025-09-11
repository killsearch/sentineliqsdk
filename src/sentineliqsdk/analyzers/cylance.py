from __future__ import annotations

from typing import Any, Literal

from cyapi.cyapi import CyAPI

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class CylanceAnalyzer(Analyzer):
    """Analyzer para consultar a API Cylance.

    Este analyzer consulta a API da Cylance para obter informações de ameaças
    sobre hashes SHA256, incluindo threat score, classificação e informações de dispositivos.
    """

    METADATA = ModuleMetadata(
        name="Cylance Analyzer",
        description="Consulta a API Cylance para análise de ameaças por hash SHA256",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cylance/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        """Executa a análise consultando a API da Cylance."""
        observable = self.get_data()
        data_type = self.data_type

        # Verificar se o tipo de dados é suportado (apenas hash SHA256)
        if data_type != "hash":
            taxonomy = self.build_taxonomy("info", "cylance", "Search", "unsupported data type")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Tipo de dados '{data_type}' não suportado. Apenas 'hash' (SHA256) é suportado.",
            }
            return self.report(full)

        # Verificar se é SHA256 (64 caracteres)
        if len(str(observable)) != 64:
            taxonomy = self.build_taxonomy("info", "cylance", "Search", "invalid hash format")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": "Hash inválido. Apenas hashes SHA256 (64 caracteres) são suportados.",
            }
            return self.report(full)

        try:
            # Obter credenciais via get_secret
            tenant_id = self.get_secret(
                "cylance.tenant_id", message="Credencial obrigatória: Cylance Tenant ID"
            )
            app_id = self.get_secret(
                "cylance.app_id", message="Credencial obrigatória: Cylance App ID"
            )
            app_secret = self.get_secret(
                "cylance.app_secret", message="Credencial obrigatória: Cylance App Secret"
            )
            region = self.get_secret(
                "cylance.region", message="Credencial obrigatória: Cylance Region"
            )

            # Inicializar API Cylance
            api = CyAPI(tenant_id, app_id, app_secret, region)
            api.create_conn()

            # Consultar a API Cylance
            threat_info = api.get_file_list_by_hash(observable)
            threats_results: dict[str, Any] = {}

            verdict: Literal["info", "safe", "suspicious", "malicious"] = "info"
            predicate = "No results"

            if threat_info and "sample" in threat_info:
                sample_data = threat_info["sample"]
                threats_results["sample"] = sample_data

                # Determinar verdict baseado no cylance_score
                # Cylance scores: valores negativos indicam malware, positivos indicam seguro
                cylance_score = sample_data.get("cylance_score")
                if cylance_score is not None:
                    if cylance_score <= -0.7:  # Muito negativo = malicioso
                        verdict = "malicious"
                        predicate = "malware"
                    elif cylance_score <= -0.1:  # Negativo = suspeito
                        verdict = "suspicious"
                        predicate = "abnormal"
                    else:  # Positivo ou próximo de zero = seguro
                        verdict = "safe"
                        predicate = "clean"
                else:
                    verdict = "info"
                    predicate = "Unknown score"
            else:
                verdict = "info"
                predicate = "not-found"
                threats_results["hash_not_found"] = True

            taxonomy = self.build_taxonomy(verdict, "cylance", predicate, str(observable))

            full = {
                "observable": observable,
                "verdict": verdict,
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "hashlookup": threats_results,
            }

            return self.report(full)

        except Exception as e:
            taxonomy = self.build_taxonomy("info", "cylance", "Search", "error")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Erro na consulta à API: {e!s}",
            }
            return self.report(full)

    def run(self) -> AnalyzerReport:
        """Executa o analyzer."""
        return self.execute()
