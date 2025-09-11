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
        name="Cylance",
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
            taxonomy = self.build_taxonomy("info", "Cylance", "Search", "unsupported data type")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Data type '{data_type}' not supported. Only 'hash' (SHA256) is supported.",
            }
            return self.report(full)

        # Verificar se é SHA256 (64 caracteres)
        if len(str(observable)) != 64:
            taxonomy = self.build_taxonomy("info", "Cylance", "Search", "invalid hash format")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": "Only SHA256 hashes (64 characters) are supported.",
            }
            return self.report(full)

        try:
            # Obter credenciais da configuração segura
            tenant_id = self.get_secret(
                "cylance.tenant_id", message="Cylance Tenant ID is required"
            )
            app_id = self.get_secret("cylance.app_id", message="Cylance App ID is required")
            app_secret = self.get_secret(
                "cylance.app_secret", message="Cylance App Secret is required"
            )
            region = self.get_secret("cylance.region", message="Cylance Region is required")

            # Inicializar API Cylance
            api = CyAPI(tenant_id, app_id, app_secret, region)
            api.create_conn()

            # Buscar informações de dispositivos com ameaças
            threats = api.get_threat_devices(str(observable))
            threats_results: dict[str, Any] = {}

            verdict: Literal["info", "safe", "suspicious", "malicious"] = "info"
            predicate = "No results"

            if threats.data:
                # Processar resultados de dispositivos
                for i, threat_device in enumerate(threats.data):
                    threats_results[str(i)] = {
                        "name": threat_device["name"],
                        "state": threat_device["state"],
                        "found": threat_device["date_found"],
                        "status": threat_device["file_status"],
                        "path": threat_device["file_path"],
                        "ip": ", ".join(threat_device["ip_addresses"]),
                    }

                # Obter informações detalhadas da ameaça
                threat_info = api.get_threat(str(observable))
                if threat_info.data:
                    sample_data = {
                        "sample_name": threat_info.data["name"],
                        "sha256": threat_info.data["sha256"],
                        "md5": threat_info.data["md5"],
                        "signed": threat_info.data["signed"],
                        "cylance_score": threat_info.data["cylance_score"],
                        "av_industry": threat_info.data["av_industry"],
                        "classification": threat_info.data["classification"],
                        "sub_classification": threat_info.data["sub_classification"],
                        "global_quarantined": threat_info.data["global_quarantined"],
                        "safelisted": threat_info.data["safelisted"],
                        "cert_publisher": threat_info.data["cert_publisher"],
                        "cert_issuer": threat_info.data["cert_issuer"],
                        "cert_timestamp": threat_info.data["cert_timestamp"],
                        "file_size": threat_info.data["file_size"],
                        "unique_to_cylance": threat_info.data["unique_to_cylance"],
                        "running": threat_info.data["running"],
                        "autorun": threat_info.data["auto_run"],
                        "detected_by": threat_info.data["detected_by"],
                    }
                    threats_results["sample"] = sample_data

                    # Determinar verdict baseado no cylance_score
                    cylance_score = threat_info.data.get("cylance_score", -1)
                    if cylance_score >= 0:
                        if cylance_score >= 70:
                            verdict = "malicious"
                        elif cylance_score >= 30:
                            verdict = "suspicious"
                        else:
                            verdict = "safe"
                        predicate = str(cylance_score)
                    else:
                        verdict = "info"
                        predicate = "Unknown score"
                else:
                    verdict = "info"
                    predicate = "Threat found but no details"
            else:
                verdict = "info"
                predicate = "Hash not found"
                threats_results["status"] = "hash_not_found"

            taxonomy = self.build_taxonomy(verdict, "Cylance", "Score", predicate)

            full = {
                "observable": observable,
                "verdict": verdict,
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "hashlookup": threats_results,
            }

            return self.report(full)

        except Exception as e:
            taxonomy = self.build_taxonomy("info", "Cylance", "Search", "error")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"API request failed: {e!s}",
            }
            return self.report(full)

    def run(self) -> AnalyzerReport:
        """Executa o analyzer."""
        return self.execute()
