"""Analyzer para consultar a API CyberProtect.

Este módulo implementa um analyzer que consulta a API da CyberProtect
para obter informações de ameaças sobre hashes SHA256.
"""

from __future__ import annotations

from typing import Literal

import requests

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class CyberprotectAnalyzer(Analyzer):
    """Analyzer para consultar a API ThreatScore da Cyberprotect.

    Este analyzer consulta a API da Cyberprotect para obter informações de threat score
    sobre observáveis como domínios, hashes, IPs, URLs e user-agents.
    """

    METADATA = ModuleMetadata(
        name="Cyberprotect ThreatScore",
        description="Consulta a API ThreatScore da Cyberprotect para análise de ameaças",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cyberprotect/",
        version_stage="TESTING",
    )

    URL = "https://api.threatscore.cyberprotect.cloud/api/v3/observables/search/by-value"

    def execute(self) -> AnalyzerReport:
        """Executa a análise consultando a API da Cyberprotect."""
        observable = self.get_data()
        data_type = self.data_type

        # Verificar se o tipo de dados é suportado
        supported_types = ["domain", "hash", "ip", "url", "user-agent"]
        if data_type not in supported_types:
            taxonomy = self.build_taxonomy(
                "info", "Cyberprotect", "ThreatScore", "unsupported data type"
            )
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Data type '{data_type}' not supported. Supported types: {', '.join(supported_types)}",
            }
            return self.report(full)

        try:
            # Fazer requisição para a API
            response = requests.post(self.URL, json={"data": str(observable)}, timeout=30)
            response.raise_for_status()
            result = response.json()

            # Processar resposta
            verdict: Literal["info", "safe", "suspicious", "malicious"] = "info"
            value = "not in database"

            if "threatscore" in result:
                if "value" in result["threatscore"] and "level" in result["threatscore"]:
                    value = result["threatscore"]["value"]
                    level = result["threatscore"]["level"]

                    # Mapear level para verdict
                    if level in ["malicious", "high"]:
                        verdict = "malicious"
                    elif level in ["suspicious", "medium"]:
                        verdict = "suspicious"
                    elif level in ["safe", "low"]:
                        verdict = "safe"
                    else:
                        verdict = "info"
                else:
                    value = "not analyzed yet"

            taxonomy = self.build_taxonomy(verdict, "Cyberprotect", "ThreatScore", str(value))

            full = {
                "observable": observable,
                "verdict": verdict,
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "raw_response": result,
            }

            return self.report(full)

        except requests.exceptions.RequestException as e:
            taxonomy = self.build_taxonomy("info", "Cyberprotect", "ThreatScore", "api error")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"API request failed: {e!s}",
            }
            return self.report(full)

        except Exception as e:
            taxonomy = self.build_taxonomy("info", "Cyberprotect", "ThreatScore", "error")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Unexpected error: {e!s}",
            }
            return self.report(full)

    def run(self) -> AnalyzerReport:
        """Executa o analyzer."""
        return self.execute()
