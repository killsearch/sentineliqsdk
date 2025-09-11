"""Analyzer para verificação de registros SPF e DMARC de domínios.

Este módulo implementa um analyzer que verifica a configuração de SPF e DMARC
de domínios usando a biblioteca checkdmarc para análise de segurança de email.
"""

from __future__ import annotations

from typing import Literal

import checkdmarc

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class DomainMailSpfDmarcAnalyzer(Analyzer):
    """Analyzer para verificação de registros SPF e DMARC.

    Este analyzer verifica a configuração de SPF (Sender Policy Framework) e DMARC
    (Domain-based Message Authentication, Reporting & Conformance) de domínios para
    avaliar a segurança da configuração de email.
    """

    METADATA = ModuleMetadata(
        name="Domain Mail SPF DMARC",
        description="Verifica registros SPF e DMARC de domínios para análise de segurança de email",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/domain_mail_spf_dmarc/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        """Executa a análise de SPF e DMARC do domínio."""
        observable = self.get_data()
        data_type = self.data_type

        # Verificar se o tipo de dados é suportado
        supported_types = ["domain", "fqdn"]
        if data_type not in supported_types:
            taxonomy = self.build_taxonomy("info", "DomainMailSPF_DMARC", "DataType", "unsupported")
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Data type '{data_type}' not supported. Supported types: {', '.join(supported_types)}",
            }
            return self.report(full)

        try:
            # Executar verificação usando checkdmarc
            result = checkdmarc.check_domains([str(observable)])

            # Extrair informações de SPF e DMARC
            domain_result = result[str(observable)]
            spf_info = domain_result.get("spf", {})
            dmarc_info = domain_result.get("dmarc", {})

            # Determinar verdict baseado na presença de erros
            spf_has_error = "error" in spf_info
            dmarc_has_error = "error" in dmarc_info

            verdict: Literal["safe", "suspicious", "malicious"] = "safe"
            taxonomies = []

            # Lógica de classificação baseada no código original
            if dmarc_has_error:
                if spf_has_error:
                    # Ambos com erro - malicioso
                    verdict = "malicious"
                    taxonomies.extend(
                        [
                            self.build_taxonomy("malicious", "DomainMailSPF_DMARC", "DMARC", "no"),
                            self.build_taxonomy("malicious", "DomainMailSPF_DMARC", "SPF", "no"),
                        ]
                    )
                else:
                    # Apenas DMARC com erro - suspeito
                    verdict = "suspicious"
                    taxonomies.extend(
                        [
                            self.build_taxonomy("safe", "DomainMailSPF_DMARC", "SPF", "yes"),
                            self.build_taxonomy("suspicious", "DomainMailSPF_DMARC", "DMARC", "no"),
                        ]
                    )
            elif spf_has_error:
                # Apenas SPF com erro - suspeito
                verdict = "suspicious"
                taxonomies.extend(
                    [
                        self.build_taxonomy("suspicious", "DomainMailSPF_DMARC", "SPF", "no"),
                        self.build_taxonomy("safe", "DomainMailSPF_DMARC", "DMARC", "yes"),
                    ]
                )
            else:
                # Ambos configurados corretamente - seguro
                verdict = "safe"
                taxonomies.extend(
                    [
                        self.build_taxonomy("safe", "DomainMailSPF_DMARC", "SPF", "yes"),
                        self.build_taxonomy("safe", "DomainMailSPF_DMARC", "DMARC", "yes"),
                    ]
                )

            full = {
                "observable": observable,
                "verdict": verdict,
                "taxonomy": [tax.to_dict() for tax in taxonomies],
                "metadata": self.METADATA.to_dict(),
                "spf": spf_info,
                "dmarc": dmarc_info,
                "raw_result": {"DomainMailSPFDMARC": dict(result)},
            }

            return self.report(full)

        except Exception as e:
            taxonomy = self.build_taxonomy(
                "info", "DomainMailSPF_DMARC", "Error", "analysis_failed"
            )
            full = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
                "error": f"Analysis failed: {e!s}",
            }
            return self.report(full)

    def run(self) -> AnalyzerReport:
        """Executa o analyzer."""
        return self.execute()
