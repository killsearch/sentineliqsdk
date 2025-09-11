"""Testes unitários para DomainMailSpfDmarcAnalyzer."""

from __future__ import annotations

from typing import Literal
from unittest.mock import Mock, patch

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.domain_mail_spf_dmarc import DomainMailSpfDmarcAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestDomainMailSpfDmarcAnalyzer:
    """Testes para o DomainMailSpfDmarcAnalyzer."""

    def setup_method(self):
        """Configuração inicial para cada teste."""
        self.config = WorkerConfig(
            check_tlp=True, max_tlp=2, check_pap=True, max_pap=2, auto_extract=True, secrets={}
        )

    def create_analyzer(
        self,
        data: str,
        data_type: Literal[
            "ip",
            "url",
            "domain",
            "fqdn",
            "hash",
            "mail",
            "user-agent",
            "uri_path",
            "registry",
            "file",
            "other",
            "asn",
            "cve",
            "ip_port",
            "mac",
            "cidr",
        ],
    ) -> DomainMailSpfDmarcAnalyzer:
        """Cria uma instância do analyzer para testes."""
        worker_input = WorkerInput(data_type=data_type, data=data, tlp=2, pap=2, config=self.config)
        return DomainMailSpfDmarcAnalyzer(worker_input)

    def test_metadata(self):
        """Testa se os metadados estão corretos."""
        analyzer = self.create_analyzer("example.com", "domain")
        metadata = analyzer.METADATA

        assert metadata.name == "Domain Mail SPF DMARC"
        assert "SPF" in metadata.description
        assert "DMARC" in metadata.description
        assert metadata.version_stage == "TESTING"
        assert metadata.pattern == "threat-intel"

    def test_supported_data_types(self):
        """Testa se os tipos de dados suportados funcionam."""
        supported_types = ["domain", "fqdn"]

        for data_type in supported_types:
            analyzer = self.create_analyzer("example.com", data_type)
            assert analyzer.data_type == data_type

    def test_unsupported_data_type(self):
        """Testa se tipos de dados não suportados retornam erro apropriado."""
        analyzer = self.create_analyzer("1.2.3.4", "ip")
        result = analyzer.execute()

        assert result.full_report["verdict"] == "info"
        assert "not supported" in result.full_report["error"]
        assert result.full_report["taxonomy"][0]["predicate"] == "DataType"
        assert result.full_report["taxonomy"][0]["value"] == "unsupported"

    @patch("checkdmarc.check_domains")
    def test_successful_analysis_both_configured(self, mock_checkdmarc):
        """Testa análise bem-sucedida com SPF e DMARC configurados."""
        # Mock da resposta do checkdmarc com ambos configurados
        mock_checkdmarc.return_value = {
            "example.com": {
                "spf": {"record": "v=spf1 include:_spf.google.com ~all", "valid": True},
                "dmarc": {
                    "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                    "valid": True,
                },
            }
        }

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "safe"
        assert result.full_report["observable"] == "example.com"

        # Verificar taxonomias
        taxonomies = result.full_report["taxonomy"]
        assert len(taxonomies) == 2

        spf_tax = next(t for t in taxonomies if t["predicate"] == "SPF")
        dmarc_tax = next(t for t in taxonomies if t["predicate"] == "DMARC")

        assert spf_tax["level"] == "safe"
        assert spf_tax["value"] == "yes"
        assert dmarc_tax["level"] == "safe"
        assert dmarc_tax["value"] == "yes"

    @patch("checkdmarc.check_domains")
    def test_analysis_spf_error_only(self, mock_checkdmarc):
        """Testa análise com erro apenas no SPF."""
        mock_checkdmarc.return_value = {
            "example.com": {
                "spf": {"error": "No SPF record found"},
                "dmarc": {
                    "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                    "valid": True,
                },
            }
        }

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert result.full_report["verdict"] == "suspicious"

        taxonomies = result.full_report["taxonomy"]
        spf_tax = next(t for t in taxonomies if t["predicate"] == "SPF")
        dmarc_tax = next(t for t in taxonomies if t["predicate"] == "DMARC")

        assert spf_tax["level"] == "suspicious"
        assert spf_tax["value"] == "no"
        assert dmarc_tax["level"] == "safe"
        assert dmarc_tax["value"] == "yes"

    @patch("checkdmarc.check_domains")
    def test_analysis_dmarc_error_only(self, mock_checkdmarc):
        """Testa análise com erro apenas no DMARC."""
        mock_checkdmarc.return_value = {
            "example.com": {
                "spf": {"record": "v=spf1 include:_spf.google.com ~all", "valid": True},
                "dmarc": {"error": "No DMARC record found"},
            }
        }

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert result.full_report["verdict"] == "suspicious"

        taxonomies = result.full_report["taxonomy"]
        spf_tax = next(t for t in taxonomies if t["predicate"] == "SPF")
        dmarc_tax = next(t for t in taxonomies if t["predicate"] == "DMARC")

        assert spf_tax["level"] == "safe"
        assert spf_tax["value"] == "yes"
        assert dmarc_tax["level"] == "suspicious"
        assert dmarc_tax["value"] == "no"

    @patch("checkdmarc.check_domains")
    def test_analysis_both_errors(self, mock_checkdmarc):
        """Testa análise com erros em ambos SPF e DMARC."""
        mock_checkdmarc.return_value = {
            "example.com": {
                "spf": {"error": "No SPF record found"},
                "dmarc": {"error": "No DMARC record found"},
            }
        }

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert result.full_report["verdict"] == "malicious"

        taxonomies = result.full_report["taxonomy"]
        spf_tax = next(t for t in taxonomies if t["predicate"] == "SPF")
        dmarc_tax = next(t for t in taxonomies if t["predicate"] == "DMARC")

        assert spf_tax["level"] == "malicious"
        assert spf_tax["value"] == "no"
        assert dmarc_tax["level"] == "malicious"
        assert dmarc_tax["value"] == "no"

    @patch("checkdmarc.check_domains")
    def test_checkdmarc_exception(self, mock_checkdmarc):
        """Testa tratamento de exceção do checkdmarc."""
        mock_checkdmarc.side_effect = Exception("DNS resolution failed")

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert result.full_report["verdict"] == "info"
        assert "Analysis failed" in result.full_report["error"]
        assert result.full_report["taxonomy"][0]["predicate"] == "Error"
        assert result.full_report["taxonomy"][0]["value"] == "analysis_failed"

    def test_run_method(self):
        """Testa se o método run() chama execute()."""
        analyzer = self.create_analyzer("example.com", "domain")

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = Mock(spec=AnalyzerReport)
            analyzer.run()
            mock_execute.assert_called_once()

    def test_different_data_types(self):
        """Testa diferentes tipos de dados suportados."""
        test_cases = [
            ("example.com", "domain"),
            ("www.example.com", "fqdn"),
        ]

        for data, data_type in test_cases:
            analyzer = self.create_analyzer(data, data_type)
            assert analyzer.get_data() == data
            assert analyzer.data_type == data_type

    @patch("checkdmarc.check_domains")
    def test_taxonomy_structure(self, mock_checkdmarc):
        """Testa a estrutura das taxonomias geradas."""
        mock_checkdmarc.return_value = {
            "example.com": {
                "spf": {"record": "v=spf1 ~all", "valid": True},
                "dmarc": {"record": "v=DMARC1; p=none", "valid": True},
            }
        }

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        taxonomies = result.full_report["taxonomy"]

        for taxonomy in taxonomies:
            assert "level" in taxonomy
            assert "namespace" in taxonomy
            assert "predicate" in taxonomy
            assert "value" in taxonomy
            assert taxonomy["namespace"] == "DomainMailSPF_DMARC"
            assert taxonomy["predicate"] in ["SPF", "DMARC"]
            assert taxonomy["value"] in ["yes", "no"]

    @patch("checkdmarc.check_domains")
    def test_report_includes_raw_data(self, mock_checkdmarc):
        """Testa se o relatório inclui dados brutos."""
        mock_result = {
            "example.com": {
                "spf": {"record": "v=spf1 ~all", "valid": True},
                "dmarc": {"record": "v=DMARC1; p=none", "valid": True},
            }
        }
        mock_checkdmarc.return_value = mock_result

        analyzer = self.create_analyzer("example.com", "domain")
        result = analyzer.execute()

        assert "spf" in result.full_report
        assert "dmarc" in result.full_report
        assert "raw_result" in result.full_report
        assert result.full_report["raw_result"]["DomainMailSPFDMARC"] == dict(mock_result)
        assert "metadata" in result.full_report

    def test_fqdn_data_type(self):
        """Testa especificamente o tipo de dados FQDN."""
        analyzer = self.create_analyzer("www.example.com", "fqdn")
        assert analyzer.data_type == "fqdn"
        assert analyzer.get_data() == "www.example.com"
