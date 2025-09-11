#!/usr/bin/env python3
"""Testes unitários para o CylanceAnalyzer."""

from __future__ import annotations

from unittest.mock import Mock, patch

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestCylanceAnalyzer:
    """Testes para o CylanceAnalyzer."""

    def setup_method(self) -> None:
        """Configuração para cada teste."""
        self.valid_sha256 = "a" * 64  # Hash SHA256 válido
        self.invalid_hash = "invalid_hash"

        self.config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "cylance": {
                    "tenant_id": "test_tenant",
                    "app_id": "test_app_id",
                    "app_secret": "test_app_secret",
                    "region": "us",
                }
            },
        )

    def test_metadata(self) -> None:
        """Testa se os metadados estão corretos."""
        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)

        assert analyzer.METADATA.name == "Cylance Analyzer"
        assert "Cylance" in analyzer.METADATA.description
        assert analyzer.METADATA.author == ("SentinelIQ Team <team@sentineliq.com.br>",)
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"

    def test_invalid_data_type(self) -> None:
        """Testa comportamento com tipo de dados inválido."""
        worker_input = WorkerInput(
            data_type="ip",
            data="1.2.3.4",
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "info"
        assert "Tipo de dados 'ip' não suportado" in result.full_report["error"]

    def test_invalid_hash_format(self) -> None:
        """Testa comportamento com hash inválido."""
        worker_input = WorkerInput(
            data_type="hash",
            data=self.invalid_hash,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "info"
        assert "Hash inválido" in str(result.full_report)

    def test_missing_credentials(self):
        """Testa comportamento quando credenciais estão ausentes."""
        config_no_secrets = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={},
        )

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=config_no_secrets,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        # Verifica se há erro no resultado
        assert "error" in result.full_report
        assert "Credencial obrigatória: Cylance Tenant ID" in result.full_report["error"]

    @patch("sentineliqsdk.analyzers.cylance.CyAPI")
    def test_successful_analysis_malicious(self, mock_cyapi: Mock) -> None:
        """Testa análise bem-sucedida com resultado malicioso."""
        # Mock da resposta da API
        mock_api_instance = Mock()
        mock_cyapi.return_value = mock_api_instance

        mock_api_instance.get_file_list_by_hash.return_value = {
            "sample": {
                "sample_name": "malware.exe",
                "cylance_score": -0.95,
                "classification": "Malware",
                "signed": False,
                "global_quarantined": True,
            },
            "device1": {
                "name": "Test Device",
                "state": "Quarantined",
            },
        }

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "malicious"
        assert len(result.full_report["taxonomy"]) == 1
        assert result.full_report["taxonomy"][0]["level"] == "malicious"
        assert result.full_report["taxonomy"][0]["namespace"] == "cylance"
        assert result.full_report["taxonomy"][0]["predicate"] == "malware"

        # Verificar se a API foi chamada corretamente
        mock_cyapi.assert_called_once()
        mock_api_instance.get_file_list_by_hash.assert_called_once_with(self.valid_sha256)

    @patch("sentineliqsdk.analyzers.cylance.CyAPI")
    def test_successful_analysis_safe(self, mock_cyapi: Mock) -> None:
        """Testa análise bem-sucedida com resultado seguro."""
        # Mock da resposta da API
        mock_api_instance = Mock()
        mock_cyapi.return_value = mock_api_instance

        mock_api_instance.get_file_list_by_hash.return_value = {
            "sample": {
                "sample_name": "legitimate.exe",
                "cylance_score": 0.85,
                "classification": "Safe",
                "signed": True,
                "global_quarantined": False,
            }
        }

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "safe"
        assert len(result.full_report["taxonomy"]) == 1
        assert result.full_report["taxonomy"][0]["level"] == "safe"
        assert result.full_report["taxonomy"][0]["namespace"] == "cylance"
        assert result.full_report["taxonomy"][0]["predicate"] == "clean"

    @patch("sentineliqsdk.analyzers.cylance.CyAPI")
    def test_successful_analysis_suspicious(self, mock_cyapi: Mock) -> None:
        """Testa análise bem-sucedida com resultado suspeito."""
        # Mock da resposta da API
        mock_api_instance = Mock()
        mock_cyapi.return_value = mock_api_instance

        mock_api_instance.get_file_list_by_hash.return_value = {
            "sample": {
                "sample_name": "suspicious.exe",
                "cylance_score": -0.3,
                "classification": "Abnormal",
                "signed": False,
                "global_quarantined": False,
            }
        }

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "suspicious"
        assert len(result.full_report["taxonomy"]) == 1
        assert result.full_report["taxonomy"][0]["level"] == "suspicious"
        assert result.full_report["taxonomy"][0]["namespace"] == "cylance"
        assert result.full_report["taxonomy"][0]["predicate"] == "abnormal"

    @patch("sentineliqsdk.analyzers.cylance.CyAPI")
    def test_hash_not_found(self, mock_cyapi: Mock) -> None:
        """Testa comportamento quando hash não é encontrado."""
        # Mock da resposta da API para hash não encontrado
        mock_api_instance = Mock()
        mock_cyapi.return_value = mock_api_instance

        mock_api_instance.get_file_list_by_hash.return_value = {}

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "info"
        assert len(result.full_report["taxonomy"]) == 1
        assert result.full_report["taxonomy"][0]["level"] == "info"
        assert result.full_report["taxonomy"][0]["namespace"] == "cylance"
        assert result.full_report["taxonomy"][0]["predicate"] == "not-found"
        assert "hash_not_found" in result.full_report["hashlookup"]

    @patch("sentineliqsdk.analyzers.cylance.CyAPI")
    def test_api_error(self, mock_cyapi: Mock) -> None:
        """Testa comportamento com erro da API."""
        # Mock da resposta da API com erro
        mock_api_instance = Mock()
        mock_cyapi.return_value = mock_api_instance

        mock_api_instance.get_file_list_by_hash.side_effect = Exception("API Error")

        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        assert result.full_report["verdict"] == "info"
        assert "Erro na consulta" in str(result.full_report)
        assert "API Error" in str(result.full_report)

    def test_run_method(self) -> None:
        """Testa se o método run() chama execute()."""
        worker_input = WorkerInput(
            data_type="hash",
            data=self.invalid_hash,  # Usar hash inválido para teste rápido
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)

        # Mock do método execute
        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = Mock(spec=AnalyzerReport)

            result = analyzer.run()

            mock_execute.assert_called_once()
            assert result == mock_execute.return_value

    def test_get_secret_calls(self) -> None:
        """Testa se get_secret é chamado corretamente para todas as credenciais."""
        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)

        with patch.object(analyzer, "get_secret") as mock_get_secret:
            mock_get_secret.side_effect = ["test_tenant", "test_app_id", "test_app_secret", "us"]

            with patch("sentineliqsdk.analyzers.cylance.CyAPI") as mock_cyapi:
                mock_api_instance = Mock()
                mock_cyapi.return_value = mock_api_instance
                mock_api_instance.get_file_list_by_hash.return_value = {}

                analyzer.execute()

                # Verificar se get_secret foi chamado para todas as credenciais
                expected_calls = [
                    ("cylance.tenant_id",),
                    ("cylance.app_id",),
                    ("cylance.app_secret",),
                    ("cylance.region",),
                ]

                actual_calls = [call[0] for call in mock_get_secret.call_args_list]
                for expected_call in expected_calls:
                    assert expected_call in actual_calls

    def test_taxonomy_building(self) -> None:
        """Testa se a taxonomia é construída corretamente."""
        worker_input = WorkerInput(
            data_type="hash",
            data=self.valid_sha256,
            tlp=2,
            pap=2,
            config=self.config,
        )

        analyzer = CylanceAnalyzer(worker_input)

        # Testar diferentes cenários de taxonomia
        from typing import Literal

        test_cases: list[tuple[Literal["info", "safe", "suspicious", "malicious"], str, str]] = [
            ("malicious", "malware", "malicious"),
            ("safe", "clean", "safe"),
            ("suspicious", "abnormal", "suspicious"),
            ("info", "not-found", "info"),
        ]

        for verdict, predicate, expected_level in test_cases:
            taxonomy = analyzer.build_taxonomy(verdict, "cylance", predicate, self.valid_sha256)

            assert taxonomy.level == expected_level
            assert taxonomy.namespace == "cylance"
            assert taxonomy.predicate == predicate
            assert taxonomy.value == self.valid_sha256
