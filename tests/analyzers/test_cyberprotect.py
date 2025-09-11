"""Testes unitários para CyberprotectAnalyzer."""

from __future__ import annotations

import json
from typing import Literal
from unittest.mock import Mock, patch

import requests

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cyberprotect import CyberprotectAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestCyberprotectAnalyzer:
    """Testes para o CyberprotectAnalyzer."""

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
    ) -> CyberprotectAnalyzer:
        """Cria uma instância do analyzer para testes."""
        worker_input = WorkerInput(data_type=data_type, data=data, tlp=2, pap=2, config=self.config)
        return CyberprotectAnalyzer(worker_input)

    def test_metadata(self):
        """Testa se os metadados estão configurados corretamente."""
        analyzer = self.create_analyzer("example.com", "domain")

        assert analyzer.METADATA.name == "Cyberprotect ThreatScore"
        assert "Cyberprotect" in analyzer.METADATA.description
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"
        assert len(analyzer.METADATA.author) > 0

    def test_supported_data_types(self):
        """Testa se os tipos de dados suportados funcionam corretamente."""
        supported_types = ["domain", "hash", "ip", "url", "user-agent"]

        for data_type in supported_types:
            analyzer = self.create_analyzer("test_data", data_type)
            assert analyzer.data_type == data_type

    def test_unsupported_data_type(self):
        """Testa o comportamento com tipo de dados não suportado."""
        analyzer = self.create_analyzer("test_data", "other")
        result = analyzer.execute()

        assert isinstance(result, AnalyzerReport)
        data = result.full_report
        assert data["verdict"] == "info"
        assert "unsupported data type" in data["taxonomy"][0]["value"]
        assert "error" in data
        assert "not supported" in data["error"]

    @patch("requests.post")
    def test_successful_api_call_malicious(self, mock_post):
        """Testa uma chamada de API bem-sucedida com resultado malicioso."""
        # Mock da resposta da API
        mock_response = Mock()
        mock_response.json.return_value = {"threatscore": {"value": "95", "level": "malicious"}}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("malicious.com", "domain")
        result = analyzer.execute()

        # Verificar se a requisição foi feita corretamente
        mock_post.assert_called_once_with(
            "https://api.threatscore.cyberprotect.cloud/api/v3/observables/search/by-value",
            json={"data": "malicious.com"},
            timeout=30,
        )

        # Verificar resultado
        data = result.full_report
        assert data["verdict"] == "malicious"
        assert data["taxonomy"][0]["level"] == "malicious"
        assert data["taxonomy"][0]["value"] == "95"
        assert "raw_response" in data

    @patch("requests.post")
    def test_successful_api_call_safe(self, mock_post):
        """Testa uma chamada de API bem-sucedida com resultado seguro."""
        mock_response = Mock()
        mock_response.json.return_value = {"threatscore": {"value": "10", "level": "safe"}}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("safe.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "safe"
        assert data["taxonomy"][0]["level"] == "safe"
        assert data["taxonomy"][0]["value"] == "10"

    @patch("requests.post")
    def test_successful_api_call_suspicious(self, mock_post):
        """Testa uma chamada de API bem-sucedida com resultado suspeito."""
        mock_response = Mock()
        mock_response.json.return_value = {"threatscore": {"value": "60", "level": "suspicious"}}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("suspicious.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "suspicious"
        assert data["taxonomy"][0]["level"] == "suspicious"
        assert data["taxonomy"][0]["value"] == "60"

    @patch("requests.post")
    def test_api_call_not_in_database(self, mock_post):
        """Testa resposta quando o observable não está na base de dados."""
        mock_response = Mock()
        mock_response.json.return_value = {}  # Resposta vazia
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("unknown.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "info"
        assert data["taxonomy"][0]["value"] == "not in database"

    @patch("requests.post")
    def test_api_call_not_analyzed_yet(self, mock_post):
        """Testa resposta quando o observable ainda não foi analisado."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "threatscore": {}  # Sem value e level
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("pending.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "info"
        assert data["taxonomy"][0]["value"] == "not analyzed yet"

    @patch("requests.post")
    def test_api_request_exception(self, mock_post):
        """Testa o tratamento de exceções de requisição."""
        mock_post.side_effect = requests.exceptions.RequestException("Connection error")

        analyzer = self.create_analyzer("test.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "info"
        assert data["taxonomy"][0]["value"] == "api error"
        assert "error" in data
        assert "API request failed" in data["error"]

    @patch("requests.post")
    def test_api_http_error(self, mock_post):
        """Testa o tratamento de erros HTTP."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("test.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "info"
        assert data["taxonomy"][0]["value"] == "api error"
        assert "error" in data

    @patch("requests.post")
    def test_json_decode_error(self, mock_post):
        """Testa o tratamento de erro de decodificação JSON."""
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        analyzer = self.create_analyzer("test.com", "domain")
        result = analyzer.execute()

        data = result.full_report
        assert data["verdict"] == "info"
        assert data["taxonomy"][0]["value"] == "error"
        assert "error" in data

    def test_run_method(self):
        """Testa se o método run() chama execute() corretamente."""
        analyzer = self.create_analyzer("test.com", "domain")

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = Mock(spec=AnalyzerReport)
            result = analyzer.run()

            mock_execute.assert_called_once()
            assert result == mock_execute.return_value

    def test_different_data_types(self):
        """Testa diferentes tipos de dados suportados."""
        test_cases = [
            ("example.com", "domain"),
            ("1.2.3.4", "ip"),
            ("https://example.com", "url"),
            ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "user-agent"),
        ]

        for data, data_type in test_cases:
            analyzer = self.create_analyzer(data, data_type)
            assert analyzer.get_data() == data
            assert analyzer.data_type == data_type

    def test_taxonomy_structure(self):
        """Testa se a estrutura da taxonomia está correta."""
        analyzer = self.create_analyzer("test.com", "other")  # Tipo não suportado
        result = analyzer.execute()

        data = result.full_report
        taxonomy = data["taxonomy"][0]

        assert "level" in taxonomy
        assert "namespace" in taxonomy
        assert "predicate" in taxonomy
        assert "value" in taxonomy
        assert taxonomy["namespace"] == "Cyberprotect"
        assert taxonomy["predicate"] == "ThreatScore"

    def test_level_mapping(self):
        """Testa o mapeamento correto de levels para verdicts."""
        test_cases = [
            ("malicious", "malicious"),
            ("high", "malicious"),
            ("suspicious", "suspicious"),
            ("medium", "suspicious"),
            ("safe", "safe"),
            ("low", "safe"),
            ("unknown", "info"),
        ]

        for level, expected_verdict in test_cases:
            with patch("requests.post") as mock_post:
                mock_response = Mock()
                mock_response.json.return_value = {"threatscore": {"value": "50", "level": level}}
                mock_response.raise_for_status.return_value = None
                mock_post.return_value = mock_response

                analyzer = self.create_analyzer("test.com", "domain")
                result = analyzer.execute()

                data = result.full_report
                assert data["verdict"] == expected_verdict
