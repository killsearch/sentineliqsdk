from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
import requests

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cluster25 import Cluster25Analyzer
from sentineliqsdk.clients.cluster25 import Cluster25Client


class TestCluster25Client:
    """Test Cluster25Client functionality."""

    def test_init(self):
        """Test client initialization."""
        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        assert client.client_id == "test_id"
        assert client.client_key == "test_key"
        assert client.base_url == "https://api.test.com"
        assert client.timeout == 30
        assert client.max_retries == 3
        assert client.current_token is None
        assert client.headers == {}

    def test_init_with_custom_params(self):
        """Test client initialization with custom parameters."""
        client = Cluster25Client(
            client_id="test_id",
            client_key="test_key",
            base_url="https://api.test.com",
            timeout=60,
            max_retries=5,
        )

        assert client.timeout == 60
        assert client.max_retries == 5

    def test_init_strips_trailing_slash(self):
        """Test that base_url trailing slash is stripped."""
        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com/"
        )

        assert client.base_url == "https://api.test.com"

    @patch("requests.post")
    def test_get_token_success(self, mock_post):
        """Test successful token retrieval."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"token": "test_token_123"}}
        mock_post.return_value = mock_response

        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        token = client._get_token()

        assert token == "test_token_123"
        assert client.current_token == "test_token_123"
        assert client.headers == {"Authorization": "Bearer test_token_123"}

        # Verify API call
        mock_post.assert_called_once_with(
            url="https://api.test.com/token",
            json={"client_id": "test_id", "client_secret": "test_key"},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

    @patch("requests.post")
    def test_get_token_failure(self, mock_post):
        """Test token retrieval failure."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Client Error"
        )
        mock_post.return_value = mock_response

        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        with pytest.raises(Exception, match="Unable to retrieve token from Cluster25 platform"):
            client._get_token()

    @patch("requests.post")
    def test_get_token_request_exception(self, mock_post):
        """Test token retrieval with request exception."""
        mock_post.side_effect = requests.exceptions.RequestException("Network error")

        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        with pytest.raises(Exception, match="Unable to retrieve token from Cluster25 platform"):
            client._get_token()

    @patch("requests.get")
    @patch.object(Cluster25Client, "_get_token")
    def test_investigate_success(self, mock_get_token, mock_get):
        """Test successful investigation."""
        # Mock token
        mock_get_token.return_value = "test_token_123"

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"indicator": "1.2.3.4", "indicator_type": "ip", "score": 75}
        }
        mock_get.return_value = mock_response

        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        # Set headers manually to simulate what _get_token would do
        client.headers = {"Authorization": "Bearer test_token_123"}

        result = client.investigate("1.2.3.4")

        assert result == {"indicator": "1.2.3.4", "indicator_type": "ip", "score": 75}

        # Verify API call
        mock_get.assert_called_once_with(
            url="https://api.test.com/investigate",
            params={"indicator": "1.2.3.4"},
            headers={"Authorization": "Bearer test_token_123"},
            timeout=30,
        )

    @patch("requests.get")
    @patch.object(Cluster25Client, "_get_token")
    def test_investigate_failure(self, mock_get_token, mock_get):
        """Test investigation failure."""
        # Mock token
        mock_get_token.return_value = "test_token_123"

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        mock_get.side_effect = requests.exceptions.RequestException("Not found")

        client = Cluster25Client(
            client_id="test_id", client_key="test_key", base_url="https://api.test.com"
        )

        result = client.investigate("1.2.3.4")

        assert "error" in result
        assert "Unable to retrieve investigate result" in result["error"]
        assert "1.2.3.4" in result["error"]


class TestCluster25Analyzer:
    """Test Cluster25Analyzer functionality."""

    def create_input_data(self, data_type="ip", data="1.2.3.4"):
        """Create test input data."""
        secrets = {"cluster25": {"client_id": "test_client_id", "client_key": "test_client_key"}}

        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            params={
                "cluster25.base_url": "https://api.test.com",
                "cluster25.timeout": 30,
                "cluster25.max_retries": 3,
            },
            secrets=secrets,
        )

        return WorkerInput(data_type=data_type, data=data, tlp=2, pap=2, config=config)

    def test_init(self):
        """Test analyzer initialization."""
        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            assert analyzer.client_id == "test_client_id"
            assert analyzer.client_key == "test_client_key"
            assert analyzer.base_url == "https://api.test.com"
            assert analyzer.timeout == 30
            assert analyzer.max_retries == 3

    def test_init_missing_client_id(self):
        """Test analyzer initialization with missing client ID."""
        secrets = {"cluster25": {"client_key": "test_client_key"}}

        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with pytest.raises(RuntimeError):
            Cluster25Analyzer(input_data)

    def test_init_missing_client_key(self):
        """Test analyzer initialization with missing client key."""
        secrets = {"cluster25": {"client_id": "test_client_id"}}

        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with pytest.raises(RuntimeError):
            Cluster25Analyzer(input_data)

    def test_init_default_config(self):
        """Test analyzer initialization with default configuration."""
        secrets = {"cluster25": {"client_id": "test_client_id", "client_key": "test_client_key"}}

        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            assert analyzer.base_url == "https://api.cluster25.com"
            assert analyzer.timeout == 30
            assert analyzer.max_retries == 3

    @patch.object(Cluster25Client, "investigate")
    def test_execute_success(self, mock_investigate):
        """Test successful execution."""
        # Mock investigation result
        mock_investigate.return_value = {
            "indicator": "1.2.3.4",
            "indicator_type": "ip",
            "score": 75,
        }

        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)
            report = analyzer.execute()

            assert report.success is True
            assert report.full_report["observable"] == "1.2.3.4"
            assert report.full_report["indicator_data"]["score"] == 75
            assert "metadata" in report.full_report
            assert "taxonomy" in report.full_report

    @patch.object(Cluster25Client, "investigate")
    def test_execute_with_error(self, mock_investigate):
        """Test execution with API error."""
        # Mock investigation error
        mock_investigate.return_value = {"error": "API rate limit exceeded"}

        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)
            report = analyzer.execute()

            assert report.success is True  # Report is successful even with API error
            assert "error" in report.full_report
            assert report.full_report["error"] == "API rate limit exceeded"

    @patch.object(Cluster25Client, "investigate")
    def test_execute_exception(self, mock_investigate):
        """Test execution with exception."""
        # Mock investigation exception
        mock_investigate.side_effect = Exception("Network error")

        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)
            report = analyzer.execute()

            assert report.success is True  # Report is successful even with exception
            assert "error" in report.full_report
            assert "Network error" in report.full_report["error"]

    def test_build_taxonomies_with_score(self):
        """Test taxonomy building with score."""
        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            indicator_data = {"indicator": "1.2.3.4", "indicator_type": "ip", "score": 75}

            taxonomies = analyzer._build_taxonomies(indicator_data)

            assert len(taxonomies) == 3

            # Check indicator taxonomy
            assert taxonomies[0].level == "info"
            assert taxonomies[0].namespace == "C25"
            assert taxonomies[0].predicate == "Indicator"
            assert taxonomies[0].value == "1.2.3.4"

            # Check indicator type taxonomy
            assert taxonomies[1].level == "info"
            assert taxonomies[1].namespace == "C25"
            assert taxonomies[1].predicate == "Indicator Type"
            assert taxonomies[1].value == "ip"

            # Check score taxonomy (suspicious level for score 75)
            assert taxonomies[2].level == "suspicious"
            assert taxonomies[2].namespace == "C25"
            assert taxonomies[2].predicate == "Score"
            assert taxonomies[2].value == "75"

    def test_build_taxonomies_score_levels(self):
        """Test taxonomy building with different score levels."""
        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            # Test safe level (score < 50)
            indicator_data = {"score": 30}
            taxonomies = analyzer._build_taxonomies(indicator_data)
            score_tax = next(t for t in taxonomies if t.predicate == "Score")
            assert score_tax.level == "safe"

            # Test suspicious level (50 <= score < 80)
            indicator_data = {"score": 60}
            taxonomies = analyzer._build_taxonomies(indicator_data)
            score_tax = next(t for t in taxonomies if t.predicate == "Score")
            assert score_tax.level == "suspicious"

            # Test malicious level (score >= 80)
            indicator_data = {"score": 90}
            taxonomies = analyzer._build_taxonomies(indicator_data)
            score_tax = next(t for t in taxonomies if t.predicate == "Score")
            assert score_tax.level == "malicious"

    def test_build_taxonomies_empty_data(self):
        """Test taxonomy building with empty data."""
        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            taxonomies = analyzer._build_taxonomies({})

            assert len(taxonomies) == 1
            assert taxonomies[0].level == "info"
            assert taxonomies[0].namespace == "C25"
            assert taxonomies[0].predicate == "Threat"
            assert taxonomies[0].value == "Not found"

    def test_create_error_report(self):
        """Test error report creation."""
        input_data = self.create_input_data()

        with patch.object(Cluster25Client, "__init__", return_value=None):
            analyzer = Cluster25Analyzer(input_data)

            report = analyzer._create_error_report("1.2.3.4", "Test error")

            assert report.success is True
            assert report.full_report["observable"] == "1.2.3.4"
            assert report.full_report["error"] == "Test error"
            assert "metadata" in report.full_report
            assert "taxonomy" in report.full_report

    def test_run(self):
        """Test run method."""
        input_data = self.create_input_data()

        with (
            patch.object(Cluster25Client, "__init__", return_value=None),
            patch.object(Cluster25Analyzer, "execute") as mock_execute,
            patch("builtins.print") as mock_print,
        ):
            mock_report = Mock()
            mock_report.full_report = {"test": "data"}
            mock_execute.return_value = mock_report

            analyzer = Cluster25Analyzer(input_data)
            result = analyzer.run()

            assert result == mock_report
            mock_execute.assert_called_once()
            mock_print.assert_called_once()

    def test_metadata(self):
        """Test analyzer metadata."""
        assert Cluster25Analyzer.METADATA.name == "Cluster25 Analyzer"
        assert Cluster25Analyzer.METADATA.pattern == "threat-intel"
        assert Cluster25Analyzer.METADATA.version_stage == "TESTING"
        assert "Cluster25" in Cluster25Analyzer.METADATA.description


class TestCluster25AnalyzerIntegration:
    """Integration tests for Cluster25Analyzer."""

    @patch("requests.get")
    @patch("requests.post")
    def test_full_workflow_success(self, mock_post, mock_get):
        """Test full workflow with successful API calls."""
        # Mock token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {"data": {"token": "test_token_123"}}
        mock_post.return_value = mock_token_response

        # Mock investigation response
        mock_investigation_response = Mock()
        mock_investigation_response.status_code = 200
        mock_investigation_response.json.return_value = {
            "data": {"indicator": "1.2.3.4", "indicator_type": "ip", "score": 85}
        }
        mock_get.return_value = mock_investigation_response

        # Create input data
        secrets = {"cluster25": {"client_id": "test_client_id", "client_key": "test_client_key"}}

        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            params={
                "cluster25.base_url": "https://api.test.com",
            },
            secrets=secrets,
        )

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2, config=config)

        # Run analyzer
        analyzer = Cluster25Analyzer(input_data)
        report = analyzer.execute()

        # Verify results
        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["indicator_data"]["score"] == 85

        # Verify taxonomy
        taxonomy = report.full_report["taxonomy"]
        score_tax = next(t for t in taxonomy if t["predicate"] == "Score")
        assert score_tax["level"] == "malicious"  # Score 85 >= 80

        # Verify API calls
        mock_post.assert_called_once()
        mock_get.assert_called_once()
