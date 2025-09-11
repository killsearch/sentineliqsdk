"""AutoFocus Analyzer: query Palo Alto Networks AutoFocus for threat intelligence.

Features:
- Supports multiple data types: ip, domain, fqdn, hash, url, user-agent, mutex, imphash, tag
- Two main services: get_sample_analysis (for hashes) and search_ioc (for other types)
- Returns detailed metadata, tags, and analysis results from AutoFocus
- Builds taxonomy based on search results and sample findings

Configuration (dataclasses only):
- API key via `WorkerConfig.secrets['autofocus']['apikey']`.
- Service type via `WorkerConfig.params['autofocus']['service']`
  (get_sample_analysis or search_ioc).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

    inp = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(
            secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
            params={"autofocus": {"service": "search_ioc"}}
        ),
    )
    report = AutoFocusAnalyzer(inp).execute()
"""

from __future__ import annotations

from typing import Any

try:
    from autofocus import AFClientError, AFSample, AFSampleAbsent, AFServerError, AutoFocusAPI
except ImportError:
    AFClientError = Exception
    AFSample = None
    AFSampleAbsent = Exception
    AFServerError = Exception
    AutoFocusAPI = None

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel


class AutoFocusAnalyzer(Analyzer):
    """Analyzer for Palo Alto Networks AutoFocus threat intelligence platform."""

    METADATA = ModuleMetadata(
        name="AutoFocus Analyzer",
        description="Query Palo Alto Networks AutoFocus for threat intelligence and sample analysis",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/autofocus/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        """Execute AutoFocus analysis based on data type and service configuration."""
        if AutoFocusAPI is None:
            self.error("autofocus library not installed. Install with: pip install autofocus")

        observable = self.get_data()
        data_type = self.data_type

        # Get configuration
        apikey = self.get_secret("autofocus.apikey", message="AutoFocus API key required")
        service = self.get_config("autofocus.service", "search_ioc")

        # Set API key
        AutoFocusAPI.api_key = apikey

        try:
            if service == "get_sample_analysis" and data_type in ["hash"]:
                result = self._get_sample_analysis(observable)
            elif service == "search_ioc":
                result = self._search_ioc(observable, data_type)
            elif service == "search_json" and data_type == "other":
                result = self._search_json(observable)
            else:
                self.error(
                    f"Unknown AutoFocus service '{service}' or invalid data type '{data_type}'"
                )

            # Build taxonomy
            taxonomy = self._build_taxonomy(result)

            full_report = {
                "observable": observable,
                "data_type": data_type,
                "service": service,
                "result": result,
                "taxonomy": [taxonomy.to_dict()],
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

        except AFSampleAbsent:
            self.error("Sample not found in AutoFocus")
        except AFServerError as e:
            self.error(f"AutoFocus server error: {e}")
        except AFClientError as e:
            self.error(f"AutoFocus client error: {e}")
        except Exception as e:
            self.error(f"Unknown error while running AutoFocus analyzer: {e}")

    def _get_sample_analysis(self, hash_value: str) -> dict[str, Any]:
        """Get detailed analysis for a hash sample."""
        sample = AFSample.get(hash_value)
        result = {
            "metadata": sample.serialize(),
            "tags": [tag.serialize() for tag in sample.__getattribute__("tags")],
            "analysis": {},
        }

        for analysis in sample.get_analyses():
            analysis_type = analysis.__class__.__name__
            if analysis_type not in result["analysis"]:
                result["analysis"][analysis_type] = []
            result["analysis"][analysis_type].append(analysis.serialize())

        return result

    def _search_ioc(self, observable: str, data_type: str) -> dict[str, Any]:
        """Search for IOC in AutoFocus based on data type."""
        search_classes = {
            "ip": self._SearchJsonIp,
            "domain": self._SearchJsonDomain,
            "fqdn": self._SearchJsonDomain,
            "url": self._SearchJsonUrl,
            "user-agent": self._SearchJsonUserAgent,
        }

        if data_type not in search_classes:
            self.error(f"Unsupported data type for search_ioc: {data_type}")

        search_instance = search_classes[data_type](observable)
        return search_instance.do_search()

    def _search_json(self, search_query: str) -> dict[str, Any]:
        """Search using custom JSON query."""
        search_instance = self._SearchJson(search_query)
        return search_instance.do_search()

    def _build_taxonomy(self, result: dict[str, Any]) -> Any:
        """Build taxonomy entry based on search results."""
        level: TaxonomyLevel = "info"
        namespace = "PaloAltoNetworks"
        predicate = "AutoFocus"

        if "metadata" in result:
            value = "Sample found"
        elif "records" in result:
            record_count = len(result["records"])
            value = f"{record_count} sample(s) found"
            if record_count > 0:
                level = "suspicious"
        else:
            value = "No results"

        return self.build_taxonomy(level, namespace, predicate, value)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()

    # Search classes for different IOC types
    class _SearchJson:
        """Base class for AutoFocus search queries."""

        def __init__(self, search: str | dict[str, Any] = ""):
            self.search = search

        def do_search(self) -> dict[str, Any]:
            """Execute the search and return results."""
            res = [
                {
                    "metadata": sample.serialize(),
                    "tags": [tag.serialize() for tag in sample.__getattribute__("tags")],
                }
                for sample in AFSample.search(self.search)
            ]
            return {"search": self.search, "records": res}

    class _SearchJsonIp(_SearchJson):
        """Search for IP addresses."""

        def __init__(self, value: str):
            self.search = {
                "operator": "all",
                "children": [{"field": "alias.ip_address", "operator": "contains", "value": value}],
            }

    class _SearchJsonDomain(_SearchJson):
        """Search for domains."""

        def __init__(self, value: str):
            self.search = {
                "operator": "all",
                "children": [{"field": "alias.domain", "operator": "contains", "value": value}],
            }

    class _SearchJsonUrl(_SearchJson):
        """Search for URLs."""

        def __init__(self, value: str):
            self.search = {
                "operator": "all",
                "children": [
                    {"field": "sample.tasks.http", "operator": "is in the list", "value": [value]}
                ],
            }

    class _SearchJsonUserAgent(_SearchJson):
        """Search for user agents."""

        def __init__(self, value: str):
            self.search = {
                "operator": "all",
                "children": [{"field": "alias.user_agent", "operator": "contains", "value": value}],
            }
