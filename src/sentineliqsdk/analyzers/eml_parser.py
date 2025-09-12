"""EML Parser Analyzer: parse and analyze EML email files.

Features:
- Accepts `data_type == "file"` and parses EML email files.
- Extracts headers, body, attachments, URLs, and authentication information.
- Provides comprehensive email analysis including SPF, DKIM, and DMARC validation.
- Supports both text and HTML email content parsing.

Configuration:
- No API keys required - uses local parsing.
- Optional configuration for parsing depth and feature extraction.

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.eml_parser import EmlParserAnalyzer

    inp = WorkerInput(
        data_type="file",
        data="path/to/email.eml",
        filename="suspicious_email.eml",
        config=WorkerConfig(),
    )
    report = EmlParserAnalyzer(inp).execute()
"""

from __future__ import annotations

import os
from typing import Any

try:
    import eml_parser  # type: ignore[import-untyped]
except ImportError:
    eml_parser = None  # type: ignore[assignment]

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel


class EmlParserAnalyzer(Analyzer):
    """Analyzer that parses EML email files and extracts comprehensive information."""

    METADATA = ModuleMetadata(
        name="EML Parser Analyzer",
        description="Parse and analyze EML email files with comprehensive feature extraction",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/eml_parser/",
        version_stage="TESTING",
    )

    def _check_dependencies(self) -> None:
        """Check if eml_parser library is available."""
        if eml_parser is None:
            self.error(
                "eml_parser library is not installed. Install it with: pip install eml-parser"
            )

    def _parse_eml_file(self, file_path: str) -> dict[str, Any]:
        """Parse EML file and extract all information."""
        try:
            with open(file_path, "rb") as f:
                raw_email = f.read()

            # Parse email with eml_parser
            ep = eml_parser.EmlParser()
            parsed_email = ep.decode_email_bytes(raw_email)

            return parsed_email
        except Exception as exc:
            self.error(f"Failed to parse EML file: {exc}")

    def _extract_urls(self, parsed_email: dict[str, Any]) -> list[str]:
        """Extract URLs from parsed email."""
        urls = []

        # Extract from body
        if "body" in parsed_email:
            for body_part in parsed_email["body"]:
                if "content" in body_part:
                    content = body_part["content"]
                    # Simple URL extraction (could be enhanced with regex)
                    if "http" in content:
                        import re

                        url_pattern = r'https?://[^\s<>"]+'
                        found_urls = re.findall(url_pattern, content)
                        urls.extend(found_urls)

        # Extract from header URLs if available
        if "header" in parsed_email and "received" in parsed_email["header"]:
            for received in parsed_email["header"]["received"]:
                if "by" in received:
                    # Extract potential URLs from received headers
                    pass

        return list(set(urls))  # Remove duplicates

    def _extract_attachments_info(self, parsed_email: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract attachment information."""
        attachments = []

        if "attachment" in parsed_email:
            for attachment in parsed_email["attachment"]:
                att_info = {
                    "filename": attachment.get("filename", "unknown"),
                    "content_type": attachment.get("content_type", "unknown"),
                    "size": len(attachment.get("raw", b"")),
                    "hash": attachment.get("hash", {}),
                }
                attachments.append(att_info)

        return attachments

    def _analyze_authentication(self, parsed_email: dict[str, Any]) -> dict[str, Any]:
        """Analyze email authentication (SPF, DKIM, DMARC)."""
        auth_info: dict[str, str] = {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
        }

        if "header" in parsed_email:
            headers = parsed_email["header"]

            # Check for authentication results
            if "authentication-results" in headers:
                auth_results = headers["authentication-results"]
                if isinstance(auth_results, list):
                    for result in auth_results:
                        if "spf=" in result.lower():
                            auth_info["spf"] = "pass" if "spf=pass" in result.lower() else "fail"
                        if "dkim=" in result.lower():
                            auth_info["dkim"] = "pass" if "dkim=pass" in result.lower() else "fail"
                        if "dmarc=" in result.lower():
                            auth_info["dmarc"] = (
                                "pass" if "dmarc=pass" in result.lower() else "fail"
                            )

            # Check individual headers
            if "received-spf" in headers:
                spf_result = headers["received-spf"]
                auth_info["spf"] = "pass" if "pass" in spf_result.lower() else "fail"

        return auth_info

    def _determine_verdict(
        self,
        parsed_email: dict[str, Any],
        urls: list[str],
        attachments: list[dict[str, Any]],
        auth_info: dict[str, Any],
    ) -> TaxonomyLevel:
        """Determine the overall verdict based on analysis."""
        # Start with safe assumption
        verdict: TaxonomyLevel = "safe"

        # Check for suspicious indicators
        suspicious_indicators = 0

        # Check authentication failures
        auth_failures = sum(1 for result in auth_info.values() if result == "fail")
        if auth_failures >= 2:
            suspicious_indicators += 1

        # Check for multiple URLs (potential phishing)
        if len(urls) > 5:
            suspicious_indicators += 1

        # Check for executable attachments
        dangerous_extensions = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"]
        for attachment in attachments:
            filename = attachment.get("filename", "").lower()
            if any(filename.endswith(ext) for ext in dangerous_extensions):
                suspicious_indicators += 2  # Executable attachments are more suspicious

        # Check for suspicious subject patterns
        if "header" in parsed_email and "subject" in parsed_email["header"]:
            subject = parsed_email["header"]["subject"].lower()
            suspicious_keywords = ["urgent", "verify", "suspended", "click here", "act now"]
            if any(keyword in subject for keyword in suspicious_keywords):
                suspicious_indicators += 1

        # Determine final verdict
        if suspicious_indicators >= 3:
            verdict = "malicious"
        elif suspicious_indicators >= 1:
            verdict = "suspicious"

        return verdict

    def execute(self) -> AnalyzerReport:
        """Execute the EML parsing analysis."""
        self._check_dependencies()

        dtype = self.data_type
        observable = self.get_data()

        if dtype != "file":
            self.error(f"EmlParserAnalyzer only supports file data type, got: {dtype}")

        # Get file path
        file_path = str(observable)
        if not os.path.exists(file_path):
            filename = getattr(self, "filename", None) or os.path.basename(file_path)
            self.error(f"EML file not found: {filename}")

        # Parse the EML file
        parsed_email = self._parse_eml_file(file_path)

        # Extract additional information
        urls = self._extract_urls(parsed_email)
        attachments = self._extract_attachments_info(parsed_email)
        auth_info = self._analyze_authentication(parsed_email)

        # Determine verdict
        verdict = self._determine_verdict(parsed_email, urls, attachments, auth_info)

        # Build taxonomies
        taxonomies = []

        # Main verdict taxonomy
        taxonomies.append(
            self.build_taxonomy(verdict, "eml_parser", "analysis", str(observable)).to_dict()
        )

        # Authentication taxonomy
        for auth_type, result in auth_info.items():
            if result:
                level: TaxonomyLevel = "safe" if result == "pass" else "suspicious"
                taxonomies.append(
                    self.build_taxonomy(level, "eml_parser", f"auth_{auth_type}", result).to_dict()
                )

        # URLs taxonomy
        if urls:
            url_level: TaxonomyLevel = "suspicious" if len(urls) > 5 else "info"
            taxonomies.append(
                self.build_taxonomy(url_level, "eml_parser", "urls_count", str(len(urls))).to_dict()
            )

        # Attachments taxonomy
        if attachments:
            att_level: TaxonomyLevel = "info"
            dangerous_extensions = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"]
            for attachment in attachments:
                filename = attachment.get("filename", "").lower()
                if any(filename.endswith(ext) for ext in dangerous_extensions):
                    att_level = "suspicious"
                    break

            taxonomies.append(
                self.build_taxonomy(
                    att_level, "eml_parser", "attachments_count", str(len(attachments))
                ).to_dict()
            )

        # Prepare detailed results
        details = {
            "parsed_email": parsed_email,
            "extracted_urls": urls,
            "attachments_info": attachments,
            "authentication_info": auth_info,
            "file_path": file_path,
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        }

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": taxonomies,
            "source": "eml_parser",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
