#!/usr/bin/env python3
"""Example of using SentinelIQ SDK in programmatic mode without file I/O.

This example demonstrates how to use analyzers and responders directly in code
without needing to read from files or write to files.
"""

from __future__ import annotations

from typing import cast

from sentineliqsdk import Analyzer, Responder
from sentineliqsdk.analyzers.base import TaxonomyLevel


class ReputationAnalyzer(Analyzer):
    """Example analyzer that marks specific IPs as malicious."""

    def run(self) -> None:
        observable = self.get_data()

        # Simple reputation check
        malicious_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
        verdict = cast(TaxonomyLevel, "malicious" if observable in malicious_ips else "safe")

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "confidence": 0.95 if verdict == "malicious" else 0.85,
            "taxonomy": [
                self.build_taxonomy(
                    level=verdict,
                    namespace="reputation",
                    predicate="static",
                    value=str(observable),
                )
            ],
        }

        self.report(full_report)


class BlockIpResponder(Responder):
    """Example responder that blocks IPs."""

    def run(self) -> None:
        ip = self.get_data()

        # Simulate blocking action
        result = {
            "action": "block",
            "target": ip,
            "status": "success",
            "timestamp": "2024-01-01T12:00:00Z",
            "message": f"IP {ip} has been blocked successfully",
        }

        self.report(result)


def main():
    """Demonstrate programmatic usage of SentinelIQ SDK."""
    # Example 1: Using Analyzer in programmatic mode
    print("=== Analyzer Example ===")

    # Create input data directly
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2,
        "config": {"check_tlp": True, "max_tlp": 2, "auto_extract": True},
    }

    # Create analyzer instance with input data
    analyzer = ReputationAnalyzer(input_data)

    # Run the analyzer and get result in memory
    analyzer.run()

    # Example 2: Using Responder in programmatic mode
    print("\n=== Responder Example ===")

    # Create input data for responder
    responder_input = {
        "dataType": "ip",
        "data": "5.6.7.8",
        "tlp": 2,
        "pap": 2,
        "config": {"check_tlp": True, "max_tlp": 2},
    }

    # Create responder instance with input data
    responder = BlockIpResponder(responder_input)

    # Run the responder and get result in memory
    responder.run()

    # Example 3: Getting results in memory without writing to files
    print("\n=== In-Memory Results Example ===")

    # Create analyzer for in-memory processing
    analyzer_memory = ReputationAnalyzer(input_data)

    # Get the result directly in memory
    observable = analyzer_memory.get_data()
    malicious_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
    verdict = cast(TaxonomyLevel, "malicious" if observable in malicious_ips else "safe")

    full_report = {
        "observable": observable,
        "verdict": verdict,
        "confidence": 0.95 if verdict == "malicious" else 0.85,
        "taxonomy": [
            analyzer_memory.build_taxonomy(
                level=verdict,
                namespace="reputation",
                predicate="static",
                value=str(observable),
            )
        ],
    }

    # Get result in memory
    result = analyzer_memory.report(full_report)
    print(f"Analyzer result: {result}")

    # Example 4: Batch processing multiple observables
    print("\n=== Batch Processing Example ===")

    observables = ["1.2.3.4", "8.8.8.8", "5.6.7.8", "1.1.1.1"]
    results = []

    for obs in observables:
        batch_input = {
            "dataType": "ip",
            "data": obs,
            "tlp": 2,
            "pap": 2,
            "config": {"auto_extract": True},
        }

        batch_analyzer = ReputationAnalyzer(batch_input)
        observable = batch_analyzer.get_data()
        malicious_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
        verdict = cast(TaxonomyLevel, "malicious" if observable in malicious_ips else "safe")

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "confidence": 0.95 if verdict == "malicious" else 0.85,
        }

        result = batch_analyzer.report(full_report)
        results.append(result)

    print(f"Processed {len(results)} observables:")
    for i, result in enumerate(results):
        print(f"  {i + 1}. {result['full']['observable']}: {result['full']['verdict']}")


if __name__ == "__main__":
    main()
