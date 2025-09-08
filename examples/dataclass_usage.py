#!/usr/bin/env python3
"""Advanced example showing SentinelIQ SDK dataclass usage.

This example demonstrates the new dataclass-based API and how it provides
better type safety and developer experience compared to JSON dictionaries.
"""

from __future__ import annotations

from typing import cast

from sentineliqsdk import (
    Analyzer,
    Artifact,
    Operation,
    ProxyConfig,
    Responder,
    TaxonomyEntry,
    TaxonomyLevel,
    WorkerConfig,
    WorkerInput,
)


class AdvancedAnalyzer(Analyzer):
    """Advanced analyzer example using dataclasses."""

    def run(self):
        """Run the advanced analyzer to analyze the observable."""
        observable = self.get_data()

        # Simple reputation check
        malicious_ips = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
        verdict = cast(TaxonomyLevel, "malicious" if observable in malicious_ips else "safe")

        # Build taxonomy using dataclass
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="reputation",
            predicate="static",
            value=str(observable),
        )

        # Build artifacts using dataclass
        artifacts = [
            self.build_artifact("ip", "8.8.8.8", tlp=2, pap=2),
            self.build_artifact("domain", "example.com", confidence=0.9),
        ]

        # Build operations using dataclass
        operations = [
            self.build_operation("hunt", target=observable, priority="high"),
            self.build_operation("investigate", source="reputation_check"),
        ]

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "confidence": 0.95 if verdict == "malicious" else 0.85,
            "taxonomy": [taxonomy],
            "artifacts": artifacts,
            "operations": operations,
        }

        return self.report(full_report)


class AdvancedResponder(Responder):
    """Advanced responder example using dataclasses."""

    def run(self):
        """Run the advanced responder to block the IP."""
        ip = self.get_data()

        # Build operations using dataclass
        operations = [
            self.build_operation("block", target=ip, duration="24h"),
            self.build_operation("alert", severity="high", message=f"Blocked IP {ip}"),
        ]

        result = {
            "action": "block",
            "target": ip,
            "status": "success",
            "timestamp": "2024-01-01T12:00:00Z",
            "message": f"IP {ip} has been blocked successfully",
            "operations": operations,
        }

        return self.report(result)


def demonstrate_dataclass_features():
    """Demonstrate various dataclass features."""
    print("=== Dataclass Features Demo ===")

    # 1. Creating WorkerInput with different configurations
    print("\n1. WorkerInput configurations:")

    # Basic input
    basic_input = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)
    print(f"Basic input: {basic_input}")

    # Input with custom config
    custom_config = WorkerConfig(
        check_tlp=True,
        max_tlp=3,
        check_pap=True,
        max_pap=3,
        auto_extract=True,
        proxy=ProxyConfig(http="http://proxy:8080", https="https://proxy:8080"),
    )
    advanced_input = WorkerInput(
        data_type="url", data="https://example.com", tlp=3, pap=3, config=custom_config
    )
    print(f"Advanced input: {advanced_input}")

    # 2. Creating taxonomy entries
    print("\n2. Taxonomy entries:")
    taxonomy = TaxonomyEntry(
        level="malicious", namespace="reputation", predicate="static", value="1.2.3.4"
    )
    print(f"Taxonomy: {taxonomy}")

    # 3. Creating artifacts
    print("\n3. Artifacts:")
    artifact = Artifact(
        data_type="ip", data="8.8.8.8", tlp=2, pap=2, extra={"confidence": 0.9, "source": "dns"}
    )
    print(f"Artifact: {artifact}")

    # 4. Creating operations
    print("\n4. Operations:")
    operation = Operation(
        operation_type="hunt", parameters={"target": "1.2.3.4", "priority": "high"}
    )
    print(f"Operation: {operation}")


def main():
    """Demonstrate the SentinelIQ SDK dataclass usage examples."""
    print("SentinelIQ SDK Dataclass Usage Examples")
    print("=" * 50)

    # Demonstrate dataclass features
    demonstrate_dataclass_features()

    # Run analyzer example
    print("\n=== Running Analyzer Example ===")
    input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)

    analyzer = AdvancedAnalyzer(input_data)
    analyzer.run()

    # Run responder example
    print("\n=== Running Responder Example ===")
    responder_input = WorkerInput(data_type="ip", data="5.6.7.8", tlp=2, pap=2)

    responder = AdvancedResponder(responder_input)
    responder.run()

    print("\n=== Benefits of Dataclasses ===")
    print("✓ Type safety at development time")
    print("✓ Better IDE support with autocomplete")
    print("✓ Immutable data structures")
    print("✓ Clear data contracts")
    print("✓ Modern Python API")


if __name__ == "__main__":
    main()
