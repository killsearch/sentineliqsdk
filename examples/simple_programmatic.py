#!/usr/bin/env python3
"""Simple example of using SentinelIQ SDK without file I/O."""

from __future__ import annotations

from typing import cast

from sentineliqsdk import Analyzer, TaxonomyLevel, WorkerInput


class SimpleAnalyzer(Analyzer):
    """Simple analyzer example."""

    def run(self) -> None:
        """Run the simple analyzer to check if the IP is malicious."""
        observable = self.get_data()

        # Simple analysis logic
        if observable == "1.2.3.4":
            verdict = cast(TaxonomyLevel, "malicious")
        else:
            verdict = cast(TaxonomyLevel, "safe")

        full_report = {
            "observable": observable,
            "verdict": verdict,
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


def main():
    """Demonstrate simple programmatic usage of the SentinelIQ SDK."""
    # Create input data using dataclass (no file needed)
    input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)

    # Create analyzer with input data
    analyzer = SimpleAnalyzer(input_data)

    # Run and get result in memory
    observable = analyzer.get_data()
    verdict = cast(TaxonomyLevel, "malicious" if observable == "1.2.3.4" else "safe")

    taxonomy = analyzer.build_taxonomy(
        level=verdict,
        namespace="reputation",
        predicate="static",
        value=str(observable),
    )

    full_report = {
        "observable": observable,
        "verdict": verdict,
        "taxonomy": [taxonomy],
    }

    # Get result in memory
    result = analyzer.report(full_report)
    print(f"Result: {result}")


if __name__ == "__main__":
    main()
