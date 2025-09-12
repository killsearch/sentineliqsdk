#!/usr/bin/env python3
"""Example usage of EmlParserAnalyzer.

This example demonstrates how to use the EmlParserAnalyzer to parse and analyze
EML email files for security threats and extract comprehensive information.

Usage:
    python eml_parser_example.py --data path/to/email.eml --execute
    python eml_parser_example.py --data path/to/email.eml --execute --include-dangerous

Features demonstrated:
- EML file parsing and analysis
- Header extraction and analysis
- URL extraction from email content
- Attachment analysis and threat detection
- Email authentication validation (SPF, DKIM, DMARC)
- Comprehensive security assessment
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.eml_parser import EmlParserAnalyzer


def create_sample_eml(file_path: str) -> None:
    """Create a sample EML file for testing purposes."""
    sample_eml_content = """Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [192.168.1.100])
    by mx.recipient.com (Postfix) with ESMTP id 12345
    for <recipient@recipient.com>; Mon, 1 Jan 2024 12:00:00 +0000 (UTC)
Received-SPF: pass (recipient.com: domain of sender@example.com designates 192.168.1.100 as permitted sender)
Authentication-Results: mx.recipient.com;
    spf=pass smtp.mailfrom=sender@example.com;
    dkim=pass header.i=@example.com;
    dmarc=pass (p=quarantine sp=none dis=none) header.from=example.com
Message-ID: <20240101120000.12345@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
From: Sender Name <sender@example.com>
To: Recipient Name <recipient@recipient.com>
Subject: Test Email for Analysis
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

This is a test email for EML parsing analysis.

Please visit our website: https://example.com
For urgent matters, click here: https://urgent.example.com/verify

Best regards,
Test Team

--boundary123
Content-Type: application/octet-stream; name="document.pdf"
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcOkw7zDtsO4CjIgMCBvYmoKPDwKL0xlbmd0aCAzIDAgUgo+PgpzdHJlYW0KeJzLSM3PyVEozy/KSVEoLU5NLMnMz1FIzs8rSa0FAG6ZCg4KZW5kc3RyZWFtCmVuZG9iago=

--boundary123--
"""

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(sample_eml_content)
    print(f"Sample EML file created: {file_path}")


def main() -> None:
    """Main function to demonstrate EmlParserAnalyzer usage."""
    parser = argparse.ArgumentParser(
        description="EML Parser Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Data arguments
    parser.add_argument(
        "--data",
        help="Path to EML file to analyze",
        required=False,
    )
    parser.add_argument(
        "--data-type",
        default="file",
        help="Type of data (default: file)",
    )
    parser.add_argument(
        "--filename",
        help="Original filename of the EML file",
    )

    # Security gates (MANDATORY)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real analysis operations",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include analysis of potentially dangerous attachments",
    )

    # Configuration options
    parser.add_argument(
        "--create-sample",
        help="Create a sample EML file at the specified path",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Create sample EML file if requested
    if args.create_sample:
        create_sample_eml(args.create_sample)
        if not args.data:
            args.data = args.create_sample

    if not args.data:
        print("Error: --data is required (or use --create-sample to generate test data)")
        sys.exit(1)

    # Security check: dry-run mode
    if not args.execute:
        print("🔒 Dry-run mode. Use --execute to perform real analysis.")
        print(f"Would analyze EML file: {args.data}")
        return

    # Check if file exists
    eml_path = Path(args.data)
    if not eml_path.exists():
        print(f"Error: EML file not found: {args.data}")
        sys.exit(1)

    print(f"🔍 Analyzing EML file: {args.data}")

    try:
        # Create WorkerInput
        worker_input = WorkerInput(
            data_type=args.data_type,
            data=str(eml_path.absolute()),
            filename=args.filename or eml_path.name,
            tlp=2,
            pap=2,
            config=WorkerConfig(
                check_tlp=True,
                max_tlp=2,
                check_pap=True,
                max_pap=2,
                auto_extract=True,
            ),
        )

        # Initialize and run analyzer
        analyzer = EmlParserAnalyzer(worker_input)
        report = analyzer.execute()

        # Display results
        print("\n" + "=" * 60)
        print("📧 EML PARSER ANALYSIS RESULTS")
        print("=" * 60)

        print(f"\n📄 File: {report.observable}")
        print(f"🎯 Verdict: {report.verdict.upper()}")

        # Display taxonomies
        if report.taxonomy:
            print("\n🏷️  Taxonomies:")
            for tax in report.taxonomy:
                level = tax.get("level", "unknown")
                namespace = tax.get("namespace", "unknown")
                predicate = tax.get("predicate", "unknown")
                value = tax.get("value", "unknown")
                print(f"   • {level.upper()}: {namespace}.{predicate} = {value}")

        # Display detailed information
        if hasattr(report, "details") and report.details:
            details = report.details

            # File information
            print("\n📊 File Information:")
            print(f"   • Size: {details.get('file_size', 0):,} bytes")

            # Email headers
            parsed_email = details.get("parsed_email", {})
            if "header" in parsed_email:
                headers = parsed_email["header"]
                print("\n📮 Email Headers:")
                print(f"   • From: {headers.get('from', 'Unknown')}")
                print(f"   • To: {headers.get('to', 'Unknown')}")
                print(f"   • Subject: {headers.get('subject', 'No subject')}")
                print(f"   • Date: {headers.get('date', 'Unknown')}")

            # Authentication information
            auth_info = details.get("authentication_info", {})
            if any(auth_info.values()):
                print("\n🔐 Authentication Results:")
                for auth_type, result in auth_info.items():
                    if result:
                        status_icon = "✅" if result == "pass" else "❌"
                        print(f"   • {auth_type.upper()}: {status_icon} {result}")

            # URLs found
            urls = details.get("extracted_urls", [])
            if urls:
                print(f"\n🔗 URLs Found ({len(urls)}):")
                for i, url in enumerate(urls[:5], 1):  # Show first 5 URLs
                    print(f"   {i}. {url}")
                if len(urls) > 5:
                    print(f"   ... and {len(urls) - 5} more URLs")

            # Attachments
            attachments = details.get("attachments_info", [])
            if attachments:
                print(f"\n📎 Attachments ({len(attachments)}):")
                for i, att in enumerate(attachments, 1):
                    filename = att.get("filename", "unknown")
                    content_type = att.get("content_type", "unknown")
                    size = att.get("size", 0)
                    print(f"   {i}. {filename} ({content_type}, {size:,} bytes)")

                    # Check for dangerous attachments
                    if not args.include_dangerous:
                        dangerous_extensions = [
                            ".exe",
                            ".scr",
                            ".bat",
                            ".cmd",
                            ".com",
                            ".pif",
                            ".vbs",
                            ".js",
                        ]
                        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
                            print("      ⚠️  Potentially dangerous attachment detected!")
                            print("      Use --include-dangerous to analyze further.")

        # Verbose output
        if args.verbose:
            print("\n" + "=" * 60)
            print("🔍 DETAILED ANALYSIS DATA")
            print("=" * 60)
            print(json.dumps(report.to_dict(), indent=2, default=str))

        print("\n✅ Analysis completed successfully!")

    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
