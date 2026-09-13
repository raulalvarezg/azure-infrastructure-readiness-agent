"""Command line interface for the Azure Infrastructure Readiness Agent."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from src.ai.assessment import assess_deployment_file
from src.models import ReadinessAssessment, ReadinessStatus, Severity

_STATUS_EXIT_CODES = {
    ReadinessStatus.READY: 0,
    ReadinessStatus.READY_WITH_WARNINGS: 0,
    ReadinessStatus.NOT_READY: 1,
}

_STATUS_LABELS = {
    ReadinessStatus.READY: "READY",
    ReadinessStatus.READY_WITH_WARNINGS: "READY WITH WARNINGS",
    ReadinessStatus.NOT_READY: "NOT READY",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="readiness-agent",
        description=(
            "AI-powered Azure Infrastructure Readiness Agent: validates YAML deployment "
            "files, detects Azure/Linux HA/SAP HA risks, and generates a readiness assessment."
        ),
    )
    parser.add_argument("file", help="Path to the YAML deployment file to assess.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for the assessment report (default: text).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with a non-zero status code if the deployment is not fully READY.",
    )
    return parser


def render_text_report(assessment: ReadinessAssessment) -> str:
    lines: List[str] = []
    label = _STATUS_LABELS[assessment.status]
    lines.append("=" * 60)
    lines.append("Azure Infrastructure Readiness Assessment")
    lines.append("=" * 60)
    lines.append(f"Status: {label}")
    lines.append(f"Score:  {assessment.score}/100")
    lines.append("")
    lines.append(assessment.summary)

    if assessment.issues:
        lines.append("")
        lines.append("Findings:")
        for index, issue in enumerate(assessment.issues, start=1):
            lines.append(
                f"  {index}. [{issue.severity.value.upper()}] ({issue.rule_id}) {issue.message}"
            )
            lines.append(f"     Recommendation: {issue.recommendation}")
    return "\n".join(lines)


def render_json_report(assessment: ReadinessAssessment) -> str:
    return json.dumps(assessment.to_dict(), indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        assessment = assess_deployment_file(args.file)
    except OSError as exc:
        print(f"Error: could not read file '{args.file}': {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(render_json_report(assessment))
    else:
        print(render_text_report(assessment))

    if args.strict:
        return 0 if assessment.status == ReadinessStatus.READY else 1
    return _STATUS_EXIT_CODES[assessment.status]


if __name__ == "__main__":
    sys.exit(main())
