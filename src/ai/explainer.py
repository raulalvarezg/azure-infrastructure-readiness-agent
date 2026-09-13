"""Human-readable explanation generation.

This module does not call any external LLM/AI service (to keep the agent
self-contained and testable offline). Instead it implements a lightweight,
deterministic "AI-style" natural language generator that turns structured
:class:`~src.models.Issue` objects into human-readable explanations and
narrative summaries. The interface is intentionally decoupled so a real
LLM-backed implementation could be swapped in later without touching the
rule engine or CLI.
"""

from __future__ import annotations

from typing import List

from src.models import Issue, Severity

_SEVERITY_NARRATIVE = {
    Severity.CRITICAL: "This is a critical issue that will very likely cause the deployment to fail or result in an outage.",
    Severity.HIGH: "This is a high severity issue that puts reliability or security at significant risk.",
    Severity.MEDIUM: "This is a moderate issue that should be addressed before going to production.",
    Severity.LOW: "This is a minor issue that represents a best-practice improvement.",
    Severity.INFO: "This is an informational note for your awareness.",
}


def explain_issue(issue: Issue) -> str:
    """Produce a human-readable, multi-sentence explanation for a single issue."""

    narrative = _SEVERITY_NARRATIVE.get(issue.severity, "")
    parts = [
        f"[{issue.severity.value.upper()}] {issue.message}",
        narrative,
        f"Recommended action: {issue.recommendation}",
    ]
    return " ".join(part for part in parts if part)


def explain_issues(issues: List[Issue]) -> List[str]:
    """Produce human-readable explanations for a list of issues."""

    return [explain_issue(issue) for issue in issues]


def summarize(issues: List[Issue]) -> str:
    """Produce a short narrative summary describing the overall state of the deployment."""

    if not issues:
        return (
            "No issues were detected. The deployment configuration follows Azure, "
            "Linux HA, and SAP HA best practices."
        )

    counts = {severity: 0 for severity in Severity}
    for issue in issues:
        counts[issue.severity] += 1

    ordered = [severity for severity in Severity if counts[severity]]
    count_phrases = [f"{counts[severity]} {severity.value}" for severity in ordered]

    total = len(issues)
    plural = "issue" if total == 1 else "issues"
    return (
        f"Found {total} {plural} across the deployment ({', '.join(count_phrases)}). "
        "Review the detailed findings below before proceeding to production."
    )
