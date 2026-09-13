"""Deployment readiness assessment engine.

Combines YAML validation, rule evaluation, and human-readable explanation
generation into a single high-level API used by the CLI (and reusable by
any other integration).
"""

from __future__ import annotations

from typing import List

from src.ai.explainer import explain_issues, summarize
from src.models import Issue, ReadinessAssessment, ReadinessStatus, Severity
from src.rules.azure_rules import default_azure_rules
from src.rules.base import RuleSet
from src.rules.linux_ha_rules import default_linux_ha_rules
from src.rules.sap_ha_rules import default_sap_ha_rules
from src.validators.yaml_validator import validate_structure, validate_yaml_syntax

# Deducted from a starting score of 100 for each issue, based on severity.
_SEVERITY_PENALTY = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


def build_default_rule_set() -> RuleSet:
    """Build the rule set containing every built-in rule module."""

    rules = default_azure_rules() + default_linux_ha_rules() + default_sap_ha_rules()
    return RuleSet(rules)


def compute_score(issues: List[Issue]) -> int:
    """Compute a 0-100 readiness score based on the severity of found issues."""

    score = 100
    for issue in issues:
        score -= _SEVERITY_PENALTY.get(issue.severity, 0)
    return max(score, 0)


def determine_status(issues: List[Issue]) -> ReadinessStatus:
    """Determine the overall readiness status from the list of issues."""

    if any(issue.severity == Severity.CRITICAL for issue in issues):
        return ReadinessStatus.NOT_READY
    if any(issue.severity in (Severity.HIGH, Severity.MEDIUM) for issue in issues):
        return ReadinessStatus.READY_WITH_WARNINGS
    return ReadinessStatus.READY


def assess_deployment(content: str, rule_set: RuleSet = None) -> ReadinessAssessment:
    """Run the full pipeline (syntax -> structure -> rules -> explanations).

    ``content`` is the raw YAML text of the deployment file. Returns a
    :class:`ReadinessAssessment` describing the outcome even when the YAML
    itself is invalid (in which case ``status`` is ``NOT_READY``).
    """

    rule_set = rule_set or build_default_rule_set()

    syntax_result = validate_yaml_syntax(content)
    if not syntax_result.valid:
        issue = Issue(
            rule_id="yaml-syntax-000",
            category="syntax",
            severity=Severity.CRITICAL,
            message=f"Invalid YAML syntax: {syntax_result.error}",
            recommendation="Fix the YAML syntax error and re-run the assessment.",
        )
        return ReadinessAssessment(
            status=ReadinessStatus.NOT_READY,
            score=0,
            issues=[issue],
            summary=summarize([issue]),
            explanations=explain_issues([issue]),
        )

    structure_result = validate_structure(syntax_result.data)
    if not structure_result.valid:
        issue = Issue(
            rule_id="yaml-structure-001",
            category="syntax",
            severity=Severity.CRITICAL,
            message=structure_result.error,
            recommendation="Ensure the YAML document defines a top-level mapping with deployment configuration.",
        )
        return ReadinessAssessment(
            status=ReadinessStatus.NOT_READY,
            score=0,
            issues=[issue],
            summary=summarize([issue]),
            explanations=explain_issues([issue]),
        )

    deployment = structure_result.data
    issues = rule_set.evaluate(deployment)
    issues.sort(key=lambda issue: issue.severity.rank, reverse=True)

    return ReadinessAssessment(
        status=determine_status(issues),
        score=compute_score(issues),
        issues=issues,
        summary=summarize(issues),
        explanations=explain_issues(issues),
    )


def assess_deployment_file(path: str, rule_set: RuleSet = None) -> ReadinessAssessment:
    """Run :func:`assess_deployment` against a YAML file on disk."""

    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    return assess_deployment(content, rule_set=rule_set)
