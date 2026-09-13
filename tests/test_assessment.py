import unittest

from src.ai.assessment import assess_deployment, compute_score, determine_status
from src.models import Issue, ReadinessStatus, Severity
from tests.helpers import read_sample


class AssessDeploymentTests(unittest.TestCase):
    def test_invalid_syntax_yields_not_ready(self):
        assessment = assess_deployment(read_sample("invalid_syntax.yaml"))
        self.assertEqual(assessment.status, ReadinessStatus.NOT_READY)
        self.assertEqual(assessment.score, 0)
        self.assertEqual(len(assessment.issues), 1)
        self.assertEqual(assessment.issues[0].rule_id, "yaml-syntax-000")

    def test_non_mapping_document_yields_not_ready(self):
        assessment = assess_deployment("- just\n- a\n- list\n")
        self.assertEqual(assessment.status, ReadinessStatus.NOT_READY)
        self.assertEqual(assessment.issues[0].rule_id, "yaml-structure-001")

    def test_valid_deployment_yields_ready(self):
        assessment = assess_deployment(read_sample("valid_sap_ha_deployment.yaml"))
        self.assertEqual(assessment.status, ReadinessStatus.READY)
        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.issues, [])

    def test_risky_azure_config_yields_not_ready(self):
        assessment = assess_deployment(read_sample("risky_azure_config.yaml"))
        self.assertEqual(assessment.status, ReadinessStatus.NOT_READY)
        self.assertLess(assessment.score, 100)
        self.assertTrue(len(assessment.issues) > 0)
        self.assertEqual(len(assessment.explanations), len(assessment.issues))

    def test_risky_sap_deployment_yields_not_ready(self):
        assessment = assess_deployment(read_sample("risky_sap_ha_deployment.yaml"))
        self.assertEqual(assessment.status, ReadinessStatus.NOT_READY)

    def test_issues_sorted_by_descending_severity(self):
        assessment = assess_deployment(read_sample("risky_azure_config.yaml"))
        ranks = [issue.severity.rank for issue in assessment.issues]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class ScoreAndStatusTests(unittest.TestCase):
    def test_no_issues_full_score_and_ready(self):
        self.assertEqual(compute_score([]), 100)
        self.assertEqual(determine_status([]), ReadinessStatus.READY)

    def test_critical_issue_forces_not_ready(self):
        issue = Issue(
            rule_id="x",
            category="c",
            severity=Severity.CRITICAL,
            message="m",
            recommendation="r",
        )
        self.assertEqual(determine_status([issue]), ReadinessStatus.NOT_READY)
        self.assertEqual(compute_score([issue]), 65)

    def test_medium_issue_is_ready_with_warnings(self):
        issue = Issue(
            rule_id="x",
            category="c",
            severity=Severity.MEDIUM,
            message="m",
            recommendation="r",
        )
        self.assertEqual(determine_status([issue]), ReadinessStatus.READY_WITH_WARNINGS)

    def test_score_never_negative(self):
        issues = [
            Issue(rule_id=f"x{i}", category="c", severity=Severity.CRITICAL, message="m", recommendation="r")
            for i in range(10)
        ]
        self.assertEqual(compute_score(issues), 0)


if __name__ == "__main__":
    unittest.main()
