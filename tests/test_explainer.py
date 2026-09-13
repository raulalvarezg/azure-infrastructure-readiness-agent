import unittest

from src.ai.explainer import explain_issue, explain_issues, summarize
from src.models import Issue, Severity


class ExplainerTests(unittest.TestCase):
    def _issue(self, severity=Severity.HIGH):
        return Issue(
            rule_id="test-001",
            category="azure",
            severity=severity,
            message="Something is misconfigured.",
            recommendation="Fix the misconfiguration.",
        )

    def test_explain_issue_includes_message_and_recommendation(self):
        text = explain_issue(self._issue())
        self.assertIn("Something is misconfigured.", text)
        self.assertIn("Fix the misconfiguration.", text)
        self.assertIn("HIGH", text)

    def test_explain_issues_returns_one_per_issue(self):
        issues = [self._issue(), self._issue(Severity.CRITICAL)]
        explanations = explain_issues(issues)
        self.assertEqual(len(explanations), 2)

    def test_summarize_no_issues(self):
        summary = summarize([])
        self.assertIn("No issues", summary)

    def test_summarize_with_issues_mentions_counts(self):
        issues = [self._issue(Severity.CRITICAL), self._issue(Severity.HIGH), self._issue(Severity.HIGH)]
        summary = summarize(issues)
        self.assertIn("3", summary)
        self.assertIn("1 critical", summary)
        self.assertIn("2 high", summary)


if __name__ == "__main__":
    unittest.main()
