import unittest

import yaml

from src.models import Severity
from src.rules.base import RuleSet
from src.rules.linux_ha_rules import (
    ClusterQuorumRule,
    ClusterTypeRule,
    HighAvailabilityFencingRule,
    SupportedDistroRule,
    default_linux_ha_rules,
)
from tests.helpers import read_sample


def rule_ids(issues):
    return {issue.rule_id for issue in issues}


class HighAvailabilityFencingRuleTests(unittest.TestCase):
    def test_disabled_ha_not_evaluated(self):
        rule = HighAvailabilityFencingRule()
        self.assertEqual(rule.evaluate({"high_availability": {"enabled": False}}), [])

    def test_missing_fencing_agent_flagged_critical(self):
        rule = HighAvailabilityFencingRule()
        issues = rule.evaluate({"high_availability": {"enabled": True}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)

    def test_unknown_fencing_agent_flagged_medium(self):
        rule = HighAvailabilityFencingRule()
        issues = rule.evaluate(
            {"high_availability": {"enabled": True, "fencing_agent": "made_up_agent"}}
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.MEDIUM)

    def test_valid_fencing_agent_not_flagged(self):
        rule = HighAvailabilityFencingRule()
        issues = rule.evaluate({"high_availability": {"enabled": True, "fencing_agent": "sbd"}})
        self.assertEqual(issues, [])


class ClusterQuorumRuleTests(unittest.TestCase):
    def test_even_nodes_without_qdevice_flagged(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate({"high_availability": {"enabled": True, "number_of_nodes": 2}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.HIGH)

    def test_even_nodes_with_qdevice_not_flagged(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate(
            {
                "high_availability": {
                    "enabled": True,
                    "number_of_nodes": 2,
                    "quorum_device": "qdevice-1",
                }
            }
        )
        self.assertEqual(issues, [])

    def test_odd_nodes_not_flagged(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate({"high_availability": {"enabled": True, "number_of_nodes": 3}})
        self.assertEqual(issues, [])

    def test_single_node_flagged_critical(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate({"high_availability": {"enabled": True, "number_of_nodes": 1}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)

    def test_missing_node_count_flagged(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate({"high_availability": {"enabled": True}})
        self.assertEqual(len(issues), 1)

    def test_boolean_node_count_treated_as_invalid(self):
        rule = ClusterQuorumRule()
        issues = rule.evaluate({"high_availability": {"enabled": True, "number_of_nodes": True}})
        self.assertEqual(len(issues), 1)
        self.assertIn("does not specify", issues[0].message)


class ClusterTypeRuleTests(unittest.TestCase):
    def test_missing_cluster_type_flagged(self):
        rule = ClusterTypeRule()
        issues = rule.evaluate({"high_availability": {"enabled": True}})
        self.assertEqual(len(issues), 1)

    def test_present_cluster_type_not_flagged(self):
        rule = ClusterTypeRule()
        issues = rule.evaluate(
            {"high_availability": {"enabled": True, "cluster_type": "pacemaker"}}
        )
        self.assertEqual(issues, [])


class SupportedDistroRuleTests(unittest.TestCase):
    def test_unsupported_distro_flagged(self):
        rule = SupportedDistroRule()
        deployment = {
            "high_availability": {"enabled": True},
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"os_type": "Linux", "os_distro": "ubuntu"},
                }
            ],
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_supported_distro_not_flagged(self):
        rule = SupportedDistroRule()
        deployment = {
            "high_availability": {"enabled": True},
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"os_type": "Linux", "os_distro": "sles_sap"},
                }
            ],
        }
        self.assertEqual(rule.evaluate(deployment), [])


class DefaultLinuxHaRuleSetTests(unittest.TestCase):
    def test_risky_deployment_produces_expected_hits(self):
        deployment = yaml.safe_load(read_sample("risky_linux_ha_deployment.yaml"))
        rule_set = RuleSet(default_linux_ha_rules())
        issues = rule_set.evaluate(deployment)

        ids = rule_ids(issues)
        self.assertIn("linux-ha-fencing-001", ids)
        self.assertIn("linux-ha-quorum-002", ids)
        self.assertIn("linux-ha-distro-004", ids)

    def test_valid_deployment_has_no_linux_ha_issues(self):
        deployment = yaml.safe_load(read_sample("valid_sap_ha_deployment.yaml"))
        rule_set = RuleSet(default_linux_ha_rules())
        issues = rule_set.evaluate(deployment)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
