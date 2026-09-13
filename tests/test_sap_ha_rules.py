import unittest

import yaml

from src.models import Severity
from src.rules.base import RuleSet
from src.rules.sap_ha_rules import (
    SapHanaBackupRule,
    SapHanaHAFencingRule,
    SapScsHighAvailabilityRule,
    SapSharedStorageRule,
    SapVmSizingRule,
    default_sap_ha_rules,
)
from tests.helpers import read_sample


def rule_ids(issues):
    return {issue.rule_id for issue in issues}


class SapHanaHAFencingRuleTests(unittest.TestCase):
    def test_missing_fencing_agent_flagged_critical(self):
        rule = SapHanaHAFencingRule()
        issues = rule.evaluate({"sap": {"enabled": True, "hana_ha_enabled": True}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)

    def test_present_fencing_agent_not_flagged(self):
        rule = SapHanaHAFencingRule()
        issues = rule.evaluate(
            {"sap": {"enabled": True, "hana_ha_enabled": True, "fencing_agent": "sbd"}}
        )
        self.assertEqual(issues, [])

    def test_sap_disabled_not_evaluated(self):
        rule = SapHanaHAFencingRule()
        self.assertEqual(rule.evaluate({"sap": {"enabled": False}}), [])

    def test_hana_ha_disabled_not_evaluated(self):
        rule = SapHanaHAFencingRule()
        self.assertEqual(rule.evaluate({"sap": {"enabled": True, "hana_ha_enabled": False}}), [])


class SapSharedStorageRuleTests(unittest.TestCase):
    def test_missing_storage_type_flagged(self):
        rule = SapSharedStorageRule()
        issues = rule.evaluate({"sap": {"enabled": True, "hana_ha_enabled": True}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.HIGH)

    def test_valid_storage_type_not_flagged(self):
        rule = SapSharedStorageRule()
        issues = rule.evaluate(
            {"sap": {"enabled": True, "hana_ha_enabled": True, "shared_storage_type": "ANF"}}
        )
        self.assertEqual(issues, [])

    def test_unrecognized_storage_type_flagged_medium(self):
        rule = SapSharedStorageRule()
        issues = rule.evaluate(
            {
                "sap": {
                    "enabled": True,
                    "hana_ha_enabled": True,
                    "shared_storage_type": "local_disk",
                }
            }
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.MEDIUM)


class SapScsHighAvailabilityRuleTests(unittest.TestCase):
    def test_missing_scs_ha_flagged(self):
        rule = SapScsHighAvailabilityRule()
        issues = rule.evaluate({"sap": {"enabled": True, "hana_ha_enabled": True}})
        self.assertEqual(len(issues), 1)

    def test_scs_ha_enabled_not_flagged(self):
        rule = SapScsHighAvailabilityRule()
        issues = rule.evaluate(
            {"sap": {"enabled": True, "hana_ha_enabled": True, "scs_ha_enabled": True}}
        )
        self.assertEqual(issues, [])


class SapVmSizingRuleTests(unittest.TestCase):
    def test_undersized_hana_vm_flagged(self):
        rule = SapVmSizingRule()
        deployment = {
            "sap": {"enabled": True},
            "resources": [
                {
                    "name": "hana01",
                    "sap_role": "hana",
                    "properties": {"size": "Standard_D8s_v5"},
                }
            ],
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_memory_optimized_hana_vm_not_flagged(self):
        rule = SapVmSizingRule()
        deployment = {
            "sap": {"enabled": True},
            "resources": [
                {
                    "name": "hana01",
                    "sap_role": "hana",
                    "properties": {"size": "Standard_M32ts"},
                }
            ],
        }
        self.assertEqual(rule.evaluate(deployment), [])


class SapHanaBackupRuleTests(unittest.TestCase):
    def test_missing_backup_flagged_low(self):
        rule = SapHanaBackupRule()
        issues = rule.evaluate({"sap": {"enabled": True, "hana_ha_enabled": True}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.LOW)

    def test_backup_enabled_not_flagged(self):
        rule = SapHanaBackupRule()
        issues = rule.evaluate(
            {"sap": {"enabled": True, "hana_ha_enabled": True, "backup_enabled": True}}
        )
        self.assertEqual(issues, [])


class DefaultSapHaRuleSetTests(unittest.TestCase):
    def test_risky_deployment_produces_expected_hits(self):
        deployment = yaml.safe_load(read_sample("risky_sap_ha_deployment.yaml"))
        rule_set = RuleSet(default_sap_ha_rules())
        issues = rule_set.evaluate(deployment)

        ids = rule_ids(issues)
        self.assertIn("sap-ha-fencing-001", ids)
        self.assertIn("sap-ha-storage-002", ids)
        self.assertIn("sap-ha-scs-003", ids)
        self.assertIn("sap-ha-vmsize-004", ids)
        self.assertIn("sap-ha-backup-005", ids)

    def test_valid_deployment_has_no_sap_ha_issues(self):
        deployment = yaml.safe_load(read_sample("valid_sap_ha_deployment.yaml"))
        rule_set = RuleSet(default_sap_ha_rules())
        issues = rule_set.evaluate(deployment)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
