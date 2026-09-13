import unittest

from src.models import Severity
from src.rules.azure_rules import (
    HighAvailabilityPlacementRule,
    ManagedDiskRule,
    MetadataCompletenessRule,
    NetworkVnetRule,
    OpenNetworkSecurityGroupRule,
    RegionValidityRule,
    ResourcesPresenceRule,
    VirtualMachineSizeRule,
    default_azure_rules,
)
from src.rules.base import RuleSet


def rule_ids(issues):
    return {issue.rule_id for issue in issues}


class MetadataCompletenessRuleTests(unittest.TestCase):
    def test_missing_all_fields_reports_three_issues(self):
        rule = MetadataCompletenessRule()
        issues = rule.evaluate({"metadata": {}})
        self.assertEqual(len(issues), 3)
        self.assertTrue(all(issue.severity == Severity.HIGH for issue in issues))

    def test_complete_metadata_has_no_issues(self):
        rule = MetadataCompletenessRule()
        issues = rule.evaluate(
            {"metadata": {"name": "app", "environment": "production", "region": "eastus"}}
        )
        self.assertEqual(issues, [])

    def test_non_mapping_metadata_reports_single_critical_issue(self):
        rule = MetadataCompletenessRule()
        issues = rule.evaluate({"metadata": "oops"})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)


class RegionValidityRuleTests(unittest.TestCase):
    def test_unknown_region_flagged(self):
        rule = RegionValidityRule()
        issues = rule.evaluate({"metadata": {"region": "mars-central"}})
        self.assertEqual(len(issues), 1)

    def test_known_region_not_flagged(self):
        rule = RegionValidityRule()
        issues = rule.evaluate({"metadata": {"region": "eastus"}})
        self.assertEqual(issues, [])

    def test_missing_region_not_flagged_by_this_rule(self):
        rule = RegionValidityRule()
        self.assertEqual(rule.evaluate({"metadata": {}}), [])


class ResourcesPresenceRuleTests(unittest.TestCase):
    def test_no_resources_flagged_critical(self):
        rule = ResourcesPresenceRule()
        issues = rule.evaluate({})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)

    def test_resources_present_not_flagged(self):
        rule = ResourcesPresenceRule()
        issues = rule.evaluate({"resources": [{"type": "Microsoft.Compute/virtualMachines"}]})
        self.assertEqual(issues, [])


class VirtualMachineSizeRuleTests(unittest.TestCase):
    def test_missing_size_flagged(self):
        rule = VirtualMachineSizeRule()
        deployment = {
            "resources": [
                {"type": "Microsoft.Compute/virtualMachines", "name": "vm1", "properties": {}}
            ]
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)
        self.assertIn("vm1", issues[0].message)

    def test_size_present_not_flagged(self):
        rule = VirtualMachineSizeRule()
        deployment = {
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"size": "Standard_D2s_v3"},
                }
            ]
        }
        self.assertEqual(rule.evaluate(deployment), [])


class HighAvailabilityPlacementRuleTests(unittest.TestCase):
    def test_production_vm_without_zone_flagged(self):
        rule = HighAvailabilityPlacementRule()
        deployment = {
            "metadata": {"environment": "production"},
            "resources": [
                {"type": "Microsoft.Compute/virtualMachines", "name": "vm1", "properties": {}}
            ],
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_non_production_not_flagged(self):
        rule = HighAvailabilityPlacementRule()
        deployment = {
            "metadata": {"environment": "dev"},
            "resources": [
                {"type": "Microsoft.Compute/virtualMachines", "name": "vm1", "properties": {}}
            ],
        }
        self.assertEqual(rule.evaluate(deployment), [])

    def test_production_vm_with_zone_not_flagged(self):
        rule = HighAvailabilityPlacementRule()
        deployment = {
            "metadata": {"environment": "production"},
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"availability_zone": 1},
                }
            ],
        }
        self.assertEqual(rule.evaluate(deployment), [])


class ManagedDiskRuleTests(unittest.TestCase):
    def test_unmanaged_disk_flagged(self):
        rule = ManagedDiskRule()
        deployment = {
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"managed_disk_type": "Unmanaged"},
                }
            ]
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_managed_disk_not_flagged(self):
        rule = ManagedDiskRule()
        deployment = {
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "name": "vm1",
                    "properties": {"managed_disk_type": "Premium_LRS"},
                }
            ]
        }
        self.assertEqual(rule.evaluate(deployment), [])


class NetworkVnetRuleTests(unittest.TestCase):
    def test_missing_vnet_flagged(self):
        rule = NetworkVnetRule()
        self.assertEqual(len(rule.evaluate({})), 1)

    def test_present_vnet_not_flagged(self):
        rule = NetworkVnetRule()
        self.assertEqual(rule.evaluate({"networking": {"vnet": "vnet-1"}}), [])


class OpenNetworkSecurityGroupRuleTests(unittest.TestCase):
    def test_open_ssh_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-ssh",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "22",
                                "source_address_prefix": "*",
                            }
                        ],
                    }
                ]
            }
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)

    def test_restricted_ssh_not_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-ssh",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "22",
                                "source_address_prefix": "10.0.0.0/24",
                            }
                        ],
                    }
                ]
            }
        }
        self.assertEqual(rule.evaluate(deployment), [])

    def test_non_sensitive_port_open_not_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-https",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "443",
                                "source_address_prefix": "*",
                            }
                        ],
                    }
                ]
            }
        }
        self.assertEqual(rule.evaluate(deployment), [])

    def test_wildcard_port_range_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-all",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "*",
                                "source_address_prefix": "*",
                            }
                        ],
                    }
                ]
            }
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_port_range_covering_sensitive_port_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-range",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "20-25",
                                "source_address_prefix": "*",
                            }
                        ],
                    }
                ]
            }
        }
        issues = rule.evaluate(deployment)
        self.assertEqual(len(issues), 1)

    def test_port_range_not_covering_sensitive_port_not_flagged(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    {
                        "name": "nsg1",
                        "rules": [
                            {
                                "name": "allow-range",
                                "direction": "Inbound",
                                "access": "Allow",
                                "destination_port_range": "80-443",
                                "source_address_prefix": "*",
                            }
                        ],
                    }
                ]
            }
        }
        self.assertEqual(rule.evaluate(deployment), [])


    def test_malformed_nsg_and_rule_entries_are_skipped_safely(self):
        rule = OpenNetworkSecurityGroupRule()
        deployment = {
            "networking": {
                "network_security_groups": [
                    "not-a-mapping",
                    {"name": "nsg1", "rules": ["also-not-a-mapping", None]},
                ]
            }
        }
        self.assertEqual(rule.evaluate(deployment), [])


class DefaultAzureRuleSetTests(unittest.TestCase):
    def test_risky_config_produces_expected_rule_hits(self):
        from tests.helpers import read_sample
        import yaml

        deployment = yaml.safe_load(read_sample("risky_azure_config.yaml"))
        rule_set = RuleSet(default_azure_rules())
        issues = rule_set.evaluate(deployment)

        ids = rule_ids(issues)
        self.assertIn("azure-region-002", ids)
        self.assertIn("azure-vmsize-004", ids)
        self.assertIn("azure-availability-005", ids)
        self.assertIn("azure-disks-006", ids)
        self.assertIn("azure-network-007", ids)
        self.assertIn("azure-nsg-008", ids)

    def test_valid_config_has_no_azure_issues(self):
        from tests.helpers import read_sample
        import yaml

        deployment = yaml.safe_load(read_sample("valid_sap_ha_deployment.yaml"))
        rule_set = RuleSet(default_azure_rules())
        issues = rule_set.evaluate(deployment)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
