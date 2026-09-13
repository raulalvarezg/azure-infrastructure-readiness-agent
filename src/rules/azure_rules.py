"""Rules that detect common Azure infrastructure configuration issues.

These rules focus on the general shape of an Azure deployment: metadata,
networking, and compute resource definitions. They are intentionally
independent of any particular workload (Linux HA / SAP rules live in their
own modules).
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.models import Issue, Severity
from src.rules.base import Rule, get_in

# A small, representative set of valid Azure region names. This is not an
# exhaustive list of every Azure region, but is enough to catch obvious
# typos/placeholder values in deployment files.
KNOWN_AZURE_REGIONS = {
    "eastus",
    "eastus2",
    "westus",
    "westus2",
    "westus3",
    "centralus",
    "northcentralus",
    "southcentralus",
    "westeurope",
    "northeurope",
    "uksouth",
    "ukwest",
    "southeastasia",
    "eastasia",
    "australiaeast",
    "australiasoutheast",
    "japaneast",
    "japanwest",
    "brazilsouth",
    "canadacentral",
    "canadaeast",
    "centralindia",
    "southindia",
    "westindia",
}

SENSITIVE_PORTS = {"22", "3389"}
COMPUTE_RESOURCE_TYPE = "microsoft.compute/virtualmachines"
INTERNET_SOURCE_PREFIXES = {"*", "0.0.0.0/0", "internet", "any"}


class MetadataCompletenessRule(Rule):
    """Ensures required deployment metadata is present."""

    rule_id = "azure-metadata-001"
    category = "azure"

    REQUIRED_FIELDS = ("name", "environment", "region")

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        metadata = deployment.get("metadata") or {}
        issues: List[Issue] = []

        if not isinstance(metadata, dict):
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    message="'metadata' section must be a mapping.",
                    recommendation="Define 'metadata' as a mapping with 'name', 'environment' and 'region'.",
                    path="metadata",
                )
            ]

        for field_name in self.REQUIRED_FIELDS:
            if not metadata.get(field_name):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.HIGH,
                        message=f"Deployment metadata is missing required field '{field_name}'.",
                        recommendation=(
                            f"Add 'metadata.{field_name}' to the deployment file so the "
                            "deployment can be uniquely identified and tracked."
                        ),
                        path=f"metadata.{field_name}",
                    )
                )
        return issues


class RegionValidityRule(Rule):
    """Flags Azure regions that look invalid or misspelled."""

    rule_id = "azure-region-002"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        region = get_in(deployment, "metadata", "region")
        if not region:
            return []

        normalized = str(region).strip().lower().replace(" ", "")
        if normalized not in KNOWN_AZURE_REGIONS:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message=f"Region '{region}' is not a recognized Azure region name.",
                    recommendation=(
                        "Double-check the region identifier (e.g. 'eastus', 'westeurope') "
                        "against the Azure region list to avoid deployment failures."
                    ),
                    path="metadata.region",
                )
            ]
        return []


class ResourcesPresenceRule(Rule):
    """Ensures the deployment declares at least one resource."""

    rule_id = "azure-resources-003"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        resources = deployment.get("resources")
        if not resources:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    message="Deployment does not define any 'resources'.",
                    recommendation="Add at least one resource definition under 'resources'.",
                    path="resources",
                )
            ]
        return []


class VirtualMachineSizeRule(Rule):
    """Ensures every virtual machine resource specifies a VM size/SKU."""

    rule_id = "azure-vmsize-004"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        issues: List[Issue] = []
        for index, resource in enumerate(_virtual_machines(deployment)):
            properties = resource.get("properties") or {}
            name = resource.get("name", f"resource[{index}]")
            if not properties.get("size"):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.HIGH,
                        message=f"Virtual machine '{name}' does not specify a 'size'.",
                        recommendation=(
                            f"Set 'resources[{index}].properties.size' to a valid Azure VM SKU "
                            "(e.g. 'Standard_D4s_v5')."
                        ),
                        path=f"resources[{index}].properties.size",
                    )
                )
        return issues


class HighAvailabilityPlacementRule(Rule):
    """Production VMs should use availability zones/sets to avoid single points of failure."""

    rule_id = "azure-availability-005"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        environment = str(get_in(deployment, "metadata", "environment", default="")).lower()
        if environment not in ("production", "prod"):
            return []

        issues: List[Issue] = []
        for index, resource in enumerate(_virtual_machines(deployment)):
            properties = resource.get("properties") or {}
            name = resource.get("name", f"resource[{index}]")
            has_zone = bool(properties.get("availability_zone"))
            has_set = bool(properties.get("availability_set"))
            if not has_zone and not has_set:
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.HIGH,
                        message=(
                            f"Production virtual machine '{name}' is not placed in an "
                            "availability zone or availability set."
                        ),
                        recommendation=(
                            "Set 'availability_zone' (preferred) or 'availability_set' for "
                            f"'resources[{index}]' to protect against datacenter/rack failures."
                        ),
                        path=f"resources[{index}].properties",
                    )
                )
        return issues


class ManagedDiskRule(Rule):
    """Flags virtual machines using unmanaged disks."""

    rule_id = "azure-disks-006"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        issues: List[Issue] = []
        for index, resource in enumerate(_virtual_machines(deployment)):
            properties = resource.get("properties") or {}
            name = resource.get("name", f"resource[{index}]")
            disk_type = properties.get("managed_disk_type")
            if disk_type == "Unmanaged" or properties.get("use_unmanaged_disks"):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        message=f"Virtual machine '{name}' uses unmanaged disks.",
                        recommendation=(
                            "Migrate to managed disks (e.g. 'Premium_LRS') for better "
                            "reliability, scalability and simplified management."
                        ),
                        path=f"resources[{index}].properties.managed_disk_type",
                    )
                )
        return issues


class NetworkVnetRule(Rule):
    """Ensures a virtual network is defined for the deployment."""

    rule_id = "azure-network-007"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        vnet = get_in(deployment, "networking", "vnet")
        if not vnet:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.HIGH,
                    message="No virtual network ('networking.vnet') is defined.",
                    recommendation="Define 'networking.vnet' so resources are deployed into an isolated network.",
                    path="networking.vnet",
                )
            ]
        return []


class OpenNetworkSecurityGroupRule(Rule):
    """Flags NSG rules that expose sensitive management ports to the public internet."""

    rule_id = "azure-nsg-008"
    category = "azure"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        issues: List[Issue] = []
        nsgs = get_in(deployment, "networking", "network_security_groups", default=[]) or []

        for nsg_index, nsg in enumerate(nsgs):
            nsg_name = nsg.get("name", f"nsg[{nsg_index}]")
            for rule_index, rule in enumerate(nsg.get("rules") or []):
                if self._is_open_to_internet(rule):
                    port = rule.get("destination_port_range")
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity=Severity.CRITICAL,
                            message=(
                                f"NSG '{nsg_name}' rule '{rule.get('name', rule_index)}' allows "
                                f"inbound traffic from the public internet on port {port}."
                            ),
                            recommendation=(
                                "Restrict 'source_address_prefix' to trusted IP ranges (e.g. a "
                                "bastion subnet or VPN range) instead of '*' or 'Internet' for "
                                "management ports such as 22 (SSH) and 3389 (RDP)."
                            ),
                            path=(
                                f"networking.network_security_groups[{nsg_index}]"
                                f".rules[{rule_index}]"
                            ),
                        )
                    )
        return issues

    @staticmethod
    def _is_open_to_internet(rule: Dict[str, Any]) -> bool:
        direction = str(rule.get("direction", "")).lower()
        access = str(rule.get("access", "")).lower()
        source = str(rule.get("source_address_prefix", "")).strip().lower()
        port_range = str(rule.get("destination_port_range", ""))

        return (
            direction == "inbound"
            and access == "allow"
            and source in INTERNET_SOURCE_PREFIXES
            and _port_range_includes_sensitive_port(port_range)
        )


def _port_range_includes_sensitive_port(port_range: str) -> bool:
    """Return True if ``port_range`` (a single port, range, or '*') covers a sensitive port."""

    port_range = port_range.strip()
    if port_range in ("*", ""):
        return bool(port_range)

    if "-" in port_range:
        start_str, _, end_str = port_range.partition("-")
        try:
            start, end = int(start_str), int(end_str)
        except ValueError:
            return False
        return any(start <= int(sensitive_port) <= end for sensitive_port in SENSITIVE_PORTS)

    return port_range in SENSITIVE_PORTS


def _virtual_machines(deployment: Dict[str, Any]) -> List[Dict[str, Any]]:
    resources = deployment.get("resources") or []
    return [
        resource
        for resource in resources
        if isinstance(resource, dict)
        and str(resource.get("type", "")).lower() == COMPUTE_RESOURCE_TYPE
    ]


def default_azure_rules() -> List[Rule]:
    """Return an instance of every Azure infrastructure rule."""

    return [
        MetadataCompletenessRule(),
        RegionValidityRule(),
        ResourcesPresenceRule(),
        VirtualMachineSizeRule(),
        HighAvailabilityPlacementRule(),
        ManagedDiskRule(),
        NetworkVnetRule(),
        OpenNetworkSecurityGroupRule(),
    ]
