"""Rules that detect Linux high-availability (Pacemaker/SUSE/RHEL) deployment risks."""

from __future__ import annotations

from typing import Any, Dict, List

from src.models import Issue, Severity
from src.rules.base import Rule, get_in

SUPPORTED_HA_DISTROS = {
    "sles",
    "sles_sap",
    "rhel",
    "rhel_ha",
}

VALID_FENCING_AGENTS = {
    "sbd",
    "azure_fence_agent",
    "fence_azure_arm",
}


class HighAvailabilityFencingRule(Rule):
    """A Pacemaker cluster without a fencing/STONITH mechanism is unsafe."""

    rule_id = "linux-ha-fencing-001"
    category = "linux-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        ha = deployment.get("high_availability") or {}
        if not ha.get("enabled"):
            return []

        fencing_agent = str(ha.get("fencing_agent", "")).strip().lower()
        if not fencing_agent:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    message="High availability cluster is enabled without a fencing (STONITH) agent.",
                    recommendation=(
                        "Configure a fencing mechanism such as 'sbd' (STONITH Block Device) "
                        "or the Azure fence agent to prevent split-brain scenarios."
                    ),
                    path="high_availability.fencing_agent",
                )
            ]

        if fencing_agent not in VALID_FENCING_AGENTS:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message=f"Fencing agent '{fencing_agent}' is not a recognized/supported agent.",
                    recommendation=(
                        "Use a validated fencing agent for Azure, such as 'sbd' or "
                        "'azure_fence_agent'."
                    ),
                    path="high_availability.fencing_agent",
                )
            ]
        return []


class ClusterQuorumRule(Rule):
    """Pacemaker clusters need an odd node count (or a quorum device) to avoid split-brain."""

    rule_id = "linux-ha-quorum-002"
    category = "linux-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        ha = deployment.get("high_availability") or {}
        if not ha.get("enabled"):
            return []

        node_count = ha.get("number_of_nodes")
        has_qdevice = bool(ha.get("quorum_device"))

        if not isinstance(node_count, int):
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message="High availability cluster does not specify 'number_of_nodes'.",
                    recommendation="Set 'high_availability.number_of_nodes' to document the cluster topology.",
                    path="high_availability.number_of_nodes",
                )
            ]

        if node_count < 2:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    message="High availability cluster has fewer than 2 nodes.",
                    recommendation="Deploy at least 2 cluster nodes to provide failover capability.",
                    path="high_availability.number_of_nodes",
                )
            ]

        if node_count % 2 == 0 and not has_qdevice:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.HIGH,
                    message=(
                        f"Cluster has an even number of nodes ({node_count}) without a quorum device, "
                        "risking split-brain during network partitions."
                    ),
                    recommendation=(
                        "Add a quorum device ('high_availability.quorum_device') or adjust the "
                        "topology to an odd number of nodes."
                    ),
                    path="high_availability.number_of_nodes",
                )
            ]
        return []


class ClusterTypeRule(Rule):
    """Ensures the cluster resource manager is explicitly declared."""

    rule_id = "linux-ha-clustertype-003"
    category = "linux-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        ha = deployment.get("high_availability") or {}
        if not ha.get("enabled"):
            return []

        if not ha.get("cluster_type"):
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message="High availability cluster does not specify a 'cluster_type'.",
                    recommendation="Set 'high_availability.cluster_type' (e.g. 'pacemaker').",
                    path="high_availability.cluster_type",
                )
            ]
        return []


class SupportedDistroRule(Rule):
    """Pacemaker HA on Azure is only supported on specific Linux distributions."""

    rule_id = "linux-ha-distro-004"
    category = "linux-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        ha = deployment.get("high_availability") or {}
        if not ha.get("enabled"):
            return []

        issues: List[Issue] = []
        for index, resource in enumerate(deployment.get("resources") or []):
            if not isinstance(resource, dict):
                continue
            properties = resource.get("properties") or {}
            os_type = str(properties.get("os_type", "")).lower()
            os_distro = str(properties.get("os_distro", "")).lower().replace("-", "_")

            if os_type != "linux":
                continue
            if not os_distro:
                continue
            if os_distro not in SUPPORTED_HA_DISTROS:
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Resource '{resource.get('name', index)}' uses distro "
                            f"'{properties.get('os_distro')}' which is not a validated "
                            "distro for Pacemaker HA on Azure."
                        ),
                        recommendation=(
                            "Use a distribution with official Azure HA support, such as "
                            "SLES for SAP or RHEL HA."
                        ),
                        path=f"resources[{index}].properties.os_distro",
                    )
                )
        return issues


def default_linux_ha_rules() -> List[Rule]:
    """Return an instance of every Linux HA rule."""

    return [
        HighAvailabilityFencingRule(),
        ClusterQuorumRule(),
        ClusterTypeRule(),
        SupportedDistroRule(),
    ]
