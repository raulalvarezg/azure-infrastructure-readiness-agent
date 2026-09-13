"""Rules that detect SAP-specific high-availability deployment risks on Azure."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from src.models import Issue, Severity
from src.rules.base import Rule

# VM families certified/recommended for SAP HANA memory-intensive workloads.
# The entire 'Standard_M' family (M-series) is memory-optimized and built
# specifically for SAP HANA, so a prefix match is sufficient and there is no
# other Azure VM family sharing the 'standard_m' prefix. 'Standard_E' is a
# general-purpose family where only the storage-optimized, versioned
# variants (e.g. 'Standard_E20s_v4') are HANA-certified, so those require
# the more precise regex below.
SAP_HANA_VM_PREFIX = "standard_m"
SAP_HANA_VM_ESERIES_PATTERN = re.compile(r"^standard_e\d+(-\d+)?s_v\d+$")

VALID_SHARED_STORAGE_TYPES = {"anf", "azure_netapp_files", "azure_files", "nfs"}


def _is_sap_hana_certified_size(size: str) -> bool:
    """Return True if ``size`` looks like a SAP HANA-certified memory-optimized VM size."""

    return size.startswith(SAP_HANA_VM_PREFIX) or bool(SAP_HANA_VM_ESERIES_PATTERN.match(size))


class SapHanaHAFencingRule(Rule):
    """SAP HANA HA clusters must use a supported fencing mechanism."""

    rule_id = "sap-ha-fencing-001"
    category = "sap-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        sap = deployment.get("sap") or {}
        if not sap.get("enabled") or not sap.get("hana_ha_enabled"):
            return []

        fencing_agent = str(sap.get("fencing_agent", "")).strip().lower()
        if not fencing_agent:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    message="SAP HANA HA is enabled without a fencing agent configured.",
                    recommendation=(
                        "Configure 'sap.fencing_agent' (e.g. 'sbd' or 'azure_fence_agent') to "
                        "prevent data corruption from split-brain during failover."
                    ),
                    path="sap.fencing_agent",
                )
            ]
        return []


class SapSharedStorageRule(Rule):
    """SAP HANA HA requires shared storage reachable by all cluster nodes."""

    rule_id = "sap-ha-storage-002"
    category = "sap-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        sap = deployment.get("sap") or {}
        if not sap.get("enabled") or not sap.get("hana_ha_enabled"):
            return []

        storage_type = str(sap.get("shared_storage_type", "")).strip().lower()
        if not storage_type:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.HIGH,
                    message="SAP HANA HA does not define a shared storage type for '/hana/shared'.",
                    recommendation=(
                        "Set 'sap.shared_storage_type' to a supported option such as "
                        "'ANF' (Azure NetApp Files) or 'azure_files'."
                    ),
                    path="sap.shared_storage_type",
                )
            ]

        if storage_type not in VALID_SHARED_STORAGE_TYPES:
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message=f"Shared storage type '{storage_type}' is not a recognized option for SAP HA.",
                    recommendation="Use 'ANF', 'azure_files', or another NFS-compatible shared storage service.",
                    path="sap.shared_storage_type",
                )
            ]
        return []


class SapScsHighAvailabilityRule(Rule):
    """The SAP Central Services (SCS/ASCS) instance should also be made highly available."""

    rule_id = "sap-ha-scs-003"
    category = "sap-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        sap = deployment.get("sap") or {}
        if not sap.get("enabled"):
            return []

        if sap.get("hana_ha_enabled") and not sap.get("scs_ha_enabled"):
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message=(
                        "HANA database HA is enabled, but the SAP Central Services "
                        "(SCS/ASCS) instance is not configured for high availability."
                    ),
                    recommendation=(
                        "Enable 'sap.scs_ha_enabled' and cluster the ASCS/ERS instances "
                        "to avoid a single point of failure at the application layer."
                    ),
                    path="sap.scs_ha_enabled",
                )
            ]
        return []


class SapVmSizingRule(Rule):
    """SAP HANA workloads should run on memory-optimized VM families."""

    rule_id = "sap-ha-vmsize-004"
    category = "sap-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        sap = deployment.get("sap") or {}
        if not sap.get("enabled"):
            return []

        issues: List[Issue] = []
        for index, resource in enumerate(deployment.get("resources") or []):
            if not isinstance(resource, dict):
                continue
            if not resource.get("sap_role"):
                continue
            if str(resource.get("sap_role")).lower() not in ("hana", "hana_db", "database"):
                continue

            properties = resource.get("properties") or {}
            size = str(properties.get("size", "")).strip().lower()
            if size and not _is_sap_hana_certified_size(size):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        message=(
                            f"SAP HANA resource '{resource.get('name', index)}' uses VM size "
                            f"'{properties.get('size')}', which is not a memory-optimized "
                            "SAP-certified series."
                        ),
                        recommendation=(
                            "Use a memory-optimized, SAP-certified VM size such as a "
                            "'Standard_M' series instance, or a certified 'Standard_E<size>s_v<version>' "
                            "(premium-storage, versioned) E-series instance."
                        ),
                        path=f"resources[{index}].properties.size",
                    )
                )
        return issues


class SapHanaBackupRule(Rule):
    """SAP HANA HA deployments should have backup configured."""

    rule_id = "sap-ha-backup-005"
    category = "sap-ha"

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        sap = deployment.get("sap") or {}
        if not sap.get("enabled") or not sap.get("hana_ha_enabled"):
            return []

        if not sap.get("backup_enabled"):
            return [
                Issue(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.LOW,
                    message="SAP HANA HA deployment does not have backups explicitly enabled.",
                    recommendation="Set 'sap.backup_enabled' to true and configure a backup schedule/retention policy.",
                    path="sap.backup_enabled",
                )
            ]
        return []


def default_sap_ha_rules() -> List[Rule]:
    """Return an instance of every SAP HA rule."""

    return [
        SapHanaHAFencingRule(),
        SapSharedStorageRule(),
        SapScsHighAvailabilityRule(),
        SapVmSizingRule(),
        SapHanaBackupRule(),
    ]
