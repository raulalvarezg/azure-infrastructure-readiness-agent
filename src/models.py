"""Shared data models used across the Azure Infrastructure Readiness Agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity level of a detected issue."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


@dataclass
class Issue:
    """Represents a single detected configuration issue or risk."""

    rule_id: str
    category: str
    severity: Severity
    message: str
    recommendation: str
    path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "recommendation": self.recommendation,
            "path": self.path,
            "details": self.details,
        }


@dataclass
class ValidationResult:
    """Result of validating YAML syntax (before rule evaluation)."""

    valid: bool
    data: Optional[Any] = None
    error: Optional[str] = None


class ReadinessStatus(str, Enum):
    READY = "ready"
    READY_WITH_WARNINGS = "ready_with_warnings"
    NOT_READY = "not_ready"


@dataclass
class ReadinessAssessment:
    """The overall deployment readiness assessment."""

    status: ReadinessStatus
    score: int
    issues: List[Issue]
    summary: str
    explanations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "score": self.score,
            "summary": self.summary,
            "explanations": self.explanations,
            "issues": [issue.to_dict() for issue in self.issues],
        }
