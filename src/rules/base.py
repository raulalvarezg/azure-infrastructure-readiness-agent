"""Base classes for the rule engine.

Each rule inspects the parsed deployment document and returns a list of
:class:`~src.models.Issue` objects describing any problems it finds. Rules
are intentionally simple, composable, pure functions/classes so they are
easy to unit test in isolation and combine into a larger rule set.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from src.models import Issue


class Rule(ABC):
    """Base class for a single deployment readiness rule."""

    #: Unique, stable identifier for the rule (used in reports/tests).
    rule_id: str = "base-rule"
    #: Category used for grouping in reports (e.g. "azure", "linux-ha", "sap-ha").
    category: str = "general"

    @abstractmethod
    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        """Evaluate the rule against ``deployment`` and return found issues."""

        raise NotImplementedError


class RuleSet:
    """A collection of rules that can be evaluated together."""

    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def evaluate(self, deployment: Dict[str, Any]) -> List[Issue]:
        issues: List[Issue] = []
        for rule in self.rules:
            issues.extend(rule.evaluate(deployment or {}))
        return issues


def get_in(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dictionaries, returning ``default`` if missing."""

    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current
