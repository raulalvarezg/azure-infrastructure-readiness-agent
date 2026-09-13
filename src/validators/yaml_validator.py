"""Validators for the raw YAML deployment file (syntax and basic structure)."""

from __future__ import annotations

from typing import Any

import yaml

from src.models import ValidationResult


class YamlSyntaxError(Exception):
    """Raised when a YAML file cannot be parsed."""


def validate_yaml_syntax(content: str) -> ValidationResult:
    """Validate that ``content`` is syntactically valid YAML.

    Returns a :class:`ValidationResult` with ``valid=True`` and the parsed
    data on success, or ``valid=False`` and a human readable error message
    on failure. This never raises for malformed YAML input.
    """

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return ValidationResult(valid=False, data=None, error=_format_yaml_error(exc))

    return ValidationResult(valid=True, data=data, error=None)


def validate_yaml_file(path: str) -> ValidationResult:
    """Validate a YAML file at ``path`` on disk."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError as exc:
        return ValidationResult(valid=False, data=None, error=f"Could not read file '{path}': {exc}")

    return validate_yaml_syntax(content)


def validate_structure(data: Any) -> ValidationResult:
    """Validate that the parsed YAML has the minimal expected structure.

    A valid deployment document must be a mapping (dictionary). This does
    not check business-specific rules; those are handled by the rule
    engine modules.
    """

    if data is None:
        return ValidationResult(valid=False, data=data, error="The YAML document is empty.")

    if not isinstance(data, dict):
        return ValidationResult(
            valid=False,
            data=data,
            error=(
                "The YAML document must define a top-level mapping/object, "
                f"got {type(data).__name__} instead."
            ),
        )

    return ValidationResult(valid=True, data=data, error=None)


def _format_yaml_error(exc: yaml.YAMLError) -> str:
    problem_mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)

    if problem_mark is not None:
        return (
            f"YAML syntax error near line {problem_mark.line + 1}, "
            f"column {problem_mark.column + 1}: {problem}"
        )

    return f"YAML syntax error: {problem}"
