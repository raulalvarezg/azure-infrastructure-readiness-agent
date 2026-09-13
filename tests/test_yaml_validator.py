import unittest

from src.validators.yaml_validator import (
    validate_structure,
    validate_yaml_file,
    validate_yaml_syntax,
)
from tests.helpers import read_sample, sample_path


class YamlSyntaxValidatorTests(unittest.TestCase):
    def test_valid_yaml_parses_successfully(self):
        result = validate_yaml_syntax(read_sample("valid_sap_ha_deployment.yaml"))
        self.assertTrue(result.valid)
        self.assertIsNone(result.error)
        self.assertIsInstance(result.data, dict)

    def test_invalid_yaml_reports_error(self):
        result = validate_yaml_syntax(read_sample("invalid_syntax.yaml"))
        self.assertFalse(result.valid)
        self.assertIsNone(result.data)
        self.assertIn("line", result.error)

    def test_empty_string_parses_to_none(self):
        result = validate_yaml_syntax("")
        self.assertTrue(result.valid)
        self.assertIsNone(result.data)

    def test_validate_yaml_file_reads_from_disk(self):
        result = validate_yaml_file(sample_path("risky_azure_config.yaml"))
        self.assertTrue(result.valid)
        self.assertIsInstance(result.data, dict)

    def test_validate_yaml_file_missing_file(self):
        result = validate_yaml_file(sample_path("does_not_exist.yaml"))
        self.assertFalse(result.valid)
        self.assertIn("Could not read file", result.error)


class StructureValidatorTests(unittest.TestCase):
    def test_none_document_is_invalid(self):
        result = validate_structure(None)
        self.assertFalse(result.valid)
        self.assertIn("empty", result.error)

    def test_non_mapping_document_is_invalid(self):
        result = validate_structure(["a", "list", "not", "a", "map"])
        self.assertFalse(result.valid)
        self.assertIn("mapping", result.error)

    def test_mapping_document_is_valid(self):
        result = validate_structure({"metadata": {"name": "x"}})
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main()
