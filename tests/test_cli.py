import json
import unittest
from io import StringIO
from unittest.mock import patch

from src.cli.main import main
from tests.helpers import sample_path


class CliTests(unittest.TestCase):
    def test_valid_deployment_exits_zero_text_format(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            exit_code = main([sample_path("valid_sap_ha_deployment.yaml")])
        self.assertEqual(exit_code, 0)
        self.assertIn("READY", out.getvalue())

    def test_invalid_syntax_exits_nonzero(self):
        with patch("sys.stdout", new_callable=StringIO):
            exit_code = main([sample_path("invalid_syntax.yaml")])
        self.assertEqual(exit_code, 1)

    def test_json_format_output_is_parseable(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            main([sample_path("risky_azure_config.yaml"), "--format", "json"])
        payload = json.loads(out.getvalue())
        self.assertIn("status", payload)
        self.assertIn("issues", payload)
        self.assertGreater(len(payload["issues"]), 0)

    def test_missing_file_returns_exit_code_two(self):
        with patch("sys.stderr", new_callable=StringIO):
            exit_code = main([sample_path("does_not_exist.yaml")])
        self.assertEqual(exit_code, 2)

    def test_generic_os_error_returns_exit_code_two(self):
        with patch("sys.stderr", new_callable=StringIO) as err, patch(
            "builtins.open", side_effect=PermissionError("permission denied")
        ):
            exit_code = main([sample_path("valid_sap_ha_deployment.yaml")])
        self.assertEqual(exit_code, 2)
        self.assertIn("permission denied", err.getvalue())

    def test_strict_mode_fails_on_warnings(self):
        with patch("sys.stdout", new_callable=StringIO):
            exit_code = main([sample_path("risky_linux_ha_deployment.yaml"), "--strict"])
        self.assertEqual(exit_code, 1)

    def test_non_strict_mode_succeeds_on_warnings_only(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            exit_code = main([sample_path("warnings_only_deployment.yaml")])
        self.assertEqual(exit_code, 0)
        self.assertIn("READY WITH WARNINGS", out.getvalue())

    def test_strict_mode_fails_when_only_warnings_present(self):
        with patch("sys.stdout", new_callable=StringIO):
            exit_code = main([sample_path("warnings_only_deployment.yaml"), "--strict"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
