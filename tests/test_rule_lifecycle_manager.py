"""Tests for the database connection handling in rule_lifecycle_manager.py."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rule-synthesis-engine"))

import rule_lifecycle_manager  # noqa: E402


class TestDatabaseConnection(unittest.TestCase):
    def test_missing_database_url_raises_clear_error(self):
        with patch.object(rule_lifecycle_manager, "DATABASE_URL", None):
            with self.assertRaises(RuntimeError):
                rule_lifecycle_manager._get_connection()

    def test_sqlalchemy_dialect_suffix_is_stripped_before_connecting(self):
        url = "postgresql+psycopg2://user:pw@localhost:5432/db"
        with patch.object(rule_lifecycle_manager, "DATABASE_URL", url), patch.object(
            rule_lifecycle_manager.psycopg2, "connect"
        ) as connect:
            rule_lifecycle_manager._get_connection()
        connect.assert_called_once_with("postgresql://user:pw@localhost:5432/db")


if __name__ == "__main__":
    unittest.main()
