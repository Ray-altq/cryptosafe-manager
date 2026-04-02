import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gui.widgets.secure_table import SecureTable


class FakeTree:
    def __init__(self):
        self.displaycolumns = None

    def configure(self, **kwargs):
        if "displaycolumns" in kwargs:
            self.displaycolumns = list(kwargs["displaycolumns"])


class TestSecureTable(unittest.TestCase):
    def test_reorder_display_columns_updates_visible_order(self):
        table = SecureTable.__new__(SecureTable)
        table._column_order = ["title", "username", "url"]
        table.tree = FakeTree()

        table._reorder_display_columns("url", "username")

        self.assertEqual(table._column_order, ["title", "url", "username"])
        self.assertEqual(table.tree.displaycolumns, ["title", "url", "username"])

    def test_reorder_display_columns_ignores_unknown_columns(self):
        table = SecureTable.__new__(SecureTable)
        table._column_order = ["title", "username", "url"]
        table.tree = FakeTree()

        table._reorder_display_columns("missing", "username")

        self.assertEqual(table._column_order, ["title", "username", "url"])
        self.assertIsNone(table.tree.displaycolumns)


if __name__ == "__main__":
    unittest.main()
