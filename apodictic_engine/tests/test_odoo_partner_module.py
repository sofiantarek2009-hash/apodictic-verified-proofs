import ast
import csv
import hashlib
import hmac
import importlib.util
import os
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ADDON_DIR = Path(__file__).resolve().parents[2] / "addons" / "apodictic_odoo_guard"


def _load_main_controller():
    ctrl_path = ADDON_DIR / "controllers" / "main.py"
    spec = importlib.util.spec_from_file_location("apodictic_odoo_guard_main", ctrl_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestOdooPartnerModule(unittest.TestCase):
    def test_manifest_valid_odoo18_to_20(self):
        manifest_path = ADDON_DIR / "__manifest__.py"
        self.assertTrue(manifest_path.exists(), f"Missing manifest at {manifest_path}")
        manifest = ast.literal_eval(manifest_path.read_text(encoding="utf-8"))
        self.assertIsInstance(manifest, dict)
        self.assertEqual(manifest.get("license"), "LGPL-3")
        self.assertTrue(manifest.get("installable"))
        self.assertIn("account", manifest.get("depends", []))
        self.assertTrue(manifest.get("version", "").startswith("18.0."))
        for rel in manifest.get("data", []):
            self.assertTrue((ADDON_DIR / rel).exists(), f"Manifest data file missing: {rel}")

    def test_python_files_valid_ast(self):
        py_files = list(ADDON_DIR.rglob("*.py"))
        self.assertGreaterEqual(len(py_files), 6)
        for pyf in py_files:
            ast.parse(pyf.read_text(encoding="utf-8"), filename=str(pyf))

    def test_views_valid_xml_and_settings_xpath(self):
        xml_files = list((ADDON_DIR / "views").glob("*.xml"))
        self.assertEqual(len(xml_files), 2)
        for xmlf in xml_files:
            root = ET.fromstring(xmlf.read_text(encoding="utf-8"))
            self.assertEqual(root.tag, "odoo")

    def test_acl_csv_valid(self):
        csv_path = ADDON_DIR / "security" / "ir.model.access.csv"
        with csv_path.open("r", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["model_id:id"], "model_apodictic_audit_event")

    def test_hmac_sha256_ingest_signature_verification(self):
        mod = _load_main_controller()
        secret = "odoo_partner_shared_secret"
        raw = b'{"model":"account.payment","method":"create","amount":85000}'
        good_sig = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()

        self.assertTrue(mod.verify_apodictic_signature(secret, raw, good_sig))
        self.assertFalse(mod.verify_apodictic_signature(secret, raw + b" ", good_sig))
        self.assertFalse(mod.verify_apodictic_signature("wrong_secret", raw, good_sig))
        self.assertFalse(mod.verify_apodictic_signature(secret, raw, ""))


if __name__ == "__main__":
    unittest.main()
