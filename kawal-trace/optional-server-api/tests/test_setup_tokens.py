from __future__ import annotations
import unittest
import os
import tempfile
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup_tokens

class SetupTokenMapTests(unittest.TestCase):
    def test_upsert_preserves_other_device_entries(self):
        raw = "device-old|" + "a" * 64 + ";device-new|" + "b" * 64
        result = setup_tokens._upsert_token_map(raw, "device-third", "c" * 64)
        self.assertIn("device-old|" + "a" * 64, result)
        self.assertIn("device-new|" + "b" * 64, result)
        self.assertIn("device-third|" + "c" * 64, result)

    def test_upsert_replaces_only_same_identity(self):
        raw = "device-one|" + "a" * 64 + ";device-two|" + "b" * 64
        result = setup_tokens._upsert_token_map(raw, "device-one", "c" * 64)
        self.assertEqual(result, "device-one|" + "c" * 64 + ";device-two|" + "b" * 64)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "legacy token setup refusal requires root")
    def test_main_refuses_to_rotate_existing_ids(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "api.env"
            original = "KAWAL_AUDIT_TOKENS=cl-same-device-0001|" + "a" * 64 + "\nKAWAL_API_PORT=8765\n"
            path.write_text(original)
            old_path = setup_tokens.ENV_PATH
            setup_tokens.ENV_PATH = path
            answers = iter(["cl-same-device-0001", "ubuntu-new", ""])
            try:
                with patch("builtins.input", side_effect=lambda _prompt: next(answers)):
                    with self.assertRaises(SystemExit) as cm:
                        setup_tokens.main()
                self.assertIn("Tidak ada konfigurasi yang diubah", str(cm.exception))
                self.assertEqual(path.read_text(), original)
            finally:
                setup_tokens.ENV_PATH = old_path

if __name__ == "__main__":
    unittest.main(verbosity=2)
