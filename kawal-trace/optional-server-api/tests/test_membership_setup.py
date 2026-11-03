from __future__ import annotations
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup_admin_token

@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "setup_admin_token security behavior requires root")
class AdminTokenSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "api.env"
        self.path.write_text(
            "KAWAL_AUDIT_TOKENS=cl-legacy|" + "a" * 64 + "\n"
            + "KAWAL_RESPONSE_TOKENS=cl-legacy|" + "b" * 64 + "\n"
            + "KAWAL_API_PORT=8765\n"
        )
        setup_admin_token.ENV_PATH = self.path

    def tearDown(self):
        self.temp.cleanup()

    def test_adds_admin_key_without_touching_device_tokens(self):
        before = self.path.read_text()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = setup_admin_token.main()
        self.assertEqual(code, 0)
        after = self.path.read_text()
        self.assertIn("KAWAL_ADMIN_TOKEN=", after)
        self.assertIn("KAWAL_AUDIT_TOKENS=cl-legacy|" + "a" * 64, after)
        self.assertIn("KAWAL_RESPONSE_TOKENS=cl-legacy|" + "b" * 64, after)
        self.assertIn("KAWAL_API_PORT=8765", after)
        admin_line = next(line for line in after.splitlines() if line.startswith("KAWAL_ADMIN_TOKEN="))
        self.assertEqual(len(admin_line.split("=", 1)[1]), 64)
        self.assertNotIn("KAWAL_ADMIN_TOKEN", before)

    def test_second_run_does_not_rotate_or_print_existing_key(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            setup_admin_token.main()
        once = self.path.read_text()
        first_token = next(line for line in once.splitlines() if line.startswith("KAWAL_ADMIN_TOKEN="))
        output2 = io.StringIO()
        with contextlib.redirect_stdout(output2):
            setup_admin_token.main()
        self.assertEqual(self.path.read_text(), once)
        self.assertIn("sudah dikonfigurasi", output2.getvalue())
        self.assertNotIn(first_token.split("=", 1)[1], output2.getvalue())

if __name__ == "__main__":
    unittest.main(verbosity=2)
