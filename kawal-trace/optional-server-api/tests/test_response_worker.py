import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import response_worker

class ResponseWorkerValidationTests(unittest.TestCase):
    def test_public_ipv4_allowed_when_not_admin_ip(self):
        self.assertEqual(response_worker.validate_target("8.8.8.8", 300, {"1.1.1.1"}), "8.8.8.8")
    def test_private_address_rejected(self):
        with self.assertRaises(ValueError): response_worker.validate_target("127.0.0.1", 300, {"1.1.1.1"})
    def test_admin_allowlisted_address_rejected(self):
        with self.assertRaises(ValueError): response_worker.validate_target("1.1.1.1", 300, {"1.1.1.1"})
    def test_empty_allowlist_fails_closed(self):
        with self.assertRaises(ValueError): response_worker.validate_target("8.8.8.8", 300, set())
    def test_ttl_is_bounded(self):
        with self.assertRaises(ValueError): response_worker.validate_target("8.8.8.8", 3600, {"1.1.1.1"})
    def test_marker_is_bound_to_generated_action_id(self):
        self.assertEqual(response_worker.marker_for("abcdef0123456789abcdef0123456789"), "Kawal-Trace-abcdef012345")
        with self.assertRaises(ValueError): response_worker.marker_for("not-an-id")

if __name__ == "__main__": unittest.main(verbosity=2)
