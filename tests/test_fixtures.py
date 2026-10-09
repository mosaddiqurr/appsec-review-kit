"""Behavioral evidence behind examples, not a general vulnerability scanner."""

import unittest

from examples.fixtures.object_access import insecure_get_note, secure_get_note
from examples.fixtures.unsafe_config import UNSAFE_CONFIG, SYNTHETIC_MARKER, production_config


class FixtureTests(unittest.TestCase):
    def test_before_allows_cross_user_access(self):
        # The harness passes by reproducing a failed security requirement.
        self.assertEqual(insecure_get_note("bob", "alice-note")["owner"], "alice")

    def test_after_denies_cross_user_access(self):
        with self.assertRaises(PermissionError):
            secure_get_note("bob", "alice-note")

    def test_owner_still_reads_own_note(self):
        self.assertEqual(secure_get_note("alice", "alice-note")["text"], "Synthetic Alice note")

    def test_missing_and_anonymous_access_denied(self):
        for caller, note_id in (("alice", "missing"), (None, "alice-note")):
            with self.subTest(caller=caller, note_id=note_id):
                with self.assertRaises(PermissionError):
                    secure_get_note(caller, note_id)

    def test_results_cannot_mutate_stored_note(self):
        note = secure_get_note("alice", "alice-note")
        note["owner"] = "bob"
        self.assertEqual(secure_get_note("alice", "alice-note")["owner"], "alice")

    def test_unsafe_flag_is_only_configuration_evidence(self):
        self.assertTrue(UNSAFE_CONFIG["debug"])
        self.assertEqual(UNSAFE_CONFIG["environment"], "production")
        self.assertEqual(SYNTHETIC_MARKER, "SYNTHETIC-NOT-A-CREDENTIAL")

    def test_secure_production_configuration(self):
        self.assertFalse(production_config()["debug"])
        with self.assertRaises(ValueError):
            production_config(debug=True)


if __name__ == "__main__":
    unittest.main()
