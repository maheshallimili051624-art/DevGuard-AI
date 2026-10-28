import unittest
from app.main import local_checks, scrub_secrets


class DevGuardChecksTest(unittest.TestCase):
    def test_eval_is_flagged(self):
        findings = local_checks("const result = eval(input);", "sample.js")
        self.assertTrue(any("eval" in item["title"].lower() for item in findings))

    def test_no_match_is_not_proof_of_safety(self):
        findings = local_checks("const x = 2 + 2;")
        self.assertTrue(findings)
        self.assertIn("does not prove", findings[0]["details"])

    def test_secret_redaction(self):
        cleaned, count = scrub_secrets('api_key = "abcdefghijklmno"')
        self.assertEqual(count, 1)
        self.assertNotIn("abcdefghijklmno", cleaned)


if __name__ == "__main__":
    unittest.main()
