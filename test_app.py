import unittest

import app as scam_app


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        scam_app.app.config["TESTING"] = True
        self.client = scam_app.app.test_client()

    def test_message_flags_credential_and_urgency(self):
        result = scam_app.analyze_message(
            "URGENT: verify your account now and send your one-time code."
        )
        ids = {flag["id"] for flag in result["flags"]}
        self.assertIn("urgency", ids)
        self.assertIn("credentials", ids)
        self.assertGreater(result["score"], 0)

    def test_url_checks_do_not_fetch_and_flag_http(self):
        result = scam_app.inspect_url("http://bit.ly/login")
        ids = {flag["id"] for flag in result["flags"]}
        self.assertTrue({"http", "shortener", "sensitive-path"}.issubset(ids))
        self.assertEqual(result["host"], "bit.ly")

    def test_rejects_invalid_url(self):
        with self.assertRaises(ValueError):
            scam_app.inspect_url("javascript:alert(1)")

    def test_rejects_malformed_host(self):
        with self.assertRaises(ValueError):
            scam_app.inspect_url("https://not a valid host.example")

    def test_accepts_ip_and_unicode_domain_hosts(self):
        self.assertEqual(scam_app.inspect_url("https://192.0.2.1")["host"], "192.0.2.1")
        self.assertEqual(scam_app.inspect_url("https://пример.рф")["host"], "пример.рф")

    def test_api_validates_input_and_returns_explanations(self):
        response = self.client.post(
            "/api/analyze",
            json={"mode": "message", "text": "You won a prize, pay now with bitcoin!"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["flags"])
        self.assertTrue(data["recommendations"])
        self.assertIn("not an AI/ML model", data["method"])

    def test_api_rejects_oversized_input(self):
        response = self.client.post(
            "/api/analyze",
            json={"mode": "message", "text": "x" * (scam_app.MAX_INPUT_LENGTH + 1)},
        )
        self.assertEqual(response.status_code, 413)

    def test_home_page_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
