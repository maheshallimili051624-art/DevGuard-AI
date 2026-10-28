import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app


class TestDevGuardAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch("app.services.ollama_client.requests.get")
    def test_health_endpoint_connected(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [{"name": "gemma4:e2b"}, {"name": "llama3:latest"}]
        }
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["ollama"], "connected")
        self.assertTrue(data["model_available"])

    @patch("app.services.ollama_client.requests.get")
    def test_health_endpoint_disconnected(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "offline")
        self.assertFalse(data["model_available"])

    def test_invalid_zip_archive_rejected(self):
        # Uploading non-zip file or corrupt bytes
        files = {"file": ("test.zip", b"not a valid zip binary", "application/zip")}
        res = self.client.post("/api/analyze-archive", files=files)
        self.assertEqual(res.status_code, 400)
        self.assertIn("not a valid ZIP", res.json()["detail"])

    def test_empty_code_rejected(self):
        res = self.client.post("/api/analyze", json={"code": ""})
        self.assertEqual(res.status_code, 422)

    @patch("app.services.ollama_client.requests.post")
    def test_analyze_snippet_mock_ollama(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "message": {"content": "Mocked security review: Found eval and debug=True."}
        }
        res = self.client.post("/api/analyze", json={
            "code": "eval('print(1)'); debug = True",
            "language": "Python"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("Mocked security review", data["analysis"])
        self.assertTrue(any(f["severity"] == "High" for f in data["findings"]))

    def test_dependency_scan_offline(self):
        req_content = "fastapi==0.115.0\npydantic>=2.0"
        res = self.client.post("/api/scan-dependencies", json={
            "manifest_type": "requirements.txt",
            "content": req_content,
            "enable_online_lookup": False
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["packages_parsed"], 2)
        self.assertFalse(data["online_lookup_performed"])

    def test_scans_history_listing(self):
        res = self.client.get("/api/scans")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)


if __name__ == "__main__":
    unittest.main()
