import unittest
import requests
import time
import threading
import sys
import os

# To test the API without mocking, we assume the server is running.
API_URL = "http://127.0.0.1:5000"

class TestPhishGuardAPI(unittest.TestCase):
    def test_health(self):
        try:
            res = requests.get(f"{API_URL}/health")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "ok")
            self.assertTrue(data["model_loaded"])
        except requests.exceptions.ConnectionError:
            self.skipTest("Backend server is not running on port 5000")

    def test_predict_legitimate(self):
        try:
            res = requests.post(f"{API_URL}/predict", json={"url": "https://google.com"})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertIn("prediction", data)
            self.assertIn("confidence", data)
        except requests.exceptions.ConnectionError:
            self.skipTest("Backend server is not running on port 5000")

    def test_predict_invalid_url(self):
        try:
            res = requests.post(f"{API_URL}/predict", json={"url": "not-a-url"})
            self.assertEqual(res.status_code, 400)
            self.assertIn("error", res.json())
        except requests.exceptions.ConnectionError:
            self.skipTest("Backend server is not running on port 5000")

if __name__ == '__main__':
    print("Ensure the Flask backend is running on port 5000 before executing tests.")
    unittest.main()
