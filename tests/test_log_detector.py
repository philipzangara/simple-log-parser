import unittest
from log_detector import detect_log_type

class TestDetectLogType(unittest.TestCase):

    def test_windows_event(self):
        self.assertEqual(detect_log_type("<xml> Sample</xml>"), "windows_event")

    def test_apache(self):
        self.assertEqual(detect_log_type("192.168.1.1 Blah Blah"), "apache")

    def test_auth_log(self):
        self.assertEqual(detect_log_type("Jul 18 10:13:22 ubuntu sshd[12456]: Failed password"), "auth_log")
    
    def test_unknown_log(self):
        self.assertEqual(detect_log_type("Failed password"), "unknown")

if __name__ == "__main__":
    unittest.main()