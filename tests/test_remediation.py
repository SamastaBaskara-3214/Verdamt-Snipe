import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.recon.tech_detector import TechStackDetector
from reports.remediation import ContextAwareFixGenerator
from reports.engine import PoCGenerator, ReportEngine


class TestFrameworkRemediation(unittest.TestCase):
    def test_tech_stack_detector_headers(self):
        service = {
            "headers": {
                "server": "nginx/1.18.0",
                "x-powered-by": "Express",
                "set-cookie": "connect.sid=s%3A1234; Path=/; HttpOnly"
            },
            "body": "<html><body><div data-reactroot=''></div></body></html>"
        }
        techs = TechStackDetector.detect_from_service(service)
        self.assertIn("Express.js", techs)
        self.assertIn("Nginx", techs)
        self.assertIn("React", techs)

    def test_remediation_generator_laravel(self):
        fix = ContextAwareFixGenerator.generate_fix("dom_xss", ["Laravel", "PHP"])
        self.assertIn("Blade", fix["desc"])
        self.assertIn("{{ $userInput }}", fix["code"])

    def test_remediation_generator_express(self):
        fix = ContextAwareFixGenerator.generate_fix("sqli_error", ["Express.js", "Node.js"])
        self.assertIn("pg", fix["desc"])
        self.assertIn("db.query", fix["code"])

    def test_poc_generator_steps_includes_remediation(self):
        finding = {
            "type": "dom_xss",
            "title": "DOM XSS in innerHTML",
            "url": "https://example.com/app#test",
            "detail": "Sink: innerHTML, Source: location.hash"
        }
        steps = PoCGenerator.generate_steps(finding, tech_stack=["Laravel"])
        self.assertEqual(len(steps), 6)
        self.assertIn("Step 6:", steps[5]["title"])
        self.assertIn("Laravel", steps[5]["title"])
        self.assertIn("Blade", steps[5]["desc"])


if __name__ == "__main__":
    unittest.main()
