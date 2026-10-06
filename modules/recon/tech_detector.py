import re
from typing import Dict, List, Set


class TechStackDetector:
    """
    Analyzes HTTP response headers, cookies, and HTML body signatures to identify
    frameworks, web servers, and programming languages.
    """

    HEADER_FINGERPRINTS = [
        # (Header_Name, Regex_Pattern, Tech_Name, Category)
        ("x-powered-by", r"express", "Express.js", "Framework"),
        ("x-powered-by", r"next\.js", "Next.js", "Framework"),
        ("x-powered-by", r"php", "PHP", "Language"),
        ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"),
        ("x-powered-by", r"laravel", "Laravel", "Framework"),
        ("x-powered-by", r"rails|ruby", "Ruby on Rails", "Framework"),
        ("x-powered-by", r"django", "Django", "Framework"),
        ("server", r"nginx", "Nginx", "WebServer"),
        ("server", r"apache", "Apache", "WebServer"),
        ("server", r"cloudflare", "Cloudflare", "WAF/CDN"),
        ("server", r"werkzeug|gunicorn", "Flask/Python", "Framework"),
        ("server", r"kestrel", "ASP.NET Core", "Framework"),
        ("server", r"caddy", "Caddy", "WebServer"),
    ]

    COOKIE_FINGERPRINTS = [
        # (Cookie_Name_Regex, Tech_Name, Category)
        (r"laravel_session|XSRF-TOKEN", "Laravel", "Framework"),
        (r"PHPSESSID", "PHP", "Language"),
        (r"connect\.sid", "Express.js", "Framework"),
        (r"csrftoken|sessionid", "Django", "Framework"),
        (r"JSESSIONID", "Java / Spring Boot", "Framework"),
        (r"ASP\.NET_SessionId|__RequestVerificationToken", "ASP.NET", "Framework"),
        (r"_rails_session|_session_id", "Ruby on Rails", "Framework"),
    ]

    BODY_FINGERPRINTS = [
        # (Regex_Pattern, Tech_Name, Category)
        (r"wp-content|wp-includes", "WordPress", "CMS"),
        (r"_next/static|__NEXT_DATA__", "Next.js", "Framework"),
        (r"data-reactroot|react-dom", "React", "Frontend"),
        (r"v-data-|data-v-|vue", "Vue.js", "Frontend"),
        (r"ng-version|ng-app", "Angular", "Frontend"),
        (r"livewire/livewire\.js", "Laravel Livewire", "Framework"),
        (r"csrf-param.*csrf-token.*rails", "Ruby on Rails", "Framework"),
        (r"django-form", "Django", "Framework"),
    ]

    @classmethod
    def detect_from_service(cls, service: Dict) -> List[str]:
        """Detect tech stack from a single service dict (headers, body, cookies)."""
        detected: Set[str] = set()

        headers = service.get("headers", {}) or {}
        # Normalize header keys to lowercase
        headers_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}

        # 1. Header fingerprinting
        for header_name, pattern, tech_name, _ in cls.HEADER_FINGERPRINTS:
            if header_name in headers_lower:
                val = headers_lower[header_name]
                if re.search(pattern, val, re.I):
                    detected.add(tech_name)

        # 2. Cookie fingerprinting
        cookies_header = headers_lower.get("set-cookie", "")
        for cookie_pat, tech_name, _ in cls.COOKIE_FINGERPRINTS:
            if re.search(cookie_pat, cookies_header, re.I):
                detected.add(tech_name)

        # 3. HTML Body fingerprinting
        body = service.get("body", "") or ""
        if body:
            for pattern, tech_name, _ in cls.BODY_FINGERPRINTS:
                if re.search(pattern, body, re.I):
                    detected.add(tech_name)

        return sorted(list(detected))

    @classmethod
    def detect_from_services(cls, services: List[Dict]) -> List[str]:
        """Detect combined tech stack across all probed services."""
        combined: Set[str] = set()
        for svc in services:
            techs = cls.detect_from_service(svc)
            combined.update(techs)
        return sorted(list(combined))
