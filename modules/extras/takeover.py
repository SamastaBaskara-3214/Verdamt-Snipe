import sys
import os
import socket
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import concurrent.futures
from typing import List, Dict
from core.ui import ph, i, p, w, draw_table, Spinner, G, Y, R, N, GY, W, C, B

class TakeoverChecker:
    """Check for dangling CNAMEs and potential subdomain takeovers."""

    SERVICES = {
        "amazonaws.com": "AWS/S3",
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "bitbucket.io": "Bitbucket",
        "cloudfront.net": "Cloudfront",
        "azurewebsites.net": "Azure",
        "wpengine.com": "WPEngine",
        "zendesk.com": "Zendesk",
        "readme.io": "Readme.io",
        "myshopify.com": "Shopify"
    }

    def __init__(self, subdomains: List[str]):
        self.subdomains = subdomains
        self.findings = []

    def _check_cname(self, sub: str) -> Dict:
        try:
            # We use a simple way to find CNAME without external libs
            # On Linux, 'host' or 'dig' is usually available, or we can use socket
            # But socket.gethostbyname doesn't return CNAME.
            # We'll use a hacky way or assume 'host' is available.
            import subprocess
            cmd = ["host", "-t", "CNAME", sub]
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            if "is an alias for" in res:
                cname = res.split("is an alias for")[-1].strip().rstrip(".")
                for sig, name in self.SERVICES.items():
                    if sig in cname:
                        return {"sub": sub, "cname": cname, "service": name, "risk": "High"}
        except Exception:
            pass
        return None

    def run(self) -> List[Dict]:
        ph("TAKEOVER ENGINE: Hunting Dangling CNAMEs")
        i(f"Checking {W}{len(self.subdomains)}{N} subdomains for takeover risks...")
        
        results = []
        spin = Spinner("Analyzing CNAME records...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futs = {executor.submit(self._check_cname, s): s for s in self.subdomains}
            for f in concurrent.futures.as_completed(futs):
                spin.next()
                r = f.result()
                if r:
                    spin.stop()
                    results.append(r)
                    print(f"  {R}[!!]{N} {B}{R}POTENTIAL TAKEOVER:{N} {W}{r['sub']}{N} -> {Y}{r['cname']}{N} ({r['service']})")
        spin.stop()
        
        if results:
            rows = [[f"{R}HIGH{N}", r["sub"], r["service"]] for r in results]
            draw_table(["RISK", "SUBDOMAIN", "SERVICE"], rows, title="Subdomain Takeover Findings")
        else:
            p("No dangling CNAMEs found.")
            
        return results
