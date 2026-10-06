from typing import List, Dict, Optional


class ContextAwareFixGenerator:
    """
    Generates context-aware, framework-specific code remediation snippets
    based on the detected technology stack and vulnerability type.
    """

    REMEDIATION_RULES = {
        # XSS (Reflected / Stored / DOM)
        "xss": {
            "Laravel": {
                "desc": "Use Blade automatic escaping `{{ $var }}` instead of raw `{!! $var !!}`. For DOM XSS in React/Vue components, sanitize with DOMPurify.",
                "code": """// Laravel Blade Template:
// ❌ Dangerous (Raw HTML unescaped):
{!! $userInput !!}

// ✅ Secure (Blade Auto-Escaping):
{{ $userInput }}

// Frontend (React/Vue inside Laravel SPA):
import DOMPurify from 'dompurify';
const cleanHTML = DOMPurify.sanitize(userInput);""",
            },
            "Express.js": {
                "desc": "Sanitize user input before rendering in templates or returning HTML, and use DOMPurify for frontend rendering.",
                "code": """// Express.js & Node.js:
const sanitizeHtml = require('sanitize-html');

app.get('/search', (req, res) => {
    // ✅ Sanitize untrusted input before rendering
    const safeQuery = sanitizeHtml(req.query.q, { allowedTags: [], allowedAttributes: {} });
    res.send(`<h1>Results for: ${safeQuery}</h1>`);
});""",
            },
            "Django": {
                "desc": "Rely on Django template engine auto-escaping. Avoid using `|safe` filter or `mark_safe()` on untrusted data.",
                "code": """# Django Template / View:
# ❌ Dangerous:
# {{ user_input|safe }}

# ✅ Secure (Django template default auto-escape):
{{ user_input }}

# Python View:
from django.utils.html import escape
safe_text = escape(request.GET.get('q', ''))""",
            },
            "Java / Spring Boot": {
                "desc": "Escape output using Spring's `HtmlUtils` or Thymeleaf default `th:text` evaluation.",
                "code": """// Spring Boot Controller:
import org.springframework.web.util.HtmlUtils;

@GetMapping("/search")
public String search(@RequestParam String query, Model model) {
    // ✅ Escape HTML entities
    String safeQuery = HtmlUtils.htmlEscape(query);
    model.addAttribute("query", safeQuery);
    return "search";
}

// Thymeleaf View:
// ✅ Secure (escaped by default): <span th:text="${query}"></span>""",
            },
            "Default": {
                "desc": "Sanitize all user-controllable input using context-aware encoding or DOMPurify before inserting into DOM/HTML.",
                "code": """// Standard JavaScript / Web Fix:
import DOMPurify from 'dompurify';

// ❌ Dangerous: element.innerHTML = location.hash;
// ✅ Secure:
element.textContent = userInput; // or DOMPurify.sanitize(userInput)""",
            },
        },

        # SQL Injection
        "sqli": {
            "Laravel": {
                "desc": "Always use Laravel Eloquent ORM or DB query builder with bound parameter placeholders `?` / `:param`.",
                "code": """// Laravel Eloquent / DB Builder:
// ❌ Dangerous (Raw String Concatenation):
DB::select("SELECT * FROM users WHERE email = '" . $request->input('email') . "'");

// ✅ Secure (Parameter Binding):
$users = DB::table('users')->where('email', $request->input('email'))->get();
// Or raw with bindings:
DB::select("SELECT * FROM users WHERE email = ?", [$email]);""",
            },
            "Express.js": {
                "desc": "Use parameterized queries with pg/mysql2/Knex/Prisma ORM instead of string concatenation.",
                "code": """// Node.js (pg / Knex / Prisma):
// ❌ Dangerous:
db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);

// ✅ Secure (Parameterized Query):
db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);""",
            },
            "Django": {
                "desc": "Use Django ORM methods (`filter`, `get`). Avoid `RawSQL` or raw `.raw()` queries with string formatting.",
                "code": """# Django ORM:
# ❌ Dangerous:
# User.objects.raw(f"SELECT * FROM myapp_user WHERE username = '{user_input}'")

# ✅ Secure (Django ORM parameterized query):
user = User.objects.filter(username=request.GET.get('user')).first()""",
            },
            "Java / Spring Boot": {
                "desc": "Use JPA Repositories or Named Parameter Queries with `@Param` annotations.",
                "code": """// Spring Data JPA:
// ❌ Dangerous:
// entityManager.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");

// ✅ Secure (JPA Query Parameters):
@Query("SELECT u FROM User u WHERE u.username = :username")
Optional<User> findByUsername(@Param("username") String username);""",
            },
            "Default": {
                "desc": "Use prepared statements (parameterized queries) with PDO / database drivers.",
                "code": """// Prepared Statements (PDO / Standard DB):
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();""",
            },
        },

        # SSRF (Server-Side Request Forgery)
        "ssrf": {
            "Express.js": {
                "desc": "Validate hostnames against an explicit domain whitelist and restrict requests to private IP ranges (RFC 1918).",
                "code": """// Node.js SSRF Protection:
const ipaddr = require('ipaddr.js');
const { URL } = require('url');

function isSafeUrl(targetUrl) {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    // Disallow local/private IPs (127.0.0.1, 10.x, 192.168.x, 169.254.x)
    const addr = ipaddr.parse(parsed.hostname);
    return addr.range() === 'unicast'; // Block loopback/private ranges
}""",
            },
            "Django": {
                "desc": "Use Python's `ipaddress` module to verify that destination IP is non-private before performing HTTP fetches.",
                "code": """# Python / Django SSRF Protection:
import socket, ipaddress
from urllib.parse import urlparse

def validate_url(url):
    parsed = urlparse(url)
    ip_str = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(ip_str)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("Access to internal IP range is prohibited")
    return True""",
            },
            "Default": {
                "desc": "Validate outbound URLs against a domain whitelist and enforce private IP blocking (127.0.0.1, 169.254.169.254).",
                "code": """// SSRF Defense Rule:
// 1. Enforce strict HTTP/HTTPS protocol scheme.
// 2. Resolve DNS and reject loopback/RFC 1918 internal addresses.
// 3. Disable HTTP redirects or re-validate redirect target URLs.""",
            },
        },

        # LFI / Path Traversal
        "lfi": {
            "Laravel": {
                "desc": "Use `basename()` or Storage disk abstraction instead of passing raw path parameters to file operations.",
                "code": """// Laravel File Storage:
// ❌ Dangerous: return response()->file(storage_path('app/' . $request->input('file')));

// ✅ Secure:
$filename = basename($request->input('file'));
return Storage::disk('local')->download($filename);""",
            },
            "Express.js": {
                "desc": "Resolve paths using `path.resolve()` and verify that the target path stays inside the intended root directory.",
                "code": """// Node.js Path Traversal Defense:
const path = require('path');
const ROOT_DIR = path.resolve('/var/www/uploads');

function getSafeFilePath(userInput) {
    const safePath = path.resolve(ROOT_DIR, path.basename(userInput));
    if (!safePath.startsWith(ROOT_DIR)) {
        throw new Error("Directory traversal detected!");
    }
    return safePath;
}""",
            },
            "Default": {
                "desc": "Sanitize file input with `basename()` and verify path canonicalization.",
                "code": """// Secure Path Canonicalization:
$baseDir = '/var/www/public/uploads/';
$realPath = realpath($baseDir . basename($userFile));
if ($realPath === false || strpos($realPath, $baseDir) !== 0) {
    die("Access Denied: Path Traversal Detected");
}""",
            },
        },
        # RCE / Command Injection
        "rce": {

            "Express.js": {
                "desc": "Avoid using `eval()` or `child_process.exec()` with user input. Use `execFile` or `spawn` with an explicit argument array.",
                "code": """// Node.js Exec Security:
const { execFile } = require('child_process');

// ❌ Dangerous: exec(`ping ${req.query.host}`);
// ✅ Secure (Argument Array - No Shell Invocation):
execFile('/bin/ping', ['-c', '1', req.query.host], (error, stdout) => {
    res.send(stdout);
});""",
            },
            "Django": {
                "desc": "Avoid `os.system()` or `subprocess.Popen(..., shell=True)`. Pass arguments as a list without shell execution.",
                "code": """# Python Exec Security:
import subprocess

# ❌ Dangerous: subprocess.Popen(f"ping {host}", shell=True)
# ✅ Secure (shell=False with argument list):
subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True)""",
            },
            "Default": {
                "desc": "Avoid executing dynamic system commands. If required, sanitize inputs against an strict regex whitelist and avoid shell execution.",
                "code": """// Secure Command Execution Rule:
// Pass arguments in an isolated array to prevent shell command chained execution (&&, ||, ;, `).""",
            },
        },

        # SSTI (Server-Side Template Injection)
        "ssti": {
            "Laravel": {
                "desc": "Avoid compiling unverified user strings into Blade templates dynamically using `Blade::render()`.",
                "code": """// Laravel Blade SSTI Fix:
// ❌ Dangerous: Blade::render($request->input('template_code'));
// ✅ Secure: Pass user input as a variable parameter into static blade views.
return view('pages.custom', ['content' => $userInput]);""",
            },
            "Django": {
                "desc": "Render static template files instead of passing raw user input strings to `Template(user_string)`.",
                "code": """# Django SSTI Fix:
# ❌ Dangerous: Template(request.GET.get('tpl')).render(Context({}))
# ✅ Secure:
return render(request, 'my_template.html', {'data': user_data})""",
            },
            "Default": {
                "desc": "Never pass user-controlled input as raw template source code. Render predefined static template files and bind variables contextually.",
                "code": "",
            },
        },

        # CORS Misconfiguration
        "cors": {
            "Express.js": {
                "desc": "Specify an explicit domain origin whitelist instead of `cors({ origin: '*' })` with credentials enabled.",
                "code": """// Node.js CORS Security:
const cors = require('cors');

const corsOptions = {
    origin: ['https://app.target.com', 'https://admin.target.com'],
    credentials: true,
};
app.use(cors(corsOptions));""",
            },
            "Laravel": {
                "desc": "Configure `config/cors.php` with trusted origins and avoid wildcard `*` with `supports_credentials = true`.",
                "code": """// config/cors.php:
return [
    'paths' => ['api/*'],
    'allowed_origins' => ['https://app.target.com'],
    'supports_credentials' => true,
];""",
            },
            "Default": {
                "desc": "Set strict `Access-Control-Allow-Origin` response headers and do not reflect untrusted `Origin` request headers blindly.",
                "code": "",
            },
        },
    }


    @classmethod
    def generate_fix(cls, finding_type: str, tech_stack: List[str]) -> Dict[str, str]:
        """
        Generates a remediation description and code snippet matching the vulnerability type
        and detected framework.
        """
        ftype_lower = finding_type.lower()

        # Categorize vulnerability type
        category = None
        if "xss" in ftype_lower:
            category = "xss"
        elif "sqli" in ftype_lower or "sql" in ftype_lower:
            category = "sqli"
        elif "ssrf" in ftype_lower:
            category = "ssrf"
        elif "lfi" in ftype_lower or "traversal" in ftype_lower or "file" in ftype_lower:
            category = "lfi"
        elif "rce" in ftype_lower or "command" in ftype_lower:
            category = "rce"
        elif "ssti" in ftype_lower or "template" in ftype_lower:
            category = "ssti"
        elif "cors" in ftype_lower:
            category = "cors"

        if not category or category not in cls.REMEDIATION_RULES:
            return {
                "desc": "Enforce strict input validation, sanitize output, and apply the Principle of Least Privilege across all layers.",
                "code": "",
            }


        rules = cls.REMEDIATION_RULES[category]

        # Match against detected tech stack
        for tech in tech_stack:
            if tech in rules:
                return rules[tech]

        # Fallback to Default
        return rules.get("Default", {
            "desc": "Apply contextual input validation and output encoding.",
            "code": "",
        })
