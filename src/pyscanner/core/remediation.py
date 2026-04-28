"""Remediation catalog — maps rule IDs to actionable fix guidance."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Remediation:
    owasp: str
    impact: str
    fix_hint: str
    safe_code: str | None = None


_CATALOG: dict[str, Remediation] = {
    "py.injection.eval-exec": Remediation(
        owasp="A03:2021 Injection",
        impact="Arbitrary code execution — attacker can run any Python on your server.",
        fix_hint="Replace eval() with ast.literal_eval() for data parsing, or remove entirely.",
        safe_code="import ast\nresult = ast.literal_eval(user_input)",
    ),
    "py.subprocess.shell-true": Remediation(
        owasp="A03:2021 Injection",
        impact="Shell meta-character injection — attacker can chain arbitrary OS commands.",
        fix_hint="Pass command as a list and set shell=False (the default).",
        safe_code='subprocess.run(["ls", "-la"], shell=False, check=True)',
    ),
    "py.os.system": Remediation(
        owasp="A03:2021 Injection",
        impact="Full shell access — any user-controlled substring becomes executable.",
        fix_hint="Replace os.system() with subprocess.run() using a list argument.",
        safe_code='subprocess.run(["ls", "-la"], check=True)',
    ),
    "py.pickle.loads": Remediation(
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Remote code execution via crafted pickle payloads.",
        fix_hint="Use json, msgpack, or protobuf instead of pickle for untrusted data.",
        safe_code="import json\ndata = json.loads(raw_bytes)",
    ),
    "py.yaml.unsafe-load": Remediation(
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Arbitrary object instantiation — attacker-controlled YAML triggers code execution.",
        fix_hint="Replace yaml.load() with yaml.safe_load().",
        safe_code="data = yaml.safe_load(stream)",
    ),
    "py.secrets.aws-cred": Remediation(
        owasp="A07:2021 Identification and Authentication Failures",
        impact="Leaked AWS credentials enable full account takeover.",
        fix_hint="Move credentials to environment variables or a secrets manager.",
        safe_code='import os\naws_key = os.environ["AWS_ACCESS_KEY_ID"]',
    ),
    "py.secrets.generic-assignment": Remediation(
        owasp="A07:2021 Identification and Authentication Failures",
        impact="Hardcoded secrets in source control are easily discovered by attackers.",
        fix_hint="Use environment variables, .env files (git-ignored), or a vault.",
        safe_code='api_key = os.environ.get("API_KEY")',
    ),
    "py.secrets.private-key": Remediation(
        owasp="A02:2021 Cryptographic Failures",
        impact="Exposed private key compromises all encrypted communications.",
        fix_hint="Store private keys in a secrets manager, never in source files.",
    ),
    "py.secrets.long-string": Remediation(
        owasp="A07:2021 Identification and Authentication Failures",
        impact="High-entropy string may be a token or key; verify it is not sensitive.",
        fix_hint="If this is a credential, externalize it. If not, consider adding a comment.",
    ),
    "py.ssl.verify-false": Remediation(
        owasp="A02:2021 Cryptographic Failures",
        impact="Disabling TLS verification enables man-in-the-middle attacks.",
        fix_hint="Remove verify=False; use a proper CA bundle if needed.",
        safe_code='requests.get(url, verify="/path/to/ca-bundle.crt")',
    ),
    "py.crypto.weak-hash": Remediation(
        owasp="A02:2021 Cryptographic Failures",
        impact="MD5/SHA1 are collision-prone; not suitable for security-sensitive hashing.",
        fix_hint="Use hashlib.sha256() or hashlib.blake2b() for integrity checks.",
        safe_code="digest = hashlib.sha256(data).hexdigest()",
    ),
    "py.crypto.random-not-secrets": Remediation(
        owasp="A02:2021 Cryptographic Failures",
        impact="random module uses a predictable PRNG; tokens generated with it are guessable.",
        fix_hint="Use secrets.token_urlsafe() or secrets.choice() for security-sensitive randomness.",
        safe_code="import secrets\ntoken = secrets.token_urlsafe(32)",
    ),
    "py.sql.injection": Remediation(
        owasp="A03:2021 Injection",
        impact="Attacker can read, modify, or delete database contents via crafted input.",
        fix_hint="Use parameterized queries with placeholders (?, %s) instead of string formatting.",
        safe_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    ),
    "py.path.traversal": Remediation(
        owasp="A01:2021 Broken Access Control",
        impact="Attacker can read or write files outside the intended directory.",
        fix_hint="Resolve the path and verify it stays within an allowed base directory.",
        safe_code=(
            "resolved = Path(base_dir, user_input).resolve()\n"
            "if not resolved.is_relative_to(base_dir):\n"
            '    raise ValueError("path traversal blocked")'
        ),
    ),
    "py.path.open-variable": Remediation(
        owasp="A01:2021 Broken Access Control",
        impact="If the path is user-controlled, attacker can access sensitive system files.",
        fix_hint="Validate and sanitize the path before opening.",
        safe_code=(
            "safe_path = Path(base_dir, filename).resolve()\n"
            "assert safe_path.is_relative_to(base_dir)\n"
            "data = safe_path.read_text()"
        ),
    ),
    "py.xss.markup": Remediation(
        owasp="A03:2021 Injection",
        impact="Unescaped HTML renders attacker-controlled scripts in users' browsers.",
        fix_hint="Escape user input before wrapping in Markup(), or use template auto-escaping.",
        safe_code="from markupsafe import escape\nresult = Markup(escape(user_input))",
    ),
    "py.xss.render-template-string": Remediation(
        owasp="A03:2021 Injection",
        impact="Server-side template injection — attacker can execute arbitrary server code.",
        fix_hint="Never pass user input as the template. Use render_template() with a file instead.",
        safe_code='return render_template("page.html", data=user_input)',
    ),
    "py.xss.mark-safe": Remediation(
        owasp="A03:2021 Injection",
        impact="Bypasses Django auto-escaping, allowing XSS if input is attacker-controlled.",
        fix_hint="Only use mark_safe() on content you fully control. Escape user input first.",
        safe_code="from django.utils.html import escape\nresult = mark_safe(escape(user_input))",
    ),
    "py.xss.response-html": Remediation(
        owasp="A03:2021 Injection",
        impact="Raw HTML response with dynamic content enables reflected XSS.",
        fix_hint="Use a template engine with auto-escaping instead of raw string responses.",
    ),
    "py.upload.unrestricted": Remediation(
        owasp="A04:2021 Insecure Design",
        impact="Attacker can upload web shells or malware without file-type validation.",
        fix_hint="Validate file extension and content-type; use werkzeug.utils.secure_filename().",
        safe_code=(
            "from werkzeug.utils import secure_filename\n"
            "fname = secure_filename(file.filename)\n"
            "if not fname.endswith(('.png', '.jpg', '.pdf')):\n"
            "    abort(400)"
        ),
    ),
    "py.upload.no-validation": Remediation(
        owasp="A04:2021 Insecure Design",
        impact="Files moved without validation may overwrite system files or execute malware.",
        fix_hint="Validate file type, size, and destination path before copying.",
    ),
    "py.config.debug-enabled": Remediation(
        owasp="A05:2021 Security Misconfiguration",
        impact="Debug mode exposes stack traces, environment variables, and interactive debugger (RCE).",
        fix_hint="Set DEBUG = False in production; use environment variables to toggle.",
        safe_code='DEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
    ),
    "py.config.cors-wildcard": Remediation(
        owasp="A05:2021 Security Misconfiguration",
        impact="Any website can make authenticated requests to your API.",
        fix_hint="Restrict CORS to specific trusted origins.",
        safe_code='CORS_ALLOWED_ORIGINS = ["https://yourdomain.com"]',
    ),
    "py.config.allowed-hosts-wildcard": Remediation(
        owasp="A05:2021 Security Misconfiguration",
        impact="Disables Django host header validation, enabling cache poisoning and password reset attacks.",
        fix_hint="Set ALLOWED_HOSTS to your actual domain(s).",
        safe_code='ALLOWED_HOSTS = ["yourdomain.com", "www.yourdomain.com"]',
    ),
    "py.config.weak-secret-key": Remediation(
        owasp="A02:2021 Cryptographic Failures",
        impact="Weak SECRET_KEY lets attackers forge session cookies and CSRF tokens.",
        fix_hint="Generate a strong random key and store it outside source code.",
        safe_code=(
            "import secrets\n"
            "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', secrets.token_urlsafe(64))"
        ),
    ),
    "py.supply.typosquat": Remediation(
        owasp="A06:2021 Vulnerable and Outdated Components",
        impact="Installing a typosquatted package may execute malicious code during install.",
        fix_hint="Verify the package name spelling on PyPI before installing.",
    ),
    "py.supply.known-malicious": Remediation(
        owasp="A06:2021 Vulnerable and Outdated Components",
        impact="This package is known to contain malware. It may steal credentials or install backdoors.",
        fix_hint="Remove this package immediately and audit your environment for compromise.",
    ),
}


def get_remediation(rule_id: str) -> Remediation | None:
    return _CATALOG.get(rule_id)


def get_owasp(rule_id: str) -> str | None:
    r = _CATALOG.get(rule_id)
    return r.owasp if r else None
