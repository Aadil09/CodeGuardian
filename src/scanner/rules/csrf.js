'use strict';

// A01:2021 / A04:2021 — Cross-Site Request Forgery (CSRF)
// Covers: Node.js/Express, PHP, Python/Django/Flask, Java/Spring

const RULES = [
  // ── Node.js / Express ────────────────────────────────────────
  {
    id: 'CSRF-001',
    name: 'Express POST Route Without CSRF Protection',
    severity: 'HIGH',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['javascript', 'typescript'],
    pattern: /router\.post\s*\(\s*['"`][^'"`)]+['"`]\s*,\s*(?!.*csrf|.*csurf|.*xsrfToken)/gi,
    description: 'Express POST route registered without CSRF middleware. State-changing operations without CSRF tokens are vulnerable to cross-site request forgery.',
    remediation: 'Apply the csurf middleware (or Helmet\'s csrf) to all state-changing routes. Use SameSite=Strict cookies as an additional layer.',
  },
  {
    id: 'CSRF-002',
    name: 'Cookie Without SameSite Attribute',
    severity: 'MEDIUM',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['javascript', 'typescript'],
    pattern: /res\.cookie\s*\(\s*['"`]\w+['"`]\s*,[^)]*(?!\bsameSite\b)(?!\bSameSite\b)\)/gi,
    description: 'Session cookie set without SameSite attribute. Browsers default to SameSite=Lax, but explicit Strict is recommended for auth cookies.',
    remediation: 'Add sameSite: "strict" to all authentication cookies: res.cookie("session", val, { sameSite: "strict", httpOnly: true, secure: true }).',
  },
  {
    id: 'CSRF-003',
    name: 'CORS with Credentials Allowed from Wildcard Origin',
    severity: 'CRITICAL',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['javascript', 'typescript'],
    pattern: /cors\s*\(\s*\{[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*['"`]\*['"`]|cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`][^}]*credentials\s*:\s*true/gi,
    description: 'CORS configured with credentials:true AND wildcard origin is both invalid (browsers block it) and a sign of a dangerous misconfiguration that could lead to CSRF/auth bypass.',
    remediation: 'Specify the exact origin: cors({ origin: "https://yourdomain.com", credentials: true }). Never combine wildcard with credentials.',
  },

  // ── PHP ──────────────────────────────────────────────────────
  {
    id: 'CSRF-004',
    name: 'PHP Form Processing Without CSRF Token Check',
    severity: 'HIGH',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['php'],
    pattern: /\$_(?:POST|REQUEST)\s*\[['"`](?!(?:csrf|_token|nonce|xsrf)['"`)]).+['"`]\s*\](?![\s\S]{0,200}csrf_token|_token|nonce)/gi,
    description: 'POST data processed without CSRF token verification. Attackers can forge cross-site requests on behalf of victims.',
    remediation: 'Verify a CSRF token on every state-changing request: if (!hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])) { die("Invalid CSRF token"); }',
  },

  // ── Python ───────────────────────────────────────────────────
  {
    id: 'CSRF-005',
    name: 'Flask Route Without CSRF Protection',
    severity: 'HIGH',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['python'],
    pattern: /@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*['"`]POST['"`][^\]]*\]\s*\)(?![\s\S]{0,300}@csrf|@login_required|csrf\.protect)/gi,
    description: 'Flask POST route without Flask-WTF CSRF protection or explicit @csrf decorator.',
    remediation: 'Use Flask-WTF with csrf = CSRFProtect(app). Include {{ form.hidden_tag() }} in forms or send the X-CSRFToken header in AJAX.',
  },
  {
    id: 'CSRF-006',
    name: 'Django View With csrf_exempt',
    severity: 'HIGH',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['python'],
    pattern: /@csrf_exempt/g,
    description: '@csrf_exempt disables Django\'s built-in CSRF protection for the decorated view. Only acceptable for public/idempotent APIs authenticated via tokens.',
    remediation: 'Remove @csrf_exempt and use Django\'s CSRF framework. For REST APIs, use DRF with SessionAuthentication which enforces CSRF, or use token-based auth (JWT).',
  },

  // ── Java / Spring ─────────────────────────────────────────────
  {
    id: 'CSRF-007',
    name: 'Spring Security CSRF Disabled',
    severity: 'CRITICAL',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['java'],
    pattern: /\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)/gi,
    description: 'Spring Security CSRF protection explicitly disabled. This leaves all POST/PUT/DELETE endpoints vulnerable to CSRF attacks.',
    remediation: 'Remove .csrf().disable(). For stateless REST APIs (JWT-based), CSRF is less critical but still configure CookieCsrfTokenRepository.withHttpOnlyFalse() for browser clients.',
  },

  // ── ASP.NET ───────────────────────────────────────────────────
  {
    id: 'CSRF-008',
    name: 'ASP.NET Action Without ValidateAntiForgeryToken',
    severity: 'HIGH',
    category: 'CSRF',
    owasp: 'A01:2021',
    cwe: 'CWE-352',
    tech: ['csharp'],
    pattern: /\[HttpPost\](?![\s\S]{0,200}\[ValidateAntiForgeryToken\])/gi,
    description: 'ASP.NET controller action handles POST requests without [ValidateAntiForgeryToken] attribute.',
    remediation: 'Add [ValidateAntiForgeryToken] to all [HttpPost] actions, or add [AutoValidateAntiforgeryToken] at the controller level.',
  },
];

function detectColumn(line, pattern) {
  const p = new RegExp(pattern.source, pattern.flags.replace('g', ''));
  const match = p.exec(line);
  return match ? match.index + 1 : 1;
}

function scan(code, filePath) {
  const findings = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          owasp: rule.owasp,
          cwe: rule.cwe,
          tech: rule.tech,
          description: rule.description,
          file: filePath,
          line: i + 1,
          column: detectColumn(line, rule.pattern),
          snippet: line.trim().substring(0, 300),
          remediation: rule.remediation,
          source: 'owasp-rules',
        });
      }
    }
  }
  return findings;
}

module.exports = { scan, RULES };
