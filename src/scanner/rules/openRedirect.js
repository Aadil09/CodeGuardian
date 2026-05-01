'use strict';

// A01:2021 — Open Redirect (Unvalidated Redirects and Forwards)
// Covers: Node.js, PHP, Python, Java, Go, Ruby, ASP.NET

const RULES = [
  // ── Node.js / Express ────────────────────────────────────────
  {
    id: 'ORP-001',
    name: 'Open Redirect via res.redirect() with User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['javascript', 'typescript'],
    pattern: /res\.redirect\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'res.redirect() with user-controlled URL enables open redirect. Attackers use this for phishing: /login?next=https://evil.com',
    remediation: 'Validate the redirect URL against an allowlist of trusted internal paths. Use a safe redirect helper that checks the URL is relative or matches your domain.',
  },
  {
    id: 'ORP-002',
    name: 'Open Redirect via Location Header with User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['javascript', 'typescript'],
    pattern: /res\.(?:setHeader|header)\s*\(\s*['"`](?:Location|location)['"`]\s*,\s*(?:req\.|request\.)\w+/gi,
    description: 'Location header set from user-controlled input allows open redirect exploitation.',
    remediation: 'Use path.normalize() and verify the URL starts with "/" without "//". Reject absolute URLs to external domains.',
  },
  {
    id: 'ORP-003',
    name: 'Open Redirect via window.location Assignment',
    severity: 'MEDIUM',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['javascript', 'typescript'],
    pattern: /window\.location(?:\.href)?\s*=\s*(?:document\.location|location\.search|location\.hash|new URLSearchParams|urlParams\.get)/gi,
    description: 'Client-side open redirect via window.location assignment with URL parameter value.',
    remediation: 'Validate redirect targets against an allowlist. For "next" URL params, ensure they are relative paths only (no // or absolute URLs).',
  },

  // ── PHP ──────────────────────────────────────────────────────
  {
    id: 'ORP-004',
    name: 'PHP header() Open Redirect',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['php'],
    pattern: /header\s*\(\s*['"`]Location\s*:\s*['"`]\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
    description: 'PHP header("Location: " . $_GET[...]) is a classic open redirect vulnerability.',
    remediation: 'Validate redirect URL with filter_var($url, FILTER_VALIDATE_URL). Maintain a whitelist of allowed redirect destinations.',
  },
  {
    id: 'ORP-005',
    name: 'PHP wp_redirect() Without Validation',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['php'],
    pattern: /wp_redirect\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
    description: 'WordPress wp_redirect() with unvalidated user input enables open redirect.',
    remediation: 'Use wp_safe_redirect() instead. It validates against the allowed redirect hosts list.',
  },

  // ── Python ───────────────────────────────────────────────────
  {
    id: 'ORP-006',
    name: 'Flask redirect() With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['python'],
    pattern: /redirect\s*\(\s*(?:request\.args|request\.form|request\.values|request\.json)(?:\[|\.get)/gi,
    description: 'Flask redirect() with user-supplied URL allows phishing via open redirect.',
    remediation: 'Check the URL with is_safe_url(): from urllib.parse import urlparse; only redirect to internal paths (no scheme or matching host).',
  },
  {
    id: 'ORP-007',
    name: 'Django HttpResponseRedirect With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['python'],
    pattern: /HttpResponseRedirect\s*\(\s*(?:request\.GET|request\.POST|request\.data)(?:\[|\.get)/gi,
    description: 'Django HttpResponseRedirect with user-controlled URL enables open redirect.',
    remediation: 'Use django.utils.http.url_has_allowed_host_and_scheme() to validate the redirect target.',
  },

  // ── Java / Spring ─────────────────────────────────────────────
  {
    id: 'ORP-008',
    name: 'Spring sendRedirect() With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['java'],
    pattern: /(?:response|resp|httpResponse)\.sendRedirect\s*\(\s*(?:request|req)\.getParameter/gi,
    description: 'HttpServletResponse.sendRedirect() with user-supplied parameter enables open redirect.',
    remediation: 'Validate the URL against a whitelist. Use a relative path if redirecting within the app.',
  },

  // ── Go ───────────────────────────────────────────────────────
  {
    id: 'ORP-009',
    name: 'Go http.Redirect() With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['go'],
    pattern: /http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*r\.(?:URL\.Query|FormValue|Header\.Get)/gi,
    description: 'Go http.Redirect with user-controlled URL parameter enables open redirect.',
    remediation: 'Validate the redirect URL starts with "/" and does not contain "//". Use url.Parse to check scheme.',
  },

  // ── Ruby on Rails ─────────────────────────────────────────────
  {
    id: 'ORP-010',
    name: 'Rails redirect_to With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['ruby'],
    pattern: /redirect_to\s*(?:params\[|request\.(?:params|referrer))/gi,
    description: 'Rails redirect_to with params[] input enables open redirect. CVE-2013-4073 affected older Rails versions.',
    remediation: 'Use only: :host restriction, or validate with URI.parse(url).host == request.host. Avoid redirecting to user-supplied URLs.',
  },

  // ── ASP.NET ───────────────────────────────────────────────────
  {
    id: 'ORP-011',
    name: 'ASP.NET Response.Redirect With User Input',
    severity: 'HIGH',
    category: 'Open Redirect',
    owasp: 'A01:2021',
    cwe: 'CWE-601',
    tech: ['csharp'],
    pattern: /Response\.Redirect\s*\(\s*(?:Request\.QueryString|Request\.Form|Request\.Params)\[/gi,
    description: 'ASP.NET Response.Redirect with QueryString/Form input allows open redirect attacks.',
    remediation: 'Use Url.IsLocalUrl() before redirecting: if (Url.IsLocalUrl(returnUrl)) { return Redirect(returnUrl); }',
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
