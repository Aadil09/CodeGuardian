'use strict';

const RULES = [
  {
    id: 'SMC-001',
    name: 'Helmet Not Used',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /const\s+app\s*=\s*express\s*\(\s*\)(?![\s\S]*app\.use\s*\(\s*helmet)/g,
    description: 'Express application created without helmet security headers middleware',
    remediation: 'Add app.use(helmet()) immediately after creating the Express app.',
  },
  {
    id: 'SMC-002',
    name: 'Debug Mode in Production',
    severity: 'HIGH',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /debug\s*[:=]\s*true(?!\s*(?:&&|\|\||,)[^;]*(?:NODE_ENV|development|test))/gi,
    description: 'Debug mode enabled — may expose stack traces and internal details in production',
    remediation: 'Set debug: process.env.NODE_ENV !== "production"',
  },
  {
    id: 'SMC-003',
    name: 'Verbose Error Stack in Response',
    severity: 'HIGH',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /res\.(?:json|send)\s*\([^)]*err(?:or)?\.stack/gi,
    description: 'Error stack trace returned in HTTP response exposes internal structure',
    remediation: 'Log stack traces server-side only. Return generic error messages to clients in production.',
  },
  {
    id: 'SMC-004',
    name: 'X-Powered-By Header Not Disabled',
    severity: 'LOW',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /app\.use\s*\(\s*express\.(?:static|json)\s*\((?![\s\S]*app\.disable\s*\(\s*['"`]x-powered-by['"`])/g,
    description: 'X-Powered-By header reveals the framework to potential attackers',
    remediation: 'Add app.disable("x-powered-by") or use helmet() which disables it automatically.',
  },
  {
    id: 'SMC-005',
    name: 'Exposed .env or Config File via Static Server',
    severity: 'CRITICAL',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /express\.static\s*\(\s*['"`]\.['"`]\s*\)/g,
    description: 'Serving project root as static files may expose .env, package.json, and secrets',
    remediation: 'Serve only a dedicated public/ directory: express.static(path.join(__dirname, "public"))',
  },
  {
    id: 'SMC-006',
    name: 'HTTP Instead of HTTPS in Configuration',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"`]+['"`]/g,
    description: 'Non-localhost HTTP URL configured — data transmitted without encryption',
    remediation: 'Use HTTPS for all external service URLs. Enforce HSTS in production.',
  },
  {
    id: 'SMC-007',
    name: 'Missing Rate Limiting',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /router\.post\s*\(\s*['"`]\/(?:login|register|reset-password|auth)[^'"`)]*['"`]/gi,
    description: 'Authentication endpoint without visible rate limiting is vulnerable to brute force',
    remediation: 'Apply express-rate-limit to all authentication endpoints.',
  },
  {
    id: 'SMC-008',
    name: 'Insecure TLS Configuration',
    severity: 'HIGH',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    pattern: /rejectUnauthorized\s*:\s*false/g,
    description: 'TLS certificate verification disabled — enables man-in-the-middle attacks',
    remediation: 'Remove rejectUnauthorized: false. Fix the certificate issue properly instead.',
  },
];

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
          description: rule.description,
          file: filePath,
          line: i + 1,
          column: 0,
          snippet: line.trim().substring(0, 200),
          remediation: rule.remediation,
          source: 'owasp-rules',
        });
      }
    }
  }
  return findings;
}

module.exports = { scan, RULES };
