'use strict';

const RULES = [
  {
    id: 'AUTH-001',
    name: 'JWT Without Expiry',
    severity: 'HIGH',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /jwt\.sign\s*\([^,]+,\s*[^,]+(?:,\s*\{[^}]*\})?(?!\s*\{[^}]*expiresIn)/g,
    description: 'JWT token created without expiration allows indefinite access if compromised',
    remediation: 'Always set expiresIn in jwt.sign() options: { expiresIn: "1h" }.',
  },
  {
    id: 'AUTH-002',
    name: 'JWT Verification Skipped',
    severity: 'CRITICAL',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /jwt\.decode\s*\(/g,
    description: 'jwt.decode() does not verify the signature — use jwt.verify() instead',
    remediation: 'Replace jwt.decode() with jwt.verify() to validate the token signature and claims.',
  },
  {
    id: 'AUTH-003',
    name: 'Weak Password Hashing (MD5/SHA)',
    severity: 'CRITICAL',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /crypto\.createHash\s*\(\s*['"`](?:md5|sha1|sha256)['"`]\s*\).*(?:password|passwd|pwd)/gi,
    description: 'Password hashed with a non-adaptive algorithm (MD5/SHA) — breakable by brute force',
    remediation: 'Use bcrypt, argon2, or scrypt for password hashing instead of SHA/MD5.',
  },
  {
    id: 'AUTH-004',
    name: 'Missing Authentication Check',
    severity: 'HIGH',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /router\.(?:get|post|put|patch|delete)\s*\(\s*['"`][^'"`)]+['"`]\s*,\s*(?:async\s+)?\([^)]*\)\s*=>/g,
    description: 'Route handler registered without visible authentication middleware',
    remediation: 'Ensure all sensitive routes include authentication middleware before the handler.',
  },
  {
    id: 'AUTH-005',
    name: 'Hardcoded Default Credentials',
    severity: 'CRITICAL',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /(?:username|user|login)\s*[:=]\s*['"`](?:admin|root|test|demo|user|guest)['"`]\s*(?:&&|,|\n)/gi,
    description: 'Default username found in code may indicate hardcoded credentials',
    remediation: 'Remove default credentials. Enforce credential configuration through environment variables.',
  },
  {
    id: 'AUTH-006',
    name: 'Session Secret Not From Environment',
    severity: 'HIGH',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /session\s*\(\s*\{[^}]*secret\s*:\s*['"`][^'"`]{1,}['"`]/g,
    description: 'Session secret hardcoded in source — should come from environment variable',
    remediation: 'Use process.env.SESSION_SECRET and generate a strong random value.',
  },
  {
    id: 'AUTH-007',
    name: 'Insecure Cookie (missing httpOnly/secure)',
    severity: 'MEDIUM',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /res\.cookie\s*\([^)]*(?!httpOnly)(?!secure)/g,
    description: 'Cookie set without httpOnly or secure flag',
    remediation: 'Set httpOnly: true and secure: true on all authentication cookies.',
  },
  {
    id: 'AUTH-008',
    name: 'Predictable Random Number for Token',
    severity: 'HIGH',
    category: 'Broken Authentication',
    owasp: 'A07:2021',
    pattern: /Math\.random\s*\(\s*\).*(?:token|session|secret|nonce|salt)/gi,
    description: 'Math.random() is not cryptographically secure and must not be used for tokens',
    remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for generating secure tokens.',
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
