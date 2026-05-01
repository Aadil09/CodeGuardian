'use strict';

const RULES = [
  {
    id: 'BAC-001',
    name: 'Direct Object Reference Without Authorization',
    severity: 'HIGH',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /findById\s*\(\s*req\.(?:params|body|query)\.\w+\s*\)(?!\s*\.then|\s*await)(?!.*(?:userId|ownerId|authorize|permission))/gi,
    description: 'Database record fetched by user-controlled ID without ownership verification',
    remediation: 'Add ownership check: ensure the record belongs to req.user._id before returning it.',
  },
  {
    id: 'BAC-002',
    name: 'Path Traversal',
    severity: 'CRITICAL',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^)]*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'File path constructed from user input enables path traversal attacks',
    remediation: 'Validate file paths. Use path.basename() and restrict to a known safe directory.',
  },
  {
    id: 'BAC-003',
    name: 'CORS Wildcard Origin',
    severity: 'HIGH',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]/g,
    description: 'CORS configured with wildcard origin allows any site to make authenticated requests',
    remediation: 'Restrict CORS origin to known trusted domains. Never use * with credentials: true.',
  },
  {
    id: 'BAC-004',
    name: 'Role Check Missing on Admin Route',
    severity: 'HIGH',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /\/api\/admin\/[^'"`)]+['"`]\s*,\s*(?:authenticate|auth)\s*,\s*(?:async\s+)?\w+Controller/gi,
    description: 'Admin route lacks explicit role-based authorization middleware',
    remediation: 'Add role check middleware: router.use("/admin", authenticate, authorize("admin"))',
  },
  {
    id: 'BAC-005',
    name: 'Unprotected HTTP Method (DELETE/PUT)',
    severity: 'MEDIUM',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /router\.(?:delete|put|patch)\s*\(\s*['"`][^'"`)]+['"`]\s*,\s*(?:async\s+)?\([^)]*req[^)]*res\)/gi,
    description: 'Mutation endpoint lacks authentication middleware',
    remediation: 'Always apply authentication and authorization to DELETE/PUT/PATCH endpoints.',
  },
  {
    id: 'BAC-006',
    name: 'JWT Algorithm None Attack',
    severity: 'CRITICAL',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    pattern: /jwt\.verify\s*\([^)]*(?:algorithms\s*:\s*(?!.*HS256|.*RS256|.*ES256))/gi,
    description: 'JWT verification without algorithm restriction enables algorithm confusion attacks',
    remediation: 'Specify allowed algorithms: jwt.verify(token, secret, { algorithms: ["HS256"] })',
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
