'use strict';

// A09:2021 — Security Logging and Monitoring Failures

const RULES = [
  {
    id: 'LOG-001',
    name: 'Sensitive Data Logged — Password/Token',
    severity: 'HIGH',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-532',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /(?:console\.log|logger\.\w+|log\.(?:info|debug|warn|error)|print|puts|System\.out\.println|fmt\.Print)\s*\([^)]*(?:password|passwd|pwd|secret|token|api_key|apikey|credit_card|ssn|cvv|pin\b)/gi,
    description: 'Sensitive data (password, token, secret) written to logs. Log files are often accessible to ops teams, aggregated in SIEM, or stored without encryption.',
    remediation: 'Remove sensitive fields from log statements. Use data masking: log only the last 4 characters of tokens. Add a log scrubbing middleware.',
  },
  {
    id: 'LOG-002',
    name: 'No Error Logging in catch Block',
    severity: 'MEDIUM',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-778',
    tech: ['javascript', 'typescript'],
    pattern: /}\s*catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\n\s*)?}/gi,
    description: 'Empty catch block silently swallows errors. Security events (failed auth, access violations) go undetected and cannot be investigated.',
    remediation: 'Always log caught exceptions: catch(err) { logger.error("Operation failed", { error: err.message, stack: err.stack }); }',
  },
  {
    id: 'LOG-003',
    name: 'Authentication Failure Not Logged',
    severity: 'HIGH',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-778',
    tech: ['javascript', 'typescript'],
    pattern: /(?:Invalid\s+(?:email|password|credentials)|authentication\s+failed|login\s+failed)(?![\s\S]{0,100}(?:logger|log\.|console\.log|winston|pino))/gi,
    description: 'Authentication failure message found without accompanying log statement. Failed login attempts must be logged for brute-force detection.',
    remediation: 'Log all auth failures with IP, timestamp, and username (not password): logger.warn("Auth failed", { email, ip: req.ip, timestamp: new Date() })',
  },
  {
    id: 'LOG-004',
    name: 'console.log in Production Code (Information Disclosure)',
    severity: 'LOW',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-532',
    tech: ['javascript', 'typescript'],
    pattern: /console\s*\.\s*(?:log|dir|debug|info|table)\s*\(\s*(?!['"`][A-Z])/g,
    description: 'console.log left in production code. May expose internal objects, user data, or stack traces through server-side log aggregators visible to wrong teams.',
    remediation: 'Replace console.log with a structured logger (winston, pino) with log levels. Use process.env.NODE_ENV checks to suppress debug output in production.',
  },
  {
    id: 'LOG-005',
    name: 'Request Body Logged (PII Exposure)',
    severity: 'HIGH',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-532',
    tech: ['javascript', 'typescript'],
    pattern: /(?:logger|console)\.\w+\s*\([^)]*req\.body(?!\s*\.\s*(?!\s*\)))/gi,
    description: 'Entire request body logged to a log file. May contain PII, passwords, payment data, or health information in violation of GDPR/HIPAA.',
    remediation: 'Log only specific safe fields: logger.info("Request", { path: req.path, method: req.method }). Never log req.body wholesale.',
  },
  {
    id: 'LOG-006',
    name: 'Stack Trace Returned in HTTP Response',
    severity: 'HIGH',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-209',
    tech: ['javascript', 'typescript'],
    pattern: /res\.(?:json|send|status\(\d+\)\.json)\s*\([^)]*(?:err(?:or)?\.stack|err(?:or)?\.message|error\s*:\s*err)/gi,
    description: 'Internal error stack trace or error object returned in HTTP response. Reveals file paths, library versions, and code structure to attackers.',
    remediation: 'Log the error server-side, return a generic message to the client: res.status(500).json({ message: "Internal server error" })',
  },
  {
    id: 'LOG-007',
    name: 'No Audit Log for Sensitive Operations',
    severity: 'MEDIUM',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-778',
    tech: ['javascript', 'typescript'],
    pattern: /(?:deleteMany|dropTable|DROP\s+TABLE|deleteUser|deleteAccount|updatePermissions|grantRole)\s*\([^)]*\)(?![\s\S]{0,200}(?:audit|logger\.|log\.))/gi,
    description: 'Destructive or privileged operation executed without audit logging. Compliance frameworks (SOC2, PCI-DSS) require audit trails for data modification.',
    remediation: 'Log all administrative actions: auditLogger.info("User deleted", { deletedBy: req.user.id, target: userId, ip: req.ip, timestamp: new Date() })',
  },
  {
    id: 'LOG-008',
    name: 'Log Injection via Unsanitized Input',
    severity: 'HIGH',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-117',
    tech: ['javascript', 'typescript'],
    pattern: /(?:logger|console)\.\w+\s*\(\s*`[^`]*\$\{(?:req\.|request\.)\w+/gi,
    description: 'User-controlled input interpolated into log message via template literal. Attackers can inject newlines to forge log entries or escape log parsers.',
    remediation: 'Pass user data as structured metadata, not interpolated into the message: logger.info("User action", { userId: req.user.id }). This prevents log injection.',
  },
  // ── Python ───────────────────────────────────────────────────
  {
    id: 'LOG-009',
    name: 'Python print() Used Instead of Logger (Production)',
    severity: 'LOW',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-532',
    tech: ['python'],
    pattern: /\bprint\s*\(\s*(?:f?['"`](?:Error|Warning|Failed|Exception|Traceback)|exception|traceback)/gi,
    description: 'print() used to report errors in Python. print() output goes to stdout with no level, timestamp, or correlation ID — making incident response difficult.',
    remediation: 'Use the logging module: import logging; logger = logging.getLogger(__name__); logger.error("Error occurred", exc_info=True)',
  },
  {
    id: 'LOG-010',
    name: 'Django DEBUG=True in Production',
    severity: 'CRITICAL',
    category: 'Logging Failures',
    owasp: 'A09:2021',
    cwe: 'CWE-209',
    tech: ['python'],
    pattern: /DEBUG\s*=\s*True/g,
    description: 'Django DEBUG=True exposes full stack traces, local variables, settings, and SQL queries to anyone who triggers an error — directly in the browser response.',
    remediation: 'Set DEBUG = False in production. Use DJANGO_SETTINGS_MODULE to separate dev and prod settings. Never set DEBUG=True based on env in settings.py.',
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
