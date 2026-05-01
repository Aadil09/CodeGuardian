'use strict';

const RULES = [
  {
    id: 'IDS-001',
    name: 'Unsafe JSON.parse on User Input',
    severity: 'HIGH',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'JSON.parse called directly on user input without validation',
    remediation: 'Wrap JSON.parse in try/catch and validate the parsed output against a schema (Joi, Zod).',
  },
  {
    id: 'IDS-002',
    name: 'eval() for Deserialization',
    severity: 'CRITICAL',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /eval\s*\(\s*(?:JSON\.stringify|atob|Buffer\.from|decodeURIComponent)/gi,
    description: 'eval() used for deserializing data enables arbitrary code execution',
    remediation: 'Use JSON.parse() for JSON data. Never use eval() for deserialization.',
  },
  {
    id: 'IDS-003',
    name: 'Unsafe node-serialize Usage',
    severity: 'CRITICAL',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /require\s*\(\s*['"`]node-serialize['"`]\s*\)/g,
    description: 'node-serialize library is known to be vulnerable to remote code execution',
    remediation: 'Remove node-serialize. Use JSON.parse/stringify with schema validation instead.',
  },
  {
    id: 'IDS-004',
    name: 'Prototype Pollution via Object.assign',
    severity: 'HIGH',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /Object\.assign\s*\(\s*(?:this|prototype|\{\})\s*,\s*(?:req\.|request\.)\w+/gi,
    description: 'Object.assign with user-controlled data may enable prototype pollution',
    remediation: 'Validate and whitelist properties before merging. Use Object.create(null) for safe maps.',
  },
  {
    id: 'IDS-005',
    name: 'Prototype Pollution via __proto__',
    severity: 'CRITICAL',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /__proto__\s*[=\[]/g,
    description: 'Direct __proto__ access enables prototype pollution attacks',
    remediation: 'Sanitize user input to remove __proto__, constructor, and prototype keys before object assignment.',
  },
  {
    id: 'IDS-006',
    name: 'Unsafe YAML Load',
    severity: 'HIGH',
    category: 'Insecure Deserialization',
    owasp: 'A08:2021',
    pattern: /yaml\.(?:load|safeLoad)\s*\([^)]*(?:req\.|request\.|input|data|user)/gi,
    description: 'yaml.load() with user input may execute arbitrary JavaScript in some parsers',
    remediation: 'Use yaml.safeLoad() or yaml.load() with { schema: FAILSAFE_SCHEMA } to prevent code execution.',
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
