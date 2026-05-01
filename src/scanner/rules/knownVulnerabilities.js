'use strict';

const KNOWN_VULNERABLE_PACKAGES = {
  'lodash': { below: '4.17.21', severity: 'HIGH', cve: 'CVE-2021-23337', desc: 'Prototype pollution via merge/zipObjectDeep' },
  'express': { below: '4.19.0', severity: 'HIGH', cve: 'CVE-2024-29041', desc: 'Open redirect vulnerability' },
  'axios': { below: '1.6.0', severity: 'HIGH', cve: 'CVE-2023-45857', desc: 'CSRF vulnerability via header exposure' },
  'jsonwebtoken': { below: '9.0.0', severity: 'CRITICAL', cve: 'CVE-2022-23529', desc: 'Insecure implementation of key retrieval' },
  'node-serialize': { below: '999.0.0', severity: 'CRITICAL', cve: 'CVE-2017-5941', desc: 'Remote code execution via serialized data' },
  'mongoose': { below: '5.13.15', severity: 'HIGH', cve: 'CVE-2022-24999', desc: 'Prototype pollution via query parameters' },
  'moment': { below: '2.29.4', severity: 'MEDIUM', cve: 'CVE-2022-24785', desc: 'Path traversal vulnerability' },
  'marked': { below: '4.0.10', severity: 'HIGH', cve: 'CVE-2022-21681', desc: 'ReDoS vulnerability' },
  'minimist': { below: '1.2.6', severity: 'HIGH', cve: 'CVE-2021-44906', desc: 'Prototype pollution' },
  'handlebars': { below: '4.7.7', severity: 'HIGH', cve: 'CVE-2021-23369', desc: 'Remote code execution via template injection' },
  'ejs': { below: '3.1.8', severity: 'CRITICAL', cve: 'CVE-2022-29078', desc: 'Server-side template injection via prototype pollution' },
  'pug': { below: '3.0.1', severity: 'HIGH', cve: 'CVE-2021-21317', desc: 'Remote code execution via template injection' },
};

const DANGEROUS_PACKAGES = [
  { name: 'node-serialize', severity: 'CRITICAL', reason: 'Known RCE vulnerability (CVE-2017-5941)' },
  { name: 'eval', severity: 'HIGH', reason: 'Allows arbitrary code execution' },
  { name: 'crypto-js', severity: 'MEDIUM', reason: 'Prefer Node built-in crypto module' },
  { name: 'request', severity: 'MEDIUM', reason: 'Deprecated, use axios or node-fetch' },
];

function scanPackageJson(content, filePath) {
  const findings = [];
  try {
    const pkg = JSON.parse(content);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    for (const [name, versionRange] of Object.entries(deps)) {
      const vuln = KNOWN_VULNERABLE_PACKAGES[name];
      if (vuln) {
        findings.push({
          ruleId: 'KVD-001',
          ruleName: `Known Vulnerable Package: ${name}`,
          severity: vuln.severity,
          category: 'Known Vulnerabilities',
          owasp: 'A06:2021',
          description: `${name}@${versionRange}: ${vuln.desc} (${vuln.cve})`,
          file: filePath,
          line: 1,
          column: 0,
          snippet: `"${name}": "${versionRange}"`,
          remediation: `Upgrade ${name} to a version >= ${vuln.below}. Run: npm audit fix`,
          source: 'owasp-rules',
        });
      }

      const dangerous = DANGEROUS_PACKAGES.find(d => d.name === name);
      if (dangerous) {
        findings.push({
          ruleId: 'KVD-002',
          ruleName: `Dangerous Package: ${name}`,
          severity: dangerous.severity,
          category: 'Known Vulnerabilities',
          owasp: 'A06:2021',
          description: `Package "${name}" is dangerous: ${dangerous.reason}`,
          file: filePath,
          line: 1,
          column: 0,
          snippet: `"${name}": "${versionRange}"`,
          remediation: `Remove or replace the "${name}" package with a safer alternative.`,
          source: 'owasp-rules',
        });
      }
    }
  } catch (e) {
    // not valid JSON, skip
  }
  return findings;
}

const REQUIRE_RULES = [
  {
    id: 'KVD-003',
    name: 'node-serialize Import',
    severity: 'CRITICAL',
    owasp: 'A06:2021',
    pattern: /require\s*\(\s*['"`]node-serialize['"`]\s*\)/g,
    description: 'node-serialize has a known RCE vulnerability (CVE-2017-5941)',
    remediation: 'Remove node-serialize immediately. Use JSON.parse/stringify with validation.',
  },
];

function scan(code, filePath) {
  if (filePath.endsWith('package.json')) {
    return scanPackageJson(code, filePath);
  }

  const findings = [];
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of REQUIRE_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: 'Known Vulnerabilities',
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

module.exports = { scan, KNOWN_VULNERABLE_PACKAGES };
