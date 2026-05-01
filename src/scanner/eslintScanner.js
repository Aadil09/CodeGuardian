'use strict';

const { ESLint } = require('eslint');
const path = require('path');
const logger = require('../utils/logger');

const ESLINT_CONFIG = {
  overrideConfigFile: true,
  overrideConfig: {
    plugins: { security: require('eslint-plugin-security') },
    rules: {
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-unsafe-regex': 'error',
      'security/detect-buffer-noassert': 'error',
      'security/detect-child-process': 'error',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-new-buffer': 'warn',
      'security/detect-no-csrf-before-method-override': 'error',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-non-literal-require': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      'security/detect-pseudoRandomBytes': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
  },
};

async function runESLint(files, repoDir) {
  const eslint = new ESLint(ESLINT_CONFIG);
  const findings = [];

  const jsFiles = files.filter(f => /\.(js|mjs|cjs|jsx)$/.test(f));
  if (jsFiles.length === 0) return findings;

  try {
    const results = await eslint.lintFiles(jsFiles.map(f => path.join(repoDir, f)));

    for (const result of results) {
      const relativePath = path.relative(repoDir, result.filePath);
      for (const msg of result.messages) {
        if (msg.ruleId) {
          findings.push({
            ruleId: `ESLINT-${msg.ruleId}`,
            ruleName: msg.ruleId,
            severity: msg.severity === 2 ? 'HIGH' : 'MEDIUM',
            category: 'ESLint Security',
            owasp: mapESLintRuleToOWASP(msg.ruleId),
            description: msg.message,
            file: relativePath,
            line: msg.line,
            column: msg.column,
            snippet: msg.source ? msg.source.trim().substring(0, 200) : '',
            remediation: getESLintRemediation(msg.ruleId),
            source: 'eslint',
          });
        }
      }
    }
  } catch (err) {
    logger.warn(`ESLint scan failed: ${err.message}`);
  }

  return findings;
}

function mapESLintRuleToOWASP(ruleId) {
  const mapping = {
    'security/detect-child-process': 'A03:2021',
    'security/detect-eval-with-expression': 'A03:2021',
    'security/detect-non-literal-fs-filename': 'A01:2021',
    'security/detect-unsafe-regex': 'A05:2021',
    'security/detect-pseudoRandomBytes': 'A07:2021',
    'security/detect-no-csrf-before-method-override': 'A01:2021',
    'no-eval': 'A03:2021',
    'no-implied-eval': 'A03:2021',
  };
  return mapping[ruleId] || 'A05:2021';
}

function getESLintRemediation(ruleId) {
  const remediations = {
    'security/detect-child-process': 'Validate all inputs before passing to child_process. Use execFile() with argument arrays.',
    'security/detect-eval-with-expression': 'Replace eval() with safe alternatives like JSON.parse() or Function constructors.',
    'security/detect-non-literal-fs-filename': 'Validate file paths. Restrict to known safe base directories.',
    'security/detect-unsafe-regex': 'Rewrite the regex to avoid catastrophic backtracking. Use a ReDoS checker.',
    'security/detect-pseudoRandomBytes': 'Use crypto.randomBytes() instead of pseudo-random generators.',
    'security/detect-disable-mustache-escape': 'Re-enable Mustache escaping to prevent XSS in templates.',
    'no-eval': 'Eliminate eval(). Use JSON.parse() for data, or refactor the logic.',
    'no-implied-eval': 'Pass a function reference to setTimeout/setInterval, not a string.',
  };
  return remediations[ruleId] || 'Review ESLint security rule and apply recommended fix.';
}

module.exports = { runESLint };
