'use strict';

const fs = require('fs');
const path = require('path');
const { glob } = require('glob');
const logger = require('../utils/logger');
const { isSupportedFile, isExcludedPath } = require('../utils/helpers');

const injectionScanner = require('./rules/injection');
const xssScanner = require('./rules/xss');
const sensitiveDataScanner = require('./rules/sensitiveData');
const brokenAuthScanner = require('./rules/brokenAuth');
const accessControlScanner = require('./rules/accessControl');
const securityMisconfigScanner = require('./rules/securityMisconfig');
const insecureDeserializationScanner = require('./rules/insecureDeserialization');
const knownVulnerabilitiesScanner = require('./rules/knownVulnerabilities');
const ssrfScanner = require('./rules/ssrf');
const xxeScanner = require('./rules/xxe');
const csrfScanner = require('./rules/csrf');
const openRedirectScanner = require('./rules/openRedirect');
const templateInjectionScanner = require('./rules/templateInjection');
const loggingScanner = require('./rules/logging');

const SCANNERS = [
  { name: 'Injection',                scanner: injectionScanner },
  { name: 'XSS',                      scanner: xssScanner },
  { name: 'Sensitive Data Exposure',   scanner: sensitiveDataScanner },
  { name: 'Broken Authentication',     scanner: brokenAuthScanner },
  { name: 'Broken Access Control',     scanner: accessControlScanner },
  { name: 'Security Misconfiguration', scanner: securityMisconfigScanner },
  { name: 'Insecure Deserialization',  scanner: insecureDeserializationScanner },
  { name: 'Known Vulnerabilities',     scanner: knownVulnerabilitiesScanner },
  { name: 'SSRF',                      scanner: ssrfScanner },
  { name: 'XXE',                       scanner: xxeScanner },
  { name: 'CSRF',                      scanner: csrfScanner },
  { name: 'Open Redirect',             scanner: openRedirectScanner },
  { name: 'Template Injection',        scanner: templateInjectionScanner },
  { name: 'Logging Failures',          scanner: loggingScanner },
];

// File-extension → detected technology label
const EXT_TECH_MAP = {
  '.js':   'JavaScript',
  '.mjs':  'JavaScript',
  '.cjs':  'JavaScript',
  '.ts':   'TypeScript',
  '.tsx':  'TypeScript',
  '.jsx':  'JavaScript',
  '.py':   'Python',
  '.java': 'Java',
  '.go':   'Go',
  '.rb':   'Ruby',
  '.php':  'PHP',
  '.cs':   'C#',
  '.sh':   'Bash',
  '.bash': 'Bash',
  '.vue':  'Vue',
  '.html': 'HTML',
};

function detectTech(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return EXT_TECH_MAP[ext] || null;
}

function getCodeContext(lines, lineIndex, contextSize = 3) {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length - 1, lineIndex + contextSize);
  const contextLines = [];
  for (let i = start; i <= end; i++) {
    contextLines.push({
      lineNumber: i + 1,
      content: lines[i],
      isTarget: i === lineIndex,
    });
  }
  return contextLines;
}

async function scanDirectory(dirPath, onProgress) {
  const allFindings = [];
  let filesScanned = 0;
  let linesScanned = 0;

  const files = await glob('**/*', {
    cwd: dirPath,
    nodir: true,
    absolute: true,
    ignore: [
      '**/node_modules/**',
      '**/.git/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      '**/*.min.js',
      '**/*.min.css',
      '**/*.map',
      '**/*.lock',
      '**/yarn.lock',
      '**/package-lock.json',
    ],
  });

  const supportedFiles = files.filter(f => isSupportedFile(f) && !isExcludedPath(f));
  const total = supportedFiles.length;

  logger.info(`Scanning ${total} files in ${dirPath}`);

  for (let i = 0; i < supportedFiles.length; i++) {
    const filePath = supportedFiles[i];
    const relativePath = path.relative(dirPath, filePath);

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      linesScanned += lines.length;

      const fileFindings = scanFile(content, relativePath, lines);
      allFindings.push(...fileFindings);
      filesScanned++;

      if (onProgress) {
        onProgress({
          current: i + 1,
          total,
          progress: Math.round(((i + 1) / total) * 100),
          file: relativePath,
        });
      }
    } catch (err) {
      logger.warn(`Failed to scan file ${relativePath}: ${err.message}`);
    }
  }

  return { findings: allFindings, filesScanned, linesScanned };
}

function scanFile(content, filePath, linesOverride) {
  const lines = linesOverride || content.split('\n');
  const tech = detectTech(filePath);
  const findings = [];

  for (const { scanner } of SCANNERS) {
    try {
      const results = scanner.scan(content, filePath);
      if (results && results.length > 0) {
        for (const result of results) {
          // Attach detected technology if scanner didn't provide it
          if (!result.tech && tech) result.tech = [tech];
          // Add 3-line code context window
          if (!result.codeContext) {
            result.codeContext = getCodeContext(lines, result.line - 1);
          }
          findings.push(result);
        }
      }
    } catch (err) {
      logger.warn(`Scanner "${scanner.constructor?.name || 'unknown'}" failed on ${filePath}: ${err.message}`);
    }
  }

  return deduplicateFindings(findings);
}

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function computeSummary(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH':     summary.high++;     break;
      case 'MEDIUM':   summary.medium++;   break;
      case 'LOW':      summary.low++;      break;
      case 'INFO':     summary.info++;     break;
    }
  }
  summary.total = findings.length;
  return summary;
}

module.exports = { scanDirectory, scanFile, computeSummary, detectTech, EXT_TECH_MAP };
