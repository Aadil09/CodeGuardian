'use strict';

require('dotenv').config();

const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { sequelize } = require('../src/config/database');
const { User, Scan, Report } = require('../src/models');

// ─── Sample findings shared across demo reports ────────────────────────────
const SAMPLE_FINDINGS = [
  {
    ruleId: 'INJ-001', ruleName: 'SQL Injection via String Concatenation',
    severity: 'HIGH', category: 'Injection', owasp: 'A03:2021',
    description: 'SQL query built by string concatenation allows injection attacks',
    file: 'src/routes/users.js', line: 47, column: 0,
    snippet: "db.query('SELECT * FROM users WHERE email = ' + req.body.email)",
    remediation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    source: 'owasp-rules',
  },
  {
    ruleId: 'SDE-002', ruleName: 'Hardcoded Password',
    severity: 'CRITICAL', category: 'Sensitive Data Exposure', owasp: 'A02:2021',
    description: 'Hardcoded password found in source code',
    file: 'src/config/database.js', line: 12, column: 0,
    snippet: "password: 'admin123'",
    remediation: 'Move credentials to environment variables and never hardcode them.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'XSS-001', ruleName: 'Unsafe innerHTML Assignment',
    severity: 'HIGH', category: 'XSS', owasp: 'A03:2021',
    description: 'Direct innerHTML assignment with dynamic content enables XSS',
    file: 'src/views/profile.html', line: 88, column: 0,
    snippet: "element.innerHTML = userInput",
    remediation: 'Use textContent or DOMPurify.sanitize() before innerHTML.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'AUTH-002', ruleName: 'JWT Verification Skipped',
    severity: 'CRITICAL', category: 'Broken Authentication', owasp: 'A07:2021',
    description: 'jwt.decode() does not verify signature — use jwt.verify()',
    file: 'src/middleware/auth.js', line: 23, column: 0,
    snippet: "const payload = jwt.decode(token);",
    remediation: 'Replace jwt.decode() with jwt.verify() and specify allowed algorithms.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'BAC-003', ruleName: 'CORS Wildcard Origin',
    severity: 'HIGH', category: 'Broken Access Control', owasp: 'A01:2021',
    description: 'CORS configured with wildcard origin allows any site to make authenticated requests',
    file: 'server.js', line: 8, column: 0,
    snippet: "app.use(cors({ origin: '*' }))",
    remediation: "Restrict CORS to trusted domains. Never use '*' with credentials: true.",
    source: 'owasp-rules',
  },
  {
    ruleId: 'SMC-008', ruleName: 'Insecure TLS Configuration',
    severity: 'HIGH', category: 'Security Misconfiguration', owasp: 'A05:2021',
    description: 'TLS certificate verification disabled — enables MITM attacks',
    file: 'src/services/httpClient.js', line: 5, column: 0,
    snippet: "rejectUnauthorized: false",
    remediation: 'Remove rejectUnauthorized: false. Fix the certificate issue properly.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'IDS-005', ruleName: 'Prototype Pollution via __proto__',
    severity: 'CRITICAL', category: 'Insecure Deserialization', owasp: 'A08:2021',
    description: 'Direct __proto__ access enables prototype pollution attacks',
    file: 'src/utils/merge.js', line: 31, column: 0,
    snippet: "target[key].__proto__ = source[key]",
    remediation: 'Sanitize user input to remove __proto__, constructor, and prototype keys.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'SDE-006', ruleName: 'Weak Cryptographic Algorithm (MD5)',
    severity: 'HIGH', category: 'Sensitive Data Exposure', owasp: 'A02:2021',
    description: 'MD5 is cryptographically weak and must not be used for security',
    file: 'src/helpers/hash.js', line: 9, column: 0,
    snippet: "crypto.createHash('md5').update(password).digest('hex')",
    remediation: 'Replace MD5 with bcrypt or argon2 for password hashing.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'KVD-001', ruleName: 'Known Vulnerable Package: lodash',
    severity: 'HIGH', category: 'Known Vulnerabilities', owasp: 'A06:2021',
    description: 'lodash@4.17.15: Prototype pollution via merge (CVE-2021-23337)',
    file: 'package.json', line: 1, column: 0,
    snippet: '"lodash": "4.17.15"',
    remediation: 'Upgrade lodash to >= 4.17.21. Run: npm audit fix',
    source: 'owasp-rules',
  },
  {
    ruleId: 'INJ-004', ruleName: 'Command Injection via exec()',
    severity: 'CRITICAL', category: 'Injection', owasp: 'A03:2021',
    description: 'Shell command constructed with dynamic values enables command injection',
    file: 'src/controllers/fileController.js', line: 56, column: 0,
    snippet: "exec('ls ' + req.query.path)",
    remediation: 'Validate inputs strictly. Use execFile() with argument arrays.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'SMC-002', ruleName: 'Debug Mode in Production',
    severity: 'HIGH', category: 'Security Misconfiguration', owasp: 'A05:2021',
    description: 'Debug mode enabled — may expose stack traces in production',
    file: 'src/app.js', line: 3, column: 0,
    snippet: "debug: true",
    remediation: "Set debug: process.env.NODE_ENV !== 'production'",
    source: 'owasp-rules',
  },
  {
    ruleId: 'XSS-007', ruleName: 'eval() Usage',
    severity: 'CRITICAL', category: 'XSS', owasp: 'A03:2021',
    description: 'eval() can execute injected scripts',
    file: 'src/utils/parser.js', line: 14, column: 0,
    snippet: "eval(userScript)",
    remediation: 'Eliminate eval(). Use JSON.parse() for data or redesign the logic.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'AUTH-007', ruleName: 'Insecure Cookie (missing httpOnly)',
    severity: 'MEDIUM', category: 'Broken Authentication', owasp: 'A07:2021',
    description: 'Cookie set without httpOnly flag is accessible via JavaScript',
    file: 'src/routes/auth.js', line: 78, column: 0,
    snippet: "res.cookie('session', token)",
    remediation: 'Add httpOnly: true and secure: true to all auth cookies.',
    source: 'owasp-rules',
  },
  {
    ruleId: 'BAC-002', ruleName: 'Path Traversal',
    severity: 'CRITICAL', category: 'Broken Access Control', owasp: 'A01:2021',
    description: 'File path constructed from user input enables path traversal attacks',
    file: 'src/controllers/downloadController.js', line: 22, column: 0,
    snippet: "fs.readFile(req.query.filename)",
    remediation: "Use path.basename() and restrict to a known safe directory.",
    source: 'owasp-rules',
  },
  {
    ruleId: 'SDE-005', ruleName: 'Sensitive Data Logged',
    severity: 'MEDIUM', category: 'Sensitive Data Exposure', owasp: 'A02:2021',
    description: 'Password being written to application logs',
    file: 'src/services/userService.js', line: 45, column: 0,
    snippet: "logger.info('User login attempt', { email, password })",
    remediation: 'Remove sensitive fields from log statements. Use data masking.',
    source: 'owasp-rules',
  },
];

// ─── NPM audit result sample ───────────────────────────────────────────────
const SAMPLE_NPM_AUDIT = {
  auditReportVersion: 2,
  vulnerabilities: {
    'lodash': { severity: 'high', name: 'lodash', range: '<4.17.21' },
    'minimist': { severity: 'critical', name: 'minimist', range: '<1.2.6' },
    'axios': { severity: 'moderate', name: 'axios', range: '<1.6.0' },
  },
  metadata: {
    vulnerabilities: { info: 0, low: 1, moderate: 3, high: 5, critical: 2, total: 11 },
    totalDependencies: 247,
  },
};

// ─── Helper ────────────────────────────────────────────────────────────────
function pickFindings(indices) {
  return indices.map(i => SAMPLE_FINDINGS[i]);
}

function summarize(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => {
    if (f.severity === 'CRITICAL') s.critical++;
    else if (f.severity === 'HIGH') s.high++;
    else if (f.severity === 'MEDIUM') s.medium++;
    else if (f.severity === 'LOW') s.low++;
    else s.info++;
  });
  return s;
}

async function seed() {
  console.log('\n🌱  Starting seeder...\n');

  // ── 1. Sync tables ────────────────────────────────────────────────────────
  await sequelize.authenticate();
  await sequelize.sync({ alter: true });
  console.log('✅  Tables synced');

  // ── 2. Clear existing demo data ───────────────────────────────────────────
  await Report.destroy({ where: {}, truncate: false });
  await Scan.destroy({ where: {}, truncate: false });
  await User.destroy({ where: {}, truncate: false });
  console.log('🗑️   Cleared existing data');

  // ── 3. Users ──────────────────────────────────────────────────────────────
  const users = await User.bulkCreate(
    [
      {
        email: 'admin@secscanner.dev',
        password: await bcrypt.hash('Admin@1234', 12),
        name: 'Admin User',
        role: 'admin',
        githubUrl: 'https://api.github.com',
        isActive: true,
      },
      {
        email: 'analyst@secscanner.dev',
        password: await bcrypt.hash('Analyst@1234', 12),
        name: 'Security Analyst',
        role: 'analyst',
        githubUrl: 'https://api.github.com',
        isActive: true,
      },
      {
        email: 'viewer@secscanner.dev',
        password: await bcrypt.hash('Viewer@1234', 12),
        name: 'Report Viewer',
        role: 'viewer',
        githubUrl: 'https://api.github.com',
        isActive: true,
      },
    ],
    { individualHooks: false }   // passwords already hashed above
  );

  console.log('👤  Users created:');
  users.forEach(u => console.log(`     ${u.role.padEnd(8)}  ${u.email}`));

  const adminId  = users[0].id;
  const analystId = users[1].id;

  // ── 4. Scans + Reports ────────────────────────────────────────────────────
  const demoScans = [
    {
      userId: adminId,
      projectId: '101',
      projectName: 'myorg/backend-api',
      pullRequestId: 42,
      prTitle: 'feat: add user registration endpoint',
      sourceBranch: 'feature/user-registration',
      targetBranch: 'main',
      findingIndices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
      withNpmAudit: true,
    },
    {
      userId: adminId,
      projectId: '102',
      projectName: 'myorg/frontend-app',
      pullRequestId: 18,
      prTitle: 'fix: update authentication flow',
      sourceBranch: 'fix/auth-flow',
      targetBranch: 'develop',
      findingIndices: [2, 4, 7, 12],
      withNpmAudit: false,
    },
    {
      userId: analystId,
      projectId: '103',
      projectName: 'myorg/payment-service',
      pullRequestId: 7,
      prTitle: 'refactor: payment gateway integration',
      sourceBranch: 'refactor/payment-gateway',
      targetBranch: 'main',
      findingIndices: [0, 3, 6, 8, 13],
      withNpmAudit: true,
    },
    {
      userId: analystId,
      projectId: '101',
      projectName: 'myorg/backend-api',
      pullRequestId: 55,
      prTitle: 'chore: upgrade dependencies',
      sourceBranch: 'chore/deps-upgrade',
      targetBranch: 'main',
      findingIndices: [8],
      withNpmAudit: true,
    },
    {
      userId: adminId,
      projectId: '104',
      projectName: 'myorg/admin-panel',
      pullRequestId: 3,
      prTitle: 'feat: role-based access control',
      sourceBranch: 'feature/rbac',
      targetBranch: 'main',
      findingIndices: [],   // clean scan
      withNpmAudit: false,
    },
  ];

  for (const demo of demoScans) {
    const scanId = uuidv4();
    const startedAt = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000);
    const completedAt = new Date(startedAt.getTime() + Math.random() * 300000 + 30000);

    await Scan.create({
      scanId,
      userId: demo.userId,
      projectId: demo.projectId,
      projectName: demo.projectName,
      projectUrl: `https://github.com/${demo.projectName}`,
      pullRequestId: demo.pullRequestId,
      pullRequestTitle: demo.prTitle,
      pullRequestUrl: `https://github.com/${demo.projectName}/pull/${demo.pullRequestId}`,
      sourceBranch: demo.sourceBranch,
      targetBranch: demo.targetBranch,
      commitSha: [...Array(40)].map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
      status: 'completed',
      progress: 100,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      filesScanned: Math.floor(Math.random() * 200 + 50),
      linesScanned: Math.floor(Math.random() * 15000 + 2000),
    });

    const findings = pickFindings(demo.findingIndices);
    const s = summarize(findings);

    await Report.create({
      scanId,
      userId: demo.userId,
      projectId: demo.projectId,
      projectName: demo.projectName,
      pullRequestId: demo.pullRequestId,
      pullRequestTitle: demo.prTitle,
      criticalCount: s.critical,
      highCount: s.high,
      mediumCount: s.medium,
      lowCount: s.low,
      infoCount: s.info,
      findings,
      npmAuditResult: demo.withNpmAudit ? SAMPLE_NPM_AUDIT : null,
      filesScanned: Math.floor(Math.random() * 200 + 50),
      linesScanned: Math.floor(Math.random() * 15000 + 2000),
      scannedAt: completedAt,
    });

    const total = s.critical + s.high + s.medium + s.low + s.info;
    console.log(`📋  Scan seeded: [${demo.projectName}] PR #${demo.pullRequestId} — ${total} findings`);
  }

  // ── 5. Summary ────────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(55));
  console.log('✅  Seeding complete!\n');
  console.log('📌  Login credentials:');
  console.log('     Role      Email                       Password');
  console.log('     ────────  ──────────────────────────  ────────────');
  console.log('     admin     admin@secscanner.dev         Admin@1234');
  console.log('     analyst   analyst@secscanner.dev       Analyst@1234');
  console.log('     viewer    viewer@secscanner.dev        Viewer@1234');
  console.log('─'.repeat(55) + '\n');
}

seed()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('\n❌  Seeder failed:', err.message);
    process.exit(1);
  });
