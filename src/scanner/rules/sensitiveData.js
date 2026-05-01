'use strict';

// A02:2021 — Cryptographic Failures / Sensitive Data Exposure
// Covers: hardcoded secrets, weak crypto, insecure transmission, cloud credentials

const RULES = [
  // ── Hardcoded Credentials ─────────────────────────────────────
  {
    id: 'SDE-001',
    name: 'Hardcoded API Key / Secret',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['"`][A-Za-z0-9+/=_\-]{16,}['"`]/gi,
    description: 'Hardcoded API key or secret found in source code. Secrets committed to version control are exposed to anyone with repo access and persist in git history.',
    remediation: 'Move secrets to environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Use dotenv and add .env to .gitignore.',
  },
  {
    id: 'SDE-002',
    name: 'Hardcoded Password',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-259',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"`][^'"`\s]{4,}['"`]/gi,
    description: 'Hardcoded password or credential found in source code. Exposed passwords can be used for account takeover and lateral movement.',
    remediation: 'Never hardcode passwords. Load from environment: process.env.DB_PASSWORD. Use a secrets manager for production.',
  },
  {
    id: 'SDE-003',
    name: 'Private Key / Certificate Material in Source',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-321',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/g,
    description: 'Private key material found in source code. This allows impersonation of the server, decryption of TLS traffic, and code signing forgery.',
    remediation: 'Remove the private key immediately, rotate it, and store it in a key management service or environment variable outside the repo.',
  },

  // ── AWS ───────────────────────────────────────────────────────
  {
    id: 'SDE-004',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: 'AWS IAM Access Key ID detected in source code. Combined with the secret key, an attacker gains full API access to the AWS account.',
    remediation: 'Immediately revoke the key in AWS IAM console. Use IAM roles for EC2/Lambda instead of static keys. Store secrets in AWS Secrets Manager.',
  },
  {
    id: 'SDE-005',
    name: 'AWS Secret Access Key',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9/+]{40}['"`]/gi,
    description: 'AWS Secret Access Key detected. This 40-character string paired with the Access Key ID grants full programmatic access to AWS services.',
    remediation: 'Rotate the key immediately. Use AWS IAM roles or environment variables. Never commit credentials to version control.',
  },

  // ── Google Cloud / GCP ───────────────────────────────────────
  {
    id: 'SDE-006',
    name: 'GCP Service Account Key (JSON)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go'],
    pattern: /"type"\s*:\s*"service_account"[^}]*"private_key"/gs,
    description: 'Google Cloud Platform service account key JSON detected. This grants API-level access to all GCP services the service account can access.',
    remediation: 'Delete and recreate the service account key in GCP Console. Use Workload Identity Federation instead of key files in production.',
  },
  {
    id: 'SDE-007',
    name: 'Google API Key',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php'],
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API key detected. Can be used for unauthorized API calls (Maps, YouTube, Translation) resulting in unexpected charges.',
    remediation: 'Restrict the API key to specific APIs and IP addresses in Google Cloud Console. Use application restrictions to limit usage.',
  },

  // ── Azure ─────────────────────────────────────────────────────
  {
    id: 'SDE-008',
    name: 'Azure Storage Account Key',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'csharp'],
    pattern: /DefaultEndpointsProtocol=https;AccountName=\w+;AccountKey=[A-Za-z0-9+/=]{88}/g,
    description: 'Azure Storage Account connection string with account key detected. Provides full read/write access to all blobs, tables, queues, and files.',
    remediation: 'Rotate the storage account key in Azure Portal. Use Azure Managed Identity or SAS tokens with limited scope and expiry.',
  },
  {
    id: 'SDE-009',
    name: 'Azure Client Secret / Tenant Credentials',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'csharp'],
    pattern: /(?:AZURE_CLIENT_SECRET|clientSecret|client_secret)\s*[:=]\s*['"`][A-Za-z0-9~._\-]{32,}['"`]/gi,
    description: 'Azure Active Directory client secret detected. Enables authentication as the registered application with all its granted permissions.',
    remediation: 'Rotate the secret in Azure AD App Registrations. Use Managed Identity for Azure-hosted workloads. Store in Azure Key Vault.',
  },

  // ── Stripe / Payment ──────────────────────────────────────────
  {
    id: 'SDE-010',
    name: 'Stripe Secret Key',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    description: 'Stripe secret API key detected. Can be used to charge cards, issue refunds, create customers, and read payment data.',
    remediation: 'Roll the key immediately in the Stripe Dashboard. Use environment variables: process.env.STRIPE_SECRET_KEY. Restrict to server-side only.',
  },
  {
    id: 'SDE-011',
    name: 'Stripe Webhook Signing Secret',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    pattern: /whsec_[A-Za-z0-9]{32,}/g,
    description: 'Stripe webhook endpoint signing secret detected. Allows forging of Stripe webhook events to trigger payment workflows.',
    remediation: 'Rotate in Stripe Dashboard. Load from environment variable. Verify webhook signatures using stripe.webhooks.constructEvent().',
  },

  // ── GitHub / SCM Tokens ───────────────────────────────────────
  {
    id: 'SDE-012',
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /(?:ghp_|ghs_|gho_|github[_-]token\s*[:=]\s*['"`])[A-Za-z0-9_]{36,}/gi,
    description: 'GitHub personal access token detected. Can be used to access, modify, or delete repositories the user has access to.',
    remediation: 'Revoke the token immediately at github.com/settings/tokens. Use GitHub Actions secrets or environment variables.',
  },
  {
    id: 'SDE-013',
    name: 'GitLab Personal Access Token',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /glpat-[A-Za-z0-9_\-]{20}/g,
    description: 'GitLab personal access token detected (glpat- prefix). Grants API access to GitLab projects and user account.',
    remediation: 'Revoke immediately at GitLab Profile > Access Tokens. Use CI/CD variables for pipeline secrets.',
  },

  // ── Database Connection Strings ───────────────────────────────
  {
    id: 'SDE-014',
    name: 'Database Connection String With Credentials',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-312',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    pattern: /(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql|sqlserver|oracle):\/\/[^:/?#\s]+:[^@\s]+@/gi,
    description: 'Database connection string with embedded username and password found in code. Credentials in source code are exposed to all developers and version history.',
    remediation: 'Move to environment variable: DATABASE_URL=... and load with process.env.DATABASE_URL. Add .env to .gitignore.',
  },
  {
    id: 'SDE-015',
    name: 'Hardcoded Database Credentials (host/user/password pattern)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-259',
    tech: ['javascript', 'typescript', 'python', 'php'],
    pattern: /(?:host|server|dbname|database)\s*[:=]\s*['"`]\w+['"`][^}]{0,100}(?:password|passwd|pwd)\s*[:=]\s*['"`][^'"`\s]{4,}['"`]/gis,
    description: 'Database connection parameters including a hardcoded password found in source code.',
    remediation: 'Load database credentials from environment variables or a secrets manager. Never commit credentials to version control.',
  },

  // ── Cryptographic Weaknesses ──────────────────────────────────
  {
    id: 'SDE-016',
    name: 'Weak Hash Algorithm (MD5)',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-327',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php'],
    pattern: /(?:createHash|hashlib\.new|MessageDigest\.getInstance|md5|crypto\.MD5)\s*\(\s*['"`]md5['"`]\s*\)|hashlib\.md5\s*\(/gi,
    description: 'MD5 is cryptographically broken. MD5 password hashes can be cracked with rainbow tables in seconds. MD5 should not be used for any security purpose.',
    remediation: 'For passwords: use bcrypt, argon2id, or scrypt. For data integrity: use SHA-256 or SHA-3. In Node.js: crypto.createHash("sha256").',
  },
  {
    id: 'SDE-017',
    name: 'Weak Hash Algorithm (SHA-1)',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-327',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php'],
    pattern: /(?:createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(\s*['"`]sha-?1['"`]\s*\)|hashlib\.sha1\s*\(/gi,
    description: 'SHA-1 is considered cryptographically weak (collision attacks demonstrated). SHAttered attack broke SHA-1 certificate verification.',
    remediation: 'Upgrade to SHA-256 or SHA-512. For password hashing use bcrypt/argon2 instead of any raw hash function.',
  },
  {
    id: 'SDE-018',
    name: 'Weak Symmetric Cipher (DES/3DES/RC4)',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-327',
    tech: ['javascript', 'typescript', 'python', 'java', 'go'],
    pattern: /(?:createCipher|Cipher\.getInstance|crypto\.createCipheriv)\s*\(\s*['"`](?:des|des-ede|des-ede3|des3|rc4|arcfour|bf|blowfish)['"`]/gi,
    description: 'Deprecated weak cipher algorithm (DES/3DES/RC4) in use. These are vulnerable to practical cryptanalytic attacks.',
    remediation: 'Use AES-256-GCM for symmetric encryption. In Node.js: crypto.createCipheriv("aes-256-gcm", key, iv).',
  },
  {
    id: 'SDE-019',
    name: 'JWT Signed With Weak Secret',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-326',
    tech: ['javascript', 'typescript'],
    pattern: /jwt\.sign\s*\([^,)]+,\s*['"`][^'"`]{1,15}['"`]\s*[,)]/g,
    description: 'JWT signed with a weak or short secret (under 16 characters). Short secrets can be brute-forced, allowing token forgery.',
    remediation: 'Use a cryptographically random secret of at least 256 bits (32 bytes): crypto.randomBytes(32).toString("hex"). Store in environment variable.',
  },
  {
    id: 'SDE-020',
    name: 'JWT Algorithm Set to "none" (Token Forgery)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-347',
    tech: ['javascript', 'typescript', 'python', 'java'],
    pattern: /(?:jwt\.sign|jwt\.verify|jwt\.decode)\s*\([^)]*algorithm[s]?\s*:\s*['"`]none['"`]/gi,
    description: 'JWT algorithm set to "none" disables signature verification. Attackers can forge arbitrary tokens without knowing the secret.',
    remediation: 'Always specify and verify the algorithm: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never allow "none".',
  },

  // ── Sensitive Data in Transport ───────────────────────────────
  {
    id: 'SDE-021',
    name: 'Sensitive Data in URL Query String',
    severity: 'MEDIUM',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-319',
    tech: ['javascript', 'typescript', 'python', 'php', 'ruby'],
    pattern: /(?:res\.redirect|location\.href|window\.location|redirect\s*\()\s*[^)]*(?:token|password|secret|key|apikey)=/gi,
    description: 'Sensitive data transmitted in URL query string. URLs appear in browser history, server logs, and Referer headers — exposing credentials.',
    remediation: 'Pass sensitive data in request body (POST) or as Authorization headers. Never include tokens or passwords in URLs.',
  },
  {
    id: 'SDE-022',
    name: 'TLS/SSL Verification Disabled',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-295',
    tech: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php'],
    pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false|InsecureSkipVerify\s*:\s*true|ssl_verify_host\s*,\s*0)/gi,
    description: 'TLS/SSL certificate verification disabled. This allows man-in-the-middle attacks — any certificate, including self-signed ones, will be accepted.',
    remediation: 'Never disable TLS verification in production. Fix the certificate chain issue instead. For development, use a local CA (mkcert) rather than disabling verification.',
  },
  {
    id: 'SDE-023',
    name: 'Sensitive Data Logged (Passwords / Tokens)',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-532',
    tech: ['javascript', 'typescript', 'python', 'java'],
    pattern: /(?:console\.log|logger\.\w+|log\.(?:info|debug|warn))\s*\([^)]*(?:password|passwd|token|secret|credit[_-]?card|ssn|dob|social[_-]?security)/gi,
    description: 'Sensitive data (password, token, PII) written to application logs. Log files are often accessible to ops teams and aggregated in SIEM systems.',
    remediation: 'Remove sensitive fields from log statements. Use data masking: log only last 4 chars of tokens. Implement a log scrubbing middleware.',
  },

  // ── Cloud / Infrastructure Tokens ────────────────────────────
  {
    id: 'SDE-024',
    name: 'Slack Bot / Webhook Token',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'go', 'ruby'],
    pattern: /(?:xoxb-|xoxp-|xoxa-|xoxr-|hooks\.slack\.com\/services\/)[A-Za-z0-9\/\-]{10,}/g,
    description: 'Slack bot token or webhook URL detected. Can be used to post messages, read channels, and access workspace data.',
    remediation: 'Rotate the token in Slack API settings. Store in environment variables. Restrict OAuth scopes to minimum required.',
  },
  {
    id: 'SDE-025',
    name: 'SendGrid / Mailgun / Twilio API Key',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    cwe: 'CWE-798',
    tech: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    pattern: /(?:SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|key-[a-f0-9]{32}|AC[a-f0-9]{32}|SK[a-f0-9]{32})/g,
    description: 'Email/SMS service API key (SendGrid/Mailgun/Twilio) detected. Can be used to send phishing emails or SMS messages at your expense.',
    remediation: 'Rotate the key immediately in the service dashboard. Store in environment variables. Monitor for unexpected usage.',
  },
];

function detectColumn(line, pattern) {
  const p = new RegExp(pattern.source, pattern.flags.replace('g', '').replace('s', ''));
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
          snippet: line.trim().substring(0, 300).replace(/(['"`])[A-Za-z0-9+/=_\-]{12,}\1/g, '"[REDACTED]"'),
          remediation: rule.remediation,
          source: 'owasp-rules',
        });
      }
    }
  }
  return findings;
}

module.exports = { scan, RULES };
