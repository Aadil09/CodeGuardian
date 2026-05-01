'use strict';

// A10:2021 — Server-Side Request Forgery (SSRF)
// Covers: Node.js, PHP, Python, Java, Go, Ruby, C#

const RULES = [
  // ── Node.js / JavaScript ─────────────────────────────────────
  {
    id: 'SSRF-001',
    name: 'SSRF via fetch() with User-Controlled URL',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['javascript', 'typescript'],
    pattern: /\bfetch\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'fetch() called with user-controlled URL allows attackers to probe internal services, cloud metadata endpoints, and bypass firewalls.',
    remediation: 'Validate the URL against an allowlist of trusted domains. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x) and internal hostnames.',
  },
  {
    id: 'SSRF-002',
    name: 'SSRF via axios with User-Controlled URL',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['javascript', 'typescript'],
    pattern: /\baxios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'axios request with user-supplied URL enables SSRF — attacker can reach internal APIs, AWS metadata (169.254.169.254), Redis, etc.',
    remediation: 'Parse the URL with the `URL` class, validate the hostname against an allowlist, and reject private/loopback addresses.',
  },
  {
    id: 'SSRF-003',
    name: 'SSRF via http.get / http.request',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['javascript', 'typescript'],
    pattern: /\bhttp(?:s)?\.(?:get|request)\s*\(\s*(?:req\.|request\.)\w+|(?:url|endpoint|target|host)\s*[=:]\s*(?:req\.|request\.)/gi,
    description: 'Native http(s).get/request with user-controlled URL enables full SSRF exploitation.',
    remediation: 'Validate and allowlist URLs. Use a dedicated SSRF-prevention library (e.g., ssrf-filter).',
  },
  {
    id: 'SSRF-004',
    name: 'SSRF via node-fetch / request / got',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['javascript', 'typescript'],
    pattern: /(?:nodeFetch|node-fetch|got|superagent)\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'HTTP client library called with user-controlled URL allows SSRF.',
    remediation: 'Validate URLs before passing to any HTTP client. Reject private/internal addresses.',
  },

  // ── PHP ──────────────────────────────────────────────────────
  {
    id: 'SSRF-005',
    name: 'SSRF via curl_exec() in PHP',
    severity: 'CRITICAL',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['php'],
    pattern: /curl_setopt\s*\([^)]*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST|SERVER)/gi,
    description: 'curl_exec() with $_GET/$_POST URL allows full SSRF: internal services, file:// protocol, cloud metadata.',
    remediation: 'Validate the URL with parse_url(). Allowlist domains. Block internal IP ranges.',
  },
  {
    id: 'SSRF-006',
    name: 'SSRF via file_get_contents() in PHP',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['php'],
    pattern: /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
    description: 'file_get_contents() with user input can fetch arbitrary URLs or local files via PHP wrappers (php://, file://, phar://).',
    remediation: 'Disable allow_url_fopen for remote URLs or validate strictly. Never pass user input directly.',
  },

  // ── Python ───────────────────────────────────────────────────
  {
    id: 'SSRF-007',
    name: 'SSRF via requests.get() in Python',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['python'],
    pattern: /requests\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*(?:request\.\w+|params\[|args\[|data\[|json\[)/gi,
    description: 'requests library called with user-controlled URL. Attackers can probe internal services or cloud metadata (169.254.169.254).',
    remediation: 'Validate URL against allowlist. Use the `ssrfprotect` library or custom IP-block middleware.',
  },
  {
    id: 'SSRF-008',
    name: 'SSRF via urllib in Python',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['python'],
    pattern: /urllib\.(?:request\.)?(?:urlopen|urlretrieve)\s*\(\s*(?:request\.\w+|params|args|input|url)/gi,
    description: 'urllib.urlopen with user input enables SSRF, file read, and protocol abuse.',
    remediation: 'Validate and restrict the URL scheme (https only). Block private networks using ipaddress module.',
  },

  // ── Java ─────────────────────────────────────────────────────
  {
    id: 'SSRF-009',
    name: 'SSRF via Java URL.openConnection()',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['java'],
    pattern: /new\s+URL\s*\(\s*(?:request\.getParameter|req\.getParameter|\w*[Uu]rl\w*)\s*\(?\s*\)?\s*\)/g,
    description: 'Java URL object constructed from request parameter enables SSRF through URL.openConnection() or openStream().',
    remediation: 'Validate the URL against an allowlist. Use java.net.InetAddress to check for private/loopback ranges.',
  },
  {
    id: 'SSRF-010',
    name: 'SSRF via HttpURLConnection in Java',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['java'],
    pattern: /HttpURLConnection|HttpClient\s*\.(?:newHttpClient|create)\s*\(\s*\)[\s\S]{0,100}request\.getParameter/gi,
    description: 'HttpURLConnection or Java 11 HttpClient with user-supplied URL enables SSRF.',
    remediation: 'Validate URL before making the connection. Implement a URL allowlist policy.',
  },

  // ── Go ───────────────────────────────────────────────────────
  {
    id: 'SSRF-011',
    name: 'SSRF via http.Get() in Go',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['go'],
    pattern: /http\.(?:Get|Post|NewRequest)\s*\(\s*(?:r\.(?:URL|FormValue|Header)|url|target|endpoint)\b/gi,
    description: 'Go http.Get/Post with user-controlled URL parameter enables SSRF.',
    remediation: 'Parse the URL with url.Parse(), validate the host against a domain allowlist, and reject private IPs.',
  },

  // ── Ruby ─────────────────────────────────────────────────────
  {
    id: 'SSRF-012',
    name: 'SSRF via Net::HTTP in Ruby',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['ruby'],
    pattern: /Net::HTTP\.(?:get|post_form|start)\s*\(\s*(?:params|request\.)\w+/gi,
    description: 'Ruby Net::HTTP called with user-controlled host/URL enables SSRF.',
    remediation: 'Validate the target URI. Block private addresses using the `ssrf_filter` gem.',
  },
  {
    id: 'SSRF-013',
    name: 'SSRF via open-uri in Ruby',
    severity: 'CRITICAL',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['ruby'],
    pattern: /\bopen\s*\(\s*(?:params|request\.)\w+/gi,
    description: 'Kernel#open with user input in Ruby can open URLs AND local files — extremely dangerous.',
    remediation: 'Use URI.open() with validated URLs, or File.open() for local files. Never mix user input with open().',
  },

  // ── C# ───────────────────────────────────────────────────────
  {
    id: 'SSRF-014',
    name: 'SSRF via HttpClient in C#',
    severity: 'HIGH',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['csharp'],
    pattern: /HttpClient\s*\(\s*\)[\s\S]{0,200}(?:GetAsync|PostAsync|SendAsync)\s*\(\s*(?:Request\.Query|Request\.Form|HttpContext\.Request)/gi,
    description: 'ASP.NET HttpClient with user-controlled URL enables SSRF.',
    remediation: 'Validate the URL using Uri class. Restrict allowed hosts in IHttpClientFactory configuration.',
  },

  // ── Cloud Metadata specific ───────────────────────────────────
  {
    id: 'SSRF-015',
    name: 'Cloud Metadata Endpoint Hardcoded',
    severity: 'INFO',
    category: 'SSRF',
    owasp: 'A10:2021',
    cwe: 'CWE-918',
    tech: ['javascript', 'python', 'java', 'go', 'ruby', 'php'],
    pattern: /169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/g,
    description: 'Cloud metadata endpoint referenced in code — ensure this is not reachable via SSRF.',
    remediation: 'Block access to 169.254.169.254 at the network level. Use IMDSv2 (AWS) which requires a PUT request first.',
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
