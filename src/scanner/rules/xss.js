'use strict';

// A03:2021 — Cross-Site Scripting (XSS)
// Covers: JavaScript/TypeScript, PHP, Python/Flask, Java Servlets, Go, Ruby on Rails, Angular, Vue

const RULES = [
  // ── JavaScript / TypeScript — DOM XSS ───────────────────────
  {
    id: 'XSS-001',
    name: 'Unsafe innerHTML Assignment',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /\.innerHTML\s*=\s*(?!['"`][^$`]*['"`]\s*;)/g,
    description: 'Direct innerHTML assignment with dynamic content enables XSS. Browsers parse and execute script tags and event handlers in the assigned HTML.',
    remediation: 'Use textContent for plain text. If HTML is required, sanitize first: element.innerHTML = DOMPurify.sanitize(userInput).',
  },
  {
    id: 'XSS-002',
    name: 'Unsafe document.write()',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /document\.write\s*\(/g,
    description: 'document.write() writes directly to the HTML stream. If called with user-controlled data it enables reflected XSS.',
    remediation: 'Replace document.write() with DOM manipulation methods: createElement + appendChild. Never pass user input.',
  },
  {
    id: 'XSS-003',
    name: 'Unsafe outerHTML Assignment',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /\.outerHTML\s*=\s*(?!['"`][^$`]*['"`]\s*;)/g,
    description: 'outerHTML replaces the entire element with the parsed HTML. Attacker-controlled content executes immediately.',
    remediation: 'Avoid setting outerHTML dynamically. Use replaceWith() with safe DOM nodes instead.',
  },
  {
    id: 'XSS-004',
    name: 'Unsafe insertAdjacentHTML',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /\.insertAdjacentHTML\s*\(/g,
    description: 'insertAdjacentHTML parses and inserts HTML like innerHTML. User input passed here executes as HTML/JS.',
    remediation: 'Use insertAdjacentText() for plain text. If HTML is needed: el.insertAdjacentHTML("beforeend", DOMPurify.sanitize(data)).',
  },
  {
    id: 'XSS-005',
    name: 'React dangerouslySetInnerHTML Without Sanitization',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    description: 'React dangerouslySetInnerHTML bypasses React\'s XSS protection. Unsanitized HTML here enables stored/reflected XSS.',
    remediation: 'Sanitize with DOMPurify before use: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}. Consider using a Markdown renderer with sanitization instead.',
  },
  {
    id: 'XSS-006',
    name: 'Reflected XSS via Express res.send/write',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /res\.(?:send|write|end)\s*\([^)]*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/g,
    description: 'User input directly reflected in HTTP response HTML enables reflected XSS. No encoding means browsers execute injected script.',
    remediation: 'Use a templating engine with auto-escaping (Handlebars, Pug). If sending raw HTML, HTML-encode: he.encode(userInput).',
  },
  {
    id: 'XSS-007',
    name: 'eval() With Dynamic Content',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /\beval\s*\(\s*(?!['"`][^'"`]*['"`]\s*\))/g,
    description: 'eval() executes arbitrary JavaScript. If user input reaches eval(), it becomes full script injection (XSS/RCE in Node.js).',
    remediation: 'Eliminate eval(). Use JSON.parse() for data, Function() is also dangerous. Refactor logic to avoid dynamic code execution.',
  },
  {
    id: 'XSS-008',
    name: 'setTimeout/setInterval With String (eval-equivalent)',
    severity: 'MEDIUM',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /(?:setTimeout|setInterval)\s*\(\s*(?:req\.|request\.|`|\w+\s*\+)/g,
    description: 'Passing a string (not a function) to setTimeout/setInterval is eval-equivalent. Injected code executes in the global scope.',
    remediation: 'Always pass a function reference: setTimeout(() => doWork(), 1000). Never build the argument from user input.',
  },
  {
    id: 'XSS-009',
    name: 'EJS/ERB Unescaped Output Tag (<%- or <%=raw)',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript', 'ruby'],
    pattern: /<%-\s*(?!.*(?:escape|sanitize|DOMPurify)).*(?:req\.|request\.|params\.|user\.|input)/g,
    description: 'EJS <%- tag outputs raw unescaped HTML. User-controlled values in <%- blocks are direct XSS sinks.',
    remediation: 'Use <%= for auto-HTML-escaped output. Use <%- only for pre-sanitized trusted HTML content.',
  },

  // ── PHP ──────────────────────────────────────────────────────
  {
    id: 'XSS-010',
    name: 'PHP Direct echo of $_GET/$_POST (Reflected XSS)',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['php'],
    pattern: /(?:echo|print)\s+(?:\(?\s*)?(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[|htmlspecialchars\s*\(\s*\$_(?:GET|POST|REQUEST))/gi,
    description: 'PHP echo/print directly outputs user input from $_GET/$_POST without encoding. Classic reflected XSS vulnerability.',
    remediation: 'Always encode before output: echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8"); For rich HTML use HTMLPurifier.',
  },
  {
    id: 'XSS-011',
    name: 'PHP Short Echo Tag With User Input (<?= XSS)',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['php'],
    pattern: /<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
    description: '<?= is shorthand for <?php echo. Outputting $_GET/$_POST directly causes reflected XSS.',
    remediation: 'Use <?= htmlspecialchars($var, ENT_QUOTES, "UTF-8") ?> or use a templating engine (Twig) that auto-escapes by default.',
  },
  {
    id: 'XSS-012',
    name: 'PHP header("Location") With User Input Enables Header Injection',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['php'],
    pattern: /header\s*\(\s*['"`]Location\s*:\s*['"`]\s*\.\s*\$(?!_SERVER\b)\w+/gi,
    description: 'Concatenating user input into Location header enables open redirect and potential header injection attacks.',
    remediation: 'Validate the redirect URL against a whitelist. Use filter_var($url, FILTER_VALIDATE_URL) and check the domain.',
  },

  // ── Python / Flask / Jinja2 ───────────────────────────────────
  {
    id: 'XSS-013',
    name: 'Flask Markup() Bypasses Jinja2 Auto-escape (XSS)',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['python'],
    pattern: /Markup\s*\(\s*(?:request\.(?:args|form|json|values|data)|f['"`]|str\()/gi,
    description: 'Markup() marks a string as safe, bypassing Jinja2\'s auto-escaping. User input wrapped in Markup() is rendered as raw HTML.',
    remediation: 'Never wrap user input in Markup(). Only wrap strings that have been fully sanitized by bleach.clean() or similar.',
  },
  {
    id: 'XSS-014',
    name: 'Python String Concatenation Into HTML Response',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['python'],
    pattern: /return\s+['"`]<[^'"`]*['"`]\s*\+\s*(?:request\.|str\(request\.)/gi,
    description: 'HTML built by string concatenation with user request data. Python does not auto-escape HTML — this is a reflected XSS sink.',
    remediation: 'Use render_template() with Jinja2 auto-escaping. If returning HTML from code, use html.escape(): html.escape(request.args.get("q", ""))',
  },

  // ── Java — Servlets / JSP ─────────────────────────────────────
  {
    id: 'XSS-015',
    name: 'Java Servlet PrintWriter Direct Reflection (XSS)',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['java'],
    pattern: /(?:out|response\.getWriter\s*\(\s*\))\.(?:print|println|write)\s*\(\s*request\.getParameter/gi,
    description: 'Java servlet writes request.getParameter() directly to the response HTML without encoding. Classic reflected XSS in Java.',
    remediation: 'Encode before output: out.print(ESAPI.encoder().encodeForHTML(request.getParameter("x"))); Use OWASP Java Encoder: Encode.forHtml().',
  },
  {
    id: 'XSS-016',
    name: 'JSP EL Expression Without Escaping (${param.x})',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['java'],
    pattern: /\$\{param\.\w+\}/g,
    description: 'JSP EL expression ${param.x} outputs request parameters directly. Without fn:escapeXml() this is a reflected XSS sink.',
    remediation: 'Use <c:out value="${param.x}"/> or ${fn:escapeXml(param.x)} to HTML-encode the output.',
  },

  // ── Go ───────────────────────────────────────────────────────
  {
    id: 'XSS-017',
    name: 'Go fmt.Fprintf With User Input Into HTTP Response',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['go'],
    pattern: /fmt\.Fprintf\s*\(\s*\w+\s*,[^)]*r\.(?:FormValue|URL\.Query\(\)\.Get|Header\.Get)/gi,
    description: 'Go fmt.Fprintf writes formatted user input directly into the HTTP response without HTML encoding — reflected XSS.',
    remediation: 'Use html/template package (not text/template) which auto-escapes: tmpl.Execute(w, data). Or use html.EscapeString(r.FormValue("q")).',
  },
  {
    id: 'XSS-018',
    name: 'Go io.WriteString / w.Write With Raw User Input',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['go'],
    pattern: /(?:io\.WriteString|w\.Write)\s*\([^)]*r\.(?:FormValue|URL\.Query)/gi,
    description: 'Writing raw user input to http.ResponseWriter without escaping causes reflected XSS in Go applications.',
    remediation: 'Escape user input: io.WriteString(w, html.EscapeString(r.FormValue("name"))). Better: use html/template for rendering.',
  },

  // ── Ruby on Rails ─────────────────────────────────────────────
  {
    id: 'XSS-019',
    name: 'Rails html_safe on User Input (XSS Bypass)',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['ruby'],
    pattern: /params\s*\[.+\]\s*\.html_safe|(?:@\w+|params\[\w+\])\s*\.html_safe/gi,
    description: 'Calling .html_safe on params or user input marks it as trusted HTML, bypassing Rails\' auto-escaping and enabling XSS.',
    remediation: 'Never call .html_safe on user input. Use the sanitize() helper if rich HTML is needed: sanitize(params[:content], tags: %w[b i em strong]).',
  },
  {
    id: 'XSS-020',
    name: 'Rails raw() Helper With User Input',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['ruby'],
    pattern: /raw\s*\(\s*(?:params\[|@\w*(?:input|content|html|body|text)\w*)/gi,
    description: 'Rails raw() outputs content unescaped. Passing user input via raw() directly leads to XSS in the rendered view.',
    remediation: 'Use html_escape() (or h()) for encoding, or the sanitize() helper with a tag allowlist for rich text.',
  },

  // ── Angular ───────────────────────────────────────────────────
  {
    id: 'XSS-021',
    name: 'Angular [innerHTML] Binding With Unsanitized Data',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /\[innerHTML\]\s*=\s*['"`](?!.*sanitize)/gi,
    description: 'Angular [innerHTML] binding bypasses template encoding. Data bound here is parsed as HTML — script injection is possible if input is not sanitized.',
    remediation: 'Use DomSanitizer.sanitizeHtml() before binding: constructor(private sanitizer: DomSanitizer) {} then this.sanitizer.sanitize(SecurityContext.HTML, value).',
  },
  {
    id: 'XSS-022',
    name: 'Angular bypassSecurityTrustHtml Usage',
    severity: 'CRITICAL',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/gi,
    description: 'bypassSecurityTrust* explicitly disables Angular\'s built-in XSS protection for the value. Misuse leads to XSS.',
    remediation: 'Only use bypassSecurityTrust* for values generated entirely server-side with no user input. Document why each call is safe.',
  },

  // ── Vue.js ────────────────────────────────────────────────────
  {
    id: 'XSS-023',
    name: 'Vue v-html Directive With User Data',
    severity: 'HIGH',
    category: 'XSS',
    owasp: 'A03:2021',
    cwe: 'CWE-79',
    tech: ['javascript', 'typescript'],
    pattern: /v-html\s*=\s*['"`]/gi,
    description: 'Vue v-html renders content as raw HTML, bypassing Vue\'s template escaping. If bound to user data, it enables stored or reflected XSS.',
    remediation: 'Sanitize content before binding: v-html="sanitize(userContent)". Use DOMPurify: import DOMPurify from "dompurify"; sanitize = DOMPurify.sanitize.',
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
