'use strict';

// A03:2021 — Server-Side Template Injection (SSTI)
// Covers: Node.js (Pug/EJS/Handlebars/Nunjucks/Mustache), Python (Jinja2/Mako), PHP (Twig/Smarty), Java (Freemarker/Velocity), Ruby (ERB)

const RULES = [
  // ── Node.js — Pug ────────────────────────────────────────────
  {
    id: 'SSTI-001',
    name: 'Pug Compiled From User Input (SSTI)',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['javascript', 'typescript'],
    pattern: /pug\.(?:compile|render|renderFile)\s*\(\s*(?:req\.|request\.)\w+|pug\.render\s*\(\s*['"`][^'"`)]*\$\{/gi,
    description: 'Pug template compiled or rendered with user-controlled template string. Pug templates execute arbitrary JavaScript — full RCE is possible.',
    remediation: 'Never compile user-supplied template strings. Only compile trusted static templates at startup. Pass user data as template variables, not as the template itself.',
  },
  {
    id: 'SSTI-002',
    name: 'EJS Rendered With User-Controlled Template',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['javascript', 'typescript'],
    pattern: /ejs\.render\s*\(\s*(?:req\.|request\.)\w+(?:\.(?:query|params|body)\.\w+)?/gi,
    description: 'ejs.render() called with user-supplied template content. EJS tags (<%- code %>) execute arbitrary JavaScript, enabling RCE.',
    remediation: 'Render only pre-approved, static EJS templates. Pass user data exclusively as the template data object (second argument), never as the template string.',
  },
  {
    id: 'SSTI-003',
    name: 'Handlebars Compiled From User Input (SSTI)',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['javascript', 'typescript'],
    pattern: /(?:Handlebars|handlebars)\.compile\s*\(\s*(?:req\.|request\.)\w+|hbs\.compile\s*\(\s*(?:req\.|request\.)/gi,
    description: 'Handlebars.compile() with user-controlled template. Handlebars has had prototype pollution CVEs (CVE-2021-23369) enabling RCE through template compilation.',
    remediation: 'Pre-compile all templates at build time. Never allow users to provide template strings.',
  },
  {
    id: 'SSTI-004',
    name: 'Nunjucks renderString With User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['javascript', 'typescript'],
    pattern: /nunjucks\.renderString\s*\(\s*(?:req\.|request\.)\w+/gi,
    description: 'nunjucks.renderString() with user-supplied template enables SSTI and RCE via Nunjucks sandbox escape.',
    remediation: 'Use nunjucks.render() with static template files only. Never renderString with user content.',
  },
  {
    id: 'SSTI-005',
    name: 'Mustache render() With User Template',
    severity: 'HIGH',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['javascript', 'typescript'],
    pattern: /Mustache\.render\s*\(\s*(?:req\.|request\.)\w+/gi,
    description: 'Mustache.render() with user-controlled template string. While Mustache has limited execution, injected templates can leak sensitive template variables.',
    remediation: 'Use Mustache.render() only with static template strings. Pass user data as the second (view) argument only.',
  },

  // ── Python — Jinja2 ──────────────────────────────────────────
  {
    id: 'SSTI-006',
    name: 'Jinja2 render_template_string With User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['python'],
    pattern: /render_template_string\s*\(\s*(?:request\.(?:args|form|json|data|values)|f['"`]|['"`][^'"`)]*\{)/gi,
    description: 'Flask render_template_string() with user-supplied content enables full SSTI. Attackers can use {{ config }} to leak secrets or {{ "".__class__.__mro__[1].__subclasses__() }} for RCE.',
    remediation: 'NEVER pass user input to render_template_string(). Use render_template() with static .html files and pass user data as context variables.',
  },
  {
    id: 'SSTI-007',
    name: 'Jinja2 Template.render With User Template Source',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['python'],
    pattern: /jinja2\.Template\s*\(\s*(?:request\.|input|user_|data_|\w*template\w*)/gi,
    description: 'jinja2.Template() compiled from user-controlled string enables SSTI/RCE. Jinja2 sandbox can be escaped.',
    remediation: 'Use jinja2.Environment.get_template() with template files from a trusted directory. Enable the sandbox but do not rely on it alone.',
  },

  // ── Python — Mako ─────────────────────────────────────────────
  {
    id: 'SSTI-008',
    name: 'Mako Template From User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['python'],
    pattern: /mako\.template\.Template\s*\(\s*(?:request\.|input|user)/gi,
    description: 'Mako Template compiled from user input. Mako templates have no sandbox — ${code} executes arbitrary Python.',
    remediation: 'Pre-compile all Mako templates from disk. Never build templates from user-supplied strings.',
  },

  // ── PHP — Twig ────────────────────────────────────────────────
  {
    id: 'SSTI-009',
    name: 'Twig createTemplate() With User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['php'],
    pattern: /\$twig->createTemplate\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
    description: 'Twig createTemplate() with user-controlled template enables SSTI. Twig sandbox can be bypassed.',
    remediation: 'Use $twig->load("fixed_template.html"). Never dynamically compile user-supplied Twig strings.',
  },
  {
    id: 'SSTI-010',
    name: 'Smarty Template From User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['php'],
    pattern: /\$smarty->(?:fetch|display)\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
    description: 'Smarty fetch/display with user-controlled template name enables SSTI and potential file read/RCE.',
    remediation: 'Only use hardcoded template names. Validate template names against a whitelist of known templates.',
  },

  // ── Java — Freemarker ─────────────────────────────────────────
  {
    id: 'SSTI-011',
    name: 'Freemarker Template From User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['java'],
    pattern: /new\s+Template\s*\(\s*['"`]\w+['"`]\s*,\s*new\s+StringReader\s*\(\s*(?:request\.getParameter|req\.getParameter)/gi,
    description: 'Freemarker template compiled from user input. FreeMarker allows calling arbitrary Java methods — full RCE.',
    remediation: 'Only load templates from trusted classpath or file system locations. Never create templates from user input.',
  },

  // ── Ruby — ERB ────────────────────────────────────────────────
  {
    id: 'SSTI-012',
    name: 'Ruby ERB.new() With User Input',
    severity: 'CRITICAL',
    category: 'Template Injection',
    owasp: 'A03:2021',
    cwe: 'CWE-94',
    tech: ['ruby'],
    pattern: /ERB\.new\s*\(\s*(?:params\[|request\.|@?\w*(?:input|template|content)\w*)/gi,
    description: 'ERB.new() with user-supplied template enables full RCE. ERB <%= code %> executes arbitrary Ruby.',
    remediation: 'Use pre-compiled ERB templates from disk. If dynamic content is needed, pass it as ERB binding variables, not as template code.',
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
