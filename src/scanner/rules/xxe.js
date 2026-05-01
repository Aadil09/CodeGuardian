'use strict';

// A03:2021 — XML External Entity (XXE) Injection
// Covers: Java, PHP, Python, C#, JavaScript (libxmljs), Ruby

const RULES = [
  // ── Java ─────────────────────────────────────────────────────
  {
    id: 'XXE-001',
    name: 'Java DocumentBuilderFactory Without External Entity Protection',
    severity: 'CRITICAL',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['java'],
    pattern: /DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)/g,
    description: 'DocumentBuilderFactory created without disabling external entity processing. Attackers can use XXE to read /etc/passwd, SSRF internal services, or cause DoS via Billion Laughs.',
    remediation: 'Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).',
  },
  {
    id: 'XXE-002',
    name: 'Java SAXParserFactory Without External Entity Protection',
    severity: 'CRITICAL',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['java'],
    pattern: /SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)/g,
    description: 'SAXParserFactory created without external entity protection enables XXE attacks.',
    remediation: 'Disable DOCTYPE: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
  },
  {
    id: 'XXE-003',
    name: 'Java XMLInputFactory Without External Entity Protection',
    severity: 'CRITICAL',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['java'],
    pattern: /XMLInputFactory\s*\.\s*newInstance\s*\(\s*\)/g,
    description: 'XMLInputFactory (StAX) without external entity restrictions is vulnerable to XXE.',
    remediation: 'Set factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false) and factory.setProperty(XMLInputFactory.SUPPORT_DTD, false).',
  },
  {
    id: 'XXE-004',
    name: 'Java XPathFactory Without External Entity Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['java'],
    pattern: /XPathFactory\s*\.\s*newInstance\s*\(\s*\)/g,
    description: 'XPathFactory without external entity restrictions can enable XXE if the input XML is user-controlled.',
    remediation: 'Restrict external entities on the underlying DocumentBuilderFactory before using XPath.',
  },

  // ── PHP ──────────────────────────────────────────────────────
  {
    id: 'XXE-005',
    name: 'PHP libxml Entity Loader Enabled',
    severity: 'CRITICAL',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['php'],
    pattern: /libxml_disable_entity_loader\s*\(\s*false\s*\)/gi,
    description: 'Explicitly enabling external entity loading in PHP makes the XML parser vulnerable to XXE.',
    remediation: 'Remove this call. Since PHP 8.0, entity loading is disabled by default. For older PHP: libxml_disable_entity_loader(true).',
  },
  {
    id: 'XXE-006',
    name: 'PHP simplexml_load_string Without Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['php'],
    pattern: /simplexml_load_(?:string|file)\s*\(\s*\$_(?:POST|GET|REQUEST|INPUT)/gi,
    description: 'simplexml_load_string/file parsing user-supplied XML without entity disabling enables XXE.',
    remediation: 'Call libxml_disable_entity_loader(true) before parsing. Use LIBXML_NOENT | LIBXML_DTDLOAD options carefully.',
  },
  {
    id: 'XXE-007',
    name: 'PHP DOMDocument loadXML Without Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['php'],
    pattern: /\$\w*[Dd]oc(?:ument)?\s*->\s*loadXML\s*\(\s*\$_(?:POST|GET|REQUEST)/gi,
    description: 'DOMDocument::loadXML with user-supplied data and external entities enabled causes XXE.',
    remediation: 'Set libxml_disable_entity_loader(true) and use LIBXML_NONET option: $doc->loadXML($xml, LIBXML_NOENT | LIBXML_NONET).',
  },

  // ── Python ───────────────────────────────────────────────────
  {
    id: 'XXE-008',
    name: 'Python lxml etree.parse Without External Entity Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['python'],
    pattern: /(?:etree|lxml)\.(?:parse|fromstring|XMLParser)\s*\(/gi,
    description: 'Python lxml etree.parse may be vulnerable to XXE if the parser allows external entities (depends on lxml version and configuration).',
    remediation: 'Use defusedxml library: from defusedxml import ElementTree; ElementTree.parse(). Or disable entity resolution: parser = etree.XMLParser(resolve_entities=False).',
  },
  {
    id: 'XXE-009',
    name: 'Python xml.etree.ElementTree (Vulnerable to DoS)',
    severity: 'MEDIUM',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['python'],
    pattern: /xml\.etree\.ElementTree\.(?:parse|fromstring|iterparse)\s*\(/gi,
    description: 'xml.etree.ElementTree is vulnerable to Billion Laughs DoS attack and potentially XXE in older Python versions.',
    remediation: 'Replace with defusedxml.ElementTree which is safe by default: from defusedxml import ElementTree.',
  },
  {
    id: 'XXE-010',
    name: 'Python xml.sax Without Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['python'],
    pattern: /xml\.sax\.(?:parse|parseString|make_parser)\s*\(/gi,
    description: 'xml.sax parser is vulnerable to XXE and Billion Laughs attacks.',
    remediation: 'Use defusedxml.sax as a drop-in replacement: from defusedxml import sax.',
  },

  // ── C# ───────────────────────────────────────────────────────
  {
    id: 'XXE-011',
    name: 'C# XmlReader Without ProhibitDtd',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['csharp'],
    pattern: /XmlReader\s*\.\s*Create\s*\([^)]*(?!ProhibitDtd|DtdProcessing\.Prohibit)/gi,
    description: 'XmlReader created without ProhibitDtd=true or DtdProcessing=Prohibit is vulnerable to XXE.',
    remediation: 'Set XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }.',
  },
  {
    id: 'XXE-012',
    name: 'C# XmlDocument Without XmlResolver Null',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['csharp'],
    pattern: /new\s+XmlDocument\s*\(\s*\)(?![\s\S]{0,100}XmlResolver\s*=\s*null)/gi,
    description: 'XmlDocument with default XmlResolver processes external entities, enabling XXE.',
    remediation: 'Set doc.XmlResolver = null before calling Load() or LoadXml().',
  },

  // ── JavaScript (Node.js) ──────────────────────────────────────
  {
    id: 'XXE-013',
    name: 'Node.js libxmljs Without External Entity Protection',
    severity: 'HIGH',
    category: 'XXE',
    owasp: 'A03:2021',
    cwe: 'CWE-611',
    tech: ['javascript', 'typescript'],
    pattern: /libxmljs\.parseXml\s*\(/gi,
    description: 'libxmljs.parseXml may process external entities if not configured safely.',
    remediation: 'Pass { noent: false, nocdata: true } options. Validate the XML structure before parsing.',
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
