import { VERSION } from '../core/constants.js';

/**
 * SARIF 2.1.0 export for `vexes scan` results.
 *
 * Maps the scan JSON shape ({ summary, warnings, vulnerabilities[] }) into a
 * SARIF document suitable for github/codeql-action/upload-sarif and any other
 * SARIF 2.1.0 consumer. Zero dependencies — hand-built object graph.
 */

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const INFORMATION_URI = 'https://github.com/penumbraforge/vexes';

// severity → SARIF result level
const LEVEL_BY_SEVERITY = {
  CRITICAL: 'error',
  HIGH: 'error',
  MODERATE: 'warning',
  LOW: 'note',
};

// severity → GitHub "security-severity" numeric (CVSS-ish), as a string
// because GitHub code scanning reads this property as a string.
const SECURITY_SEVERITY = {
  CRITICAL: '9.0',
  HIGH: '7.0',
  MODERATE: '4.0',
  LOW: '1.0',
};

// Best-effort representative manifest per ecosystem, used for the physical
// location so uploads have a file to anchor on. Scan findings don't carry the
// exact source file, so this is a hint, not ground truth; the package@version
// logical location is always present as the authoritative identity.
const ECOSYSTEM_MANIFEST = {
  npm: 'package-lock.json',
  pypi: 'requirements.txt',
  cargo: 'Cargo.lock',
  go: 'go.sum',
  ruby: 'Gemfile.lock',
  php: 'composer.lock',
  nuget: 'packages.lock.json',
  java: 'pom.xml',
};

function levelFor(severity) {
  return LEVEL_BY_SEVERITY[String(severity).toUpperCase()] || 'warning';
}

function reachabilityFor(v) {
  return v.reachability || 'unknown';
}

function importEvidenceFor(v) {
  if (v.importEvidence) return v.importEvidence;
  if (v.reachability === 'reachable') return 'found_static';
  if (v.reachability === 'lazy') return 'found_dynamic';
  if (v.reachability === 'dead') return 'not_found';
  return 'unknown';
}

function securitySeverityFor(severity) {
  return SECURITY_SEVERITY[String(severity).toUpperCase()] || '0.0';
}

/**
 * Build the human-readable result message: package@version, advisory summary,
 * and the fix version when known.
 */
function messageText(v) {
  const head = `${v.package}@${v.version} (${v.ecosystem}) — ${v.displayId || v.id}`;
  const summary = v.summary ? `: ${v.summary}` : '';
  const fix = v.fixed ? ` (fix: ${v.fixed})` : '';
  return `${head}${summary}${fix}`;
}

/**
 * Convert a scan result object into a SARIF 2.1.0 document.
 *
 * @param {Object} scanResult — { summary?, warnings?, vulnerabilities: [...] }
 * @returns {Object} SARIF document
 */
export function toSarif(scanResult = {}) {
  const vulns = Array.isArray(scanResult.vulnerabilities) ? scanResult.vulnerabilities : [];
  const warnings = Array.isArray(scanResult.warnings) ? scanResult.warnings : [];

  // One rule per unique advisory id.
  const rulesMap = new Map();
  for (const v of vulns) {
    if (rulesMap.has(v.id)) continue;
    rulesMap.set(v.id, {
      id: v.id,
      name: v.displayId || v.id,
      shortDescription: { text: `${v.displayId || v.id}: ${v.summary || 'No description available'}` },
      fullDescription: { text: v.summary || 'No description available' },
      helpUri: v.url,
      properties: {
        'security-severity': securitySeverityFor(v.severity),
        severity: v.severity,
        ...(v.ecosystem ? { ecosystem: v.ecosystem } : {}),
      },
    });
  }

  const results = vulns.map(v => {
    const manifest = ECOSYSTEM_MANIFEST[v.ecosystem];
    const locations = [{
      ...(manifest ? {
        physicalLocation: {
          artifactLocation: { uri: manifest, uriBaseId: '%SRCROOT%' },
        },
      } : {}),
      logicalLocations: [{ name: `${v.package}@${v.version}`, kind: 'module' }],
    }];

    return {
      ruleId: v.id,
      level: levelFor(v.severity),
      message: { text: messageText(v) },
      locations,
      // Stable across runs so the same finding dedupes in code scanning.
      partialFingerprints: {
        'vexes/packageVulnerability/v1': `${v.ecosystem}:${v.package}:${v.id}`,
      },
      // Canonical Tier A direct-import evidence is contextual only and must
      // never suppress a security finding. `reachability` remains additive
      // compatibility data for older SARIF consumers.
      properties: {
        importEvidence: importEvidenceFor(v),
        reachability: reachabilityFor(v),
      },
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'vexes',
          version: VERSION,
          informationUri: INFORMATION_URI,
          rules: [...rulesMap.values()],
        },
      },
      results,
      invocations: [{
        executionSuccessful: scanResult.complete !== false,
        toolExecutionNotifications: warnings.map(w => ({
          level: 'warning',
          message: { text: String(w) },
        })),
        ...(scanResult.summary ? { properties: { summary: scanResult.summary } } : {}),
      }],
    }],
  };
}
