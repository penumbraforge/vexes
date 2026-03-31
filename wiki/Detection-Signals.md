# Detection Signals

vexes detects supply chain threats through signals. Each signal represents a specific suspicious pattern. Signals are combined with context-aware scoring to produce composite risk assessments.

## Signal reference

### Layer 4: Registry metadata

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `KNOWN_COMPROMISED` | CRITICAL | Package has known vulnerabilities in the OSV database |
| `MAINTAINER_CHANGE` | CRITICAL / MODERATE | Publishing account changed between versions. CRITICAL if recent (< 90 days), MODERATE if old. Downweighted for org-managed packages (3+ maintainers). |
| `POSTINSTALL_SCRIPT` | HIGH / LOW | Has install lifecycle scripts (preinstall, install, postinstall). LOW for known-good packages (esbuild, sharp, etc.). |
| `RAPID_PUBLISH` | HIGH / LOW | Version published < 10 minutes after previous version. LOW for CI multi-publish (0s interval with 2+ maintainers). |
| `VERSION_ANOMALY` | MODERATE / HIGH | Major version jumped by 3+ (MODERATE). Package dormant > 1 year then suddenly published (HIGH). |
| `NO_REPOSITORY` | LOW | No source repository link in package metadata |
| `MISSING_PROVENANCE` | MODERATE / LOW | No Sigstore provenance attestation. MODERATE if combined with other signals, LOW if standalone. |
| `TYPOSQUAT` | HIGH | Package name is within Levenshtein distance 1-2 of a popular package |
| `HOMOGLYPH` | CRITICAL | Package name contains invisible Unicode characters (zero-width, BIDI override) or non-ASCII homoglyphs |

### Layer 1: AST analysis

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `AST_DANGEROUS_PATTERN` | Varies | Dangerous code pattern found in install scripts |
| `TARBALL_DANGEROUS_PATTERN` | Varies | Dangerous code pattern found in actual package source |

**Detected patterns:**

| Pattern | Severity | Example |
|---------|----------|---------|
| `CODE_EXECUTION` | CRITICAL | `eval()`, `new Function()`, `vm.runInNewContext()`, `process.dlopen()`, indirect eval `(0,eval)()`, `setTimeout(string)`, `WebAssembly.instantiate()`, `new Worker()`, `module.constructor._load()`, `.constructor(string)` (prototype chain), `globalThis['eval']()` |
| `PROCESS_SPAWN` | CRITICAL | `child_process.exec()`, `execSync()`, `spawn()`, `process.binding('spawn_sync')`, `process.mainModule.require()` |
| `SYSTEM_PATH_WRITE` | CRITICAL | `fs.writeFile('/tmp/backdoor')`, `fs.writeFile('/etc/cron.d/...')` |
| `SELF_DELETION` | CRITICAL | `fs.unlinkSync(__filename)` -- code erases itself after execution |
| `ENV_HARVESTING` | CRITICAL | `process.env.AWS_SECRET_ACCESS_KEY`, `process.env.GITHUB_TOKEN`, `process['env']` (computed), `fs.readFileSync('.ssh/id_rsa')` (sensitive file reads) |
| `NETWORK_ACCESS` | HIGH | `fetch()`, `https.request()`, `http.get()`, `dns.resolve()` (DNS exfiltration), `dns.lookup()` |
| `BASE64_DECODE` | HIGH | `Buffer.from(x, 'base64')`, `.toString('base64')` |
| `DYNAMIC_REQUIRE` | HIGH | `require(variable)` -- loads arbitrary modules |
| `DYNAMIC_IMPORT` | HIGH | `import(variable)` -- dynamic module loading |
| `POSSIBLE_OBFUSCATION` | HIGH / CRITICAL | Computed property calls, string concatenation in `require()` |
| `FILESYSTEM_WRITE` | MODERATE | `fs.writeFile()` to non-system paths |
| `UNPARSEABLE_CODE` | HIGH | Code that can't be parsed as JavaScript |

**Python-specific patterns:**

| Pattern | Severity | Example |
|---------|----------|---------|
| `PROCESS_SPAWN` | CRITICAL | `subprocess.Popen()`, `os.system()`, `os.exec*()` |
| `CODE_EXECUTION` | CRITICAL | `eval()`, `exec()` (Python builtins) |
| `NETWORK_ACCESS` | HIGH | `urllib.request.urlopen()`, `requests.get()` |
| `BASE64_DECODE` | HIGH | `base64.b64decode()`, `base64.b64encode()` |
| `ENV_HARVESTING` | MODERATE | `os.environ`, `os.getenv()` |
| `SYSTEM_PATH_WRITE` | CRITICAL | `open('/usr/local/bin/...', 'w')` |

### Layer 2: Dependency graph

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `PHANTOM_DEPENDENCY` | CRITICAL / HIGH | Newly added dependency is < 7 days old (CRITICAL) or has 1 maintainer + 1-2 versions (HIGH) |
| `CIRCULAR_STAGING` | CRITICAL | New dependency published by the same account within 48 hours |
| `NEW_DEP_HAS_INSTALL_SCRIPTS` | HIGH | Newly added dependency has install lifecycle scripts |
| `NEW_DEPENDENCY` | MODERATE / HIGH | New dependency added. HIGH if metadata unavailable. |

### Layer 3: Behavioral fingerprinting

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `CAPABILITY_ESCALATION` | CRITICAL | Package gained dangerous capabilities between versions (e.g., process_spawn, network, credential_access) |
| `DEPENDENCY_SPIKE` | HIGH | Dependency count more than doubled and exceeds 5 |
| `MAINTAINER_REDUCTION` | MODERATE | Number of maintainers decreased between versions |
| `REPOSITORY_REMOVED` | MODERATE | Repository link was removed from metadata |
| `INITIAL_DANGEROUS_CAPABILITY` | MODERATE | First version of package has dangerous capabilities |

## Disabling signals

In `.vexesrc.json`:

```json
{
  "analyze": {
    "signals": {
      "NO_REPOSITORY": "off",
      "POSTINSTALL_SCRIPT": "off"
    }
  }
}
```

Setting a signal to `"off"` suppresses it. Use sparingly.

### Undisableable signals

The following critical signals **cannot be disabled** via config -- they detect active supply chain attacks and suppressing them would create a dangerous blind spot:

- `KNOWN_COMPROMISED` -- package has known vulnerabilities in OSV
- `PHANTOM_DEPENDENCY` -- brand-new dependency (< 7 days old)
- `CIRCULAR_STAGING` -- new dependency published by the same account
- `CAPABILITY_ESCALATION` -- package gained dangerous capabilities between versions

Attempting to set these to `"off"` in `.vexesrc.json` has no effect.

## Sensitive environment variables detected

The AST inspector specifically flags access to these credentials:

`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `DATABASE_URL`, `DB_PASSWORD`, `PRIVATE_KEY`, `SECRET_KEY`, `API_KEY`, `API_SECRET`, `STRIPE_SECRET_KEY`, `JWT_SECRET`, `SSH_PRIVATE_KEY`, `ENCRYPTION_KEY`, `MASTER_KEY`, `KUBE_TOKEN`, `KUBERNETES_TOKEN`, `DOCKER_PASSWORD`, `SLACK_TOKEN`, `DISCORD_TOKEN`, `TELEGRAM_TOKEN`
