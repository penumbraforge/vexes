# Detection Signals

vexes emits evidence signals for review. A signal may describe an upstream
advisory match, a registry fact, or a heuristic pattern. Composite scores are
prioritization aids, not verdicts; expect false positives and misses.

## Signal reference

### Layer 4: Registry metadata

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `KNOWN_MALICIOUS` | CRITICAL | OSV explicitly labels the package/version malicious (`MAL-*` or malware-typed record). This is an upstream record match, not proof of execution in this project. |
| `KNOWN_VULNERABILITY` | Upstream severity; MODERATE fallback | OSV reports this version in an ordinary affected vulnerability range. It does not imply malware or exploitation. |
| `KNOWN_COMPROMISED` / `OSV_MATCH` | Compatibility | Older policy/consumer names accepted for advisory matches; new analysis results use the two identifiers above. |
| `MAINTAINER_CHANGE` | CRITICAL / MODERATE / LOW | Publishing account changed between versions. CRITICAL if recent (< 90 days), MODERATE if old. LOW for old transfers in org-managed packages (3+ maintainers). |
| `POSTINSTALL_SCRIPT` | MODERATE / LOW | Has consumer install hooks (`preinstall`, `install`, or `postinstall`). Hook presence is an execution surface, not evidence of malicious content. LOW for curated exact-name entries such as esbuild and sharp. |
| `RAPID_PUBLISH` | HIGH / LOW | Version published < 10 minutes after previous version. LOW for an exact-name allowlist entry or likely CI multi-publish (0s interval with 2+ maintainers). |
| `VERSION_ANOMALY` | LOW / MODERATE / HIGH | A major-version jump of 3+ is MODERATE. A version after >1 year of dormancy is HIGH for its first 90 days, MODERATE until one year, then LOW. |
| `NO_REPOSITORY` | LOW | No source repository link in package metadata |
| `MISSING_PROVENANCE` | MODERATE / LOW | No npm Sigstore provenance attestation among packages selected for the provenance stage. MODERATE if combined with other signals, LOW if standalone. |
| `TYPOSQUAT` | HIGH | Package name is close to a popular package (Levenshtein ≤ 1 for names of 4–6 chars, ≤ 2 for 7+; names ≤ 3 chars are never compared). Checked against a curated list of ~165 npm / ~105 PyPI popular packages. Scoped names are compared in full, including the scope, which can weaken the heuristic. |
| `HOMOGLYPH` | CRITICAL | Legacy signal name: package name contains invisible/BIDI characters or any non-ASCII character. No visual-confusable mapping is performed. |

### Layer 1: source-pattern analysis

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `AST_DANGEROUS_PATTERN` | Varies | JavaScript AST or Python text-pattern match in inspectable inline install-script content |
| `TARBALL_DANGEROUS_PATTERN` | Varies | Pattern match in one of up to 10 selected files from a bounded tarball sample |

**Detected patterns:**

| Pattern | Severity | Example |
|---------|----------|---------|
| `CODE_EXECUTION` | HIGH / CRITICAL | `new Worker()` is HIGH; `eval()`, `new Function()`, `vm.runInNewContext()`, `process.dlopen()`, indirect eval `(0,eval)()`, `setTimeout(string)`, `WebAssembly.instantiate()`, `module.constructor._load()`, `.constructor(string)` (prototype chain), and `globalThis['eval']()` are CRITICAL |
| `PROCESS_SPAWN` | CRITICAL | `child_process.exec()`, `execSync()`, `spawn()`, `process.binding('spawn_sync')`, `process.mainModule.require()` |
| `SYSTEM_PATH_WRITE` | CRITICAL | `fs.writeFile('/tmp/backdoor')`, `fs.writeFile('/etc/cron.d/...')` |
| `SELF_DELETION` | CRITICAL | `fs.unlinkSync(__filename)` -- code erases itself after execution |
| `ENV_HARVESTING` | CRITICAL | `process.env.AWS_SECRET_ACCESS_KEY`, `process['env']['GITHUB_TOKEN']` (computed), `fs.readFileSync('.ssh/id_rsa')` (sensitive file reads) |
| `NETWORK_ACCESS` | HIGH | `fetch()`, `https.request()`, `http.get()`, `dns.resolve()` (DNS exfiltration), `dns.lookup()` |
| `BASE64_DECODE` | HIGH | `Buffer.from(x, 'base64')`, `.toString('base64')` |
| `DYNAMIC_REQUIRE` | HIGH | `require(variable)` -- loads arbitrary modules |
| `DYNAMIC_IMPORT` | HIGH | `import(variable)` -- dynamic module loading |
| `POSSIBLE_OBFUSCATION` | HIGH / CRITICAL | Computed property calls, string concatenation in `require()` |
| `FILESYSTEM_WRITE` | MODERATE | `fs.writeFile()` to non-system paths |
| `UNPARSEABLE_CODE` | HIGH | Code that can't be parsed as JavaScript |

**Python-specific text patterns (not an AST):**

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
| `PHANTOM_DEPENDENCY` | CRITICAL / HIGH | Dependency added by the analyzed npm release relative to its previous published version is < 7 days old (CRITICAL) or has at most 1 maintainer and 1–2 versions (HIGH) |
| `CIRCULAR_STAGING` | CRITICAL | Such an added dependency was published by the same account within 48 hours |
| `NEW_DEP_HAS_INSTALL_SCRIPTS` | HIGH | Such an added dependency declares a consumer install hook (`preinstall`, `install`, or `postinstall`) |
| `NEW_DEPENDENCY` | MODERATE / HIGH | Dependency added by that npm release. HIGH if registry metadata is unavailable. |

### Layer 3: Behavioral fingerprinting

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `CAPABILITY_ESCALATION` | CRITICAL | Package gained dangerous capabilities between versions (e.g., process_spawn, network, credential_access). Fires only when the previous version's capabilities are actually known — see `INITIAL_DANGEROUS_CAPABILITY`. |
| `DEPENDENCY_SPIKE` | HIGH | Dependency count more than doubled and exceeds 5 |
| `MAINTAINER_REDUCTION` | MODERATE | Profile-diff primitive for a maintainer-count decrease. The ordinary registry analysis path does not currently retain prior-version maintainer-list history, so it does not emit this signal from a live package lookup. |
| `REPOSITORY_REMOVED` | MODERATE | Profile-diff primitive for repository-link removal. The ordinary registry analysis path does not currently retain prior-version repository history, so it does not emit this signal from a live package lookup. |
| `INITIAL_DANGEROUS_CAPABILITY` | MODERATE | Analyzed version's inspectable install scripts have dangerous capabilities, but usable previous-version script data was unavailable, so no between-version change is claimed. |

### Provenance and sandbox

| Signal | Default Severity | Description |
|--------|-----------------|-------------|
| `ATTESTATION_IDENTITY_MISMATCH` | HIGH | Decoded attestation subject/repository fields disagree with package metadata. vexes does **not** verify DSSE signatures, certificates, artifact digests, or transparency-log inclusion proofs. A crafted or invalid bundle can therefore produce this signal. Repo mismatch may also occur for legitimate forks/mirrors. `SIGNATURE_SPOOF` is a compatibility name only. |
| `SANDBOX_BEHAVIOR` | CRITICAL / HIGH | Best-effort telemetry from one selected npm entrypoint under an accepted Linux `bwrap` host: recorder-observed outside writes are CRITICAL; selected process/network API use is HIGH. The recorder is bypassable and children are not instrumented. This is not a clean-execution verdict or proof of containment. |

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

Setting a signal to `"off"` suppresses it. Every documented analysis signal is
configurable. The legacy `KNOWN_COMPROMISED` switch also controls
`KNOWN_MALICIOUS` and `KNOWN_VULNERABILITY` when their own switches are absent.
Use this sparingly: project-local configuration can remove evidence from output,
so review `.vexesrc.json` as security policy.

## Sensitive environment variables detected

The AST inspector specifically flags access to these credentials:

`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `DATABASE_URL`, `DB_PASSWORD`, `PRIVATE_KEY`, `SECRET_KEY`, `API_KEY`, `API_SECRET`, `STRIPE_SECRET_KEY`, `JWT_SECRET`, `SSH_PRIVATE_KEY`, `ENCRYPTION_KEY`, `MASTER_KEY`, `KUBE_TOKEN`, `KUBERNETES_TOKEN`, `DOCKER_PASSWORD`, `SLACK_TOKEN`, `DISCORD_TOKEN`, `TELEGRAM_TOKEN`
