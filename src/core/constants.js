import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));

export const VERSION = pkg.version;
export const USER_AGENT = `vexes/${VERSION}`;

// OSV.dev — Google's open source vulnerability database
export const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
export const OSV_SINGLE_URL = 'https://api.osv.dev/v1/query';
export const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
export const OSV_BATCH_SIZE = 1000;

// Registry endpoints
export const NPM_REGISTRY_URL = 'https://registry.npmjs.org';
export const NPM_ATTESTATIONS_URL = 'https://registry.npmjs.org/-/npm/v1/attestations';
export const PYPI_JSON_URL = 'https://pypi.org/pypi';
export const GITHUB_GRAPHQL_URL = 'https://api.github.com/graphql';

// Ecosystem definitions — maps ecosystem name to lockfile patterns and OSV ecosystem ID
export const ECOSYSTEMS = Object.freeze({
  npm: {
    osvId: 'npm',
    lockfiles: ['package-lock.json'],
    manifests: ['package.json'],
    registryUrl: NPM_REGISTRY_URL,
  },
  pypi: {
    osvId: 'PyPI',
    lockfiles: ['Pipfile.lock', 'poetry.lock'],
    manifests: ['requirements.txt', 'pyproject.toml'],
    registryUrl: PYPI_JSON_URL,
  },
  cargo: {
    osvId: 'crates.io',
    lockfiles: ['Cargo.lock'],
    manifests: ['Cargo.toml'],
    registryUrl: null,
  },
  brew: {
    osvId: null, // Homebrew is not in OSV
    lockfiles: ['Brewfile.lock.json'],
    manifests: ['Brewfile'],
    registryUrl: null,
  },
});

// Cache
export const CACHE_DIR = join(homedir(), '.cache', 'vexes');
export const ADVISORY_TTL_MS = 60 * 60 * 1000;      // 1 hour
export const METADATA_TTL_MS = 24 * 60 * 60 * 1000;  // 24 hours

// Exit codes
export const EXIT = Object.freeze({
  OK: 0,
  VULNS_FOUND: 1,
  ERROR: 2,
});

// Severity ordering and weights for composite risk scoring
export const SEVERITY = Object.freeze({
  CRITICAL: { order: 4, weight: 10 },
  HIGH:     { order: 3, weight: 5 },
  MODERATE: { order: 2, weight: 2 },
  LOW:      { order: 1, weight: 1 },
});

// Fetch defaults
export const FETCH_TIMEOUT_MS = 15_000;
export const FETCH_RETRIES = 3;
export const FETCH_BACKOFF_MS = 1000;

// Analysis concurrency
export const ANALYZE_CONCURRENCY = 10;
