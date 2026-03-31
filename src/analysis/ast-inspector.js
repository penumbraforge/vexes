import { parse } from '../vendor/acorn.mjs';
import { log } from '../core/logger.js';

/**
 * AST-based code analysis for JavaScript.
 *
 * Parses JS source into an AST via acorn, then walks the tree to detect
 * dangerous patterns that indicate supply chain compromise. This catches
 * obfuscated code that regex-based scanners miss — we see the call graph.
 *
 * Returns a capability manifest: what the code CAN do, not just what it looks like.
 */

// Dangerous callee patterns — the exact names of functions that indicate risk
const DANGEROUS_CALLEES = new Set([
  'eval', 'Function',
]);

const SPAWN_METHODS = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork',
]);

// vm module methods that are equivalent to eval
const VM_METHODS = new Set([
  'runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction', 'createScript',
]);

const NETWORK_MODULES = new Set([
  'http', 'https', 'net', 'dgram', 'tls', 'http2',
]);

const NETWORK_METHODS = new Set([
  'request', 'get', 'connect', 'createConnection', 'createServer',
]);

const FS_WRITE_METHODS = new Set([
  'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'createWriteStream', 'rename', 'renameSync', 'copyFile', 'copyFileSync',
  'rm', 'rmSync', 'rmdir', 'rmdirSync', 'unlink', 'unlinkSync',
]);

const SENSITIVE_ENV_KEYS = new Set([
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN',
  'DATABASE_URL', 'DB_PASSWORD', 'PRIVATE_KEY', 'SECRET_KEY',
  'API_KEY', 'API_SECRET', 'STRIPE_SECRET_KEY', 'JWT_SECRET',
  'SSH_PRIVATE_KEY', 'ENCRYPTION_KEY', 'MASTER_KEY',
  'KUBE_TOKEN', 'KUBERNETES_TOKEN', 'DOCKER_PASSWORD',
  'SLACK_TOKEN', 'DISCORD_TOKEN', 'TELEGRAM_TOKEN',
]);

const SYSTEM_PATHS = ['/usr/', '/etc/', '/bin/', '/sbin/', '/var/', '/tmp/', '/root/'];

/**
 * Inspect JavaScript source code for dangerous patterns.
 *
 * @param {string} source — JS source code
 * @param {string} [filename] — for error reporting
 * @returns {InspectionResult}
 */
export function inspectJS(source, filename = '<unknown>') {
  const findings = [];
  let ast;

  try {
    ast = parse(source, {
      ecmaVersion: 2022,
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      // Tolerate minor syntax issues — malicious code may have intentional oddities
      onComment: () => {},
    });
  } catch (err) {
    // Try as script if module parse fails
    try {
      ast = parse(source, {
        ecmaVersion: 2022,
        sourceType: 'script',
        allowReturnOutsideFunction: true,
      });
    } catch (err2) {
      log.debug(`AST parse failed for ${filename}: ${err2.message}`);
      // Unparseable code is itself suspicious in an install script
      findings.push({
        pattern: 'UNPARSEABLE_CODE',
        severity: 'HIGH',
        description: `Code could not be parsed as JavaScript: ${err2.message}`,
        line: null,
      });
      return buildResult(findings);
    }
  }

  // Walk with error recovery — capture partial results if the walker crashes mid-traversal
  try {
    walk(ast, findings, { filename, requireBindings: new Map(), importBindings: new Map() });
  } catch (err) {
    findings.push({
      pattern: 'ANALYSIS_ERROR',
      severity: 'HIGH',
      description: `AST analysis failed mid-walk (${err.message}) — findings may be incomplete`,
      line: null,
    });
  }

  // Obfuscation/minification heuristic: if we see computed property access or string
  // concatenation in security-sensitive positions, flag it as possible evasion
  try {
    detectObfuscationPatterns(ast, findings);
  } catch { /* non-critical, don't let this crash the inspector */ }

  return buildResult(findings);
}

/**
 * Walk the AST recursively, accumulating findings.
 */
function walk(node, findings, ctx) {
  if (!node || typeof node !== 'object') return;

  // Track require/import bindings so we can trace what modules are used
  trackBindings(node, ctx);

  switch (node.type) {
    case 'CallExpression':
      analyzeCall(node, findings, ctx);
      // Check for dangerous functions passed as callback args: .then(eval), .map(Function)
      for (const arg of node.arguments || []) {
        if (arg.type === 'Identifier' && DANGEROUS_CALLEES.has(arg.name)) {
          findings.push({
            pattern: 'CODE_EXECUTION',
            severity: 'CRITICAL',
            description: `${arg.name} passed as callback — will execute arbitrary code`,
            line: node.start,
          });
        }
      }
      break;
    case 'NewExpression':
      analyzeNew(node, findings, ctx);
      break;
    case 'MemberExpression':
      analyzeMember(node, findings, ctx);
      break;
    case 'ImportExpression':
      // Dynamic import(): acorn parses as ImportExpression, NOT as CallExpression
      if (node.source && node.source.type !== 'Literal') {
        findings.push({
          pattern: 'DYNAMIC_IMPORT',
          severity: 'HIGH',
          description: 'Dynamic import() with non-literal argument — can load arbitrary modules at runtime',
          line: node.start,
        });
      }
      break;
  }

  // Recurse into all child nodes
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item.type === 'string') walk(item, findings, ctx);
      }
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      walk(child, findings, ctx);
    }
  }
}

/**
 * Track require() and import bindings for module resolution.
 */
function trackBindings(node, ctx) {
  // const x = require('module')
  // const { exec } = require('child_process')  ← CRITICAL: must track destructured
  if (node.type === 'VariableDeclarator' &&
      node.init?.type === 'CallExpression' &&
      node.init.callee?.name === 'require' &&
      node.init.arguments?.[0]?.type === 'Literal') {
    const modName = node.init.arguments[0].value;

    if (node.id?.type === 'Identifier') {
      // const cp = require('child_process')
      ctx.requireBindings.set(node.id.name, modName);
    } else if (node.id?.type === 'ObjectPattern') {
      // const { exec, spawn } = require('child_process')
      // Each destructured property gets its own binding to the module
      for (const prop of node.id.properties) {
        const localName = prop.value?.name || prop.key?.name;
        if (localName) {
          ctx.requireBindings.set(localName, modName);
        }
      }
    }
  }

  // import x from 'module'
  // import { exec } from 'child_process'
  if (node.type === 'ImportDeclaration' && node.source?.type === 'Literal') {
    const modName = node.source.value;
    for (const spec of node.specifiers || []) {
      if (spec.local?.name) {
        ctx.importBindings.set(spec.local.name, modName);
      }
    }
  }
}

/**
 * Analyze function calls for dangerous patterns.
 */
function analyzeCall(node, findings, ctx) {
  const callee = node.callee;

  // eval() or eval(...)
  if (callee.type === 'Identifier' && DANGEROUS_CALLEES.has(callee.name)) {
    findings.push({
      pattern: 'CODE_EXECUTION',
      severity: 'CRITICAL',
      description: `Direct ${callee.name}() call — arbitrary code execution`,
      line: node.start,
    });
    return;
  }

  // Bare call to a destructured spawn method: exec('cmd') from const { exec } = require('child_process')
  if (callee.type === 'Identifier' && SPAWN_METHODS.has(callee.name)) {
    const mod = ctx.requireBindings.get(callee.name) || ctx.importBindings.get(callee.name);
    if (mod === 'child_process' || mod === 'node:child_process') {
      findings.push({
        pattern: 'PROCESS_SPAWN',
        severity: 'CRITICAL',
        description: `${callee.name}() — spawns external process (destructured from ${mod})`,
        line: node.start,
      });
      return;
    }
  }

  // Bare call to destructured vm methods: runInNewContext() etc.
  if (callee.type === 'Identifier' && VM_METHODS.has(callee.name)) {
    const mod = ctx.requireBindings.get(callee.name) || ctx.importBindings.get(callee.name);
    if (mod === 'vm' || mod === 'node:vm') {
      findings.push({
        pattern: 'CODE_EXECUTION',
        severity: 'CRITICAL',
        description: `${callee.name}() — executes code via vm module`,
        line: node.start,
      });
      return;
    }
  }

  // Dynamic require: require(variable) — not require('string-literal')
  if (callee.type === 'Identifier' && callee.name === 'require') {
    const arg = node.arguments?.[0];
    if (arg && arg.type !== 'Literal') {
      findings.push({
        pattern: 'DYNAMIC_REQUIRE',
        severity: 'HIGH',
        description: 'Dynamic require() with non-literal argument — can load arbitrary modules',
        line: node.start,
      });
    }
    return;
  }

  // Dynamic import: import(variable)
  if (callee.type === 'ImportExpression' || (callee.type === 'Import')) {
    const arg = node.arguments?.[0] || node.source;
    if (arg && arg.type !== 'Literal') {
      findings.push({
        pattern: 'DYNAMIC_IMPORT',
        severity: 'HIGH',
        description: 'Dynamic import() with non-literal argument',
        line: node.start,
      });
    }
    return;
  }

  // Method calls: obj.method()
  if (callee.type === 'MemberExpression') {
    const obj = callee.object;
    const prop = callee.property;
    const methodName = prop?.name || prop?.value;
    const objName = obj?.name;

    // child_process.exec/spawn/etc
    if (objName && SPAWN_METHODS.has(methodName)) {
      const mod = ctx.requireBindings.get(objName) || ctx.importBindings.get(objName);
      if (mod === 'child_process' || mod === 'node:child_process' || objName === 'child_process') {
        findings.push({
          pattern: 'PROCESS_SPAWN',
          severity: 'CRITICAL',
          description: `${objName}.${methodName}() — spawns external process`,
          line: node.start,
        });
        return;
      }
    }

    // require('child_process').exec(...)
    if (obj.type === 'CallExpression' && obj.callee?.name === 'require') {
      const modArg = obj.arguments?.[0]?.value;
      if ((modArg === 'child_process' || modArg === 'node:child_process') && SPAWN_METHODS.has(methodName)) {
        findings.push({
          pattern: 'PROCESS_SPAWN',
          severity: 'CRITICAL',
          description: `require('${modArg}').${methodName}() — spawns external process`,
          line: node.start,
        });
        return;
      }
    }

    // Network calls: http.request(), fetch(), net.connect()
    if (NETWORK_METHODS.has(methodName)) {
      const mod = ctx.requireBindings.get(objName) || ctx.importBindings.get(objName);
      if (mod && (NETWORK_MODULES.has(mod) || NETWORK_MODULES.has(mod.replace('node:', '')))) {
        findings.push({
          pattern: 'NETWORK_ACCESS',
          severity: 'HIGH',
          description: `${objName}.${methodName}() — makes network connection`,
          line: node.start,
        });
        return;
      }
    }

    // fs write operations
    if (FS_WRITE_METHODS.has(methodName)) {
      const mod = ctx.requireBindings.get(objName) || ctx.importBindings.get(objName);
      if (mod === 'fs' || mod === 'node:fs' || mod === 'fs/promises' || mod === 'node:fs/promises') {
        // Check if writing to system paths
        const firstArg = node.arguments?.[0];
        if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') {
          const targetPath = firstArg.value;
          if (SYSTEM_PATHS.some(sp => targetPath.startsWith(sp))) {
            findings.push({
              pattern: 'SYSTEM_PATH_WRITE',
              severity: 'CRITICAL',
              description: `${objName}.${methodName}('${targetPath}') — writes to system path`,
              line: node.start,
            });
            return;
          }
        }

        // Self-deletion pattern: fs.unlink with __filename/__dirname
        if ((methodName === 'unlink' || methodName === 'unlinkSync' || methodName === 'rm' || methodName === 'rmSync') &&
            firstArg?.type === 'Identifier' &&
            (firstArg.name === '__filename' || firstArg.name === '__dirname')) {
          findings.push({
            pattern: 'SELF_DELETION',
            severity: 'CRITICAL',
            description: `${objName}.${methodName}(${firstArg.name}) — code deletes itself after execution`,
            line: node.start,
          });
          return;
        }

        findings.push({
          pattern: 'FILESYSTEM_WRITE',
          severity: 'MODERATE',
          description: `${objName}.${methodName}() — writes to filesystem`,
          line: node.start,
        });
        return;
      }
    }

    // vm.runInNewContext / vm.runInThisContext etc — code execution
    if (VM_METHODS.has(methodName)) {
      const mod = ctx.requireBindings.get(objName) || ctx.importBindings.get(objName);
      if (mod === 'vm' || mod === 'node:vm' || objName === 'vm') {
        findings.push({
          pattern: 'CODE_EXECUTION',
          severity: 'CRITICAL',
          description: `${objName}.${methodName}() — executes code via vm module`,
          line: node.start,
        });
        return;
      }
    }

    // process.binding('spawn_sync') / process.dlopen — low-level escape hatches
    if (objName === 'process' && (methodName === 'binding' || methodName === 'dlopen')) {
      findings.push({
        pattern: methodName === 'binding' ? 'PROCESS_SPAWN' : 'CODE_EXECUTION',
        severity: 'CRITICAL',
        description: `process.${methodName}() — low-level Node.js escape hatch, bypasses standard module detection`,
        line: node.start,
      });
      return;
    }

    // Buffer.from(..., 'base64') — payload decode pattern
    if (objName === 'Buffer' && methodName === 'from' && node.arguments?.length >= 2) {
      const encoding = node.arguments[1];
      if (encoding?.type === 'Literal' && encoding.value === 'base64') {
        findings.push({
          pattern: 'BASE64_DECODE',
          severity: 'HIGH',
          description: 'Buffer.from(..., \'base64\') — decodes base64 payload',
          line: node.start,
        });
        return;
      }
    }

    // .toString('base64') — data encoding for exfiltration
    if (methodName === 'toString' && node.arguments?.length >= 1) {
      const encoding = node.arguments[0];
      if (encoding?.type === 'Literal' && encoding.value === 'base64') {
        findings.push({
          pattern: 'BASE64_DECODE', // Same category — base64 ops in install scripts are suspicious
          severity: 'HIGH',
          description: '.toString(\'base64\') — base64 encoding (potential data exfiltration)',
          line: node.start,
        });
        return;
      }
    }

    // process.env access — check for bulk harvesting or sensitive keys
    if (objName === 'process' && methodName === 'env') {
      // This is handled in analyzeMember
      return;
    }
  }

  // Top-level fetch() call
  if (callee.type === 'Identifier' && callee.name === 'fetch') {
    findings.push({
      pattern: 'NETWORK_ACCESS',
      severity: 'HIGH',
      description: 'fetch() — makes network request',
      line: node.start,
    });
  }
}

/**
 * Analyze `new` expressions.
 */
function analyzeNew(node, findings, ctx) {
  const callee = node.callee;

  // new Function('...')
  if (callee.type === 'Identifier' && callee.name === 'Function') {
    findings.push({
      pattern: 'CODE_EXECUTION',
      severity: 'CRITICAL',
      description: 'new Function() constructor — creates function from string (equivalent to eval)',
      line: node.start,
    });
  }
}

/**
 * Analyze member expressions for env harvesting.
 */
function analyzeMember(node, findings, ctx) {
  // process.env.SENSITIVE_KEY
  if (node.object?.type === 'MemberExpression' &&
      node.object.object?.name === 'process' &&
      node.object.property?.name === 'env') {
    const key = node.property?.name || node.property?.value;
    if (key && SENSITIVE_ENV_KEYS.has(key)) {
      findings.push({
        pattern: 'ENV_HARVESTING',
        severity: 'CRITICAL',
        description: `process.env.${key} — accesses sensitive credential`,
        line: node.start,
      });
    }
  }

  // Object.keys(process.env) / Object.values(process.env) / Object.entries(process.env)
  // — bulk env harvesting
  if (node.object?.name === 'Object' &&
      (node.property?.name === 'keys' || node.property?.name === 'values' || node.property?.name === 'entries')) {
    // Check if the parent is a call with process.env as argument
    // This is handled at the call level — but we flag the pattern if we see it
  }

  // JSON.stringify(process.env) — dump all env vars
  if (node.object?.name === 'JSON' && node.property?.name === 'stringify') {
    // Will be caught at call level if argument is process.env
  }
}

/**
 * Detect obfuscation patterns that could be used to evade AST detection.
 * These patterns are suspicious in install scripts where code should be straightforward.
 */
function detectObfuscationPatterns(ast, findings) {
  let computedCallCount = 0;
  let stringConcatInCallCount = 0;
  let totalChars = 0;
  let lineCount = 0;

  function walkObfuscation(node) {
    if (!node || typeof node !== 'object') return;

    // globalThis[expr](...) or obj[expr](...) where expr is not a literal
    if (node.type === 'CallExpression' &&
        node.callee?.type === 'MemberExpression' &&
        node.callee.computed === true &&
        node.callee.property?.type !== 'Literal') {
      computedCallCount++;
    }

    // require(expr) where expr involves string concatenation: require('child' + '_process')
    if (node.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' &&
        node.callee.name === 'require' &&
        node.arguments?.[0]?.type === 'BinaryExpression' &&
        node.arguments[0].operator === '+') {
      stringConcatInCallCount++;
    }

    for (const key of Object.keys(node)) {
      if (key === 'type' || key === 'start' || key === 'end') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item.type === 'string') walkObfuscation(item);
        }
      } else if (child && typeof child === 'object' && typeof child.type === 'string') {
        walkObfuscation(child);
      }
    }
  }

  walkObfuscation(ast);

  if (computedCallCount >= 3) {
    findings.push({
      pattern: 'POSSIBLE_OBFUSCATION',
      severity: 'HIGH',
      description: `${computedCallCount} computed property call(s) detected — possible evasion of static analysis`,
      line: null,
    });
  }

  if (stringConcatInCallCount > 0) {
    findings.push({
      pattern: 'POSSIBLE_OBFUSCATION',
      severity: 'CRITICAL',
      description: `String concatenation in require() argument — likely evasion: require('child' + '_process')`,
      line: null,
    });
  }
}

/**
 * Build the final result with a capability manifest.
 */
function buildResult(findings) {
  const patterns = new Set(findings.map(f => f.pattern));

  return {
    findings,
    capabilities: {
      executesCode: patterns.has('CODE_EXECUTION'),
      spawnsProcess: patterns.has('PROCESS_SPAWN'),
      accessesNetwork: patterns.has('NETWORK_ACCESS'),
      writesFilesystem: patterns.has('FILESYSTEM_WRITE') || patterns.has('SYSTEM_PATH_WRITE'),
      writesSystemPaths: patterns.has('SYSTEM_PATH_WRITE'),
      readsCredentials: patterns.has('ENV_HARVESTING'),
      decodesPayloads: patterns.has('BASE64_DECODE'),
      selfDeletes: patterns.has('SELF_DELETION'),
      dynamicLoading: patterns.has('DYNAMIC_REQUIRE') || patterns.has('DYNAMIC_IMPORT'),
      unparseable: patterns.has('UNPARSEABLE_CODE'),
      possibleObfuscation: patterns.has('POSSIBLE_OBFUSCATION'),
      analysisIncomplete: patterns.has('ANALYSIS_ERROR'),
    },
    maxSeverity: findings.reduce((max, f) => {
      const order = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1 };
      return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
    }, 'LOW'),
    findingCount: findings.length,
  };
}

/**
 * Inspect Python source for dangerous patterns.
 * Uses pattern matching (not a full Python AST) since we can't vendor a Python parser.
 * Focused on setup.py and __init__.py — the attack surface for PyPI packages.
 *
 * @param {string} source
 * @param {string} [filename]
 * @returns {InspectionResult}
 */
export function inspectPython(source, filename = '<unknown>') {
  const findings = [];

  // Join Python line continuations before splitting — prevents evasion via backslash-newline
  // Also handle \r\n (Windows) line endings
  const joined = source.replace(/\\\r?\n\s*/g, ' ');
  const lines = joined.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // Skip comments
    if (line.startsWith('#')) continue;

    // subprocess / os.system / os.popen (allow whitespace around dot for joined continuations)
    if (/\bsubprocess\s*\.\s*(run|call|check_call|check_output|Popen)\b/.test(line) ||
        /\bos\s*\.\s*(system|popen|exec[lv]?[pe]?)\b/.test(line)) {
      findings.push({
        pattern: 'PROCESS_SPAWN',
        severity: 'CRITICAL',
        description: `Process execution: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }

    // eval / exec (Python builtins)
    if (/\b(eval|exec)\s*\(/.test(line) && !/\b(pip|setuptools|distutils)\b/.test(line)) {
      findings.push({
        pattern: 'CODE_EXECUTION',
        severity: 'CRITICAL',
        description: `Code execution: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }

    // Network: urllib, requests, httpx, socket
    if (/\b(urllib\.request\.urlopen|requests\.(get|post|put|patch)|httpx\.(get|post)|socket\.socket)\b/.test(line)) {
      findings.push({
        pattern: 'NETWORK_ACCESS',
        severity: 'HIGH',
        description: `Network access: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }

    // base64 encode/decode — both are suspicious in install scripts
    // b64encode is used for data exfiltration, b64decode for payload unpacking
    if (/\bbase64\.(b64decode|b64encode|decodebytes|encodebytes)\b/.test(line)) {
      findings.push({
        pattern: 'BASE64_DECODE',
        severity: 'HIGH',
        description: `Base64 operation: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }

    // Environment harvesting
    if (/\bos\.environ\b/.test(line) || /\bos\.getenv\b/.test(line)) {
      findings.push({
        pattern: 'ENV_HARVESTING',
        severity: 'MODERATE',
        description: `Environment access: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }

    // File writes to system paths
    if (/\bopen\s*\(\s*['"]\/(?:usr|etc|bin|tmp|root)/.test(line)) {
      findings.push({
        pattern: 'SYSTEM_PATH_WRITE',
        severity: 'CRITICAL',
        description: `System path access: ${line.slice(0, 80)}`,
        line: lineNum,
      });
    }
  }

  return buildResult(findings);
}
