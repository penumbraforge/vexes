/**
 * `vexes explain` — AI-assisted triage of a scan's findings.
 *
 * Turns the wall of CVEs a scan produces into a prioritized, plain-English
 * action plan: what to fix first, why it matters (blast radius), and the
 * upgrade sequence. The scanner stays deterministic and offline; this is an
 * opt-in layer on top of the pluggable provider (local OpenAI-compatible
 * endpoint by default, Anthropic when ANTHROPIC_API_KEY is set — see
 * src/ai/provider.js). Nothing leaves the machine unless a provider is
 * configured, and only the sanitized extracted-findings payload is sent.
 *
 * Input, in order of preference:
 *   --input <file>   a scan JSON report (`vexes scan --format json > f.json`)
 *   stdin            piped scan JSON (`vexes scan --format json | vexes explain`)
 *   --path <dir>     otherwise, run a scan of the directory first
 *
 * @module commands/explain
 */

import { readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { C, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT } from '../core/constants.js';
import { complete, detectProvider, providerLabel } from '../ai/provider.js';

const MAX_FINDINGS_IN_PROMPT = 60;

const SYSTEM_PROMPT = `You are a supply-chain security triage assistant embedded in the "vexes" dependency scanner. You receive a JSON summary of vulnerability findings and produce a concise, prioritized action plan for a developer.

Rules:
- Be decisive and specific. Name packages and versions.
- Prioritize by real-world exploitability and blast radius, not just raw severity counts. A CRITICAL in a transitive dev-only dependency can matter less than a HIGH in a direct runtime one.
- Group findings that share a single fix (one upgrade resolving several advisories).
- Give a concrete upgrade sequence the developer can act on.
- Never invent advisory IDs, versions, or packages not present in the input.
- Keep it tight: a short prioritized list, then a one-paragraph "biggest risk" note. No preamble, no restating the input.
- Output plain text with simple headers. No markdown tables.`;

function readStdin() {
  try {
    // fd 0; returns '' if it's a TTY with nothing piped
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

async function loadReport(flags) {
  // 1. --input file
  if (flags.input) {
    const path = resolve(flags.input);
    try {
      return JSON.parse(readFileSync(path, 'utf8'));
    } catch (err) {
      log.error(`could not read scan report from ${path}: ${err.message}`);
      return null;
    }
  }

  // 2. piped stdin (only when not a TTY)
  if (!process.stdin.isTTY) {
    const raw = readStdin();
    if (raw.trim()) {
      try {
        return JSON.parse(raw);
      } catch (err) {
        log.error(`stdin was not valid scan JSON: ${err.message}`);
        return null;
      }
    }
  }

  // 3. run a fresh scan of --path by spawning our own CLI in JSON mode.
  // Decoupled from the scan command's internals — explain composes over its
  // output, exactly as a piped invocation would.
  return await scanToJson(flags.path || process.cwd());
}

function scanToJson(path) {
  const binPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'vexes.js');
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [binPath, 'scan', '--path', path, '--format', 'json'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let buf = '';
    child.stdout.on('data', (d) => { buf += d; });
    child.on('error', (err) => {
      log.error(`could not run scan: ${err.message}`);
      resolvePromise(null);
    });
    child.on('close', () => {
      try {
        resolvePromise(JSON.parse(buf));
      } catch (err) {
        log.error(`scan did not produce valid JSON: ${err.message}`);
        resolvePromise(null);
      }
    });
  });
}

/**
 * Build a compact prompt payload from a scan report — small enough to send,
 * complete enough to prioritize. Caps the finding list and notes truncation.
 *
 * Every field is sanitized because a package name, summary, or advisory can
 * carry attacker-controlled text (package descriptions, typosqatted names,
 * malicious maintainer metadata). We never pass raw untrusted content to the
 * model — only this sanitized, spec-shaped payload crosses the boundary.
 */
function buildPayload(report) {
  const vulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];
  const capped = vulns.slice(0, MAX_FINDINGS_IN_PROMPT);
  const findings = capped.map(v => ({
    id: sanitize(v.displayId || v.id).slice(0, 64),
    package: sanitize(v.package || '??'),
    version: sanitize(String(v.version ?? '')).slice(0, 32),
    ecosystem: sanitize(String(v.ecosystem ?? '')).slice(0, 32),
    severity: sanitize(String(v.severity ?? '')).slice(0, 16),
    fixed: sanitize(String(v.fixed ?? '')).slice(0, 64) || null,
    summary: sanitize(String(v.summary ?? '')).slice(0, 200),
  }));

  return {
    summary: report.summary || {},
    complete: report.complete,
    truncated: vulns.length > capped.length ? vulns.length - capped.length : 0,
    findings,
  };
}

export async function runExplain(flags, args) {
  const provider = detectProvider();
  if (!provider) {
    out(`
  ${C.bold}vexes explain${C.reset} needs an AI provider. AI triage is opt-in.

  Point it at a local endpoint (recommended — nothing leaves your machine):

    ${C.dim}export VEXES_AI_BASE=http://localhost:11434${C.reset}   ${C.dim}# Ollama${C.reset}
    ${C.dim}export VEXES_AI_MODEL=qwen2.5-coder:7b${C.reset}${C.dim}   # or your Spark endpoint${C.reset}
    ${C.dim}vexes scan --format json | vexes explain${C.reset}

  or use Anthropic:

    ${C.dim}export ANTHROPIC_API_KEY=sk-ant-...${C.reset}
    ${C.dim}vexes scan --format json | vexes explain${C.reset}

  vexes never sends data to any AI service unless a provider is configured.
`);
    return EXIT.ERROR;
  }

  const report = await loadReport(flags);
  if (!report) return EXIT.ERROR;

  const payload = buildPayload(report);

  if (payload.findings.length === 0) {
    out(`\n  ${C.green}No vulnerabilities to triage — nothing to explain.${C.reset}\n`);
    return EXIT.OK;
  }

  const spinnerText = `Triaging ${payload.findings.length} findings (${providerLabel()})...`;
  if (!flags.quiet) log.info(spinnerText);

  let answer;
  try {
    answer = await complete({
      system: SYSTEM_PROMPT,
      user: `Here is a vexes scan result. Produce the prioritized triage.\n\n${JSON.stringify(payload, null, 2)}`,
    });
  } catch (err) {
    if (err.code === 'NO_PROVIDER') {
      log.error('No AI provider configured — set VEXES_AI_BASE or ANTHROPIC_API_KEY');
    } else {
      log.error(`AI triage failed (${err.code || 'error'}): ${err.message}`);
    }
    return EXIT.ERROR;
  }

  const s = payload.summary;
  out(`\n  ${C.bold}vexes${C.reset} v${VERSION} ${C.dim}— AI triage via ${providerLabel()}${C.reset}`);
  out(`  ${C.dim}${s.vulnerable ?? payload.findings.length} findings · ${s.critical ?? 0} critical · ${s.high ?? 0} high${payload.truncated ? ` · +${payload.truncated} more not sent` : ''}${C.reset}\n`);

  // The model's answer is untrusted-ish text; run it through the same ANSI
  // sanitizer the rest of the CLI uses before printing.
  out(sanitize(answer));

  if (!report.complete) {
    out(`\n  ${C.yellow}! The underlying scan was incomplete — triage may miss findings.${C.reset}`);
  }
  out('');
  return EXIT.OK;
}
