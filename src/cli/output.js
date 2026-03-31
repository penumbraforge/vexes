const isTTY = process.stdout.isTTY;
const noColor = !!process.env.NO_COLOR;
let colorEnabled = isTTY && !noColor;

// Raw ANSI — no chalk, no deps
export const C = {
  get bold()    { return colorEnabled ? '\x1b[1m' : ''; },
  get dim()     { return colorEnabled ? '\x1b[2m' : ''; },
  get red()     { return colorEnabled ? '\x1b[31m' : ''; },
  get green()   { return colorEnabled ? '\x1b[32m' : ''; },
  get yellow()  { return colorEnabled ? '\x1b[33m' : ''; },
  get cyan()    { return colorEnabled ? '\x1b[36m' : ''; },
  get magenta() { return colorEnabled ? '\x1b[35m' : ''; },
  get white()   { return colorEnabled ? '\x1b[37m' : ''; },
  get reset()   { return colorEnabled ? '\x1b[0m' : ''; },
};

export function disableColor() { colorEnabled = false; }
export function enableColor()  { colorEnabled = isTTY && !noColor; }

/**
 * Strip non-printable and ANSI escape sequences from external data
 * to prevent terminal injection via malicious package names/summaries.
 */
export function sanitize(s) {
  return String(s).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07/g, '');
}

/** Severity → color */
export function severityColor(sev) {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL': return C.red;
    case 'HIGH':     return C.yellow;
    case 'MODERATE': return C.cyan;
    case 'LOW':      return C.dim;
    default:         return C.white;
  }
}

/** Braille spinner for progress indication */
const BRAILLE = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export function createSpinner(text) {
  if (!isTTY) {
    // Non-TTY: just print the message once
    process.stderr.write(`  ${text}\n`);
    return { update() {}, stop() {} };
  }

  let frame = 0;
  const interval = setInterval(() => {
    process.stderr.write(`\r  ${C.cyan}${BRAILLE[frame++ % BRAILLE.length]}${C.reset} ${text}`);
  }, 80);
  interval.unref(); // Don't prevent process exit on error

  return {
    update(newText) { text = newText; },
    stop(finalText) {
      clearInterval(interval);
      process.stderr.write(`\r  ${C.green}\u2713${C.reset} ${finalText || text}\n`);
    },
  };
}

/** Print a section header */
export function header(text) {
  const line = '\u2500'.repeat(50);
  return `\n  ${C.bold}${C.dim}\u2500\u2500 ${C.reset}${C.bold}${text} ${C.dim}${line}${C.reset}\n`;
}

/** Format a vulnerability for terminal output. Sanitizes all external data. */
export function formatVuln(vuln) {
  const sColor = severityColor(vuln.severity);
  const lines = [];
  lines.push(`  ${sColor}${sanitize(vuln.package)}${C.reset} ${C.dim}${sanitize(vuln.version)}${C.reset} ${C.dim}(${sanitize(vuln.ecosystem)})${C.reset}`);
  lines.push(`    ${sanitize(vuln.id)} \u2014 ${sanitize(vuln.summary)}`);
  if (vuln.fixed) lines.push(`    ${C.dim}Fixed in: ${sanitize(vuln.fixed)}${C.reset}`);
  if (vuln.url) lines.push(`    ${C.dim}${sanitize(vuln.url)}${C.reset}`);
  return lines.join('\n');
}

/** Print summary footer */
export function summary(counts, total, ecosystems, elapsed) {
  const parts = [];
  if (counts.critical) parts.push(`${C.red}${counts.critical} critical${C.reset}`);
  if (counts.high) parts.push(`${C.yellow}${counts.high} high${C.reset}`);
  if (counts.moderate) parts.push(`${C.cyan}${counts.moderate} moderate${C.reset}`);
  if (counts.low) parts.push(`${C.dim}${counts.low} low${C.reset}`);

  const line = '\u2500'.repeat(50);
  const lines = [];
  lines.push(`  ${C.dim}${line}${C.reset}`);

  const vulnTotal = counts.critical + counts.high + counts.moderate + counts.low;
  if (vulnTotal === 0) {
    lines.push(`  ${C.green}\u2713 No vulnerabilities found${C.reset}`);
  } else {
    lines.push(`  ${vulnTotal} vulnerabilit${vulnTotal === 1 ? 'y' : 'ies'} \u00b7 ${parts.join(' \u00b7 ')}`);
  }
  lines.push(`  ${C.dim}in ${total} packages across ${ecosystems.join(', ')}${C.reset}`);
  if (elapsed) lines.push(`  ${C.dim}completed in ${elapsed}${C.reset}`);
  lines.push(`  ${C.dim}${line}${C.reset}`);
  return lines.join('\n');
}

/** Write to stdout (data output) */
export function out(text) { process.stdout.write(text + '\n'); }
