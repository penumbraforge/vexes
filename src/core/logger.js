const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };

const isTTY = process.stderr.isTTY;
const noColor = !!process.env.NO_COLOR;
const useColor = isTTY && !noColor;

const C = useColor ? {
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  reset:  '\x1b[0m',
} : { dim: '', red: '', yellow: '', cyan: '', reset: '' };

let currentLevel = LEVELS.info;

/**
 * Strip non-printable and ALL terminal escape sequences from external data
 * to prevent terminal injection attacks.
 *
 * Covers: CSI (with intermediate bytes), OSC (BEL and ST terminators),
 * DCS/APC/PM/SOS sequences, C1 control codes (0x80-0x9F), and bare ESC.
 *
 * Order matters: match complete escape sequences FIRST, then strip remaining
 * control chars. Otherwise the ESC byte gets stripped before the sequence
 * regex can match the full pattern.
 */
function sanitize(s) {
  return String(s)
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b[PX^_][\s\S]*?\x1b\\/g, '')
    .replace(/\x1b\[[\x20-\x2f]*[0-9;?]*[\x20-\x7e]/g, '')
    .replace(/\x1b[\x40-\x7e]/g, '')
    .replace(/\x1b/g, '')
    .replace(/[\x80-\x9f]/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}

function timestamp() {
  return `${C.dim}${new Date().toISOString().slice(11, 19)}${C.reset}`;
}

function write(level, color, tag, ...args) {
  if (LEVELS[level] < currentLevel) return;
  const sanitized = args.map(a => sanitize(a));
  const prefix = `${timestamp()} ${color}${tag}${C.reset}`;
  process.stderr.write(`${prefix} ${sanitized.join(' ')}\n`);
}

export const log = {
  debug: (...args) => write('debug', C.dim, 'DBG', ...args),
  info:  (...args) => write('info', C.cyan, 'INF', ...args),
  warn:  (...args) => write('warn', C.yellow, 'WRN', ...args),
  error: (...args) => write('error', C.red, 'ERR', ...args),

  setLevel(name) {
    if (name in LEVELS) currentLevel = LEVELS[name];
  },
};
