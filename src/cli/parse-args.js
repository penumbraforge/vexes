const COMMANDS = new Set(['scan', 'analyze', 'fix', 'guard', 'monitor', 'help', 'version']);

const FLAGS_WITH_VALUE = new Set([
  'path', 'ecosystem', 'severity', 'format', 'config', 'explain', 'interval', 'shell',
]);

/**
 * Hand-rolled arg parser. No yargs, no commander.
 * @param {string[]} argv - process.argv.slice(2)
 * @returns {{ command: string, flags: Record<string, string|boolean>, args: string[] }}
 */
export function parseArgs(argv) {
  const result = {
    command: 'help',
    flags: {},
    args: [],
  };

  let i = 0;

  // First non-flag argument is the command
  if (argv.length > 0 && !argv[0].startsWith('-')) {
    const cmd = argv[0].toLowerCase();
    if (COMMANDS.has(cmd)) {
      result.command = cmd;
      i = 1;
    }
  }

  while (i < argv.length) {
    const arg = argv[i];

    if (arg === '--') {
      result.args.push(...argv.slice(i + 1));
      break;
    }

    if (arg.startsWith('--no-')) {
      const key = arg.slice(5);
      // Only allow --no- negation for boolean flags, not value flags
      if (!FLAGS_WITH_VALUE.has(key)) {
        result.flags[key] = false;
      }
      i++;
      continue;
    }

    if (arg === '--help' || arg === '-h') {
      result.flags.help = true;
      i++;
      continue;
    }

    if (arg === '--version' || arg === '-V') {
      result.command = 'version';
      i++;
      continue;
    }

    if (arg.startsWith('--')) {
      const key = arg.slice(2);

      if (FLAGS_WITH_VALUE.has(key) && i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        result.flags[key] = argv[i + 1];
        i += 2;
      } else {
        result.flags[key] = true;
        i++;
      }
      continue;
    }

    if (arg.startsWith('-') && arg.length === 2) {
      const SHORT_MAP = { v: 'verbose', q: 'quiet', j: 'json' };
      const mapped = SHORT_MAP[arg[1]];
      if (mapped) result.flags[mapped] = true;
      i++;
      continue;
    }

    result.args.push(arg);
    i++;
  }

  return result;
}
