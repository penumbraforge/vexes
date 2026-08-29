/**
 * Build copy-pastable POSIX-shell upgrade commands from advisory coordinates.
 *
 * Quoting alone does not stop option injection (for example a package name
 * beginning with "--"), so every ecosystem coordinate is first constrained
 * to its public-registry name/version grammar. Invalid or unsupported values
 * produce null and must be sent to manual review.
 */

const VERSION = /^[0-9A-Za-z][0-9A-Za-z.!+_-]*$/;
const NPM_NAME = /^(?:@[0-9A-Za-z._~-]+\/[0-9A-Za-z._~-]+|[0-9A-Za-z][0-9A-Za-z._~-]*)$/;
const PYPI_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/;
const CARGO_NAME = /^[0-9A-Za-z][0-9A-Za-z_-]*$/;

export function posixShellEscape(value) {
  const text = String(value);
  if (/^[0-9A-Za-z@%_+.,:/=~-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

export function buildUpgradeCommand(packageName, version, ecosystem) {
  const name = String(packageName || '');
  const ver = String(version || '');
  if (!VERSION.test(ver)) return null;

  switch (ecosystem) {
    case 'npm':
      if (!NPM_NAME.test(name)) return null;
      return `npm install -- ${posixShellEscape(`${name}@${ver}`)}`;
    case 'pypi':
      if (!PYPI_NAME.test(name)) return null;
      return `pip install -- ${posixShellEscape(`${name}==${ver}`)}`;
    case 'cargo':
      if (!CARGO_NAME.test(name)) return null;
      return `cargo update --package ${posixShellEscape(name)} --precise ${posixShellEscape(ver)}`;
    default:
      return null;
  }
}
