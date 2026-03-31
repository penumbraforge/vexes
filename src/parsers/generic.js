import { discover as discoverGo, parseLockfile as parseGoSum, parseManifest as parseGoMod } from './go.js';
import { discover as discoverRuby, parseLockfile as parseGemLock, parseManifest as parseGemfile } from './ruby.js';
import { discover as discoverPhp, parseLockfile as parseComposerLock, parseManifest as parseComposerJson } from './php.js';
import { discover as discoverNuget, parseLockfile as parseNugetLock, parseManifest as parseCsproj } from './dotnet.js';
import { discover as discoverJava, parseLockfile as parseGradleLock, parseManifest as parsePom } from './java.js';

export const GENERIC_ECOSYSTEM_PARSERS = Object.freeze({
  go: {
    discover: discoverGo,
    parseLockfile: parseGoSum,
    parseManifest: parseGoMod,
  },
  ruby: {
    discover: discoverRuby,
    parseLockfile: parseGemLock,
    parseManifest: parseGemfile,
  },
  php: {
    discover: discoverPhp,
    parseLockfile: parseComposerLock,
    parseManifest: parseComposerJson,
  },
  nuget: {
    discover: discoverNuget,
    parseLockfile: parseNugetLock,
    parseManifest: parseCsproj,
  },
  java: {
    discover: discoverJava,
    parseLockfile: parseGradleLock,
    parseManifest: parsePom,
  },
});

/**
 * Prefer lockfiles when available; otherwise fall back to manifests.
 */
export function selectGenericFiles(dir, ecosystem) {
  const parser = GENERIC_ECOSYSTEM_PARSERS[ecosystem];
  if (!parser) return { files: [], usingManifestFallback: false };

  const { lockfiles, manifests } = parser.discover(dir);
  if (lockfiles.length > 0) {
    return {
      files: lockfiles.map(path => ({ path, kind: 'lockfile' })),
      usingManifestFallback: false,
    };
  }

  return {
    files: manifests.map(path => ({ path, kind: 'manifest' })),
    usingManifestFallback: manifests.length > 0,
  };
}

export function parseGenericFile(ecosystem, file) {
  const parser = GENERIC_ECOSYSTEM_PARSERS[ecosystem];
  if (!parser) throw new Error(`unknown generic ecosystem: ${ecosystem}`);
  return file.kind === 'manifest'
    ? parser.parseManifest(file.path)
    : parser.parseLockfile(file.path);
}
