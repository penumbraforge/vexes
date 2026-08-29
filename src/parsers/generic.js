import { discover as discoverGo, parseLockfile as parseGoSum, parseManifest as parseGoMod } from './go.js';
import { discover as discoverRuby, parseLockfile as parseGemLock, parseManifest as parseGemfile } from './ruby.js';
import { discover as discoverPhp, parseLockfile as parseComposerLock, parseManifest as parseComposerJson } from './php.js';
import { discover as discoverNuget, parseLockfile as parseNugetLock, parseManifest as parseCsproj } from './dotnet.js';
import { discover as discoverJava, parseLockfile as parseGradleLock, parseManifest as parsePom } from './java.js';
import { discover as discoverHex, parseLockfile as parseMixLock } from './hex.js';
import { discover as discoverPub, parseLockfile as parsePubspecLock } from './pub.js';

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
  hex: {
    discover: discoverHex,
    parseLockfile: parseMixLock,
    parseManifest: null, // mix.lock only — no generic manifest parser yet
  },
  pub: {
    discover: discoverPub,
    parseLockfile: parsePubspecLock,
    parseManifest: null,
  },
});

/**
 * Prefer lockfiles when available; otherwise fall back to manifests.
 */
export function selectGenericFiles(dir, ecosystem) {
  const parser = GENERIC_ECOSYSTEM_PARSERS[ecosystem];
  if (!parser) return { files: [], usingManifestFallback: false };

  const { lockfiles, manifests } = parser.discover(dir);
  // go.mod is the selected module graph. go.sum is checksum history and may
  // retain stale modules that are no longer dependencies, so prefer go.mod
  // whenever it exists instead of presenting go.sum as an installed graph.
  if (ecosystem === 'go' && manifests.length > 0) {
    return {
      files: manifests.map(path => ({ path, kind: 'manifest' })),
      usingManifestFallback: false,
    };
  }
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
