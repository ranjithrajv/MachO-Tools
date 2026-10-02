/**
 * bundle.mjs — what an application bundle looks like, as data.
 *
 * ## Why a module for five lines
 *
 * Because every one of them used to be a literal in `target.mjs`: `'Contents'`,
 * `'MacOS'`, `.app`. That is a macOS fact written as if it were part of reading a
 * Mach-O, and it put a hard floor under the platform claim this package makes.
 * The parser in `macho.mjs` genuinely is portable — it is pure buffer work — but
 * a bundle is how a person actually names the binary, so hardcoding the bundle
 * layout made the *convenient* path macOS-only.
 *
 * The split this preserves: `macho.mjs` knows the file format, `bundle.mjs` knows
 * the container convention. Neither knows the other. A platform with no bundles
 * at all simply never calls `executableIn`, and the code that reads a Mach-O does
 * not change.
 *
 * ## Overriding
 *
 * `config.json` beside the source holds the shipped convention; `MACHO_CONFIG`
 * names a file to use instead. Only the `bundle` key is read here.
 *
 * `macosDir` is an array of *segments*, not a joined string, precisely because
 * `path.join` is how it must be built: joining it with a hardcoded separator is
 * the bug that makes a Windows path wrong in a way `path.join` would have fixed.
 */

import fs from 'node:fs';

/** Default: the macOS convention. */
const DEFAULT_LAYOUT = { ext: '.app', macosDir: ['Contents', 'MacOS'] };

/** Environment variable naming an override file. */
export const CONFIG_ENV = 'MACHO_CONFIG';

/** Absolute path to the shipped defaults, resolved relative to this file. */
const DEFAULT_CONFIG = new URL('../config.json', import.meta.url);

let _layout = null;

/**
 * Read the config, or `null` if no source can be read or parsed.
 *
 * An explicit `MACHO_CONFIG` that is broken falls through to the shipped
 * defaults rather than throwing: the tools are CLIs run by hand, and refusing to
 * start because an optional convenience override is malformed is a worse answer
 * than ignoring it.
 */
function readConfig() {
  const sources = [];
  if (process.env[CONFIG_ENV]) sources.push(process.env[CONFIG_ENV]);
  sources.push(DEFAULT_CONFIG);
  for (const file of sources) {
    try {
      return { file, parsed: JSON.parse(fs.readFileSync(file, 'utf8')) };
    } catch {
      // try the next source
    }
  }
  return null;
}

/**
 * The bundle convention in force: `{ ext, macosDir }`. Memoised.
 *
 * A malformed override is ignored rather than fatal: a typo in an optional
 * convenience path should not stop a tool that was handed an explicit path
 * anyway, and the shipped defaults are always a working answer.
 */
export function bundleLayout() {
  if (_layout) return _layout;
  const cfg = readConfig();
  const bundle = cfg?.parsed?.bundle || {};
  _layout = {
    ext: typeof bundle.ext === 'string' && bundle.ext ? bundle.ext : DEFAULT_LAYOUT.ext,
    macosDir:
      Array.isArray(bundle.macosDir) && bundle.macosDir.length && bundle.macosDir.every((s) => typeof s === 'string')
        ? bundle.macosDir
        : DEFAULT_LAYOUT.macosDir,
  };
  return _layout;
}

/** The bundle extension, e.g. `.app`. */
export const BUNDLE_EXT = () => bundleLayout().ext;

/**
 * The last-resort Mach-O for a bare invocation, or null.
 *
 * Keyed by platform rather than a single literal, because the original value —
 * `/bin/ls` — is a claim about what exists on a filesystem, and there is no
 * equivalent guarantee on Windows. `null` is an honest answer there; the
 * caller's error message already says what to pass.
 */
export function fallbackTarget() {
  const cfg = readConfig();
  const fb = cfg?.parsed?.fallback;
  if (fb === null) return null;
  if (process.platform === 'win32') {
    const win = fb && typeof fb.win32 !== 'undefined' ? fb.win32 : null;
    return typeof win === 'string' && win ? win : null;
  }
  const unix = fb && typeof fb.unix === 'string' && fb.unix ? fb.unix : '/bin/ls';
  return unix;
}

/** A scan tuning knob from config, with a default for a missing key. */
export function scanValue(key, fallback) {
  const cfg = readConfig();
  const v = cfg?.parsed?.scan?.[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

/** True when `p` names a bundle rather than an executable. */
export const isBundle = (p) => typeof p === 'string' && p.endsWith(BUNDLE_EXT());
