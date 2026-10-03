/**
 * target.mjs — find the binary a command should read.
 *
 * ## Why this exists
 *
 * Tools that read a Mach-O were written one at a time, and each grew its own
 * notion of "the binary": some took a path, some hardcoded one, and one read
 * the architecture's load commands at a fixed file offset, which is correct
 * only for a *thin* Mach-O and silently wrong on every universal binary. Two of
 * them could not terminate. Centralising the path resolution and the slice
 * choice here is what made those fixable in one place.
 *
 * ## Resolution order
 *
 *   1. an explicit argument, where the tool accepts one
 *   2. `$MACHO_BINARY` — a path to an executable
 *   3. `$MACHO_APP`   — a bundle; the executable is found inside it
 *   4. that tool's own fallback, so a bare invocation still finds something
 *
 * Step 4 is why each tool may pass its own default rather than sharing one
 * global: the fallbacks differ per tool, and silently unifying them would change
 * what a bare invocation does.
 *
 * Two names that used to be honoured as aliases for 2 and 3 were removed. They
 * named a specific commercial product, and this package deliberately knows
 * nothing about any application — an inherited convention from a caller is not
 * a good enough reason for a published tool to carry a vendor's name in its
 * public interface. A caller that used them can set `MACHO_BINARY`/`MACHO_APP`
 * instead; there is no behaviour here that depended on the old spelling.
 *
 * ## A bundle, not just a path
 *
 * `resolveBinary` handles application bundles, because that is what a person has:
 * the executable sits at `Contents/MacOS/<bundle name minus .app>`, and the bundle
 * name is not always the executable name.
 *
 * The `.app` convention is *data* rather than an assumption baked into the code
 * path, for the same reason the container layout is configurable elsewhere in this
 * workspace: it is a fact about macOS, not about how to read a Mach-O. On a
 * platform with no bundles — or with bundles laid out differently — the
 * separators, the `Contents` level and the executable directory all come from one
 * place, so pointing these tools at a bundle elsewhere is a config change rather
 * than a code change.
 *
 * ## About the fallback
 *
 * A bare invocation should not be a dead end, so the last resort is a system
 * binary that exists on every machine this runs on. It is a fallback, not a
 * default target — nothing here is *meant* to be pointed at it — and it is a
 * single named constant so overriding it is one edit rather than a search.
 *
 * It is a file rather than an `.app` on purpose. An earlier choice named an
 * application bundle, which was wrong twice over: it made this module refer to a
 * product, and the bundle turned out not to exist on the machine it was written
 * on, so every bare invocation failed with "no binary found".
 */
import fs from 'node:fs';
import path from 'node:path';
import { isMachOFile } from './macho.mjs';
import { bundleLayout, BUNDLE_EXT, isBundle, fallbackTarget } from './bundle.mjs';

/**
 * The last-resort target for a bare invocation: a Mach-O that exists on every
 * machine, so the tools print something useful rather than a usage error.
 * Overridable per tool, and per run via `$MACHO_BINARY`.
 */
/**
 * The last-resort target for a bare invocation.
 *
 * Chosen per platform rather than fixed to `/bin/ls`, which does not exist on
 * Windows. It is a *Mach-O* on macOS and Linux; on Windows there is no Mach-O at
 * a fixed path, so the fallback is null and a bare invocation says what to do
 * instead of reporting a missing file.
 */
export const FALLBACK_TARGET = fallbackTarget();

/**
 * Re-exported from `macho.mjs`, which owns the byte-exact check. The copy that
 * used to live here read the magic big-endian and so accepted only universal
 * binaries — meaning `executableIn` could not find a thin executable inside an
 * `.app` and reported no binary at all.
 *
 * It is worth recording how that copy broke a second time after being deleted:
 * the function stayed in the file but its module-level constants did not, so it
 * threw a `ReferenceError` on every call — and its own `catch { return false }`
 * swallowed it. Every binary was reported as "not a Mach-O" and every tool
 * exited cleanly saying it could not find one. A catch that hides programming
 * errors turns a crash into a wrong answer, which is much harder to notice.
 */
export const looksMachO = isMachOFile;

/**
 * The executable inside a `.app` bundle, or null.
 *
 * Prefers `Contents/MacOS/<bundle name>`, which is the conventional location,
 * and otherwise takes the largest Mach-O at the top level of that directory.
 * The size heuristic is a fallback rather than the rule because a bundle can
 * carry several helper binaries and the main one is normally the large one — but
 * a name match is authoritative when there is one.
 */
export function executableIn(appPath) {
  const macos = path.join(appPath, ...bundleLayout().macosDir);
  let ents;
  try {
    ents = fs.readdirSync(macos, { withFileTypes: true });
  } catch {
    return null;
  }
  const files = ents.filter((e) => e.isFile());
  if (files.length === 0) return null;

  const base = path.basename(appPath).replace(BUNDLE_EXT, '');
  const byName = files.find((e) => e.name === base);
  const order = byName ? [byName, ...files.filter((e) => e !== byName)] : files;

  let best = null;
  for (const e of order) {
    const p = path.join(macos, e.name);
    let size = 0;
    try {
      size = fs.statSync(p).size;
    } catch {
      continue;
    }
    if (size < 1024) continue;
    if (!looksMachO(p)) continue;
    if (byName && p === path.join(macos, byName.name)) return p;
    if (!best || size > best.size) best = { path: p, size };
  }
  return best ? best.path : null;
}

/**
 * Resolve the binary to read, or null when nothing is found.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.argv]    explicit path from the command line
 * @param {string}  [opts.fallback] this tool's historical no-argument default
 * @returns {string|null}
 */
export function resolveBinary({ argv, fallback } = {}) {
  if (argv) {
    // An explicit argument may name the bundle rather than the executable.
    if (isBundle(argv)) return executableIn(argv) || null;
    return argv;
  }
  const binary = process.env.MACHO_BINARY;
  if (binary) return binary;
  const app = process.env.MACHO_APP;
  if (app) return executableIn(app) || null;
  return resolveTarget(fallback) || resolveTarget(FALLBACK_TARGET);
}

/** A target may be an executable path or an `.app` bundle. */
function resolveTarget(t) {
  if (!t) return null;
  return isBundle(t) ? executableIn(t) : t;
}

/**
 * The binary an argument names, or null if it does not name one.
 *
 * This exists for one specific mistake, and it is the reason the two checks
 * below are separate from {@link resolveBinary}: `resolveBinary` answers "what
 * should I read", and when the answer would otherwise be a fallback it is
 * *correct* to fall back. This answers the prior question — "was this argument
 * meant to be a binary at all" — which has to be asked before falling back,
 * because a fallback answers about a file the caller never named.
 *
 * `sym /path/to/SomeBinary` was the observed case: `sym` takes a pattern then a
 * binary, so a lone path became the *pattern*, the binary defaulted, and the
 * tool reported a confident negative about `/bin/ls` while naming the file the
 * user had actually asked about nowhere in the output. Exit 1, no error, wrong
 * file — which is the shape README.md calls out as the thing this project exists
 * to avoid, appearing in the one command a new user is most likely to run first.
 *
 * Deliberately narrow: it only fires on a lone Mach-O or bundle path, so a
 * pattern that merely *looks* like a path still searches normally. That is why
 * `findliteral` and `mapliteral` do not use it — a literal that is also a real
 * file is not a mistake, and refusing it would break a legitimate search.
 */
export function binaryAt(arg) {
  if (!arg) return null;
  if (isBundle(arg)) return executableIn(arg);
  let st;
  try {
    st = fs.statSync(arg);
  } catch {
    return null; // does not exist, or is unreadable — either way not a target
  }
  if (!st.isFile()) return null;
  return isMachOFile(arg) ? arg : null;
}

/**
 * Resolve, and exit with a usable message when there is nothing to read.
 *
 * Every tool in this directory would otherwise repeat the same four lines of
 * null-checking, and a tool that silently does nothing on a typo'd path is
 * worse than one that stops.
 */
export function requireBinary(opts = {}) {
  const bin = resolveBinary(opts);
  if (bin) return bin;
  const where = [
    opts.argv ? `argument: ${opts.argv}` : null,
    process.env.MACHO_BINARY
      ? `MACHO_BINARY=${process.env.MACHO_BINARY}` : null,
    process.env.MACHO_APP
      ? `MACHO_APP=${process.env.MACHO_APP}` : null,
  ].filter(Boolean).join('\n  ');
  console.error(
    'no binary found.\n\n' +
      (where ? `  tried:\n  ${where}\n\n` : '') +
      '  pass a path:      node <tool>.mjs "/path/to/Some Binary' + BUNDLE_EXT() + '"\n' +
      '  or set:           MACHO_BINARY=/path/to/executable\n' +
      '  or set:           MACHO_APP="/path/to/Some App' + BUNDLE_EXT() + '"\n' +
      (process.platform === 'win32'
        ? '  note: there is no system Mach-O to fall back to on Windows, so a bare\n' +
          '        invocation has no target. Pass a path or set MACHO_BINARY.\n'
        : ''),
  );
  process.exit(2);
  return null; // unreachable; keeps callers from needing a null check
}
