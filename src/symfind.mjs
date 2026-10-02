#!/usr/bin/env node
/**
 * symfind.mjs — list symbols matching a substring.
 *
 *   node src/symfind.mjs <substring> [binary|bundle] [max] [--json]
 *
 * A plain substring search where `symgrep.mjs` is a regex, for when the name is
 * known but not its exact spelling. Output is deduplicated and address-ordered:
 * a symbol table routinely carries one name at several addresses — aliases,
 * thunks, per-architecture copies — and a list where `memcpy` appears nine times
 * is harder to read than one where it appears once.
 *
 * ## The argument order changed
 *
 * It used to be `<binary> <substring> [max]`, read as `argv[2]`, `argv[3]` and
 * `argv[4]`. That meant the binary had to be given first or not at all, and a
 * bare `symfind.mjs memcpy` read `argv[4]` as the binary path — i.e. `undefined`
 * — while searching for the substring `Core2IO`, a hardcoded default. It did
 * not crash, which is the problem: it printed a real, plausible symbol list for
 * a pattern nobody asked for. Every other tool in this directory takes the
 * query first and the binary second, so this one now does too.
 *
 * ## It shares the reader now
 *
 * This tool also parsed `LC_SYMTAB` by hand rather than calling `readSymbols`,
 * which meant it included debug (`N_STAB`) entries — `SO`, `LSDA`, `LSDA$` and
 * friends — in its results, and reported imports alongside definitions. Both
 * are answered by `api.mjs` now, so all six tools agree about what a symbol is.
 */
import { requireBinary } from './target.mjs';
import { findSymbols } from './api.mjs';
import { parseArgs, emitJSON, usage, count, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));
const substring = positional[0];

if (!substring) {
  usage([
    'usage: node src/symfind.mjs <substring> [binary|bundle] [max] [--json] [-b <binary>]',
    '',
    '  with no binary, reads $MACHO_BINARY, then $MACHO_APP.',
  ]);
}

const binary = requireBinary({ argv: opts.b || opts.binary || positional[1] });
const max = positional[2] !== undefined ? Number(positional[2]) : 4000;
if (!Number.isFinite(max) || max <= 0) usage(['max must be a positive number']);

const r = findSymbols(binary, substring, { max });

if (r.note) {
  const msg = `${binary}: ${r.note} (${r.arch}) — nothing to search`;
  if (flags.has('json')) {
    emitJSON({ tool: 'symfind', binary, ok: false, errors: ['no-symbols'], messages: [msg] }, EXIT.fail);
  }
  console.error(msg);
  process.exit(EXIT.fail);
}

if (flags.has('json')) {
  emitJSON({
    tool: 'symfind',
    binary,
    ok: true,
    notes: [r.truncated ? `truncated to ${max} unique names` : null].filter(Boolean),
    data: r,
  }, r.matches.length ? EXIT.ok : EXIT.empty);
}

console.log(
  `substring "${substring}": ${count(r.count)} matches, ` +
    `${count(r.uniqueCount)} unique\n`,
);
for (const e of r.matches) {
  // An import carries `n_value == 0`, so printing its address as a bare
  // `0x0` reads as "defined at address zero" — which is exactly the confusion
  // that made symlookup answer `function: _write, starts: 0x0` for a stub
  // binary. The marker costs one column and removes the ambiguity.
  const where = e.defined && e.addr !== 0n
    ? `0x${e.addr.toString(16).padStart(12, '0')}`
    : '  (import)'.padStart(14);
  console.log(`  ${where}  ${e.name}`);
}
if (r.truncated) console.log(`  ... and ${r.uniqueCount - max} more`);
if (r.matches.length === 0) {
  console.log('  none. A stripped binary has no symbol names to search.');
}
