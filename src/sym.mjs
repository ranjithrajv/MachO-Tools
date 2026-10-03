#!/usr/bin/env node
/**
 * sym.mjs — search a Mach-O symbol table.
 *
 *   node src/sym.mjs <pattern> [binary|bundle] [max] [--json] [--regex]
 *   node src/sym.mjs --all-imp 'malloc' /path/to/binary
 *   node src/sym.mjs --regex 'runtime\..*main' /usr/local/go/bin/go
 *
 * ## This tool used to be two
 *
 * `symgrep.mjs` searched by regex and `symfind.mjs` by substring, and they
 * disagreed about what a symbol search meant. `symgrep` returned defined symbols
 * only and one row per table entry; `symfind` included imports and collapsed a
 * name to one row. Neither default was a mistake — they were answers to
 * different questions that had drifted into looking like the same tool, and a
 * reader who had learned one had to check which convention the other used before
 * trusting a result. They are now one tool with one stated set of rules, and the
 * two old names still work (see *The old names* below).
 *
 * ## The rules, stated once
 *
 *   - **Substring by default.** The name is usually known but not its exact
 *     spelling, and a pattern that accidentally fails to compile as a regex is a
 *     worse failure than one that matches too much. `--regex` switches.
 *   - **Defined symbols only, unless you ask otherwise.** An imported name
 *     carries `n_value == 0`: it says which library a call goes out to, not
 *     where anything is implemented. `--all-imp` includes them, and they are
 *     marked `(import)` rather than printed as `0x0`, because a bare zero reads
 *     as "defined at address zero" — the confusion that once made `symlookup`
 *     answer `function: _write, starts: 0x0` for a stub binary.
 *   - **One row per name.** A symbol table routinely carries one name at several
 *     addresses (aliases, thunks, per-architecture copies), and nine rows
 *     reading `memcpy` is harder to read than one. `--no-dedupe` restores the
 *     raw per-entry form.
 *
 * ## The old names
 *
 * `symgrep.mjs` and `symfind.mjs` are gone rather than kept as aliases. Nothing
 * in this package called them except the tools themselves, the package is at
 * 0.1.0, and two superseded entry points that disagree with the rules above
 * would recreate exactly the ambiguity the merge exists to end. The
 * equivalents are `sym.mjs --regex` and `sym.mjs --all-imp`, which is why the
 * defaults above are the opposite way round from `symgrep`'s.
 *
 * ## A bug this no longer has
 *
 * This lineage used to open the file and hardcode `const SLICE = 0x4000` as the
 * base for every load-command read. 0x4000 is not "the Mach-O", it is the byte
 * offset of one binary's x86_64 slice inside its own fat header — correct for
 * exactly one file on earth. In the measured pair, the other slice sat at
 * 0xf16c000. Against any other binary it read load commands out of the middle of
 * a data section, and the failure mode was a plausible-looking wrong answer
 * rather than an error. The slice now comes from `api.mjs`, which shares one
 * reader with the other tools.
 */
import { requireBinary, binaryAt, FALLBACK_TARGET } from './target.mjs';
import { searchSymbols } from './api.mjs';
import { parseArgs, emitJSON, usage, count, EXIT, rejectUnknownFlags } from './output.mjs';

const HELP = [
  'usage: node src/sym.mjs <pattern> [binary|bundle] [max] [options]',
  '',
  '  <pattern>          substring to match, or a regex with --regex',
  '  [binary|bundle]    defaults to $MACHO_BINARY, then $MACHO_APP,',
  `                     then ${FALLBACK_TARGET}`,
  '  [max]              cap on rows when deduplicating (default 4000)',
  '',
  'options:',
  '  --regex            treat <pattern> as a regular expression',
  '  --case-sensitive   match case exactly (regex mode and substring mode)',
  '  --all-imp          include imported symbols, not just defined ones',
  '  --no-dedupe        one row per table entry rather than per name',
  '  --arch=<name>      prefer an architecture (x86_64, arm64, arm64e, arm64_32, ppc, ppc64, arm, i386)',
  '  -b, --binary <p>   the binary, if every positional is part of the query',
  '  --json             one JSON object on stdout; prose to stderr',
  '  -h, --help         this message',
];

const { flags, opts, positional } = parseArgs(process.argv.slice(2));
const pattern = positional[0];

if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

rejectUnknownFlags(
  new Set(['regex', 'case-sensitive', 'all-imp', 'no-dedupe', 'arch', 'json']),
  flags,
  HELP,
);

if (!pattern) usage(HELP);

// A lone Mach-O path is the binary the user meant, not a pattern to search for.
//
// `sym` takes a pattern and *then* a binary, so `sym /path/to/Binary` read the
// path as the pattern, fell back to a default binary, and exited 1 reporting
// that a different file had no matching symbols. Nothing in the output named
// the file that was never opened.
//
// The fallback is not the bug — falling back is right when a tool is given no
// binary at all. The bug is falling back while holding an argument that *is* a
// binary, because the answer is then about a file the caller never mentioned.
// Asking before resolving is the only place that can be caught.
const explicitBinary = opts.b || opts.binary;
if (!explicitBinary && positional.length === 1) {
  const named = binaryAt(positional[0]);
  if (named) {
    const literal = `${positional[0]}`;
    const msg =
      `${literal} names a Mach-O, and sym takes a pattern and then a binary.\n\n` +
      `  Read as a pattern it would search ${FALLBACK_TARGET} instead — a different\n` +
      `  file — so this is refused rather than answered.\n\n` +
      `    search it:          node src/sym.mjs <pattern> ${JSON.stringify(literal)}\n` +
      `    or name the binary: node src/sym.mjs <pattern> -b ${JSON.stringify(literal)}\n` +
      `    to match the path as text: node src/sym.mjs ${JSON.stringify(literal)} -b <binary>`;
    if (flags.has('json')) {
      // Emitted, because this tool already emits for `bad-pattern` above and a
      // caller piping `--json` should not have to parse prose to learn that the
      // invocation was wrong.
      emitJSON({ tool: 'sym', binary: named, ok: false, errors: ['missing-pattern'], messages: [msg] }, EXIT.usage);
    }
    usage([...HELP, '', msg]);
  }
}

const binary = requireBinary({ argv: explicitBinary || positional[1] });
const max = positional[2] !== undefined ? Number(positional[2]) : 4000;
if (!Number.isFinite(max) || max <= 0) usage(['max must be a positive number']);

const mode = flags.has('regex') ? 'regex' : 'substring';
const definedOnly = !flags.has('all-imp');
const dedupe = !flags.has('no-dedupe');
const arch = opts.arch;
const json = flags.has('json');
const regexFlags = flags.has('case-sensitive') ? '' : 'i';

let r;
try {
  r = searchSymbols(binary, pattern, { mode, definedOnly, dedupe, max, arch, flags: regexFlags });
} catch (e) {
  // A reader failure has to reach the caller as the same envelope every other
  // path emits. Without this the `--json` contract held only for a binary that
  // happened to be readable, and a consumer got an unhandled rejection instead
  // of a reason code — which is the one situation where it most needs one.
  const code = e instanceof SyntaxError ? 'bad-pattern' : (e.code ?? 'io');
  const exit = code === 'bad-pattern' ? EXIT.usage : EXIT.fail;
  if (json) emitJSON({ tool: 'sym', binary, ok: false, errors: [code], messages: [e.message] }, exit);
  console.error(`${binary}: ${e.message}`);
  process.exit(exit);
}

if (r.note) {
  const msg = `${binary}: ${r.note} (${r.arch}) — nothing to search`;
  if (json) emitJSON({ tool: 'sym', binary, ok: false, errors: ['no-symbols'], messages: [msg] }, EXIT.fail);
  console.error(msg);
  process.exit(EXIT.fail);
}

if (json) {
  emitJSON({
    tool: 'sym',
    binary,
    ok: true,
    notes: [
      r.count === 0 ? 'no symbol matched; a stripped binary has none to match against' : null,
      definedOnly ? 'defined symbols only (N_SECT)' : 'imports included',
      dedupe ? null : 'one row per table entry (--no-dedupe)',
      r.truncated ? `truncated to ${r.matches.length} rows` : null,
    ].filter(Boolean),
    data: r,
  }, r.matches.length ? EXIT.ok : EXIT.empty);
}

const what = mode === 'regex' ? `/${pattern}/${regexFlags}` : `"${pattern}"`;
const units = dedupe ? 'unique' : 'entries';
console.log(
  `${mode} ${what}: ${count(r.count)} ${r.count === 1 ? 'match' : 'matches'}, ` +
    `${count(r.uniqueCount)} unique\n`,
);
for (const e of r.matches) {
  const where = e.defined && e.addr !== 0n
    ? `0x${e.addr.toString(16).padStart(12, '0')}`
    : '  (import)'.padStart(14);
  console.log(`  ${where}  ${e.name}`);
}
if (r.truncated) console.log(`  ... and ${r.count - r.matches.length} more`);
console.log(
  `\n${count(r.matches.length)} row(s), ${units}, in ${r.arch} ` +
    `(${count(r.defined)} defined / ${count(r.total)} symbols)`,
);
if (r.matches.length === 0) {
  console.log('  none. If this binary is stripped there are no names to match against —');
  console.log('  symlookup and findcall read addresses and bytes instead, and still work.');
}

// The same exit status in both modes. This was missing here and present in the
// `--json` branch above, so the same search answered 1 under `--json` and 0
// without it — a caller branching on the status got a different answer
// depending on a flag that is supposed to change only the output format.
process.exit(r.matches.length ? EXIT.ok : EXIT.empty);