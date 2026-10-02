#!/usr/bin/env node
/**
 * symgrep.mjs — search a Mach-O symbol table by regex.
 *
 *   node src/symgrep.mjs <regex> [binary|bundle] [--json] [--arch=arm64]
 *   node src/symgrep.mjs --all-imp 'malloc' /path/to/binary
 *
 * The regex comes first and the binary is optional, so a one-argument call is
 * never ambiguous. The previous signature was `<binary> <regex>`, but it read
 * `argv[2]` as the binary and `argv[3]` as the pattern, so the one-argument
 * form its own header documented could never work — the pattern came back
 * undefined. Bare invocations are the common case, so the order is the one that
 * makes them work.
 *
 * The symbol table stores mangled names, so a pattern should match either the
 * mangled form or a distinctive substring. Demangled fragments work too —
 * 'Compress' matches `__ZN10LZ4Wrapper9compressE...`.
 *
 * ## Defined symbols only, unless you ask otherwise
 *
 * The default filter is N_SECT, so imported-but-undefined names are excluded:
 * this tool answers "where is this implemented", not "what does this link
 * against". `--all-imp` includes imports, which are occasionally the actual
 * question — an import with `n_value == 0` says which library the call goes
 * out to, and that is useful when you are tracing a call into something you
 * cannot read.
 *
 * ## A bug this no longer has
 *
 * This tool used to open the file and hardcode `const SLICE = 0x4000` as the
 * base for every load-command read. 0x4000 is not "the Mach-O", it is the byte
 * offset of one binary's x86_64 slice inside its own fat header — correct for
 * exactly one file on earth. In the measured pair, the other slice sat at
 * 0xf16c000. Against any other binary it read load commands out of the middle of
 * a data section, and the failure mode was a plausible-looking wrong answer
 * rather than an error. The slice now comes from `api.mjs`, which shares one
 * reader with the other five tools.
 */
import { requireBinary, FALLBACK_TARGET } from './target.mjs';
import { grepSymbols } from './api.mjs';
import { parseArgs, emitJSON, usage, count, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));
const pattern = positional[0];

if (!pattern) {
  usage([
    'usage: node src/symgrep.mjs <regex> [binary|bundle] [--json] [--arch=<name>] [-b <binary>] [--all-imp]',
    '',
    '  with no binary, reads $MACHO_BINARY, then $MACHO_APP,',
    `  then ${FALLBACK_TARGET}`,
  ]);
}

const binary = requireBinary({ argv: opts.b || opts.binary || positional[1] });
const json = flags.has('json');
const allImported = flags.has('all-imp');
const arch = opts.arch;

const r = grepSymbols(binary, pattern, { definedOnly: !allImported, arch });

if (r.note) {
  const msg = `${binary}: ${r.note} (${r.arch}) — nothing to search`;
  if (json) emitJSON({ tool: 'symgrep', binary, ok: false, errors: ['no-symbols'], messages: [msg] }, EXIT.fail);
  console.error(msg);
  process.exit(EXIT.fail);
}

if (json) {
  emitJSON({
    tool: 'symgrep',
    binary,
    ok: true,
    notes: [
      r.matches.length === 0 ? 'no defined symbol matched; a stripped binary has none to match' : null,
      allImported ? 'imports included' : 'defined symbols only (N_SECT)',
    ].filter(Boolean),
    data: r,
  }, r.matches.length ? EXIT.ok : EXIT.empty);
}

for (const e of r.matches) {
  console.log(`0x${e.addr.toString(16).padStart(12, '0')}  ${e.name}`);
}
console.log(
  `\n${r.matches.length} match(es) for /${pattern}/i in ${r.arch}` +
    ` (${count(r.defined)} defined / ${count(r.total)} symbols)`,
);
if (r.matches.length === 0) {
  console.log('  none. If this binary is stripped there are no names to match against —');
  console.log('  symlookup and findcall read addresses and bytes instead, and still work.');
}
