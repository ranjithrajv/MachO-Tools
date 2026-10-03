#!/usr/bin/env node
/**
 * findliteral.mjs — find every occurrence of a byte literal in a binary.
 *
 *   node src/findliteral.mjs <literal> [binary|bundle] [--text] [--json]
 *
 * Reports each hit's file offset, which architecture slice it falls in, its
 * vaddr where the slice maps one, and the surrounding bytes as printable
 * context. That combination is usually enough to tell a string literal from a
 * pointer table from bytes that happen to sit inside an instruction, without
 * opening a disassembler.
 *
 * The literal is an argument rather than a constant. A hardcoded one makes the
 * tool a one-off script with a misleading name: the searching is the reusable
 * part, not the thing being searched for.
 *
 * ## The whole file, not just __TEXT
 *
 * Most literals live in `__TEXT`, but a format magic can equally be compared
 * against a constant in `__DATA`, embedded in code, or present in only one
 * slice of a universal binary. So this scans the entire file by default and
 * attributes every hit to a slice. Pass `--text` to restrict the search to
 * `__TEXT` when you know it is there and want the scan to be cheap.
 *
 * ## Why the fat header is parsed
 *
 * A hit's file offset is meaningless without knowing which slice it came from —
 * two slices have different virtual address bases, so the same file offset in
 * each is a different address. An earlier version reimplemented the fat-header
 * walk and got it subtly wrong for thin binaries, reporting every hit as
 * belonging to an unnamed slice.
 */
import { requireBinary } from './target.mjs';
import { findLiteral } from './api.mjs';
import { parseArgs, emitJSON, usage, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/findliteral.mjs <literal> [binary|bundle] [--text] [--json] [-b <binary>]',
  '',
  '  <literal> is matched as raw latin1 bytes, so escapes work:',
  '    node src/findliteral.mjs LZ4 /Applications/Some.app',
  '    node src/findliteral.mjs \\x1f\\x8b --text',
  '',
  'options:',
  '  --text             search __TEXT only, rather than the whole file',
  '  -b, --binary <p>   the binary to read',
  '  --json             one JSON object on stdout; prose to stderr',
  '  -h, --help         this message',
];

if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

const literal = positional[0];
if (!literal) usage(HELP);

const binary = requireBinary({ argv: opts.b || opts.binary || positional[1] });
const textOnly = flags.has('text');
const needle = Buffer.from(literal, 'latin1');

let r;
try {
  r = findLiteral(binary, needle, { textOnly });
} catch (e) {
  if (flags.has('json')) {
    emitJSON({ tool: 'findliteral', binary, ok: false, errors: [e.code ?? 'io'], messages: [e.message] }, EXIT.fail);
  }
  console.error(`${binary}: ${e.message}`);
  process.exit(EXIT.fail);
}

const notes = [];
if (r.count === 0) {
  notes.push('a magic built at runtime from parts never appears as a contiguous literal');
  notes.push('a stripped binary still contains its read-only data — search the whole file, not just __TEXT, if unsure');
}

if (flags.has('json')) {
  emitJSON({
    tool: 'findliteral', binary, ok: r.count > 0,
    errors: r.count ? [] : ['no-match'], notes, data: r,
  }, r.count ? EXIT.ok : EXIT.empty);
}

console.log(
  `binary: ${(r.scanned / 1048576).toFixed(0)} MB scanned, ${r.slices.length} slice(s), ` +
    `literal ${JSON.stringify(literal)} (${needle.length} bytes)`,
);
for (const s of r.slices) {
  console.log(`  ${s.arch}: file ${s.offset}..${s.offset + s.size} (${s.hits} hit(s))`);
}

console.log(`\n${r.count} occurrence(s) of ${JSON.stringify(literal)}`);
for (const h of r.hits) {
  console.log(
    `  file 0x${h.off.toString(16).padStart(8, '0')} [${h.slice}]` +
      (h.vaddr !== null ? `  vaddr 0x${h.vaddr.toString(16)}` : '  unmapped') +
      (h.section ? `  ${h.section}` : '') +
      `\n      pre="${h.context.pre}"  hit="${h.context.hit}"`,
  );
}
if (r.count === 0) for (const n of notes) console.log(`  note: ${n}`);

// Exit 1 for "ran, found nothing" — the same negative-result code --json
// reports. The JSON path set this and the text path did not, so the two
// interfaces disagreed about the same query, which is worse than either choice.
process.exit(r.count ? EXIT.ok : EXIT.empty);
