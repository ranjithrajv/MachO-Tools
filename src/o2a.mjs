#!/usr/bin/env node
/**
 * o2a.mjs — which virtual address does this byte of the file have?
 *
 *   node src/o2a.mjs <offset> [<offset> ...] [--json] [--arch=<name>]
 *   node src/o2a.mjs 0x1000 -b /path/to/binary
 *
 * The inverse of `a2o`. Offsets are accepted in hex with an `0x` prefix or in
 * decimal, and every positional is an offset — the binary comes from `-b`, for
 * the same reason `symlookup` does it that way: a path cannot be told apart from
 * a number by position, and guessing from its shape turns a typo into a
 * confident wrong answer.
 *
 * ## Offsets are absolute; the section table is not
 *
 * A `section_64`'s `offset` is relative to the start of its *slice*, so on a
 * universal binary a relative offset and a position in the file are different
 * numbers. In `/bin/ls` the x86_64 slice begins at 0x4000 and the arm64 slice at
 * 0x10000, so the same relative offset names different bytes in each. Both bases
 * are reported per slice, and `--arch` picks one.
 *
 * Every slice is examined and each answer attributed, because a hit's meaning
 * depends on which slice it came from — the same file offset is a different
 * address in each. On a well-formed fat binary the slices do not overlap, so at
 * most one maps any given offset; where more than one does, that is reported
 * rather than resolved.
 *
 * ## Offsets that map to nothing
 *
 * The header and the load commands are inside `__TEXT`'s segment range but
 * outside every section, so they resolve to an address with no section name.
 * Past the end of the file, nothing maps at all. Both are answers: the first is
 * a real address with no section, the second is a negative result and exits 1.
 */
import { requireBinary } from './target.mjs';
import { offsetToAddress } from './api.mjs';
import { parseArgs, emitJSON, usage, EXIT, rejectUnknownFlags } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/o2a.mjs <offset> [<offset> ...] [--json] [--arch=<name>] [-b <binary>]',
  '',
  '  offsets are 0x-prefixed hex or decimal; every positional is an offset,',
  '  so the binary comes from -b/--binary, $MACHO_BINARY or $MACHO_APP.',
  '',
  'options:',
  '  --arch=<name>      read one architecture (x86_64, arm64)',
  '  -b, --binary <p>   the binary to read',
  '  --json             one JSON object on stdout; prose to stderr',
  '  -h, --help         this message',
];

if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

rejectUnknownFlags(new Set(['arch', 'json']), flags, HELP);

if (positional.length === 0) usage(HELP);

const binary = requireBinary({ argv: opts.binary || opts.b });
const arch = opts.arch;

// A bare decimal is unambiguous, but `0x` is required for hex so that `10` is
// never silently read as `0x10` — the ambiguity that makes a leading-zero typo
// in a patch script write to the wrong byte.
const bad = positional.find((a) => !/^(0[xX][0-9a-fA-F]+|[0-9]+)$/.test(a));
if (bad) {
  usage([
    'offsets must be decimal, or hex with an 0x prefix, e.g. 4096 or 0x1000',
    `  got: ${bad}`,
  ]);
}

const offsets = positional.map((a) => BigInt(a));

let result;
try {
  result = offsetToAddress(binary, offsets, { arch });
} catch (e) {
  if (flags.has('json')) {
    emitJSON({ tool: 'o2a', binary, ok: false, errors: ['io'], messages: [e.message] }, EXIT.fail);
  }
  console.error(`${binary}: ${e.message}`);
  process.exit(EXIT.fail);
}

const resolved = result.queries.filter((q) => q.vaddr !== null).length;

if (flags.has('json')) {
  emitJSON({
    tool: 'o2a',
    binary,
    ok: true,
    notes: [
      'offsets are absolute positions in the file; each slice also reports its own slice-relative offset',
      'a section-less answer is still a real address: the header and load commands sit inside __TEXT but in no section',
    ],
    data: {
      ...result,
      asked: result.queries.length,
      resolved,
      unmapped: result.queries.length - resolved,
      ambiguous: result.queries.filter((q) => q.ambiguous).length,
    },
  }, resolved ? EXIT.ok : EXIT.empty);
}

// The API already reports addresses as hex strings, so these are echoed rather
// than converted — reformatting them here risks disagreeing with the envelope.
const hex = (v) => (v === null || v === undefined ? '-' : String(v));

console.log(`${binary}${arch ? `  [${arch}]` : ''}`);
for (const q of result.queries) {
  console.log(`\n  ${hex(q.query)}`);
  for (const s of q.slices) {
    const archCol = (s.arch || '-').padEnd(9);
    if (!s.mapped) {
      console.log(`    ${archCol} ${'-'.padStart(12)}  ${s.note}`);
      continue;
    }
    // The slice-relative offset is the secondary fact and is indented under the
    // address rather than given a column of its own: on a thin binary it is the
    // same number, and on a fat one it is only meaningful once you know which
    // slice you are reading.
    console.log(`    ${archCol} ${hex(s.vaddr).padStart(12)}  ${s.section}`);
    console.log(`    ${' '.repeat(9)}   slice-relative offset ${hex(s.offset)}`);
  }
}

process.exit(resolved ? EXIT.ok : EXIT.empty);