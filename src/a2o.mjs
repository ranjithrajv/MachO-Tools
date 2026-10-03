#!/usr/bin/env node
/**
 * a2o.mjs — which byte of the file is this virtual address?
 *
 *   node src/a2o.mjs <hex-vaddr> [<hex-vaddr> ...] [--json] [--arch=<name>]
 *   node src/a2o.mjs 0x100001000 -b /path/to/binary
 *
 * The inverse of `o2a`. Every address a tool reports is a virtual address,
 * because that is what a call site or a symbol refers to; every position a hex
 * editor, a `dd` pipeline or a patch script wants is a file offset. Converting
 * between them by hand means reading the section table, and the section table is
 * where the slice-relative-offset bug in this project's own history lived.
 *
 * ## Both offsets, always
 *
 * `offset` is slice-relative, matching what the section table records, and
 * `absoluteOffset` adds the slice's own position in the file. On a thin binary
 * they are the same. On a universal binary they are not, and reporting only one
 * of them is how a reader ends up editing the wrong bytes: in `/bin/ls`, the
 * x86_64 slice starts at 0x4000, so `__TEXT` at relative 0 is absolute 0x4000.
 *
 * ## Zero-fill is an answer, not a gap
 *
 * `__bss` and `__noptrbss` have addresses and sizes but no bytes in the file —
 * the loader supplies zeros — and `__PAGEZERO` is 4 GB of address space with
 * nothing behind it. An address there is *mapped*, so reporting "not found"
 * would be wrong, and reporting a file offset would be worse: there is no byte
 * to read. Those come back as `zerofill: true` with a note, which is a third
 * answer distinct from both "mapped to a byte" and "not in this binary".
 *
 * The inverse direction has the matching trap. `toVaddr` used to test sections
 * before checking whether they occupy file bytes, and `__DATA,__bss` — whose
 * recorded offset is 0 — swallowed the first 180,760 bytes of every binary.
 * File offset 0x1000, the first byte of `__text`, came back as being inside
 * `__bss`. See `isBackedByFile` in `macho.mjs`.
 */
import { requireBinary } from './target.mjs';
import { addressToOffset } from './api.mjs';
import { parseArgs, emitJSON, usage, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/a2o.mjs <hex-vaddr> [<hex-vaddr> ...] [--json] [--arch=<name>] [-b <binary>]',
  '',
  '  every positional is an address, so the binary comes from -b/--binary,',
  '  $MACHO_BINARY or $MACHO_APP.',
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

if (positional.length === 0) usage(HELP);

const binary = requireBinary({ argv: opts.binary || opts.b });
const arch = opts.arch;

// The same rule symlookup applies, for the same reason: a path told apart from an
// address by whether it looks like one turns a typo into a confident wrong answer.
const bad = positional.find((a) => !/^0x[0-9a-fA-F]+$/.test(a));
if (bad) {
  usage(['addresses must be hex with an 0x prefix, e.g. 0x100001000', `  got: ${bad}`]);
}

const rows = [];
for (const arg of positional) {
  try {
    rows.push(addressToOffset(binary, BigInt(arg), { arch }));
  } catch (e) {
    if (flags.has('json')) {
      emitJSON({ tool: 'a2o', binary, ok: false, errors: ['bad-address'], messages: [`${arg}: ${e.message}`] }, EXIT.usage);
    }
    console.error(`${arg}: ${e.message}`);
    process.exit(EXIT.usage);
  }
}

// Three outcomes, counted apart, because they are three different answers and a
// caller patching a file needs to tell them: an address that reaches a byte, an
// address that is mapped but has no byte (`__bss`, `__PAGEZERO`), and an address
// in no slice at all.
const toByte = rows.filter((r) => r.mapped && !r.zerofill).length;
const zerofill = rows.filter((r) => r.zerofill).length;
const unmapped = rows.filter((r) => !r.mapped).length;

if (flags.has('json')) {
  emitJSON({
    tool: 'a2o',
    binary,
    ok: true,
    notes: [
      'offset is slice-relative, matching the section table; absoluteOffset is the position in the file',
      'zerofill means mapped in memory but absent from the file — there is no byte to read',
      ...(rows.some((r) => r.ambiguous) ? ['a universal binary maps one address in every slice; --arch picks one'] : []),
    ],
    data: {
      queries: rows,
      asked: rows.length,
      // `resolved` counts addresses that reached a byte; `answered` counts every
      // address the tool had something true to say about, zero-fill included.
      resolved: toByte,
      zerofill,
      unmapped,
      answered: toByte + zerofill,
      ambiguous: rows.filter((r) => r.ambiguous).length,
    },
  }, toByte + zerofill ? EXIT.ok : EXIT.empty);
}

// The API already reports addresses as hex strings, so these are echoed rather
// than converted — reformatting them here risks disagreeing with the envelope.
const hex = (v) => (v === null || v === undefined ? '-' : String(v));

console.log(`${binary}${arch ? `  [${arch}]` : ''}`);
for (const r of rows) {
  console.log(`\n  ${hex(r.query)}`);
  if (r.ambiguous) {
    console.log(`    ${r.note}`);
    for (const s of r.slices) {
      console.log(`      ${(s.arch || '-').padEnd(9)} offset ${hex(s.offset).padStart(12)}  ${s.section || '-'}`);
    }
    continue;
  }
  console.log(`    slice     ${r.arch || '-'}`);
  console.log(`    section   ${r.section || '-'}`);
  if (r.zerofill) {
    console.log(`    offset    none — ${r.note}`);
  } else {
    console.log(`    offset    ${hex(r.offset)}   (absolute ${hex(r.absoluteOffset)})`);
  }
  if (r.note && !r.zerofill) console.log(`    note      ${r.note}`);
}

process.exit(toByte + zerofill ? EXIT.ok : EXIT.empty);