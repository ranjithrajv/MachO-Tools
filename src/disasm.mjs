#!/usr/bin/env node
/**
 * disasm.mjs — decode instructions at an address in a Mach-O binary.
 *
 *   node src/disasm.mjs [<hex-addr>] [binary|bundle] [count] [--json]
 *   node src/disasm.mjs --branches [<hex-addr>] [binary|bundle] [count]
 *
 * ## What this adds that `findcall` cannot do on its own
 *
 * `findcall` finds the five bytes `e8 xx xx xx xx` and reports them as a call
 * site. It has no way to know those five bytes *begin* an instruction, because
 * the same five bytes appear inside longer instructions and in data. So its
 * output is a shortlist of places worth looking at, and it says so.
 *
 * This tool knows where instructions start and end. Given an address it reports
 * the instruction boundaries from there, and — with `--branches` — every direct
 * branch in the range as a resolved `{from, to}` edge. That is the thing that
 * turns a shortlist into edges.
 *
 * ## What it does not do
 *
 * No mnemonics, no operand decoding, no control flow graph, no decompilation.
 * Instructions are shown as bytes plus, where applicable, a branch target. A
 * tool that printed `BL` next to `fd 7b bf a9` and implied it knew what the
 * instruction did would be overclaiming; the boundary between "this is where
 * instruction boundaries fall" and "this is what the program does" is the line
 * `COMPETITIVE-LANDSCAPE.md` draws, and this stays on the near side of it.
 *
 * ## Reading the output honestly
 *
 * This is a linear sweep, not recursive descent. It decodes every byte of the
 * range in address order, which means alignment padding and any data
 * interleaved in the code section are decoded as instructions too. The summary
 * line reports how many bytes were covered and how many instructions that
 * produced, so a section with a poor instruction-per-byte ratio is visible
 * rather than something the reader has to guess at.
 *
 * The same caveat applies with more force to x86_64 than to ARM64: ARM64
 * instructions are all 4 bytes so boundaries cannot drift, while an x86_64
 * length-decoding mistake shifts every boundary after it. `src/disasm.mjs`
 * documents the known gaps in its opcode table.
 */
import { requireBinary } from './target.mjs';
import { disassemble, supportedArch } from './instruction.mjs';
import { parseArgs, emitJSON, usage, EXIT, rejectUnknownFlags } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/disasm.mjs [<hex-addr>] [binary|bundle] [count] [--json]',
  '       node src/disasm.mjs --branches [<hex-addr>] [binary|bundle] [count]',
  '',
  '  decode instructions from an address (or from the start of the first code',
  '  section) and report their lengths, and where they branch to.',
  '',
  'options:',
  '  --branches       report only branches, as resolved edges',
  '  --count=<n>      instructions to decode (default 32; 0 means no cap, which is only sensible with --bytes)',
  '  --bytes=<n>      decode a byte range instead of a count (whole section if omitted)',
  '  --arch=<name>    read one architecture (x86_64, arm64, arm64e)',
  '  -b, --binary <p> the binary to read',
  '  --json           one JSON object on stdout; prose to stderr',
  '  -h, --help       this message',
  '',
  '  arm64 and arm64e are decoded; x86_64 is decoded. Any other architecture is',
  '  reported as unknown-encoding and exits 3 rather than returning nothing.',
];

if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

rejectUnknownFlags(new Set(['branches', 'count', 'bytes', 'arch', 'json']), flags, HELP);

const json = flags.has('json');
const branchesOnly = flags.has('branches');
const arch = opts.arch;

/* ------------------------------------------------------------------ *
 * Positionals
 *
 * `[<hex-addr>] [binary|bundle] [count]` — the address is optional and is
 * recognised by its `0x` prefix, which is why it has to be probed for *before*
 * anything else is assigned. The alternative — address last — collides with
 * `findcall`'s `[addr] [binary]` ordering, and a tool in this package that took
 * its arguments in a different order from its siblings would be its own bug.
 *
 * With no address, a lone numeric positional is a count rather than a binary,
 * because a count is never a path. Anything else in that slot is the binary.
 * ------------------------------------------------------------------ */

let addr = null;
const rest = positional[0] && /^0x/i.test(positional[0]) ? positional.slice(1) : positional.slice(0);
if (positional[0] && /^0x/i.test(positional[0])) {
  try {
    addr = BigInt(positional[0]);
  } catch {
    usage([`not a hex address: ${positional[0]}`, ...HELP.slice(0, 2)]);
  }
}

/**
 * Instruction cap. 0 means "no cap", which is only reachable together with
 * `--bytes` — an uncapped sweep of a whole code section on a large binary is a
 * few million records, and offering it by accident would be a footgun wearing a
 * useful feature's clothes.
 */
function countFrom(positionalCount, optCount) {
  if (optCount !== undefined) {
    const n = Number(optCount);
    if (!Number.isInteger(n) || n < 0) usage([`--count takes a non-negative integer: ${optCount}`, ...HELP.slice(0, 2)]);
    return n;
  }
  if (positionalCount === undefined) return 32;
  const n = Number(positionalCount);
  if (!Number.isInteger(n) || n < 0) {
    usage([`count must be a non-negative integer: ${positionalCount}`, ...HELP.slice(0, 2)]);
  }
  return n;
}

let binaryArg;
let positionalCount;
if (rest.length === 1 && /^\d+$/.test(rest[0]) && !opts.b && !opts.binary) {
  positionalCount = rest[0];
} else {
  binaryArg = rest[0];
  positionalCount = rest[1];
}
const count = countFrom(positionalCount, opts.count);

let bytes = 0;
if (opts.bytes !== undefined) {
  bytes = Number(opts.bytes);
  if (!Number.isInteger(bytes) || bytes <= 0) usage([`--bytes takes a positive integer: ${opts.bytes}`, ...HELP.slice(0, 2)]);
}

if (arch !== undefined && !supportedArch(arch)) {
  // An architecture whose encoding is unknown here is not an empty result. This
  // is the same rule `findcall` applies to a matcher it has no encoding for, and
  // it is why the exit code is 3 rather than 1.
  if (json) {
    emitJSON({
      tool: 'disasm', binary: binaryArg ?? null, ok: false,
      errors: ['unknown-encoding'],
      messages: [`no instruction decoder for ${arch}; this tool decodes arm64 and x86_64`],
    }, EXIT.fail);
  }
  console.error(
    `\nerror: no instruction decoder for ${arch}. This tool decodes arm64 and x86_64.\n` +
    '  Reporting "nothing found" here would be a wrong answer, not an empty result.',
  );
  process.exit(EXIT.fail);
}

const binary = requireBinary({ argv: opts.b || opts.binary || binaryArg });
const notes = [];
let r;

try {
  r = disassemble(binary, { addr, arch, count, bytes });
} catch (e) {
  if (json) emitJSON({ tool: 'disasm', binary, ok: false, errors: [e.code ?? 'io'], messages: [e.message] }, EXIT.fail);
  console.error(`${binary}: ${e.message}`);
  process.exit(EXIT.fail);
}

notes.push(...r.notes);

if (r.unsupported.length) {
  const msg = `no instruction decoder for ${r.unsupported.join(', ')}`;
  if (json) {
    emitJSON({
      tool: 'disasm', binary, ok: false, errors: ['unknown-encoding'],
      messages: [msg], notes, data: { slices: r.slices },
    }, EXIT.fail);
  }
  console.error(
    `\nerror: ${msg}. This tool decodes arm64 and x86_64.\n` +
    '  Reporting "nothing found" here would be a wrong answer, not an empty result.',
  );
  process.exit(EXIT.fail);
}

if (r.slices.length === 0) {
  const why = addr === null
    ? 'this binary has no code sections in a decodable architecture'
    : `0x${addr.toString(16)} is not inside a code section of any decodable slice`;
  notes.push(why);
  if (json) {
    emitJSON({
      tool: 'disasm', binary, ok: false, errors: ['no-code-at-address'], notes,
      data: { addr: addr ?? null, count, slices: [] },
    }, EXIT.empty);
  }
  console.error(`\nno code to disassemble: ${why}`);
  if (addr !== null) {
    console.error('  find an address first:  node src/describe.mjs ' + JSON.stringify(binary));
  }
  process.exit(EXIT.empty);
}

/* ------------------------------------------------------------------ *
 * Reporting
 * ------------------------------------------------------------------ */

/** Bytes in address order, space separated — the order they appear in memory. */
const hexBytes = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join(' ');

const out = r.slices.map((s) => {
  const insns = branchesOnly ? s.instructions.filter((i) => i.target !== null) : s.instructions;
  const covered = insns.reduce((a, i) => a + i.length, 0);
  const span = s.sectionSize - Number(s.startAddr - s.sectionAddr);
  return {
    arch: s.arch,
    sliceOffset: s.offset,
    section: s.section,
    sectionAddr: s.sectionAddr,
    startAddr: s.startAddr,
    instructions: insns.map((i) => ({
      addr: i.addr,
      bytes: hexBytes(i.bytes),
      length: i.length,
      ...(i.kind ? { kind: i.kind, target: i.target } : {}),
    })),
    branches: s.branches,
    decoded: insns.length,
    bytesCovered: covered,
    bytesInRange: span,
  };
});

const totalInstructions = out.reduce((a, s) => a + s.decoded, 0);
const totalBranches = out.reduce((a, s) => a + s.branches.length, 0);

if (json) {
  emitJSON({
    tool: 'disasm',
    binary,
    ok: totalInstructions > 0,
    errors: totalInstructions ? [] : ['no-instructions'],
    notes,
    data: {
      addr: addr ?? null,
      count,
      ...(bytes ? { bytes } : {}),
      branchesOnly,
      slices: out,
      totals: { slices: out.length, instructions: totalInstructions, branches: totalBranches },
    },
  }, totalInstructions ? EXIT.ok : EXIT.empty);
}

const pad = (v) => v.toString(16).padStart(12, '0');
for (const s of out) {
  console.log(`\n  ${s.arch}  ${s.section}  from 0x${pad(s.startAddr)}  (${s.bytesInRange} bytes in range)`);
  if (branchesOnly) {
    for (const b of s.branches) {
      console.log(`    0x${pad(b.source)}  ${b.kind.padEnd(4)} -> 0x${pad(b.target)}`);
    }
    if (s.branches.length === 0) console.log('    no direct branches in range');
  } else {
    for (const i of s.instructions) {
      console.log(
        `    0x${pad(i.addr)}  ${String(i.length).padStart(2)}  ${i.bytes}` +
          (i.kind ? `  ${i.kind.padEnd(4)} -> 0x${pad(i.target)}` : ''),
      );
    }
  }
  // The coverage line is the honesty check: a sweep that decodes a section with
  // a poor instruction-per-byte ratio is decoding padding or data, and the
  // reader should be able to see that from the output rather than infer it.
  console.log(
    `    ${s.decoded} instruction(s) over ${s.bytesCovered}/${s.bytesInRange} bytes` +
      `, ${s.branches.length} direct branch(es)`,
  );
}

console.log(
  `\n${totalInstructions} instruction(s), ${totalBranches} direct branch(es) across ${out.length} slice(s)` +
    `${branchesOnly ? ', branches only' : ''}`,
);
for (const n of notes) console.log(`  note: ${n}`);
console.log(
  '  note: linear sweep, not recursive descent — padding and any data inside the\n' +
    '        section are decoded as instructions too. No mnemonics, no CFG.',
);

process.exit(totalInstructions ? EXIT.ok : EXIT.empty);