#!/usr/bin/env node
/**
 * mapliteral.mjs — map a literal to its addresses, and find what points at them.
 *
 *   node src/mapliteral.mjs <literal> [binary|bundle] [file-offset ...] [--json]
 *
 * Steps:
 *   1. parse the fat header and choose a slice
 *   2. locate the literal (or use the offsets given)
 *   3. map each hit to a virtual address and say which section it is in
 *   4. search the whole file for pointers to those addresses, which reveals the
 *      descriptor or vtable tables hanging off them
 *
 * Step 4 is the point of the tool. A format magic in read-only data is a label;
 * the *pointers* to it are the handler. Finding the pointer tables is how you
 * learn which code compares against the magic, and from there where the decoder
 * lives.
 *
 * The literal is an argument, not a constant, and the offsets are optional. An
 * earlier version took its two input offsets as hardcoded values recorded by hand
 * from one binary, which made it a script about that binary wearing a generic
 * name. Everything here except the needle is application independent.
 *
 * ## The bug this no longer has
 *
 * This tool used to reimplement the fat-header walk *and* hardcode
 * `if (cputype === 0x01000007) slice = ...`, then `throw new Error('x86_64 slice
 * not found')` when no x86_64 slice existed. On an arm64-only binary — which is
 * every Apple-silicon-native build — it did not degrade, it died, with a message
 * that said the file was wrong rather than that the tool was. That is the same
 * "absent architecture is fatal" defect the rest of the project fixed, and it
 * survived here for exactly one reason: this file had its own copy of the reader
 * instead of sharing one. It shares one now, so there is no second copy to be
 * wrong in a different way.
 */
import { requireBinary } from './target.mjs';
import { mapLiteral } from './api.mjs';
import { parseArgs, emitJSON, usage, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));
const literal = positional[0];

if (!literal) {
  usage([
    'usage: node src/mapliteral.mjs <literal> [binary|bundle] [file-offset ...] [--json] [-b <binary>]',
    '',
    '  maps each occurrence of <literal> to a vaddr, then finds pointers to it.',
    '  file offsets are absolute, as reported by findliteral.mjs.',
  ]);
}

const binary = requireBinary({ argv: opts.b || opts.binary || positional[1] });
// Positional offsets only when the binary came positionally too; with -b the
// first position after the literal is the first offset.
const offsets = positional.slice(opts.b || opts.binary ? 1 : 2).map((a) => {
  const n = /^0x/i.test(a) ? parseInt(a, 16) : parseInt(a, 10);
  if (!Number.isFinite(n)) usage([`not a file offset: ${a}`]);
  return n;
});

let r;
try {
  r = mapLiteral(binary, literal, { offsets: offsets.length ? offsets : null });
} catch (e) {
  if (flags.has('json')) {
    emitJSON({ tool: 'mapliteral', binary, ok: false, errors: ['io'], messages: [e.message] }, EXIT.fail);
  }
  console.error(`${binary}: ${e.message}`);
  process.exit(EXIT.fail);
}

const notes = [];
if (r.locations.length === 0) {
  notes.push(`no ${JSON.stringify(literal)} literal in __TEXT — pass file offsets explicitly if the magic is assembled at runtime rather than stored`);
}
if (r.locations.every((l) => l.pointerCount === 0)) {
  notes.push('no pointers to any of these addresses — this magic has no descriptor table pointing at it, so nothing dispatches on it by reference');
}

if (flags.has('json')) {
  emitJSON({
    tool: 'mapliteral', binary, ok: r.locations.length > 0,
    errors: r.locations.length ? [] : ['no-match'], notes, data: r,
  }, r.locations.length ? EXIT.ok : EXIT.empty);
}

console.log(
  `slice ${r.arch} at file offset 0x${r.sliceOffset.toString(16)}` +
    (r.explicit ? ' (offsets given explicitly)' : `, ${r.locations.length} literal location(s) found in __TEXT`),
);

for (const m of r.locations) {
  console.log(
    `\n  file 0x${m.off.toString(16).padStart(8, '0')} -> vaddr 0x${m.vaddr.toString(16).padStart(12, '0')}  in ${m.section}`,
  );
  console.log(`      ...${m.context.pre}|${m.context.hit}...`);
  console.log(`      ${m.pointerCount} pointer(s) to it:`);
  for (const p of m.pointers) {
    console.log(
      `        file 0x${p.off.toString(16).padStart(8, '0')}` +
        (p.vaddr !== null ? ` -> vaddr 0x${p.vaddr.toString(16).padStart(12, '0')}` : '') +
        `  ${p.section || '-'}`,
    );
  }
  if (m.pointersTruncated) console.log(`        ... and more, capped at ${m.pointers.length}`);
}
for (const u of r.unmapped) console.log(`  file 0x${u.off.toString(16)} -> UNMAPPED`);
for (const n of notes) console.log(`\n  note: ${n}`);
