#!/usr/bin/env node
/**
 * describe.mjs — what is in this binary?
 *
 *   node src/describe.mjs [binary|bundle] [--json]
 *
 * Every slice, with its architecture, file extent, whether it is thin or part of
 * a fat file, symbol counts, where its `__TEXT` starts, and how many sections
 * are flagged as instructions.
 *
 * ## Why this tool exists
 *
 * It is the first thing to run on a binary you know nothing about, and it is the
 * answer to the question every one of the other five tools defers: which slice
 * will they actually read, and is there a symbol table to read?
 *
 * Before this existed, that information was scattered. `symgrep` printed its
 * choice in a trailing summary line, `findcall` printed one line per slice it
 * scanned, `mapliteral` printed its own, and `symfind` printed nothing at all.
 * Four tools, four formats, none of them machine-readable — so a script that
 * wanted to know what it had in front of it had to parse English from whichever
 * tool happened to mention it, or open the file itself and parse the fat header,
 * which is the very thing `macho.mjs` exists so nobody has to do twice.
 *
 * It is also the cheapest way to see the `__TEXT`-is-not-all-code point: the
 * `code sections` column is usually much smaller than the file, and the gap is
 * the data that an untyped scan used to report as call sites.
 */
import { requireBinary } from './target.mjs';
import { describe } from './api.mjs';
import { parseArgs, emitJSON, usage, count, EXIT } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));
if (flags.size && !flags.has('json')) {
  usage(['usage: node src/describe.mjs [binary|bundle] [--json] [-b <binary>]']);
}

const binary = requireBinary({ argv: opts.b || opts.binary || positional[0] });

let r;
try {
  r = describe(binary);
} catch (e) {
  if (flags.has('json')) {
    emitJSON({ tool: 'describe', binary, ok: false, errors: ['io'], messages: [e.message] }, EXIT.fail);
  }
  console.error(`${binary}: ${e.message}`);
  process.exit(EXIT.fail);
}

const notes = [];
if (r.slices.some((s) => s.note)) {
  notes.push('a slice with a note carries no symbol table — nothing can grep it');
}
const stripped = r.slices.filter((s) => s.readable && s.defined === 0);
if (stripped.length && r.slices.length > 1) {
  notes.push(`${stripped.map((s) => s.arch).join(', ')}: stripped, or a dyld-cache stub — findcall and findliteral still work, since they read bytes rather than names`);
}

if (flags.has('json')) {
  emitJSON({ tool: 'describe', binary, ok: true, notes, data: r });
}

console.log(`${binary} — ${(r.size / 1048576).toFixed(1)} MB, ${r.fat ? 'universal' : 'thin'}, ${r.slices.length} slice(s)\n`);
for (const s of r.slices) {
  const text = s.textAddr !== null ? ` __text 0x${s.textAddr.toString(16)}+${count(s.textSize)}` : '';
  console.log(
    `  ${s.arch.padEnd(8)} file ${s.offset}..${s.offset + s.size}` +
      `  ${s.bits || '?'}-bit` +
      `  ${count(s.defined)} defined / ${count(s.nsyms)} symbols` +
      `  ${s.codeSections} code section(s)${text}`,
  );
  if (s.note) console.log(`           note: ${s.note}`);
}
console.log('');
for (const n of notes) console.log(`  note: ${n}`);
