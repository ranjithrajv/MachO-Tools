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
import { requireBinary, FALLBACK_TARGET } from './target.mjs';
import { isCodeSection, archMatches } from './macho.mjs';
import { describe } from './api.mjs';
import { parseArgs, emitJSON, usage, count, EXIT, rejectUnknownFlags } from './output.mjs';

const { flags, opts, positional } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/describe.mjs [binary|bundle] [--json] [--arch=<name>]',
  '                          [--sections] [--segments] [--loads] [-b <binary>]',
  '',
  '  what is in this binary: every slice, its architecture, extent, symbol',
  '  counts and where __TEXT starts. Defaults to $MACHO_BINARY, then $MACHO_APP,',
  `  then ${FALLBACK_TARGET}`,
  '',
  'options:',
  '  --sections        list every section: segment, name, address, size, flags',
  '  --segments        list every segment: name, vm range, file range',
  '  --loads           list every load command by name and size',
  '  --arch=<name>     read one slice of a universal binary (x86_64, arm64, arm64e, arm64_32, ppc, ppc64, arm, i386)',
  '  --json            one JSON object on stdout; prose to stderr',
  '  -b, --binary <p>  the binary to read',
  '  -h, --help        this message',
];

// Handled before the unknown-flag check below, or `--help` would be reported as
// an unrecognised option — the one flag every tool must accept, rejected by the
// tool whose whole job is being the first thing you run.
if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

rejectUnknownFlags(new Set(['sections', 'segments', 'loads', 'arch', 'json']), flags, HELP);

const binary = requireBinary({ argv: opts.b || opts.binary || positional[0] });

let r;
try {
  r = describe(binary);
} catch (e) {
  if (flags.has('json')) {
    emitJSON({ tool: 'describe', binary, ok: false, errors: [e.code ?? 'io'], messages: [e.message] }, EXIT.fail);
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

// `--arch` narrows a universal binary to one slice. Applied here rather than
// inside `describe` so the fat header is still walked and the other slices are
// still *counted* — reporting "this is a universal binary, here is the arm64
// half" is a different and more useful answer than pretending it is thin.
const wantArch = opts.arch;
if (wantArch && r.slices.length > 1) {
  const all = r.slices.map((s) => s.arch).join(', ');
  // `archMatches`, not `===`. Naming arm64e as its own architecture made this
  // `===` a live bug: `--arch=arm64` against a binary whose arm64 slice is
  // arm64e reported "matched none of the slices" and then showed all of them,
  // which is worse than the old silent-wrong-slice answer because it looks like
  // it checked. `archMatches` is the same rule every other `--arch` path uses.
  const match = r.slices.find((s) => archMatches(s.arch, wantArch));
  if (!match) {
    notes.push(`--arch=${wantArch} matched none of the slices (${all}); showing all ${r.slices.length}`);
  } else {
    r = { ...r, slices: [match] };
    notes.push(`--arch=${wantArch}: showing 1 of ${all.length ? all.split(', ').length : r.slices.length} slices — drop the flag for all`);
  }
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
  // The UUID identifies a *build*, which is the one thing a describe tool is
  // uniquely placed to answer: two binaries with identical sizes and symbol
  // counts can still be different builds, and this is what tells them apart.
  // Printed on its own line because it is long and it is per-slice, and inline
  // it would push the `__text` address out of view on a narrow terminal.
  if (s.uuid) console.log(`           uuid ${s.uuid}`);
  if (s.note) console.log(`           note: ${s.note}`);
}

const hex = (v) => `0x${v.toString(16)}`;

// The three listings. Each prints only what was asked for, because the default
// view above is the "what is this file" answer and a wall of section names
// buries it — but the data was always parsed, so asking costs nothing now.
if (flags.has('segments')) {
  console.log('');
  for (const s of r.slices) {
    if (!s.readable || !s.segments.length) continue;
    console.log(`segments in ${s.arch}:`);
    for (const g of s.segments) {
      console.log(
        `  ${g.segname.padEnd(16)} vm ${hex(g.vmaddr)}..${hex(g.vmaddr + g.vmsize)}` +
          `  file ${g.fileoff}..${g.fileoff + g.filesize}`,
      );
    }
  }
}

if (flags.has('sections')) {
  console.log('');
  for (const s of r.slices) {
    if (!s.readable || !s.sections.length) continue;
    console.log(`sections in ${s.arch}:`);
    for (const sec of s.sections) {
      // The instruction flag is called out because it is the one attribute that
      // changes what a byte scan means — the same signal `findcall` types its
      // scan by, shown here so the two can be checked against each other.
      // `isCodeSection` is imported rather than re-tested inline, because a
      // second copy of that predicate is a second thing to keep correct, and
      // this project has already shipped a bug from exactly that.
      const kind = isCodeSection(sec) ? 'code' : 'data';
      console.log(
        `  ${(sec.segname + ',' + sec.sectname).padEnd(34)} ${hex(sec.addr)}..${hex(sec.addr + BigInt(sec.size))}` +
          `  ${count(sec.size).padStart(12)}  file ${String(sec.offset).padStart(9)}  ${kind}`,
      );
    }
  }
}

if (flags.has('loads')) {
  console.log('');
  for (const s of r.slices) {
    if (!s.readable || !s.loadCommands.length) continue;
    console.log(`load commands in ${s.arch}: ${s.loadCommands.length}`);
    for (const c of s.loadCommands) {
      console.log(`  ${c.name.padEnd(26)} ${String(c.cmdsize).padStart(7)} bytes  at ${hex(BigInt(c.offset))}`);
    }
  }
}

console.log('');
for (const n of notes) console.log(`  note: ${n}`);
