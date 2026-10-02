#!/usr/bin/env node
/**
 * fixtures.mjs — build the test corpus, as Mach-O binaries written from scratch.
 *
 *   node test/fixtures.mjs            # write test/fixtures/*.macho
 *   node test/fixtures.mjs --check    # verify they match, write nothing
 *
 * ## Why the corpus is *built* rather than *collected*
 *
 * `smoke.mjs` originally ran against whatever binaries happened to be installed
 * on the machine: `/usr/bin/true`, `/usr/bin/ssh`, a Go toolchain, ffmpeg. That
 * has three problems, and they are all the same problem wearing different hats.
 *
 *   1. **The suite only exists where those binaries exist.** On a bare CI runner
 *      `discover()` returns nothing, the suite exits 2, and the honest answer —
 *      "I checked nothing" — is indistinguishable from a failure to run. Every
 *      result became machine-dependent, including the mutation check, which
 *      copies the tree and re-runs the suite inside the copy: on a machine
 *      without ffmpeg, the mutated tree "passed" because the mutation was never
 *      exercised, and reported that as a pass.
 *   2. **Nothing pins what is actually being tested.** The suite asserts that a
 *      "stub" and a "populated" binary were both covered, but which files those
 *      are is decided by `/usr/bin`. A binary that stops being stripped after an
 *      OS update quietly changes what the coverage assertions mean.
 *   3. **The interesting shapes are hard to find on a real machine.** The
 *      defects this project guards against need specific inputs: a fat binary
 *      whose slices sit at awkward offsets, an arm64-only binary, a slice with
 *      imported-but-addressless symbols, code and data in the *same* segment so
 *      a byte scan cannot tell them apart. Finding four real binaries with
 *      those properties is luck; building them is a page of arithmetic.
 *
 * So the corpus is generated, from code, in this file. That buys:
 *
 *   - **Portability.** The suite needs nothing but Node. It runs on a bare Linux
 *     container, on Windows, on a fresh checkout.
 *   - **Reviewability.** These are readable instructions, not opaque blobs. A
 *     reviewer can see that the x86_64 fixture contains exactly three direct
 *     calls and check the suite's claim against it.
 *   - **Sharpness.** Every fixture is minimal *on purpose*, so a failure points
 *     at one thing. A real Go toolchain fails somewhere and you go looking.
 *
 * ## What is deliberately *not* here
 *
 * Fixtures are a compiler's job. Assembling them by hand means writing correct
 * `rel32` and `BL` displacements and correct symbol tables, and a fixture whose
 * own encoding is wrong will produce a suite that passes for the wrong reason.
 * So this file encodes only what it can encode *exactly* and verify: headers,
 * fat tables, load commands, section layouts, symbol tables, and the few
 * instructions whose bytes are simple enough to write down and check by
 * reading. Every fixture is validated below before it is written — see
 * `verify()`, which re-reads each file with the project's own reader and
 * asserts the properties the suite depends on. A fixture that does not hold up
 * fails at build time rather than quietly weakening the suite.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const OUT = path.join(HERE, 'fixtures');

/* ------------------------------------------------------------------ *
 * Mach-O constants, spelled out rather than imported
 * ------------------------------------------------------------------ */

/*
 * Written out here on purpose. Importing them from `src/macho.mjs` would mean
 * the fixture builder and the thing under test shared their constants — so a
 * typo in a constant would be invisible, and the fixture would encode the bug
 * rather than catch it. The builder must be an independent witness.
 */
const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const CPU_X86_64 = 0x01000007;
const CPU_ARM64 = 0x0100000c;

const N_TYPE = 0x0e;
const N_SECT = 0x0e;      // defined
const N_EXT = 0x01;       // external

const S_REGULAR = 0x0;
const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
const S_ATTR_SOME_INSTRUCTIONS = 0x00000400;

const VMADDR_BASE = 0x100000000n;

/**
 * Size of the header plus the two load commands — i.e. where section data starts.
 *
 * Spelled out rather than derived, because the vaddr/file-offset relationship is
 * the thing under test: a section's `addr` is `vmaddr + offset`, and with
 * `__TEXT` at vmaddr 0x100000000 and fileoff 0, a section's address is
 * `VMADDR_BASE + its file offset`. Getting that wrong makes every encoded
 * displacement in the fixture point somewhere meaningless, and the fixture then
 * fails for a reason that has nothing to do with the tools.
 */
const HEADER_PLUS_LOADCMDS = 32 + (72 + 80 * 2) + 24;

/** The vaddr of the `__text` section, given its file offset. */
const textVaddr = (textOffset) => VMADDR_BASE + BigInt(textOffset);

/* ------------------------------------------------------------------ *
 * builders
 * ------------------------------------------------------------------ */

/**
 * Assemble a thin 64-bit Mach-O.
 *
 * The layout is the smallest one that is still a real Mach-O: one `__TEXT`
 * segment holding a code section and a data section, plus an `LC_SYMTAB`.
 * Real linkers emit more load commands; nothing in this reader needs them, and
 * every one omitted is a thing a fixture cannot get wrong.
 */
function thinMachO({ cputype, text, data, dataFlags = S_REGULAR, symbols, textFlags = S_ATTR_PURE_INSTRUCTIONS | 0x4 }) {
  const segname = '__TEXT';
  const ncmds = 2;
  const headerSize = 32;
  const segCmdSize = 72 + 80 * 2;              // LC_SEGMENT_64 + two section_64
  const symtabCmdSize = 24;
  const loadCommandsSize = segCmdSize + symtabCmdSize;

  // Section and symbol data start right after the load commands.
  const textOffset = headerSize + loadCommandsSize;
  const dataOffset = textOffset + text.length;

  // A string table: index 0 is a NUL, then each name NUL-terminated. Offsets are
  // accumulated as they go so a symbol's `n_strx` is computed the same way
  // `strtab` actually lays the bytes out, rather than assumed.
  const strOffsets = new Map();
  let strLen = 1; // the leading NUL
  for (const s of symbols) {
    strOffsets.set(s.name, strLen);
    strLen += Buffer.byteLength(s.name, 'latin1') + 1;
  }
  const strTable = Buffer.alloc(strLen, 0);
  for (const s of symbols) {
    Buffer.from(s.name, 'latin1').copy(strTable, strOffsets.get(s.name));
  }

  const symtabOffset = dataOffset + data.length;
  const nlist = Buffer.alloc(symbols.length * 16);
  symbols.forEach((s, i) => {
    const at = i * 16;
    nlist.writeUInt32LE(strOffsets.get(s.name), at);
    nlist[at + 4] = s.type;
    nlist[at + 5] = s.sect;                 // n_sect
    nlist.writeUInt16LE(0, at + 6);         // n_desc
    nlist.writeBigUInt64LE(s.value, at + 8);
  });
  const strOffset = symtabOffset + nlist.length;
  const totalSize = strOffset + strTable.length;

  const buf = Buffer.alloc(totalSize, 0);

  // ---- mach_header_64
  buf.writeUInt32LE(MH_MAGIC_64, 0);
  buf.writeInt32LE(cputype, 4);
  buf.writeInt32LE(3, 8);                   // cpusubtype
  buf.writeUInt32LE(2, 12);                 // filetype: MH_EXECUTE
  buf.writeUInt32LE(ncmds, 16);
  buf.writeUInt32LE(loadCommandsSize, 20);
  buf.writeUInt32LE(S_ATTR_PURE_INSTRUCTIONS, 24); // flags

  // ---- LC_SEGMENT_64
  let o = headerSize;
  const seg = o;
  buf.writeUInt32LE(LC_SEGMENT_64, o);
  buf.writeUInt32LE(segCmdSize, o + 4);
  buf.write(segname, o + 8, 'latin1');
  buf.writeBigUInt64LE(VMADDR_BASE, o + 24);      // vmaddr
  buf.writeBigUInt64LE(BigInt(totalSize), o + 32);// vmsize
  buf.writeBigUInt64LE(BigInt(0), o + 40);        // fileoff
  buf.writeBigUInt64LE(BigInt(totalSize), o + 48);// filesize
  buf.writeUInt32LE(5, o + 56);                   // maxprot
  buf.writeUInt32LE(5, o + 60);                   // initprot
  buf.writeUInt32LE(2, o + 64);                   // nsects
  buf.writeUInt32LE(0, o + 68);                   // flags

  // ---- section_64: __text (instructions)
  let s = seg + 72;
  buf.write('__text', s, 'latin1');
  buf.write(segname, s + 16, 'latin1');
  // addr = segment vmaddr + section file offset, *not* the segment's own vmaddr.
  buf.writeBigUInt64LE(textVaddr(textOffset), s + 32);
  buf.writeBigUInt64LE(BigInt(text.length), s + 40);  // size
  buf.writeUInt32LE(textOffset, s + 48);
  buf.writeUInt32LE(2, s + 52);                       // align
  // `>>> 0` for the same reason as `arm64BL`: `S_ATTR_PURE_INSTRUCTIONS` is
  // 0x80000000, so any `|` against it yields a *signed* int32 and the write
  // throws on a negative. This file has now reproduced that mistake twice while
  // writing the fixtures, which is a decent argument for how easy it is to make.
  buf.writeUInt32LE((textFlags >>> 0), s + 64);

  // ---- section_64: __data (data, deliberately inside __TEXT)
  s = seg + 72 + 80;
  buf.write('__data', s, 'latin1');
  buf.write(segname, s + 16, 'latin1');
  buf.writeBigUInt64LE(VMADDR_BASE + BigInt(dataOffset), s + 32);
  buf.writeBigUInt64LE(BigInt(data.length), s + 40);
  buf.writeUInt32LE(dataOffset, s + 48);
  buf.writeUInt32LE(2, s + 52);
  buf.writeUInt32LE(dataFlags, s + 64);

  // ---- LC_SYMTAB
  o = headerSize + segCmdSize;
  buf.writeUInt32LE(LC_SYMTAB, o);
  buf.writeUInt32LE(symtabCmdSize, o + 4);
  buf.writeUInt32LE(symtabOffset, o + 8);
  buf.writeUInt32LE(symbols.length, o + 12);
  buf.writeUInt32LE(strOffset, o + 16);
  buf.writeUInt32LE(strTable.length, o + 20);

  text.copy(buf, textOffset);
  data.copy(buf, dataOffset);
  nlist.copy(buf, symtabOffset);
  strTable.copy(buf, strOffset);
  return buf;
}

/** Wrap thin slices into a fat/universal container. */
function fat(slices) {
  const headerSize = 8 + slices.length * 20;
  // align each slice to 2^14, as dyld expects
  const align = 16384;
  const placed = [];
  let cursor = headerSize;
  for (const s of slices) {
    const pad = (align - (cursor % align)) % align;
    cursor += pad;
    placed.push({ ...s, offset: cursor });
    cursor += s.thin.length;
  }
  const buf = Buffer.alloc(cursor, 0);
  buf.writeUInt32BE(FAT_MAGIC, 0);
  buf.writeUInt32BE(slices.length, 4);
  slices.forEach((s, i) => {
    const o = 8 + i * 20;
    buf.writeInt32BE(s.cputype, o);
    buf.writeUInt32BE(3, o + 4);
    buf.writeUInt32BE(placed[i].offset, o + 8);
    buf.writeUInt32BE(s.thin.length, o + 12);
    buf.writeUInt32BE(14, o + 16);
  });
  for (const p of placed) p.thin.copy(buf, p.offset);
  return buf;
}

/* ---- instruction encoders ---------------------------------------- */

/** x86_64 `call rel32` to `dest` placed at vaddr `site`. */
function x86Call(site, dest) {
  const b = Buffer.alloc(5);
  b[0] = 0xe8;
  b.writeInt32LE(Number(BigInt(dest) - BigInt(site) - 5n), 1);
  return b;
}

/** x86_64 `jmp rel32` to `dest` placed at vaddr `site`. */
function x86Jmp(site, dest) {
  const b = Buffer.alloc(5);
  b[0] = 0xe9;
  b.writeInt32LE(Number(BigInt(dest) - BigInt(site) - 5n), 1);
  return b;
}

/** arm64 `BL` to `dest` placed at vaddr `site`. */
function arm64BL(site, dest) {
  const b = Buffer.alloc(4);
  const off = Number((BigInt(dest) - BigInt(site)) >> 2n);
  // `>>> 0`, and it is load-bearing here exactly as it is in the reader: `&`
  // yields a *signed* int32, so a negative displacement (a backward call, which
  // is the common direction in a loop) comes back negative and
  // `writeUInt32LE` throws. The first run of this file did.
  const imm = (off & 0x03ffffff) >>> 0;
  b.writeUInt32LE(((0x94000000 | imm) >>> 0), 0);
  return b;
}

/** arm64 `ret`. Aligns code so `BL`s sit on 4-byte boundaries, as real code. */
function arm64Ret() {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(0xd65f03c0, 0);
  return b;
}

/* ------------------------------------------------------------------ *
 * the fixtures
 * ------------------------------------------------------------------ */

/**
 * Three functions per architecture: `caller_a`, `caller_b`, `target_fn`.
 * Both callers call the target, and one jumps to it, so the encoded counts are
 * exactly checkable by reading the source above rather than by running the tool
 * and believing it.
 */
function codeFixture(cputype) {
  const ARM = cputype === CPU_ARM64;
  const TEXT = textVaddr(HEADER_PLUS_LOADCMDS);
  const CALLER_A = TEXT + 0x40n;
  const CALLER_B = TEXT + 0x80n;
  const TARGET = TEXT + 0x100n;

  // Instructions are laid out at explicit vaddrs; padding fills the gaps so the
  // text section is a realistic size with the interesting bytes at known places.
  const text = Buffer.alloc(0x140, ARM ? 0xd503201f : 0x90); // nop / padding
  const put = (vaddr, bytes) => bytes.copy(text, Number(vaddr - TEXT));

  if (ARM) {
    put(CALLER_A, arm64BL(CALLER_A, TARGET));
    put(CALLER_A + 4n, arm64Ret());
    put(CALLER_B, arm64BL(CALLER_B, TARGET));
    put(CALLER_B + 4n, arm64Ret());
    put(TARGET, arm64Ret());
  } else {
    put(CALLER_A, x86Call(CALLER_A, TARGET));
    put(CALLER_A + 5n, Buffer.from([0xc3]));              // ret
    put(CALLER_B, x86Jmp(CALLER_B, TARGET));
    put(TARGET, Buffer.from([0xc3]));
  }

  // The search literal lives in `__text`, because `mapliteral` deliberately
  // searches `__TEXT` only — a literal planted in `__DATA` would be invisible to
  // the tool it exists to test, and the assertion would fail for a reason that
  // has nothing to do with the pointer search.
  const LITERAL_AT = 0x120;
  Buffer.from('FIXTURELITERAL', 'latin1').copy(text, LITERAL_AT);

  // A pointer *to the literal*, standing in for the descriptor table a real
  // format's magic hangs off. This is the thing `mapliteral` exists to find, so
  // it is planted rather than hoped for: the fixture should know the answer.
  const data = Buffer.alloc(0x20);
  data.writeBigUInt64LE(TEXT + BigInt(LITERAL_AT), 0);

  return {
    text,
    data,
    symbols: [
      { name: '__mh_execute_header', type: N_SECT | N_EXT, sect: 1, value: TEXT },
      { name: 'caller_a', type: N_SECT | N_EXT, sect: 1, value: CALLER_A },
      { name: 'caller_b', type: N_SECT | N_EXT, sect: 1, value: CALLER_B },
      { name: 'target_fn', type: N_SECT | N_EXT, sect: 1, value: TARGET },
      // An *imported* symbol: undefined, so n_value is 0 and it must never be
      // reported as containing any address. This is the shape the import bug
      // needs, and the reason a real stub binary has to be in the corpus.
      { name: '_malloc', type: N_EXT, sect: 0, value: 0n },
      { name: '_free', type: N_EXT, sect: 0, value: 0n },
    ],
    addresses: { text: TEXT, callerA: CALLER_A, callerB: CALLER_B, target: TARGET },
  };
}

/**
 * The fixture that makes the typed scan testable.
 *
 * `__text` holds one real `call` to `target_fn`. `__data` holds the *same five
 * bytes*, at a vaddr where the linker would never put a call — and with a data
 * section's attributes, so the reader can tell. A byte scan that does not look
 * at section attributes reports both, and its output is indistinguishable from
 * a caller list. A typed scan reports one.
 *
 * This is the only fixture in the corpus where a *count* is the assertion, and
 * it is a count anyone can read off the source above.
 */
function decoyFixture() {
  const TEXT = textVaddr(HEADER_PLUS_LOADCMDS);
  const SITE = TEXT + 0x40n;
  const TARGET = TEXT + 0x100n;
  const text = Buffer.alloc(0x140, 0x90);
  x86Call(SITE, TARGET).copy(text, Number(SITE - TEXT));

  // The planted decoy: five bytes in a *data* section that decode as a call to
  // the same target. Its displacement is computed from where it actually sits,
  // not copied from the code site — a decoy pointing elsewhere would never have
  // been found by an untyped scan either, and the test would pass for the wrong
  // reason. `__data` follows `__text` in the file, so its vaddr is one text
  // length further along.
  const DATA_VADDR = TEXT + BigInt(0x140);
  const data = Buffer.alloc(0x40, 0xcc);
  x86Call(DATA_VADDR + 0x10n, TARGET).copy(data, 0x10);

  return {
    text,
    data,
    // `S_ATTR_PURE_INSTRUCTIONS` is *off* on __text here and `S_ATTR_SOME_INSTRUCTIONS`
    // is on, which is a real and common linker output for code that is not
    // provably pure — so the reader must accept either bit.
    textFlags: S_ATTR_SOME_INSTRUCTIONS,
    symbols: [
      { name: 'caller_a', type: N_SECT | N_EXT, sect: 1, value: SITE },
      { name: 'target_fn', type: N_SECT | N_EXT, sect: 1, value: TARGET },
    ],
    addresses: { text: TEXT, callerA: SITE, target: TARGET },
  };
}

/** An arm64-only Mach-O: no x86_64 slice exists to fall back to. */
function arm64Only() {
  const c = codeFixture(CPU_ARM64);
  return thinMachO({ cputype: CPU_ARM64, ...c });
}

/** A fat binary whose slices sit at deliberately awkward offsets. */
function universal() {
  return fat([
    { cputype: CPU_X86_64, thin: thinMachO({ cputype: CPU_X86_64, ...codeFixture(CPU_X86_64) }) },
    { cputype: CPU_ARM64, thin: thinMachO({ cputype: CPU_ARM64, ...codeFixture(CPU_ARM64) }) },
  ]);
}

/**
 * A binary with no symbol table at all — the stripped case.
 *
 * `findcall` and `findliteral` read bytes and must still work on it; `sym`
 * must say so rather than report zero matches as though that were a finding.
 */
function stripped() {
  const c = codeFixture(CPU_X86_64);
  return thinMachO({ cputype: CPU_X86_64, text: c.text, data: c.data, symbols: [] });
}

/**
 * How many bulk symbols the populated fixture carries.
 *
 * Coupled to `POPULATED_FLOOR` in `smoke.mjs`, which is what decides whether the
 * suite calls a binary "populated": 50 defined symbols. Sixty clears it by a
 * margin rather than sitting on the line, so a later tweak to either number
 * cannot silently flip this fixture into the stub bucket — which is exactly what
 * happened before it existed. The floor is repeated, not imported, for the same
 * reason the Mach-O constants above are written out: the builder must be an
 * independent witness, and importing it would run the suite.
 */
const POPULATED_FILLERS = 60;

/**
 * The *populated* shape: a binary with a real symbol table.
 *
 * The suite draws a line at 50 defined symbols and asserts that both sides of it
 * were tested, because the two shapes fail differently: the import bug only shows
 * on a symbol-less stub, while a binary with 19,000 symbols hides it completely.
 * That assertion used to be a fact about the machine rather than about the corpus.
 * Every other fixture here has between 0 and 4 defined symbols, so on a CI runner
 * — where the candidate binaries are absent or are shared-cache stubs carrying one
 * symbol each — the populated side was missing and the coverage receipt failed on
 * ubuntu, macos and windows alike.
 *
 * So the shape is built rather than hoped for. The code is `codeFixture`'s,
 * unchanged: the same three functions, the same two call sites, the same planted
 * literal. Only the symbol table is bulked out, with names and addresses a
 * reviewer can compute from the loop below. The two imports come along for free
 * from the shared symbol list, which is what makes this fixture the strongest
 * test of them: a low address must still resolve to no function at all when the
 * table around it holds sixty-four entries.
 */
function populatedFixture() {
  const c = codeFixture(CPU_X86_64);
  const TEXT_SIZE = c.text.length;

  // The four offsets `codeFixture` already claims: the two callers, the target,
  // and the search literal. Skipped rather than overwritten, so no filler address
  // can alias a planted call site or the literal — an alias would make
  // "exactly two call sites" and "exactly one name contains this address" both
  // wrong for reasons that have nothing to do with the tools.
  const CLAIMED = new Set([0x40, 0x80, 0x100, 0x120]);

  const fillers = [];
  for (let off = 0x08; off < TEXT_SIZE && fillers.length < POPULATED_FILLERS; off += 4) {
    if (CLAIMED.has(off)) continue;
    fillers.push(c.addresses.text + BigInt(off));
  }

  return {
    text: c.text,
    data: c.data,
    symbols: [
      ...c.symbols,
      ...fillers.map((value, i) => ({
        name: `_pop_${String(i).padStart(2, '0')}`,
        type: N_SECT | N_EXT,
        sect: 1,
        value,
      })),
    ],
    addresses: { ...c.addresses, fillers },
  };
}

/* ------------------------------------------------------------------ *
 * verification
 * ------------------------------------------------------------------ */

/**
 * Re-read every fixture with the project's own reader and assert the properties
 * the suite relies on.
 *
 * This runs at build time, before anything is written. A fixture that does not
 * hold up is a broken instrument: it would make the suite pass for the wrong
 * reason, or fail for a reason that has nothing to do with the tools. Catching
 * it here means a green suite means what it says.
 */
async function verify(files) {
  const { describe, findCalls, listCallTargets, findLiteral, mapLiteral, lookupAddress } =
    await import('../src/api.mjs');

  const problems = [];
  const expect = (ok, what) => { if (!ok) problems.push(what); };

  for (const [name, p] of Object.entries(files)) {
    const d = describe(p);
    expect(d.slices.every((s) => s.readable), `${name}: every slice parses`);
    if (d.slices.every((s) => s.readable)) {
      for (const s of d.slices) {
        expect(s.codeSections >= 1, `${name}/${s.arch}: at least one code section`);
        expect(s.textSize > 0, `${name}/${s.arch}: __text is non-empty`);
      }
    }
    expect(isMachO(p), `${name}: magic bytes are a Mach-O`);
  }

  // The universal fixture must really be universal, with both architectures.
  const u = describe(files.universal);
  expect(u.fat, 'universal: is a fat file');
  expect(u.slices.length === 2, 'universal: has two slices');
  expect(
    u.slices.map((s) => s.arch).sort().join(',') === 'arm64,x86_64',
    'universal: has both arm64 and x86_64',
  );
  // The point of the fat fixture is that slice offsets are *read*, not assumed.
  // 0x4000 is the offset the original tools hardcoded — one binary's first-slice
  // offset. Asserting the second slice is nowhere near it is what distinguishes
  // "parses the header" from "assumed 0x4000 and got lucky".
  expect(
    u.slices[1].offset > 0x4000 && u.slices[0].offset !== u.slices[1].offset,
    `universal: the second slice is not at the hardcoded 0x4000 (it is at 0x${u.slices[1].offset.toString(16)})`,
  );
  expect(
    u.slices[0].size > 0 && u.slices[1].size > 0 &&
      u.slices[0].offset + u.slices[0].size <= u.slices[1].offset,
    'universal: slices do not overlap',
  );

  // arm64-only: the "absent architecture is a preference" regression.
  const a = describe(files.arm64only);
  expect(!a.fat && a.slices.length === 1, 'arm64only: is thin');
  expect(a.slices[0].arch === 'arm64', 'arm64only: is arm64');
  const targetA = codeFixture(CPU_ARM64).addresses.target;
  expect(
    findCalls(files.arm64only, targetA).count === 2,
    'arm64only: finds exactly the two encoded BL sites',
  );
  expect(
    lookupAddress(files.arm64only, targetA).function === 'target_fn',
    'arm64only: resolves the target to a real symbol',
  );

  // The universal fixture: one `call` + one `jmp` per slice.
  const targetU = codeFixture(CPU_X86_64).addresses.target;
  const callsU = findCalls(files.universal, targetU);
  expect(
    callsU.count === 4,
    `universal: finds exactly four call/jmp sites (one call + one jmp per slice), got ${callsU.count}`,
  );
  expect(
    callsU.hits.filter((h) => h.arch === 'x86_64').length === 2,
    'universal: x86_64 contributes two sites',
  );
  expect(
    callsU.hits.filter((h) => h.arch === 'arm64').length === 2,
    'universal: arm64 contributes two sites',
  );
  expect(
    lookupAddress(files.universal, 0x10).function === null,
    'universal: a low address is not attributed to an import at 0x0',
  );
  expect(
    lookupAddress(files.universal, targetU).function === 'target_fn',
    'universal: the target resolves to its own symbol',
  );

  // The decoy fixture: this is the typed-scan assertion.
  const targetD = decoyFixture().addresses.target;
  const typed = findCalls(files.decoy, targetD);
  const untyped = findCalls(files.decoy, targetD, { includeData: true });
  expect(
    typed.count === 1 && typed.typed,
    `decoy: typed scan finds only the code site (got ${typed.count})`,
  );
  expect(
    typed.hits[0]?.section === '__TEXT,__text',
    'decoy: the typed hit is attributed to __text',
  );
  expect(
    untyped.count === 2,
    `decoy: the untyped scan finds the planted data bytes too (got ${untyped.count})`,
  );
  expect(
    untyped.hits.some((h) => h.section === '__TEXT,__data'),
    'decoy: the extra hit is attributed to __data',
  );

  // listCallTargets must be non-empty on the populated fixtures: a scanner that
  // finds nothing and a scanner that is broken look identical from outside.
  expect(
    listCallTargets(files.universal).total > 0,
    'universal: --list finds at least one destination',
  );

  // Literals.
  const lit = findLiteral(files.universal, 'FIXTURELITERAL');
  expect(lit.count === 2, `universal: the literal is in both slices (got ${lit.count})`);
  expect(
    lit.hits.every((h) => h.vaddr !== null),
    'universal: every literal hit maps to a vaddr',
  );
  expect(
    findLiteral(files.universal, 'zzq-not-present-zzq').count === 0,
    'universal: an absent literal finds nothing',
  );

  // mapLiteral: the fixture's __data holds a pointer *to the literal*, so the
  // descriptor-table step has a known answer. It maps one slice — the richest —
  // and the literal is present in both.
  const map = mapLiteral(files.universal, 'FIXTURELITERAL');
  expect(map.locations.length === 1, `mapliteral: maps the chosen slice's single literal (got ${map.locations.length})`);
  expect(
    map.slices.length === 2 && map.slices.every((s) => s.inText === 1),
    'mapliteral: the literal is found in both slices',
  );
  // The pointer search is whole-file while the literal search is per-slice, so
  // each slice's own descriptor table is found: two pointers, one per slice.
  expect(
    map.locations[0]?.pointerCount === 2,
    `mapliteral: finds one planted pointer per slice (got ${map.locations[0]?.pointerCount})`,
  );
  expect(
    map.locations[0]?.pointers.every((p) => p.section === '__TEXT,__data'),
    'mapliteral: every pointer is attributed to a data section',
  );

  // Stripped: bytes work, names do not.
  const s = describe(files.stripped);
  expect(s.slices[0].nsyms === 0, 'stripped: carries no symbols');
  const sc = findCalls(files.stripped, targetD);
  expect(sc.count >= 1, 'stripped: findcall still works without symbols');

  // Populated: the shape the corpus used to borrow from whatever the machine had
  // installed. Every number here is computed by `populatedFixture()` above rather
  // than written down twice, so the fixture and its assertions cannot drift.
  const p = populatedFixture();
  const dp = describe(files.populated);
  expect(!dp.fat && dp.slices.length === 1, 'populated: is thin');
  expect(
    p.addresses.fillers.length === POPULATED_FILLERS,
    `populated: carries ${POPULATED_FILLERS} bulk symbols (got ${p.addresses.fillers.length})`,
  );
  expect(
    dp.slices[0].defined === POPULATED_FILLERS + 4,
    `populated: ${POPULATED_FILLERS} bulk + 4 named symbols are all defined (got ${dp.slices[0].defined})`,
  );
  expect(
    dp.slices[0].nsyms === POPULATED_FILLERS + 6,
    `populated: ${POPULATED_FILLERS} + 4 defined + 2 imports (got ${dp.slices[0].nsyms})`,
  );
  // The floor is the suite's, not this file's; the point is that the corpus
  // satisfies it on a machine with no binaries installed at all.
  expect(
    dp.slices[0].defined > 50,
    `populated: clears smoke.mjs's POPULATED_FLOOR of 50 (got ${dp.slices[0].defined})`,
  );
  // A bulk symbol sitting on a planted call site would alias two names to one
  // address, which is legal in a Mach-O and wrong for every assertion here.
  expect(
    p.addresses.fillers.every((a) => ![0x40n, 0x80n, 0x100n, 0x120n].some((o) => a === p.addresses.text + o)),
    'populated: no bulk symbol aliases a call site or the literal',
  );
  expect(
    lookupAddress(files.populated, p.addresses.fillers[0]).function === '_pop_00',
    'populated: the lowest bulk symbol resolves by name',
  );
  expect(
    lookupAddress(files.populated, p.addresses.fillers.at(-1)).function === '_pop_59',
    'populated: the highest bulk symbol resolves by name',
  );
  expect(
    lookupAddress(files.populated, 0x10).function === null,
    'populated: a low address is still not attributed to an import at 0x0',
  );
  expect(
    findCalls(files.populated, p.addresses.target).count === 2,
    'populated: both encoded call sites still resolve beside a full symbol table',
  );

  return problems;
}

/**
 * Is this a Mach-O, by its first four bytes?
 *
 * Compared as *bytes*, not as an integer. This function was first written as
 * `head.readUInt32BE(0)` against a list of magic constants, which is the exact
 * mistake `src/macho.mjs` documents at length: a thin little-endian Mach-O
 * starts `cf fa ed fe`, which read big-endian is 0xcffaedfe — in neither the
 * fat nor the thin list. The first run of this file rejected all five fixtures
 * it had just written. The comment in the reader exists because this mistake has
 * now been made independently twice in this repository.
 */
const MACHO_MAGIC_BYTES = [
  Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // fat
  Buffer.from([0xbe, 0xba, 0xfe, 0xca]), // fat, byte-swapped
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), // 64-bit thin
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // 32-bit thin
];

function isMachO(p) {
  const head = Buffer.alloc(4);
  const fd = fs.openSync(p, 'r');
  fs.readSync(fd, head, 0, 4, 0);
  fs.closeSync(fd);
  return MACHO_MAGIC_BYTES.some((m) => head.equals(m));
}

/* ------------------------------------------------------------------ *
 * build
 * ------------------------------------------------------------------ */

/**
 * Build the corpus, write or check it, and verify it.
 *
 * This is the whole of what running the file does, and it is exported so that a
 * project testing *its own* Mach-O reader can borrow the corpus rather than
 * write its own. The argument forms are the command-line ones:
 *
 *     import { buildFixtures } from 'MachO-Tools/fixtures';
 *     await buildFixtures();                       // → test/fixtures/*.macho
 *     await buildFixtures({ out: '/tmp/corpus' }); // → somewhere of your choosing
 *     await buildFixtures({ check: true });        // verify, write nothing
 *
 * `out` is a parameter rather than a constant because the one thing a consumer
 * cannot do with this is write into this repository. `check` is exported for the
 * same reason the CI `fixtures` job exists: a corpus that has been hand-edited,
 * or has drifted from the generator, stops testing anything while still passing.
 *
 * Returns the manifest, which carries the addresses and call counts the corpus
 * asserts — so a consumer's own tests can reference the same numbers this
 * project's do, instead of re-deriving them and disagreeing.
 *
 * Throws on a mismatch or a fixture that fails `verify()`. A consumer that
 * swallows that exception is re-creating the exact failure mode this file exists
 * to prevent: a suite that passes for the wrong reason.
 */
export async function buildFixtures({ out = OUT, check = false } = {}) {
  fs.mkdirSync(out, { recursive: true });

  const x86 = codeFixture(CPU_X86_64);
  const arm = codeFixture(CPU_ARM64);
  const decoy = decoyFixture();
  const populated = populatedFixture();

  const BUILT = {
    'universal.macho': universal(),
    'thin-x86_64.macho': thinMachO({ cputype: CPU_X86_64, ...x86 }),
    'thin-arm64.macho': thinMachO({ cputype: CPU_ARM64, ...arm }),
    'arm64-only.macho': thinMachO({ cputype: CPU_ARM64, text: arm.text, data: arm.data, symbols: arm.symbols }),
    'decoy.macho': thinMachO({ cputype: CPU_X86_64, text: decoy.text, data: decoy.data, symbols: decoy.symbols, textFlags: decoy.textFlags }),
    'stripped.macho': thinMachO({ cputype: CPU_X86_64, text: x86.text, data: x86.data, symbols: [] }),
    'populated.macho': thinMachO({ cputype: CPU_X86_64, text: populated.text, data: populated.data, symbols: populated.symbols }),
  };

// Addresses are written alongside the binaries, because the suite's assertions
// are about *these* functions and a hardcoded hex constant in a test file is a
// number nobody can check. Reading them from here keeps the test and the
// generator agreeing on what was built.
  const manifest = {
    generated: 'by test/fixtures.mjs — do not hand-edit',
    universal: BUILT['universal.macho'].length,
    thin: { x86_64: BUILT['thin-x86_64.macho'].length, arm64: BUILT['thin-arm64.macho'].length },
    arm64only: BUILT['arm64-only.macho'].length,
    decoy: BUILT['decoy.macho'].length,
    stripped: BUILT['stripped.macho'].length,
    populated: BUILT['populated.macho'].length,
    x86_64: { ...Object.fromEntries(Object.entries(x86.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    arm64: { ...Object.fromEntries(Object.entries(arm.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    decoyAddrs: { ...Object.fromEntries(Object.entries(decoy.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    populatedAddrs: {
      bulk: POPULATED_FILLERS,
      defined: POPULATED_FILLERS + 4,
      first: `0x${populated.addresses.fillers[0].toString(16)}`,
      last: `0x${populated.addresses.fillers.at(-1).toString(16)}`,
    },
    callCounts: {
      universal_target: 4,
      arm64only_target: 2,
      decoy_typed: 1,
      decoy_untyped: 2,
    },
  };

  const files = {};
  for (const [name, buf] of Object.entries(BUILT)) {
    const p = path.join(out, name);
    // Key on the stem without its separator, so `arm64-only.macho` is reachable
    // as `files.arm64only` rather than as `files['arm64-only']`.
    files[name.replace('.macho', '').replace(/-/g, '')] = p;
    if (check) {
      const have = fs.existsSync(p) ? fs.readFileSync(p) : null;
      if (!have || !have.equals(buf)) {
        // Thrown rather than `process.exit`: an importer that catches this can
        // report it in its own terms, and one that does not gets a non-zero exit
        // from the unhandled rejection anyway. Calling `process.exit` here would
        // kill a host process that merely imported this module.
        throw new Error(`fixtures: ${name} is missing or differs from what this file generates`);
      }
    } else {
      fs.writeFileSync(p, buf);
    }
  }

  const problems = await verify(files);
  if (problems.length) {
    throw new Error(
      'fixtures: generated binaries failed their own verification:\n' +
        problems.map((p) => `  - ${p}`).join('\n'),
    );
  }

  const bytes = Object.values(BUILT).reduce((n, b) => n + b.length, 0);
  const count = Object.keys(BUILT).length;

  return { files, manifest, bytes, count };
}

/* ------------------------------------------------------------------ *
 * entry point
 * ------------------------------------------------------------------ */

// Only when run directly. `import`ing this module must have no side effects:
// someone borrowing `buildFixtures` should not find a corpus written into their
// working tree as a side effect of the import that asked for nothing.
/**
 * Was this file *run*, rather than imported?
 *
 * The obvious comparison — `path.resolve(process.argv[1])` against
 * `fileURLToPath(import.meta.url)` — is wrong whenever the two arrive by
 * different routes, and the commonest route is a symlink: `npm install` of a
 * local dependency links the package rather than copying it, so `argv[1]` is the
 * `node_modules/...` path while Node has already resolved `import.meta.url` to
 * the real one. The comparison then says "imported", `main` never runs, and the
 * script exits 0 having done nothing at all.
 *
 * That is the worst failure available here, because it looks exactly like
 * success. `node fixtures.mjs --check` on a drifted corpus has to fail; on a
 * symlinked path it used to pass without looking at anything. Realpath both
 * sides so the answer does not depend on how the file was reached.
 */
function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const argv = process.argv.slice(2);
  const check = argv.includes('--check');

  // `--out-dir` is what makes the corpus usable from a vendored copy, where
  // writing into the package's own `test/fixtures/` is not somewhere you want a
  // corpus appearing. `--out-dir` and `--check` combine: verify a corpus you
  // generated somewhere else.
  const flag = argv.indexOf('--out-dir');
  let out = OUT;
  if (flag !== -1) {
    if (flag + 1 >= argv.length) {
      console.error('fixtures: --out-dir needs a directory');
      process.exit(2);
    }
    out = path.resolve(argv[flag + 1]);
  } else {
    const stray = argv.find((a) => a.startsWith('-') && a !== '--check');
    if (stray) {
      console.error(`fixtures: unknown option ${stray}`);
      console.error('usage: node test/fixtures.mjs [--check] [--out-dir DIR]');
      process.exit(2);
    }
  }

  try {
    const { bytes, count } = await buildFixtures({ check, out });
    // `path.relative` for a directory outside the tree prints a wall of `../..`,
    // which is harder to read than the absolute path it is abbreviating.
    const rel = path.relative(process.cwd(), out);
    const shown = !rel || rel.startsWith('..') ? out : rel;
    console.log(
      `${check ? 'verified' : 'built'} ${count} fixture(s) in ${shown}` +
        `  (${bytes.toLocaleString('en-US')} bytes total)`,
    );
  } catch (err) {
    console.error(String(err.message ?? err));
    process.exit(1);
  }
}
