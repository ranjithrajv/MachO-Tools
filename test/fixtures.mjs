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
const MH_MAGIC_32 = 0xfeedface;
const FAT_MAGIC = 0xcafebabe;
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const LC_UUID = 0x1b;

/**
 * The UUID planted in `stripped.macho`, so the expected value in an assertion is
 * a constant in the generator next to the bytes that produce it, not a hex string
 * copied out of the reader's own output — which is the shape of a test that passes
 * with the reader broken.
 */
const FIXTURE_UUID = 'a1b2c3d4-e5f6-4708-9a0b-1c2d3e4f5061';
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

/**
 * The same figure for a fixture with a different section count.
 *
 * Every extra `section_64` is 80 bytes of load command, which pushes all the
 * section *data* later. The constant above is only right for two sections, and
 * using it for a three-section fixture silently misplaces `__text` by 80 bytes —
 * which then makes every address assertion fail for a reason that has nothing to
 * do with the tools. Derived rather than restated, for the same reason the
 * builder derives `nsects`.
 */
const headerPlusLoadcmds = (nsects = 2) => 32 + (72 + 80 * nsects) + 24;

/**
 * The 32-bit counterparts of the three constants above.
 *
 * A 32-bit Mach-O has a 28-byte `mach_header`, a 56-byte `LC_SEGMENT` and 68-byte
 * `section` entries, so its section data starts 68 bytes earlier than the 64-bit
 * form's does. And its addresses must *fit* in 32 bits, which rules out
 * `0x100000000` entirely: `VMADDR_BASE_32` is a plausible i386 base instead, so
 * that an address that accidentally gets truncated shows up as a wrong answer
 * rather than as a value that happens to survive.
 */
const VMADDR_BASE_32 = 0x8048000n;
const HEADER_PLUS_LOADCMDS_32 = 28 + (56 + 68 * 2) + 24;
const headerPlusLoadcmds32 = (nsects = 2) => 28 + (56 + 68 * nsects) + 24;

/** The vaddr of the `__text` section, given its file offset. */
const textVaddr = (textOffset, base = VMADDR_BASE) => base + BigInt(textOffset);

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
 *
 * `zerofill` adds a third section that occupies address space and no bytes. It
 * exists because a `__bss`-shaped section is the one input that makes an
 * offset-to-address mapping quietly wrong: its recorded file `offset` is 0, so a
 * reader that tests sections before testing whether they occupy bytes will
 * resolve the header and the load commands into `__bss`. In `go` that is
 * 180,760 bytes of a real binary, and offset 0x1000 — the first byte of `__text`
 * — comes back as being inside `__bss`.
 */
function thinMachO({ cputype, text, data, dataFlags = S_REGULAR, symbols, textFlags = S_ATTR_PURE_INSTRUCTIONS | 0x4, zerofill = null, bits = 64, base = VMADDR_BASE, uuid = null }) {
  const segname = '__TEXT';
  const is64 = bits === 64;
  const nsects = zerofill ? 3 : 2;
  const ncmds = uuid ? 3 : 2;
  // The three sizes that differ between the two forms. A 32-bit Mach-O has a
  // 28-byte mach_header, an `LC_SEGMENT` (not `_64`) whose own header is 56 bytes
  // with `nsects` at offset 48, and 68-byte `section` entries — so it is not the
  // 64-bit layout with smaller numbers anywhere.
  const headerSize = is64 ? 32 : 28;
  const segCmdHeader = is64 ? 72 : 56;
  const sectSize = is64 ? 80 : 68;
  const segCmdSize = segCmdHeader + sectSize * nsects;
  const symtabCmdSize = 24;
  // `lc_uuid` is 24 bytes in both forms: cmd, cmdsize, then the 16-byte value.
  // Unlike everything else in this header it does not vary with the word size,
  // because it carries a fixed-size byte string rather than an address.
  const uuidCmdSize = uuid ? 24 : 0;
  const loadCommandsSize = segCmdSize + symtabCmdSize + uuidCmdSize;
  // `nlist` is 16 bytes in the 64-bit form and 12 in the 32-bit one, which moves
  // the string table and therefore every offset after it.
  const nlistSize = is64 ? 16 : 12;

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
  const nlist = Buffer.alloc(symbols.length * nlistSize);
  symbols.forEach((s, i) => {
    const at = i * nlistSize;
    nlist.writeUInt32LE(strOffsets.get(s.name), at);   // n_strx
    nlist[at + 4] = s.type;                            // n_type
    nlist[at + 5] = s.sect;                            // n_sect
    nlist.writeUInt16LE(0, at + 6);                    // n_desc
    if (is64) nlist.writeBigUInt64LE(s.value, at + 8); // n_value, 64-bit
    else nlist.writeUInt32LE(Number(s.value), at + 8);  // n_value, 32-bit
  });
  const strOffset = symtabOffset + nlist.length;
  const totalSize = strOffset + strTable.length;

  const buf = Buffer.alloc(totalSize, 0);

  // ---- mach_header / mach_header_64
  // The 32-bit form has no `reserved` field, so `flags` sits at 24 in the 64-bit
  // header and at 24 in the 32-bit one too — but `sizeofcmds` is at 20 in both. The
  // difference that matters downstream is the 4-byte header, already handled by
  // `headerSize`.
  buf.writeUInt32LE(is64 ? MH_MAGIC_64 : MH_MAGIC_32, 0);
  buf.writeInt32LE(cputype, 4);
  buf.writeInt32LE(3, 8);                   // cpusubtype
  buf.writeUInt32LE(2, 12);                 // filetype: MH_EXECUTE
  buf.writeUInt32LE(ncmds, 16);
  buf.writeUInt32LE(loadCommandsSize, 20);
  buf.writeUInt32LE(S_ATTR_PURE_INSTRUCTIONS, 24); // flags

  // ---- LC_SEGMENT / LC_SEGMENT_64
  let o = headerSize;
  const seg = o;
  buf.writeUInt32LE(is64 ? LC_SEGMENT_64 : LC_SEGMENT, o);
  buf.writeUInt32LE(segCmdSize, o + 4);
  buf.write(segname, o + 8, 'latin1');
  if (is64) {
    buf.writeBigUInt64LE(base, o + 24);              // vmaddr
    // `vmsize` covers the zero-fill range as well as the file, which is what makes
    // an address inside `__bss` genuinely *mapped* — so a reader has to distinguish
    // "mapped with no byte behind it" from "not in this binary", and the segment is
    // where that distinction comes from.
    buf.writeBigUInt64LE(
      zerofill ? zerofill.addr + BigInt(zerofill.size) - base : BigInt(totalSize),
      o + 32,
    );                                             // vmsize
    buf.writeBigUInt64LE(BigInt(0), o + 40);        // fileoff
    buf.writeBigUInt64LE(BigInt(totalSize), o + 48);// filesize
    buf.writeUInt32LE(5, o + 56);                   // maxprot
    buf.writeUInt32LE(5, o + 60);                   // initprot
    buf.writeUInt32LE(nsects, o + 64);               // nsects
    buf.writeUInt32LE(0, o + 68);                   // flags
  } else {
    // 32-bit: every address is 4 bytes, so each field is 4 bytes earlier than in
    // the 64-bit form. This is the whole reason the reader's 32-bit path needs
    // its own offsets rather than the 64-bit ones scaled — they do not scale.
    buf.writeUInt32LE(Number(base), o + 24); // vmaddr
    buf.writeUInt32LE(
      zerofill ? Number(zerofill.addr + BigInt(zerofill.size) - base) : totalSize,
      o + 28,
    );                                             // vmsize
    buf.writeUInt32LE(0, o + 32);                   // fileoff
    buf.writeUInt32LE(totalSize, o + 36);           // filesize
    buf.writeUInt32LE(5, o + 40);                   // maxprot
    buf.writeUInt32LE(5, o + 44);                   // initprot
    buf.writeUInt32LE(nsects, o + 48);               // nsects
    buf.writeUInt32LE(0, o + 52);                   // flags
  }

  // ---- the section entries
  //
  // One writer for both forms, because the layouts are not the same shape at a
  // different scale and writing each separately is how the 64-bit-only assumption
  // got in here in the first place. The per-form offsets:
  //
  //   field       section_64   section
  //   addr            32          32
  //   size            40          36
  //   offset          48          40
  //   align           52          44
  //   reloff          56          48
  //   nreloc          60          52
  //   flags           64          56
  //   entry size      80          68
  //
  // `addr` is the only field at the same offset in both, because the two 16-byte
  // name fields above it are the same size in both. Each 32-bit field after it
  // shifts the next one 4 bytes earlier, which is why `flags` sits 8 bytes apart
  // and why the entries differ in length by 12 rather than by a factor.
  const writeSection = ({ at, sectname, secSegname, addr, size, offset, align, flags }) => {
    buf.write(sectname, at, 'latin1');
    buf.write(secSegname, at + 16, 'latin1');
    if (is64) {
      buf.writeBigUInt64LE(addr, at + 32);
      buf.writeBigUInt64LE(BigInt(size), at + 40);
      buf.writeUInt32LE(offset, at + 48);
      buf.writeUInt32LE(align, at + 52);
      buf.writeUInt32LE(0, at + 56);        // reloff
      buf.writeUInt32LE(0, at + 60);        // nreloc
      buf.writeUInt32LE(flags >>> 0, at + 64);
    } else {
      buf.writeUInt32LE(Number(addr), at + 32);
      buf.writeUInt32LE(size, at + 36);
      buf.writeUInt32LE(offset, at + 40);
      buf.writeUInt32LE(align, at + 44);
      buf.writeUInt32LE(0, at + 48);        // reloff
      buf.writeUInt32LE(0, at + 52);        // nreloc
      buf.writeUInt32LE(flags >>> 0, at + 56);
      // reserved1 (60) and reserved2 (64) stay as the zero-fill the buffer was
      // allocated with, which is what they are on every real binary.
    }
  };

  const sectBase = seg + segCmdHeader;

  writeSection({
    at: sectBase,
    sectname: '__text',
    secSegname: segname,
    // addr = segment vmaddr + section file offset, *not* the segment's own vmaddr.
    addr: textVaddr(textOffset, base),
    size: text.length,
    offset: textOffset,
    align: 2,
    // `>>> 0` for the same reason as `arm64BL`: `S_ATTR_PURE_INSTRUCTIONS` is
    // 0x80000000, so any `|` against it yields a *signed* int32 and the write
    // throws on a negative. This file has now reproduced that mistake twice while
    // writing the fixtures, which is a decent argument for how easy it is to make.
    flags: textFlags,
  });

  writeSection({
    at: sectBase + sectSize,
    sectname: '__data',
    secSegname: segname,            // deliberately inside __TEXT
    addr: base + BigInt(dataOffset),
    size: data.length,
    offset: dataOffset,
    align: 2,
    flags: dataFlags,
  });

  // __bss: zero-fill — an address range with no bytes behind it.
  //
  // `offset` is 0 and `size` is non-zero, which is exactly what a linker records
  // for a section the loader fills with zeros. `addr` continues past the end of
  // the segment's `filesize`, since that is where uninitialised data lives.
  // Anything that maps a vaddr without asking whether the section has bytes will
  // claim the header belongs here.
  if (zerofill) {
    writeSection({
      at: sectBase + sectSize * 2,
      sectname: zerofill.sectname,
      secSegname: zerofill.segname ?? segname,
      addr: zerofill.addr,
      size: zerofill.size,
      offset: 0,                    // no bytes
      align: 8,
      // S_ZEROFILL (0x1) with no S_ATTR_*_INSTRUCTIONS, so a typed scan skips it.
      flags: 0x1,
    });
  }

  // ---- LC_SYMTAB
  o = headerSize + segCmdSize;
  buf.writeUInt32LE(LC_SYMTAB, o);
  buf.writeUInt32LE(symtabCmdSize, o + 4);
  buf.writeUInt32LE(symtabOffset, o + 8);
  buf.writeUInt32LE(symbols.length, o + 12);
  buf.writeUInt32LE(strOffset, o + 16);
  buf.writeUInt32LE(strTable.length, o + 20);

  // ---- LC_UUID
  //
  // Optional, and placed *after* LC_SYMTAB rather than before it, because real
  // linkers emit it in the middle of the command list and a reader that assumed
  // a fixed order would get this one by luck. The bytes are written raw, without
  // the dashes, because that is what the file contains — the dashed form is a
  // presentation choice, and asserting the dashes are added is the test's job,
  // not the generator's.
  if (uuid) {
    o = headerSize + segCmdSize + symtabCmdSize;
    buf.writeUInt32LE(LC_UUID, o);
    buf.writeUInt32LE(uuidCmdSize, o + 4);
    const raw = Buffer.from(uuid.replace(/-/g, ''), 'hex');
    if (raw.length !== 16) {
      throw new Error(`uuid must be 16 bytes, got ${raw.length} from "${uuid}"`);
    }
    raw.copy(buf, o + 8);
  }

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
function codeFixture(cputype, { extraLoadcmds = 0 } = {}) {
  const ARM = cputype === CPU_ARM64;
  // `extraLoadcmds` shifts where `__text` begins, and with it every encoded
  // displacement. Adding a load command to a fixture without saying so here is
  // the exact mistake this parameter exists to make impossible: the bytes are
  // still a valid `call rel32`, they just point 24 bytes before the function they
  // name, so `findcall` reports zero and the failure looks like a broken reader
  // rather than a stale fixture.
  const TEXT = textVaddr(HEADER_PLUS_LOADCMDS + extraLoadcmds);
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

/**
 * A binary with a zero-fill section: address range, no bytes.
 *
 * The shape that makes offset-to-address mapping quietly wrong. `__bss` has a
 * real `addr` and a real `size`, and the linker records its file `offset` as 0 —
 * so a reader that walks sections without asking whether they occupy bytes
 * resolves every file offset from 0 up to the section's size into `__bss`. In a
 * real binary that range is the Mach-O header and its load commands.
 *
 * Here it is deliberately larger than the header, which is what makes the defect
 * reachable: `HEADER_PLUS_LOADCMDS` is 328 bytes, so a 4 KiB zero-fill section
 * covers the header *and* the whole of `__text`'s first 3,768 bytes. Without
 * this fixture, `o2a` on any offset below 0x1000 would return `__bss` and the
 * suite would pass.
 *
 * The address range starts past the end of the file, where a real `__bss` sits,
 * and `vmsize` is extended to cover it — so these addresses are genuinely mapped,
 * which is the distinction being tested. `a2o` must say "mapped, no byte" rather
 * than "not in this binary", and `o2a` must not be drawn into the section.
 */
function zerofillFixture() {
  const c = codeFixture(CPU_X86_64);
  const BSS_SIZE = 0x1000;
  const headerEnd = headerPlusLoadcmds(3); // three sections, not two
  // Past the end of the section data, as `__bss` always is. The symbol table and
  // string table follow it, so this is not the end of the file — `verify()`
  // asserts the section really is beyond the last byte rather than assuming it.
  const bssAddr = VMADDR_BASE + BigInt(headerEnd + c.text.length + c.data.length);
  const buf = thinMachO({
    cputype: CPU_X86_64,
    ...c,
    zerofill: { sectname: '__bss', segname: '__TEXT', addr: bssAddr, size: BSS_SIZE },
  });
  return {
    buf,
    // Returned separately from the buffer: `thinMachO` returns bytes, and the
    // addresses are what the assertions need. `text` is restated here against this
    // fixture's own layout, since `codeFixture`'s was computed for two sections.
    addresses: {
      ...c.addresses,
      text: VMADDR_BASE + BigInt(headerEnd),
      bss: bssAddr,
      bssSize: BSS_SIZE,
      headerEnd,
    },
  };
}

/**
 * A 32-bit Mach-O, which is the only thing in this corpus that is not 64-bit.
 *
 * It exists because the reader's 32-bit path had three defects that no fixture
 * could reach, every one of them in the same family — a 32-bit field read at the
 * 64-bit offset, or at the offset that 32-bit arithmetic would suggest, rather
 * than at the one the header actually declares:
 *
 *   - section entries were not read at all (`if (wide)`), so a 32-bit slice
 *     reported zero sections and every address lookup in it said "not in a
 *     section";
 *   - `nlist` was read as 16 bytes with a 64-bit `n_value`, when the 32-bit form
 *     is 12 bytes with a 32-bit value. This was the worst of the three: the
 *     stride was wrong, so *every* symbol was read from the wrong place, and the
 *     names still looked like names.
 *   - the section `offset` field was read at 44, which is where `align` lives.
 *
 * Two of those are invisible without a 32-bit binary to run them on, and the one
 * that produced plausible-looking output is precisely the kind of bug a test
 * suite is for. `findcall` is included because i386 and x86_64 encode a direct
 * call identically (`e8 rel32`), so the call-site scan should work here unchanged
 * — a reader that only ever saw 64-bit could have a bug that hides behind that
 * coincidence, and this is where it would show.
 *
 * The addresses are 32-bit (`VMADDR_BASE_32`), so a value that overflowed would
 * truncate rather than quietly stay large.
 */
function bits32Fixture() {
  const TEXT = textVaddr(HEADER_PLUS_LOADCMDS_32, VMADDR_BASE_32);
  const CALLER_A = TEXT + 0x40n;
  const CALLER_B = TEXT + 0x80n;
  const TARGET = TEXT + 0x100n;

  const text = Buffer.alloc(0x140, 0x90); // padding
  const put = (vaddr, bytes) => bytes.copy(text, Number(vaddr - TEXT));

  put(CALLER_A, x86Call(CALLER_A, TARGET));
  put(CALLER_A + 5n, Buffer.from([0xc3]));       // ret
  put(CALLER_B, x86Jmp(CALLER_B, TARGET));
  put(TARGET, Buffer.from([0xc3]));

  // Plain data. The 64-bit fixture plants a *pointer* to a literal here for
  // `mapliteral`; a 32-bit pointer is 4 bytes, and making this fixture exercise
  // that would mean testing two new things at once. It plants the literal as
  // bytes instead, which `findliteral` can still find — so the fixture tests the
  // reader's 32-bit arithmetic rather than the pointer search's width handling.
  const data = Buffer.from('BITS32LITERAL\0', 'latin1');

  const buf = thinMachO({
    cputype: CPU_X86_64,          // i386; there is no other 32-bit cpu here
    bits: 32,
    base: VMADDR_BASE_32,
    text,
    data,
    symbols: [
      { name: '__mh_execute_header', type: N_SECT | N_EXT, sect: 1, value: TEXT },
      { name: 'caller_a', type: N_SECT | N_EXT, sect: 1, value: CALLER_A },
      { name: 'caller_b', type: N_SECT | N_EXT, sect: 1, value: CALLER_B },
      { name: 'target_fn', type: N_SECT | N_EXT, sect: 1, value: TARGET },
      { name: '_malloc', type: N_EXT, sect: 0, value: 0n },
    ],
  });

  return {
    buf,
    addresses: { text: TEXT, callerA: CALLER_A, callerB: CALLER_B, target: TARGET },
    // What the reader must report, stated here so the assertion is written
    // against the header rather than against whatever the reader happens to say.
    expect: {
      is64: false,
      sections: ['__text', '__data'],
      textAddr: TEXT,
      textSize: 0x140,
      dataSize: data.length,
      segmentName: '__TEXT',
      loadCommands: ['LC_SEGMENT', 'LC_SYMTAB'],
      symbolNames: ['__mh_execute_header', 'caller_a', 'caller_b', 'target_fn'],
    },
  };
}

/**
 * A binary carrying NUL-terminated C strings in a real `__cstring` section.
 *
 * Every other fixture in this corpus is code and symbols only — deliberately, so
 * `--check` can pin exact byte counts — which meant `--strings` had nothing to
 * find in any of them and could only be exercised against a system binary. That
 * is how a string reader ends up untested on the machine that runs the tests.
 *
 * The strings are placed in the `__data` section and that section is *renamed*
 * to `__cstring` on the way out, because `thinMachO` writes a fixed two-section
 * layout that a dozen assertions depend on. Renaming a section changes no offsets,
 * no addresses and no lengths, so the existing checks are unaffected while
 * `findStrings` gets a section it can actually scan.
 *
 * `@@NOPTR@@` is present on purpose: it is printable and NUL-terminated, so a
 * reader that forgets to filter on section membership would report a reloc
 * placeholder as a string. It is in `__noptrdata` semantics here — inside the
 * cstring section — which is what makes the "only these sections" rule worth
 * testing rather than assuming.
 */
function stringsFixture() {
  const c = codeFixture(CPU_X86_64);
  const strings = [
    'macho-fixture-alpha',
    'macho-fixture-beta',
    'a short one',
    'macho-fixture-gamma-with-a-longer-body-to-exceed-the-default-minimum',
  ];
  // Laid out as one NUL-delimited blob, which is what a C string section really
  // is. Padding included, so the reader has to honour `size` rather than read to
  // the end of the section and pick up whatever follows.
  const blob = Buffer.concat([...strings.map((s) => Buffer.concat([Buffer.from(s, 'latin1'), Buffer.from([0])])), Buffer.alloc(7, 0)]);
  const buf = thinMachO({ cputype: CPU_X86_64, ...c, data: blob });

  // Rename __data -> __cstring in the one section_64 entry that carries it.
  //
  // Two offsets, both of which are wrong in a way that looks right: the section
  // table lives in the *load commands*, not in the section data, so it sits at
  // 32 + 72 rather than after the text it describes. And the name is at the start
  // of the 80-byte entry, while `headerPlusLoadcmds + text.length` — the obvious
  // calculation — lands in the *bytes* of that section. Writing the name over
  // data silently produced a fixture that looked generated and scanned as
  // `__data`, which is how this was caught.
  const SECTION_ENTRY_SIZE = 80;
  const segCmdHeader = 72;
  const dataSectEntry = 32 + segCmdHeader + SECTION_ENTRY_SIZE; // second section_64
  buf.fill(0, dataSectEntry, dataSectEntry + 16);
  buf.write('__cstring', dataSectEntry, 'latin1');

  return {
    buf,
    addresses: { ...c.addresses, stringDataOffset: headerPlusLoadcmds(2) + c.text.length },
    strings,
  };
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

  // The 32-bit fixture. Checked here as well as in the suite, and against the
  // generator's own arithmetic rather than against the reader's output — a
  // self-check that restates what the reader said would pass with the reader
  // broken, which is the specific failure mode `verify()` exists to prevent.
  {
    const b32 = bits32Fixture();
    const e = b32.expect;
    const d = describe(files.bits32);
    const s = d.slices[0];

    expect(!!s, 'bits32: parses');
    expect(s.bits === 32, `bits32: is reported as 32-bit (got ${s.bits})`);
    expect(
      s.sections.map((x) => x.sectname).join(',') === e.sections.join(','),
      `bits32: reads both sections (got ${s.sections.map((x) => x.sectname).join(',') || 'none'})`,
    );
    // The three defects this fixture exists for, each stated as the value the
    // header declares:
    //   - sections parsed at all (the `if (wide)` gate);
    //   - `nlist` stride, which shows up as every symbol name being wrong;
    //   - the section `offset` field, which is `align`'s offset if misread.
    expect(
      s.sections.find((x) => x.sectname === '__text')?.offset === HEADER_PLUS_LOADCMDS_32,
      `bits32: __text's file offset is the header size (got ${s.sections.find((x) => x.sectname === '__text')?.offset}, expected ${HEADER_PLUS_LOADCMDS_32})`,
    );
    expect(
      s.sections.find((x) => x.sectname === '__text')?.size === e.textSize,
      `bits32: __text's size is right (got ${s.sections.find((x) => x.sectname === '__text')?.size}, expected ${e.textSize})`,
    );
    expect(
      s.sections.find((x) => x.sectname === '__data')?.size === e.dataSize,
      `bits32: __data's size is right (got ${s.sections.find((x) => x.sectname === '__data')?.size}, expected ${e.dataSize})`,
    );
    expect(
      s.textAddr === b32.addresses.text,
      `bits32: __text's address is the 32-bit base + its file offset (got 0x${s.textAddr?.toString(16)}, expected 0x${b32.addresses.text.toString(16)})`,
    );
    expect(
      s.loadCommands.map((c) => c.name).join(',') === e.loadCommands.join(','),
      `bits32: names both load commands (got ${s.loadCommands.map((c) => c.name).join(',')})`,
    );
    expect(
      s.segments[0]?.segname === e.segmentName && s.segments[0]?.vmaddr === VMADDR_BASE_32,
      `bits32: the segment's vmaddr is 32-bit (got ${s.segments[0]?.vmaddr})`,
    );

    // Symbols: the assertion that the 12-byte stride is right. A reader using
    // 16 bytes would still produce four `defined` symbols and four plausible
    // names, so the check is that the *names* are the ones written.
    const syms = lookupAddress(files.bits32, b32.addresses.target);
    expect(
      syms.function === 'target_fn',
      `bits32: resolves target_fn through a 12-byte nlist (got ${JSON.stringify(syms.function)})`,
    );
    expect(
      syms.function && syms.start === b32.addresses.target,
      `bits32: the symbol's own address is exact, not truncated (got ${syms.start})`,
    );
    // `target_fn` is the last symbol by address, so its successor is legitimately
    // null. `caller_a` is not: its successor must be `caller_b`, one entry on in
    // a 12-byte-stride table. A reader walking 16-byte entries would land
    // somewhere else entirely and the names would stop matching.
    const ca = lookupAddress(files.bits32, b32.addresses.callerA);
    expect(
      ca.function === 'caller_a' && ca.start === b32.addresses.callerA
        && ca.next === b32.addresses.callerB,
      `bits32: caller_a's successor is caller_b (got ${ca.function} at ${ca.start}, next ${ca.next})`,
    );
    expect(
      lookupAddress(files.bits32, b32.addresses.callerB).function === 'caller_b',
      'bits32: resolves caller_b too',
    );

    // i386 and x86_64 encode a direct call identically, so the scan must work
    // unchanged. If it does not, the reader is not 32-bit-clean even where the
    // instruction format agrees.
    expect(
      findCalls(files.bits32, b32.addresses.target).count === 2,
      `bits32: finds both encoded call/jmp sites (got ${findCalls(files.bits32, b32.addresses.target).count})`,
    );
    expect(
      findLiteral(files.bits32, 'BITS32LITERAL').count === 1,
      'bits32: finds a literal in the 32-bit data section',
    );
  }

  // The UUID, and the absence of one.
  //
  // `stripped.macho` carries an LC_UUID and every other fixture does not, so both
  // halves of the contract are checkable from the same corpus: a reader that
  // always returned a value, or one that returned nothing, fails here.
  {
    const withUuid = describe(files.stripped).slices[0];
    expect(
      withUuid.uuid === FIXTURE_UUID,
      `stripped: reads its LC_UUID (got ${withUuid.uuid}, expected ${FIXTURE_UUID})`,
    );
    expect(
      withUuid.loadCommands.some((c) => c.name === 'LC_UUID'),
      'stripped: the command is named as well as read',
    );
    // Position is the part that makes it a real read rather than a coincidence:
    // the UUID bytes are at offset+8 of *its own* command, which is the last of
    // three. Reading them from the wrong load command would still be 16 bytes of
    // something.
    expect(
      withUuid.loadCommands.length === 3
        && withUuid.loadCommands[2].name === 'LC_UUID',
      `stripped: LC_UUID is the third command (got ${withUuid.loadCommands.map((c) => c.name).join(',')})`,
    );
    for (const name of ['populated', 'universal', 'bits32', 'decoy']) {
      expect(
        describe(files[name]).slices.every((s) => s.uuid === null),
        `${name}: has no LC_UUID, so reports none rather than inventing one`,
      );
    }
  }

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

  // The zero-fill fixture. Asserted here as well as in the suite, because a
  // fixture that does not hold up is a broken instrument — it would make the
  // suite pass for the wrong reason, which is the whole reason `verify()` exists.
  //
  // Every assertion below is one that fails against the reader as it was before
  // `isBackedByFile` existed, which is the point: the defect was reachable from
  // any binary with a `__bss`, and no fixture in the corpus had one.
  {
    const { addressToOffset, offsetToAddress } = await import('../src/api.mjs');
    const z = zerofillFixture().addresses;

    // The section really does start past every file-backed section, or the "mapped
    // but no byte" assertions below would pass for the wrong reason.
    //
    // Compared against the last section's end rather than the file's size: the
    // symbol table and string table follow the section data, so a `__bss` address
    // can sit at a low file offset while still being outside every section. What
    // makes it zero-fill is that no section covers it, not where the file ends.
    {
      const { opener, parseThin } = await import('../src/macho.mjs');
      const f = opener(files.zerofill);
      const thin = parseThin(f, 0);
      const backed = thin.sections.filter((s) => s.offset !== 0);
      const lastEnd = backed.reduce((m, s) => (s.addr + BigInt(s.size) > m ? s.addr + BigInt(s.size) : m), 0n);
      expect(
        z.bss >= lastEnd,
        `zerofill: __bss starts past every file-backed section (0x${z.bss.toString(16)} vs last end 0x${lastEnd.toString(16)})`,
      );
      expect(
        thin.segments[0].vmsize > thin.segments[0].filesize,
        'zerofill: the segment is mapped past the end of its file range',
      );
      f.close();
    }

    // The load commands are inside `__bss`'s *claimed* file range and must not
    // resolve to it. This is the defect, stated as an assertion.
    const hdr = offsetToAddress(files.zerofill, [0, 0x10, z.headerEnd - 1]);
    for (const q of hdr.queries) {
      const sec = q.slices[0]?.section || '';
      expect(
        !/__bss/.test(sec),
        `zerofill: file offset 0x${q.query.toString(16)} does not resolve into __bss (got ${sec})`,
      );
    }
    // And it must resolve to the real thing: the header sits in __TEXT's segment
    // range, in no section.
    // Compared as the hex string the API reports, since a 64-bit vaddr is a string on
    // the wire and `===` against a BigInt would be false for the right answer.
    expect(
      hdr.queries[0].vaddr === `0x${VMADDR_BASE.toString(16)}`,
      `zerofill: file offset 0 is the start of __TEXT (got ${hdr.queries[0].vaddr})`,
    );

    // __text still resolves, by name and by address.
    const atText = offsetToAddress(files.zerofill, [z.headerEnd]);
    expect(
      atText.queries[0].vaddr === `0x${z.text.toString(16)}` && atText.queries[0].slices[0].section === '__TEXT,__text',
      `zerofill: the first __text byte resolves to __TEXT,__text (got ${atText.queries[0].slices[0].section})`,
    );

    // An address inside __bss is *mapped* and has no byte. Three distinct answers
    // — byte / zero-fill / unmapped — and conflating the last two is what makes a
    // patch script write to the wrong place.
    const bss = addressToOffset(files.zerofill, z.bss + 0x10n);
    expect(bss.mapped, 'zerofill: an address in __bss is mapped');
    expect(bss.zerofill, 'zerofill: an address in __bss is reported as zero-fill');
    expect(bss.offset === null, 'zerofill: an address in __bss has no file offset');
    expect(
      /zero-fill/.test(bss.note || ''),
      `zerofill: the note says why there is no offset (got ${JSON.stringify(bss.note)})`,
    );

    // Just before __bss is a real byte; just after the file's end is unmapped.
    expect(
      addressToOffset(files.zerofill, z.bss - 1n).offset !== null,
      'zerofill: the address before __bss is a real byte',
    );
    expect(
      !addressToOffset(files.zerofill, 0x7fffffffffff0000n).mapped,
      'zerofill: an address past every segment is not mapped',
    );

    // Round trip both ways, on the same binary, since the two directions share the
    // zero-fill decision and one of them can be right while the other is wrong.
    for (const v of [z.text, z.callerA, z.target]) {
      const o = addressToOffset(files.zerofill, v);
      expect(o.offset === z.headerEnd + Number(v - z.text), `zerofill: 0x${v.toString(16)} maps to its own offset`);
      expect(offsetToAddress(files.zerofill, o.offset).queries[0].vaddr === `0x${v.toString(16)}`, `zerofill: 0x${v.toString(16)} round-trips`);
    }
  }

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
  // Its *own* target address, not another fixture's. `stripped` has an extra load
  // command, so its code sits 24 bytes later than the fixture it was copied from;
  // reusing the other's address here tested nothing but that the two disagreed.
  const strippedCode = codeFixture(CPU_X86_64, { extraLoadcmds: 24 });
  const sc = findCalls(files.stripped, strippedCode.addresses.target);
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
  // `stripped` gains an LC_UUID, so its code is laid out 24 bytes later than the
  // shared x86 fixture's — see `codeFixture`'s `extraLoadcmds`.
  const strippedCode = codeFixture(CPU_X86_64, { extraLoadcmds: 24 });
  const populated = populatedFixture();
  const zf = zerofillFixture();
  const zfAddrs = zf.addresses;
  const st = stringsFixture();
  const b32 = bits32Fixture();

  const BUILT = {
    'universal.macho': universal(),
    'thin-x86_64.macho': thinMachO({ cputype: CPU_X86_64, ...x86 }),
    'thin-arm64.macho': thinMachO({ cputype: CPU_ARM64, ...arm }),
    'arm64-only.macho': thinMachO({ cputype: CPU_ARM64, text: arm.text, data: arm.data, symbols: arm.symbols }),
    'decoy.macho': thinMachO({ cputype: CPU_X86_64, text: decoy.text, data: decoy.data, symbols: decoy.symbols, textFlags: decoy.textFlags }),
    // The one fixture carrying an LC_UUID, so the reader's UUID path has something
    // to read. It is here because this fixture's assertions are about a binary with
    // *no symbols*, and adding a load command shifts every offset after the header
    // — which is exactly the kind of change that silently invalidates a hardcoded
    // hex constant in someone else's test. `stripped` has none.
    'stripped.macho': thinMachO({
      cputype: CPU_X86_64,
      ...strippedCode,
      symbols: [],
      uuid: FIXTURE_UUID,
    }),
    'populated.macho': thinMachO({ cputype: CPU_X86_64, text: populated.text, data: populated.data, symbols: populated.symbols }),
    'zerofill.macho': zf.buf,
    'strings.macho': st.buf,
    'bits32.macho': b32.buf,
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
    zerofill: BUILT['zerofill.macho'].length,
    strings: BUILT['strings.macho'].length,
    bits32: BUILT['bits32.macho'].length,
    fixtureUuid: FIXTURE_UUID,
    x86_64: { ...Object.fromEntries(Object.entries(x86.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    arm64: { ...Object.fromEntries(Object.entries(arm.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    decoyAddrs: { ...Object.fromEntries(Object.entries(decoy.addresses).map(([k, v]) => [k, `0x${v.toString(16)}`])) },
    // The zero-fill section starts past the end of the file, and its size is
    // larger than the header, so `bss` past `headerEnd` is inside `__bss` and
    // `headerEnd` is not.
    zerofillAddrs: {
      bss: `0x${zfAddrs.bss.toString(16)}`,
      bssSize: zfAddrs.bssSize,
      headerEnd: zfAddrs.headerEnd,
    },
    // The expected `--strings` output, so the assertion reads the generator's
    // intent rather than a copy of what the reader happened to return. A test
    // that restates its own subject's output proves only that it is
    // deterministic; this proves it is right.
    stringsExpected: {
      all: st.strings,
      longOnly: st.strings.filter((s) => s.length > 20),
      dataOffset: st.addresses.stringDataOffset,
    },
    // The 32-bit fixture's expectations, from the generator's own arithmetic. Its
    // addresses must fit in 32 bits — asserted here as well as in the suite,
    // because an address that has silently stopped fitting is the failure mode
    // this whole fixture exists to prevent, and it is invisible in a hex dump.
    bits32Expected: {
      ...b32.expect,
      textAddr: `0x${b32.addresses.text.toString(16)}`,
      target: `0x${b32.addresses.target.toString(16)}`,
      addressFitsIn32Bits: [...Object.values(b32.addresses)].every((v) => v <= 0xffffffffn),
    },
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
