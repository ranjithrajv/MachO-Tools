#!/usr/bin/env node

/**
 * Tests for `src/disasm.mjs` — the instruction-length and branch-target decoders.
 *
 * ## Why this file exists separately from `smoke.mjs`
 *
 * `smoke.mjs` checks the *contract*: exit codes, the JSON envelope, and that a
 * decode at a planted symbol resolves the edge the fixture generator encoded.
 * That is the smallest set of checks that can fail on a real regression, and it
 * exercises a handful of instructions.
 *
 * This file checks the *tables*, which is where the actual risk lives. The length
 * decoder's output is a number, and a wrong number is always a plausible number —
 * there is no shape a consumer can validate it against. So the checks here are
 * built to fail when the decoder is wrong even though nothing about the output
 * looks wrong.
 *
 * ## The rule that makes these tests worth writing
 *
 * **No expected value in this file is a hex literal copied from an
 * implementation, an emulator, or memory.**
 *
 * Every vector is built by an *encoder* that places fields at their documented
 * bit positions, and the expected length and target are derived from the same
 * field arithmetic. The encoder and the decoder are independent readings of one
 * ISA definition, so they can disagree — which is the point. Writing the bytes
 * by hand was tried and abandoned twice over: a mistyped hex byte looks exactly
 * like a decoder bug and burns the reader's time, and a vector typed to match
 * previously-observed output is not a test at all.
 *
 * That discipline is also why this file contains no `ff e0`-style inventions.
 * `ff /2` is `call r/m64` — an *indirect* call through a register or memory
 * operand, which has no displacement field at all. Appending four bytes of
 * "displacement" to it produces an encoder that agrees with nothing, including
 * the ISA it is supposedly derived from.
 *
 * Three sources of truth are used, in increasing order of how much they cover:
 *
 *   1. **Derived vectors** below. Both architectures, every documented branch
 *      form, prefixes, REX/VEX/EVEX, and each length category. Exact, and present
 *      on every machine.
 *   2. **The `__stubs` stride oracle**, on the host's own binaries. Every x86_64
 *      entry in `__TEXT,__stubs` is `jmpq *disp(%rip)` — `ff 25 rel32` — so a
 *      correct sweep of that section yields exactly `size / 6` instructions, all
 *      6 bytes long, the last ending exactly on the section boundary. That is a
 *      real oracle over thousands of distinct instructions, and it is the check
 *      that catches a typo in an opcode-map entry for an instruction nobody
 *      happened to choose. Best-effort: absence is a skip, never a failure.
 *   3. **Coverage.** The decoded lengths of a sweep sum to the span swept. Cheap,
 *      and it is the property a desynchronising sweep violates first.
 *
 * ## What is deliberately *not* asserted here
 *
 * No test asserts that a linear sweep of a whole `__text` is correct. It is not,
 * and cannot be: real binaries embed jump tables and string literals in their
 * code sections, and a linear sweep decodes those as instructions. That is the
 * tool's documented behaviour and `smoke.mjs` asserts it as behaviour rather
 * than papering over it. The sweep's documented purpose is coverage from a
 * trustworthy start, not discovery.
 *
 * ## Residual limitation of derived vectors
 *
 * Encoder and decoder that both misread the same field position would agree with
 * each other and disagree with the hardware. That is not hypothetic here — this
 * suite was written after `arm64BranchTarget` matched masks with a bare `&`,
 * which JavaScript evaluates as signed 32-bit, so every encoding with bit 31 set
 * silently failed to match while the W-register forms passed. Section 1 asserts
 * that trap directly, and the `__stubs` oracle is independent of this file's
 * arithmetic entirely, so the two together cover the classes of error a
 * self-derived table cannot see on its own.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  arm64Length, arm64BranchTarget,
  x86_64Length, x86_64BranchTarget,
  instructionLength, branchTarget, supportedArch, linearSweep,
} from '../src/instruction.mjs';
import {
  opener, slicesOf, parseThin, preferredSlice, isMachOFile,
  readSymbols, sliceArchName,
} from '../src/macho.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ *
 * reporting
 * ------------------------------------------------------------------ */

let passed = 0;
const failures = [];
const skipped = [];

function check(ok, label, detail = '') {
  if (ok) {
    passed++;
    if (process.env.VERBOSE) console.log(`  PASS  ${label}${detail ? '  ' + detail : ''}`);
  } else {
    failures.push(`${label}${detail ? ' — ' + detail : ''}`);
    console.log(`  FAIL  ${label}${detail ? '  ' + detail : ''}`);
  }
}

const skip = (label, why) => {
  skipped.push(label);
  console.log(`  SKIP  ${label}  ${why}`);
};

/** Group heading. Quiet unless VERBOSE, so a failure is found by reading it. */
const section = (title) => {
  if (process.env.VERBOSE) console.log(`\n-- ${title}`);
};

const hex = (n) => (typeof n === 'bigint' ? `0x${n.toString(16)}` : String(n));

/* ------------------------------------------------------------------ *
 * encoders
 *
 * Each places fields at their documented bit positions and returns the bytes
 * alongside what the instruction *means*, so a test needs no separate expected
 * value to go stale.
 * ------------------------------------------------------------------ */

/**
 * Little-endian word from an instruction word.
 *
 * `BigInt.asUintN` rather than `>>> 0`, because every field below is a BigInt:
 * the displacement fields are signed and the opcode constants are 0x94… and up,
 * which do not survive a signed 32-bit round trip. That is the same hazard the
 * decoder's `is()` helper exists to handle, met from the writing side.
 */
const word = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(Number(BigInt.asUintN(32, BigInt(n))), 0);
  return b;
};

/**
 * Little-endian bytes from byte values and whole buffers, mixed.
 *
 * `Buffer.from(list.flat())` looks like it does this and does not: `flat()` walks
 * *arrays*, and a Buffer is not one, so `bytes([0xe8], i32(d))` silently produced
 * the single byte `0xe8`. Every x86 branch vector below then decoded as a
 * truncated instruction, which read as a systematic decoder failure rather than
 * as a broken helper.
 */
const bytes = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));

/** Signed 8-bit / 32-bit little-endian immediates, wrapping at the field width. */
const i8 = (n) => { const b = Buffer.alloc(1); b.writeInt8(Number(BigInt.asIntN(8, BigInt(n))), 0); return b; };
const i32 = (n) => { const b = Buffer.alloc(4); b.writeInt32LE(Number(BigInt.asIntN(32, BigInt(n))), 0); return b; };

/**
 * A64 encodings.
 *
 * `imm26`/`imm19`/`imm14` are scaled by 4 in the encoding, so the functions take
 * the *byte* displacement a reader would write down and shift it themselves —
 * which keeps the vectors reading as "BL 0x40 bytes forward" and puts the
 * scaling, the thing most likely to be misread, on the expected side too.
 */
const arm64 = {
  // `BL` and `B` differ *only* in bit 31 (`100101` against `000101`). There is no
  // link bit inside imm26 — all 26 bits belong to the displacement. ORing in a
  // bit here adds 0x4000 to every BL target, which reads as a decoder bug and is
  // not one.
  BL: (pc, d) => ({
    kind: 'BL', target: pc + d,
    bytes: word(0x94000000n | ((d >> 2n) & 0x03ffffffn)),
  }),
  B: (pc, d) => ({
    kind: 'B', target: pc + d,
    bytes: word(0x14000000n | ((d >> 2n) & 0x03ffffffn)),
  }),
  Bcond: (pc, d, cond = 0xe) => ({
    kind: 'B.cond', target: pc + d,
    bytes: word(0x54000000n | (((d >> 2n) & 0x7ffffn) << 5n) | BigInt(cond & 0xf)),
  }),
  // `sf op 0110100 imm19 Rt` — CBZ when op is 0, CBNZ when it is 1. `sf` selects
  // the register width and is bit 31, which is the field the next check is about.
  CBZ: (pc, d, sf = 0) => ({
    kind: 'CBZ', target: pc + d,
    bytes: word(0x34000000n | (BigInt(sf) << 31n) | (((d >> 2n) & 0x7ffffn) << 5n)),
  }),
  CBNZ: (pc, d, sf = 0) => ({
    kind: 'CBNZ', target: pc + d,
    bytes: word(0x34000000n | (BigInt(sf) << 31n) | (1n << 24n) | (((d >> 2n) & 0x7ffffn) << 5n)),
  }),
  // `sf op 0110110 imm14 b5 0 Rt`. Same bit slot as imm19, narrower field, so
  // TBZ has a quarter of CBZ's range: ±32 KB against ±1 MB.
  TBZ: (pc, d, sf = 0) => ({
    kind: 'TBZ', target: pc + d,
    bytes: word(0x36000000n | (BigInt(sf) << 31n) | (((d >> 2n) & 0x3fffn) << 5n)),
  }),
  TBNZ: (pc, d, sf = 0) => ({
    kind: 'TBNZ', target: pc + d,
    bytes: word(0x36000000n | (BigInt(sf) << 31n) | (1n << 24n) | (((d >> 2n) & 0x3fffn) << 5n)),
  }),
  // ADR: `0 immlo 10000 immhi Rd`. The displacement is **unscaled** — ADR names a
  // byte address — which is the whole reason it is not just another pc-relative.
  ADR: (pc, imm) => ({
    kind: 'ADR', target: pc + imm,
    bytes: word(0x10000000n | ((imm & 0x3n) << 29n) | (((imm >> 2n) & 0x7ffffn) << 5n)),
  }),
  // ADRP: the same field layout with bit 31 set, but the displacement is in
  // *pages* and the base is the instruction's own page.
  ADRP: (pc, pages) => ({
    kind: 'ADRP', target: (pc & ~0xfffn) + (pages << 12n),
    bytes: word(0x90000000n | ((pages & 0x3n) << 29n) | (((pages >> 2n) & 0x7ffffn) << 5n)),
  }),
};

/**
 * x86_64 encodings. Same contract as `arm64`.
 *
 * `d` is the byte displacement from the instruction's start, and the encoder
 * subtracts the instruction's length before encoding — because x86 branch
 * displacements are measured from the *end* of the instruction, while A64's are
 * measured from the instruction itself. Doing that subtraction here is what lets
 * every vector below read as "`jmp` 0x1000 bytes forward" instead of as a
 * displacement that has to be recomputed by hand at each call site.
 */
const x86 = {
  CALL: (d) => ({ kind: 'CALL', bytes: bytes([0xe8], i32(d - 5n)) }),
  JMP: (d) => ({ kind: 'JMP', bytes: bytes([0xe9], i32(d - 5n)) }),
  JMP8: (d) => ({ kind: 'JMP', bytes: bytes([0xeb], i8(d - 2n)) }),
  // `Jcc` is the tool's deliberate family name rather than a condition name.
  // Splitting `jl` from `jne` needs the 16-entry cc table, which is mnemonic
  // territory and belongs to a real disassembler; the resolved edge is the part
  // a caller can act on.
  Jcc8: (d) => ({ kind: 'Jcc', bytes: bytes([0x7d], i8(d - 2n)) }),
  Jcc32: (d) => ({ kind: 'Jcc', bytes: bytes([0x0f, 0x85], i32(d - 6n)) }),
  LOOP: (d) => ({ kind: 'LOOP', bytes: bytes([0xe2], i8(d - 2n)) }),
  JRCXZ: (d) => ({ kind: 'JRCXZ', bytes: bytes([0xe3], i8(d - 2n)) }),
  // A prefixed call: `2e e8 rel32`. The displacement is still from the end, so
  // this is 6 bytes and points at the same place as the unprefixed 5-byte form.
  CALLprefixed: (d) => ({ kind: 'CALL', bytes: bytes([0x2e, 0xe8], i32(d - 6n)) }),
};

/* ------------------------------------------------------------------ *
 * 1. arm64 branch targets
 * ------------------------------------------------------------------ */

section('arm64 branch targets');

{
  const PC = 0x100000160n;

  // Displacements are given per form because the three field widths differ by
  // orders of magnitude, and a delta past a form's range is not a decoder bug —
  // it is an encoder that has already discarded bits. Feeding `imm19` forms a
  // ±128 MB displacement produced eight failures that all said "wrong target"
  // and all meant "this form cannot express that far".
  //
  // Within each range the values straddle the sign boundary, the field's
  // extremes, and a couple of ordinary forward and backward branches.
  const D26 = [0x4n, 0x8n, 0x40n, -0x40n, 0x7ffffcn, -0x7ffffcn, 0x400000n, -0x400000n];
  const D19 = [0x4n, 0x8n, 0x40n, -0x40n, 0x7fffcn, -0x7fffcn, 0x400n, -0x400n];
  const D14 = [0x4n, 0x8n, 0x40n, -0x40n, 0x7ffcn, -0x7ffcn, 0x400n, -0x400n];

  // `sf` is 0 and 1 for every conditional form, because the register width is
  // bit 31 and bit 31 is exactly where a signedness mistake hides: the
  // W-register forms have it clear and pass a naive mask test, the X-register
  // forms do not.
  const FORMS = [
    { name: 'BL', d: D26, make: (d) => arm64.BL(PC, d) },
    { name: 'B', d: D26, make: (d) => arm64.B(PC, d) },
    { name: 'B.cond', d: D19, make: (d) => arm64.Bcond(PC, d) },
    { name: 'CBZ w', d: D19, make: (d) => arm64.CBZ(PC, d, 0) },
    { name: 'CBZ x', d: D19, make: (d) => arm64.CBZ(PC, d, 1) },
    { name: 'CBNZ w', d: D19, make: (d) => arm64.CBNZ(PC, d, 0) },
    { name: 'CBNZ x', d: D19, make: (d) => arm64.CBNZ(PC, d, 1) },
    { name: 'TBZ w', d: D14, make: (d) => arm64.TBZ(PC, d, 0) },
    { name: 'TBZ x', d: D14, make: (d) => arm64.TBZ(PC, d, 1) },
    { name: 'TBNZ w', d: D14, make: (d) => arm64.TBNZ(PC, d, 0) },
    { name: 'TBNZ x', d: D14, make: (d) => arm64.TBNZ(PC, d, 1) },
  ];

  for (const form of FORMS) {
    const bad = [];
    for (const d of form.d) {
      const v = form.make(d);
      const got = arm64BranchTarget(v.bytes, PC, 0);
      const at = `${d > 0n ? '+' : ''}${d}`;
      if (!got) bad.push(`${at}: no result`);
      else if (got.kind !== v.kind) bad.push(`${at}: kind ${got.kind}, expected ${v.kind}`);
      else if (got.target !== v.target) bad.push(`${at}: ${hex(got.target)}, expected ${hex(v.target)}`);
    }
    check(
      bad.length === 0,
      `arm64 ${form.name} resolves to the ISA's target`,
      bad.length ? bad.join('; ') : `${form.d.length} displacements, forward and back`,
    );
  }

  // ADR and ADRP are not "pc plus a displacement": ADR is unscaled, and ADRP is
  // a page-relative encode-decode pair. Testing them alongside the pc-relative
  // forms would hide both differences, because BL happens to share the shape of
  // neither.
  {
    const IMM = [1n, 8n, 0x1000n, -1n, -8n, 0xfffffn, -0xfffffn];
    const bad = [];
    for (const imm of IMM) {
      const v = arm64.ADR(PC, imm);
      const got = arm64BranchTarget(v.bytes, PC, 0);
      if (!got || got.kind !== 'ADR' || got.target !== v.target) {
        bad.push(`${imm}: ${got ? `${got.kind} ${hex(got.target)}` : 'no result'}, expected ${hex(v.target)}`);
      }
    }
    check(bad.length === 0, 'arm64 ADR is unscaled: the target is pc plus the 21-bit field',
      bad.length ? bad.join('; ') : `${IMM.length} immediates at byte granularity, both signs`);
  }
  {
    const PAGES = [0n, 1n, -1n, 0x4000n, -0x4000n, 0x80000n, -0x80000n];
    const bad = [];
    for (const p of PAGES) {
      const v = arm64.ADRP(PC, p);
      const got = arm64BranchTarget(v.bytes, PC, 0);
      if (!got || got.kind !== 'ADRP' || got.target !== v.target) {
        bad.push(`${p}: ${got ? `${got.kind} ${hex(got.target)}` : 'no result'}, expected ${hex(v.target)}`);
      }
    }
    check(bad.length === 0, 'arm64 ADRP is page-relative: (pc & ~0xfff) plus the field shifted 12',
      bad.length ? bad.join('; ') : `${PAGES.length} page displacements, both signs`);
  }

  // An ADRP that forgets to mask the base to its page is only detectable from a
  // PC whose low 12 bits are non-zero: the correct answer and the wrong one
  // coincide exactly when the PC is page-aligned. 0x100000160 has low bits
  // 0x160, so every non-zero page displacement above distinguishes them.
  check(
    (PC & 0xfffn) !== 0n,
    'the arm64 ADRP test PC is not page-aligned, so masking the base is observable',
    `pc ${hex(PC)}, low 12 bits ${hex(PC & 0xfffn)}`,
  );

  // The signed-32-bit trap, asserted on its own. JavaScript's bitwise `&`
  // coerces both operands to signed 32-bit, so `(insn & 0xfc000000) === 0x94000000`
  // is *false* for every instruction with bit 31 set — silently, and only for half
  // the forms, which is exactly what lets it survive a spot check and a casual
  // sweep. The `is()` helper's `>>> 0` is the fix.
  {
    const bit31 = [
      arm64.BL(PC, 0x40n), arm64.CBZ(PC, 0x40n, 1), arm64.CBNZ(PC, 0x40n, 1),
      arm64.TBZ(PC, 0x40n, 1), arm64.TBNZ(PC, 0x40n, 1), arm64.ADRP(PC, 1n),
    ];
    const allSet = bit31.every((v) => (v.bytes.readUInt32LE(0) & 0x80000000) !== 0);
    const failed = bit31.filter((v) => arm64BranchTarget(v.bytes, PC, 0) === null);
    check(
      allSet && failed.length === 0,
      'arm64 encodings with bit 31 set still match their masks',
      failed.length
        ? `${failed.length} of ${bit31.length} failed to match — the signed-32-bit trap is back`
        : `${bit31.length} bit-31 forms: BL, CBZ/CBNZ x, TBZ/TBNZ x, ADRP`,
    );
  }

  // A branch form must not match a different form. `op` is bit 24 in both the
  // CBZ family and the TBZ family, so a mask that stops at bit 25 collapses
  // CBNZ onto CBZ and TBNZ onto TBZ — and every conditional branch in the binary
  // comes back with the wrong name, which looks entirely plausible.
  {
    const kinds = new Map([
      [0x34000040n, 'CBZ'], [0x35000040n, 'CBNZ'],
      [0xb4000040n, 'CBZ'], [0xb5000040n, 'CBNZ'],
      [0x36000040n, 'TBZ'], [0x37000040n, 'TBNZ'],
      [0xb6000040n, 'TBZ'], [0xb7000040n, 'TBNZ'],
    ]);
    const bad = [];
    for (const [w, want] of kinds) {
      const got = arm64BranchTarget(word(w), PC, 0);
      if (!got || got.kind !== want) bad.push(`${hex(w)}: ${got?.kind ?? 'no result'}, expected ${want}`);
    }
    check(bad.length === 0, 'arm64 CBZ, CBNZ, TBZ and TBNZ stay distinguishable',
      bad.length ? bad.join('; ') : `${kinds.size} forms, bit 24 and bit 31 both significant`);
  }

  // Not a branch: the answer must be null, not a fabricated address. `0xd503201f`
  // is the canonical `ret` and appears in every arm64 fixture, so a nonzero
  // answer here would already be showing up as nonsense targets elsewhere.
  check(arm64BranchTarget(word(0xd503201f), PC, 0) === null, 'arm64 ret is not reported as a branch');
  // A branch field all ones is a legal encoding of a maximally-backward BL, not a
  // sentinel: imm26 = -1 word.
  check(
    (arm64BranchTarget(word(0x97ffffff), PC, 0)?.target) === PC - 4n,
    'arm64 BL with the whole imm26 field set is a branch, not a sentinel',
  );
}

/* ------------------------------------------------------------------ *
 * 2. arm64 lengths
 * ------------------------------------------------------------------ */

section('arm64 lengths');

{
  // Fixed-width: every A64 instruction is 4 bytes, with no prefixes and no
  // escapes. This is the only real property of the architecture's length model,
  // and it is cheap to assert — the check that `arm64Length` is not quietly
  // deferring to a variable-length path or, worse, to a constant.
  const WORDS = [0xd503201fn, 0x1f2003d5fn, 0xc0035fd6fn, 0x94000030n, 0x14000001n,
    0x54000060n, 0x34000040n, 0x36000040n, 0x10000040n, 0x90000020n,
    0x00000000n, 0xffffffffn, 0x9e670000n, 0xd69f03e0n];
  const bad = WORDS.filter((w) => arm64Length(word(w), 0) !== 4);
  check(bad.length === 0, 'arm64 every instruction is 4 bytes, branches included',
    bad.length ? bad.map((w) => hex(w)).join(', ') : `${WORDS.length} words, including nop, ret, branches and all-ones`);

  // A short buffer must return null rather than a partial length. A length that
  // overruns the buffer is how a sweep walks off the end of a section.
  check(arm64Length(Buffer.alloc(3), 0) === null, 'arm64 a truncated instruction is null, not a length',
    '3 bytes available, 4 needed');
  check(arm64Length(Buffer.alloc(0), 0) === null, 'arm64 an empty buffer is null');
  check(
    arm64Length(word(0x94000030), 0) === 4 && arm64Length(word(0x94000030), 1) === null,
    'arm64 length is read at the given offset',
    'offset 0 is 4 bytes; offset 1 leaves only 3',
  );
  check(arm64Length(word(0xd503201f), 4) === null, 'arm64 an offset at the buffer end is null');
  // A negative offset must not wrap around into a valid read.
  check(arm64Length(word(0xd503201f), -1) === null, 'arm64 a negative offset is null');
}

/* ------------------------------------------------------------------ *
 * 3. x86_64 branch targets
 * ------------------------------------------------------------------ */

section('x86_64 branch targets');

{
  const PC = 0x100000160n;

  // An x86 displacement is measured from the instruction's *end*, so the set of
  // reachable targets is the field's range shifted by the instruction length —
  // and the extremes are off by exactly that many, in both directions.
  //
  // Deriving it from the field bounds rather than hard-coding a list is what
  // keeps this honest: asking for a target 127 bytes behind a 2-byte form needs a
  // displacement of -129, which does not fit rel8, and it *wraps* to +127. That
  // surfaces as a "wrong target" failure in which every part looks like a decoder
  // bug and the actual fault is the test asking for something unencodable.
  const REACH = (len, lo, hi) => [BigInt(lo) + BigInt(len), BigInt(hi) + BigInt(len)];
  const deltas = (len, lo, hi, mid) => {
    const [min, max] = REACH(len, lo, hi);
    const m = BigInt(mid);
    return [BigInt(len), m, -m, min, max, (max + min) >> 1n];
  };

  const DELTAS8 = deltas(2, -128, 127, 0x40);              // jmp rel8, jcc rel8, loop, jrcxz
  const DELTAS32_5 = deltas(5, -0x80000000, 0x7fffffff, 0x1000);   // call rel32, jmp rel32
  const DELTAS32_6 = deltas(6, -0x80000000, 0x7fffffff, 0x1000);   // jcc rel32, prefixed call

  const FORMS = [
    { name: 'CALL rel32', d: DELTAS32_5, make: (d) => x86.CALL(d) },
    { name: 'JMP rel32', d: DELTAS32_5, make: (d) => x86.JMP(d) },
    { name: 'CALL rel32, prefixed', d: DELTAS32_6, make: (d) => x86.CALLprefixed(d) },
    { name: 'Jcc rel32', d: DELTAS32_6, make: (d) => x86.Jcc32(d) },
    { name: 'JMP rel8', d: DELTAS8, make: (d) => x86.JMP8(d) },
    { name: 'Jcc rel8', d: DELTAS8, make: (d) => x86.Jcc8(d) },
    { name: 'LOOP rel8', d: DELTAS8, make: (d) => x86.LOOP(d) },
    { name: 'JRCXZ rel8', d: DELTAS8, make: (d) => x86.JRCXZ(d) },
  ];

  for (const form of FORMS) {
    const bad = [];
    for (const d of form.d) {
      const v = form.make(d);
      const got = x86_64BranchTarget(v.bytes, PC, 0);
      const at = `${d > 0n ? '+' : ''}${d}`;
      if (!got) bad.push(`${at}: no result`);
      else if (got.kind !== v.kind) bad.push(`${at}: kind ${got.kind}, expected ${v.kind}`);
      else if (got.target !== PC + d) {
        bad.push(`${at}: ${hex(got.target)}, expected ${hex(PC + d)}`);
      }
    }
    check(
      bad.length === 0,
      `x86_64 ${form.name} resolves to pc + length + displacement`,
      bad.length ? bad.join('; ') : `${form.d.length} displacements, forward and back`,
    );
  }

  // An x86 displacement is measured from the end of the instruction, so a target
  // is correct under any prefix combination without the decoder needing to know
  // which prefixes were present. The prefixed vector above passes; this states
  // the reason, and pins the one-byte difference a wrong base would introduce.
  {
    const plain = x86.CALL(0x40n).bytes;      // 5 bytes
    const prefixed = x86.CALLprefixed(0x40n).bytes;  // 6 bytes, same target
    check(
      x86_64Length(plain, 0) === 5 && x86_64Length(prefixed, 0) === 6
      && x86_64BranchTarget(plain, PC, 0)?.target === x86_64BranchTarget(prefixed, PC, 0)?.target,
      'x86_64 a prefixed call measures its displacement from the end, not the start',
      '5-byte and 6-byte forms of the same edge resolve identically',
    );
  }

  // RIP-relative memory operands are deliberately *not* branches. `ff 15 rel32` is
  // `call qword ptr [rip+disp32]`: the disp32 addresses a pointer, not code, and
  // treating it as a branch displacement fabricates a target roughly 2^32 bytes
  // from the call. Reporting those is `mapliteral`'s job. A regression here would
  // produce a confidently wrong call graph, so it is asserted, not assumed.
  {
    // mod=00 rm=101 is the RIP-relative form: disp32 is relative to the end of
    // the instruction, so 0xffffffe0 from PC is PC+6-32.
    const ripCall = bytes([0xff, 0x15], i32(-32n));
    check(
      x86_64BranchTarget(ripCall, PC, 0) === null,
      'x86_64 a RIP-relative indirect call is not a branch target',
      'ff 15 rel32 — the displacement addresses a pointer, not code',
    );
    // The plain indirect register form has no displacement at all and must also
    // be absent. `ff /2` is `call r/m64`; ModRM e0 is mod=11, so 2 bytes.
    const regCall = bytes([0xff, 0xe0]);
    check(
      x86_64Length(regCall, 0) === 2 && x86_64BranchTarget(regCall, PC, 0) === null,
      'x86_64 an indirect call through a register is not a branch target',
      'ff e0 is 2 bytes: call rax',
    );
  }

  // Padding and data must read as "not a branch" rather than as something.
  for (const [b, what] of [
    [[0x90], 'nop'], [[0xcc], 'int3'], [[0xc3], 'ret'], [[0xc2, 0x08, 0x00], 'ret imm16'],
    [[0xf4], 'hlt'], [[0x00, 0x00], 'add byte [rax], al'], [[0xcc, 0xcc, 0xcc], 'int3 padding'],
  ]) {
    check(x86_64BranchTarget(Buffer.from(b), PC, 0) === null, `x86_64 ${what} is not reported as a branch`);
  }
}

/* ------------------------------------------------------------------ *
 * 4. x86_64 lengths
 * ------------------------------------------------------------------ */

section('x86_64 lengths');

{
  // One case per opcode-map category, so a table entry that loses its category
  // or its operand count fails here rather than in a sweep 400 KB into a binary.
  // `what` is the disassembly, used only in the failure message.
  const CASES = [
    // --- n: no ModRM, no immediate
    { b: [0x90], len: 1, what: 'nop' },
    { b: [0x98], len: 1, what: 'cltq' },
    { b: [0x99], len: 1, what: 'cqto' },
    { b: [0xcc], len: 1, what: 'int3' },
    { b: [0xc3], len: 1, what: 'ret' },
    { b: [0xcb], len: 1, what: 'retf' },
    { b: [0x9c], len: 1, what: 'pushfq' },
    { b: [0x9d], len: 1, what: 'popfq' },
    { b: [0xf4], len: 1, what: 'hlt' },
    { b: [0xf5], len: 1, what: 'cmc' },
    { b: [0xc2, 0x08, 0x00], len: 3, what: 'ret imm16' },
    { b: [0x05, 0x01, 0x00, 0x00, 0x00], len: 5, what: 'add eax, imm32' },
    // A two-byte opcode is the escape *plus* the opcode: `0f 05` is 2 bytes, not
    // 1. Reading the escape as the whole instruction is the natural mistake and it
    // understates by exactly one byte.
    { b: [0x0f, 0x05], len: 2, what: 'syscall' },
    { b: [0x0f, 0x0b], len: 2, what: 'ud2' },
    { b: [0x0f, 0x31], len: 2, what: 'rdtsc' },
    { b: [0x0f, 0xa2], len: 2, what: 'cpuid' },

    // --- m: ModRM, no immediate
    { b: [0x88, 0xe0], len: 2, what: 'mov r/m8, r8' },
    { b: [0x8b, 0xc0], len: 2, what: 'mov eax, eax' },
    { b: [0x01, 0xd8], len: 2, what: 'add eax, ebx' },
    { b: [0x89, 0xff], len: 2, what: 'mov edi, edi' },
    { b: [0xff, 0xe0], len: 2, what: 'call rax' },
    { b: [0x0f, 0xb6, 0xc0], len: 3, what: 'movzx eax, al' },
    { b: [0x0f, 0xbe, 0xc0], len: 3, what: 'movsx eax, al' },
    { b: [0x0f, 0xaf, 0xc0], len: 3, what: 'imul eax, eax' },

    // --- ModRM + SIB + displacement, the longest addressing forms
    // rm=100 is a *SIB*, so mod=10 means SIB *and* disp32: seven bytes. Stopping at
    // the disp32 without the SIB is the classic off-by-one here.
    { b: [0x8b, 0x84, 0x98, 0x00, 0x00, 0x00], len: 7, what: 'mov eax, [rax+rax*4+disp32] — mod=10, rm=100' },
    { b: [0x8b, 0x80, 0x00, 0x00, 0x00, 0x00], len: 6, what: 'mov eax, [rax+disp32] — mod=10, rm=000' },
    { b: [0x8b, 0x44, 0x98, 0x00], len: 4, what: 'mov eax, [rax+disp8] — mod=01' },
    // mod=00 rm=100 selects a SIB, and SIB base=101 with scale=00 selects disp32:
    // seven bytes, not six. This is the one most often decoded a byte short.
    { b: [0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00], len: 7, what: 'mov eax, fs:[disp32] — SIB base=101' },
    // mod=00 rm=101 is RIP-relative: no ModRM-routed displacement follows.
    { b: [0x8b, 0x05, 0x10, 0x00, 0x00, 0x00], len: 6, what: 'mov eax, [rip+disp32]' },
    { b: [0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00], len: 7, what: 'nop [rax+disp32] — 0F 1F, mod=10' },
    { b: [0x0f, 0x1f, 0x40, 0x00], len: 4, what: 'nop [rax+0] — 0F 1F, mod=01' },
    { b: [0x0f, 0x1f, 0x00], len: 3, what: 'nop [rax] — 0F 1F, mod=00 no displacement' },

    // --- immediates
    { b: [0x83, 0xc0, 0x01], len: 3, what: 'add eax, imm8' },
    { b: [0x81, 0xc0, 0x01, 0x00, 0x00, 0x00], len: 6, what: 'add eax, imm32' },
    { b: [0x6a, 0x01], len: 2, what: 'push imm8' },
    { b: [0x68, 0x01, 0x00, 0x00, 0x00], len: 5, what: 'push imm32' },
    { b: [0xb8, 0x01, 0x00, 0x00, 0x00], len: 5, what: 'mov eax, imm32' },
    // Without REX.W, `b8+r` is still a 32-bit immediate even in 64-bit mode. The
    // 8-byte payload below is *data*, not an imm64; only the REX makes it one.
    { b: [0xb8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], len: 5, what: 'mov eax, imm32 — the trailing bytes are the next instruction' },
    { b: [0xc6, 0xc0, 0x01], len: 3, what: 'mov al, imm8 — /0 only' },
    { b: [0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], len: 6, what: 'mov eax, imm32 — /0 only' },
    { b: [0xc6, 0xc8, 0x01], len: 2, what: 'mov al, imm8 with reg=1 — no immediate in the ISA' },
    { b: [0xf6, 0xc0, 0x01], len: 3, what: 'test al, imm8 — /0 only' },
    // `f6` takes an imm8 for /0 *and* /1 (`test r/m8, imm8`); only /2 and /3 (`not`,
    // `neg`) are immediate-free. Assuming the immediate is /0-only understates
    // `test cl, imm8` by a byte.
    { b: [0xf6, 0xc8, 0x01], len: 3, what: 'test al, imm8 — /1 takes an immediate too' },
    { b: [0xf6, 0xd0], len: 2, what: 'not al — /2 takes no immediate' },
    { b: [0xf7, 0xc8, 0x01, 0x00, 0x00, 0x00], len: 6, what: 'test eax, imm32 — /1 takes an immediate too' },
    { b: [0xf7, 0xd0], len: 2, what: 'not eax — /2 takes no immediate' },
    { b: [0xf7, 0xc0, 0x01, 0x00, 0x00, 0x00], len: 6, what: 'test eax, imm32 — /0 only' },
    { b: [0x0f, 0x70, 0xc0, 0x01], len: 4, what: 'pshufd xmm0, xmm0, imm8' },
    { b: [0x0f, 0x38, 0x00, 0xc0], len: 4, what: '0F 38 escape — SSSE3, ModRM' },
    { b: [0x0f, 0x3a, 0x0f, 0xc0, 0x01], len: 5, what: '0F 3A escape — ModRM plus imm8' },

    // --- branches
    { b: [0xe8, 0, 0, 0, 0], len: 5, what: 'call rel32' },
    { b: [0xe9, 0, 0, 0, 0], len: 5, what: 'jmp rel32' },
    { b: [0xeb, 0], len: 2, what: 'jmp rel8' },
    { b: [0x70, 0], len: 2, what: 'jo rel8' },
    { b: [0x7f, 0], len: 2, what: 'jg rel8' },
    { b: [0xe0, 0], len: 2, what: 'loopne rel8' },
    { b: [0xe1, 0], len: 2, what: 'loope rel8' },
    { b: [0xe2, 0], len: 2, what: 'loop rel8' },
    { b: [0xe3, 0], len: 2, what: 'jrcxz rel8' },
    { b: [0x0f, 0x84, 0, 0, 0, 0], len: 6, what: 'je rel32 — 0F 8x has no ModRM' },
    { b: [0x0f, 0x85, 0, 0, 0, 0], len: 6, what: 'jne rel32 — 0F 8x has no ModRM' },
    { b: [0x0f, 0x8f, 0, 0, 0, 0], len: 6, what: 'jg rel32 — 0F 8x has no ModRM' },

    // --- group opcodes: ModRM, plus an immediate for some reg values only
    { b: [0xd1, 0xe0], len: 2, what: 'shl eax, 1 — /4 takes no immediate' },
    { b: [0xd1, 0xe8], len: 2, what: 'shr eax, 1 — /5 takes no immediate' },
    { b: [0xc1, 0xe0, 0x01], len: 3, what: 'shl eax, imm8 — /4' },
    { b: [0xc1, 0xe8, 0x01], len: 3, what: 'shr eax, imm8 — /5' },
    { b: [0xc1, 0xe9, 0x01], len: 3, what: 'sar eax, imm8 — /7' },
    { b: [0xf7, 0xe0], len: 2, what: 'mul eax — /4 takes no immediate' },
    { b: [0xf7, 0xf0], len: 2, what: 'div eax — /6 takes no immediate' },
    { b: [0xf7, 0xf8], len: 2, what: 'test eax — /7 takes no immediate' },
    // `0F BA` is a two-byte *group* opcode: the byte to switch on is the second
    // one, not the `0F` escape. Reading the wrong byte matches nothing and drops
    // the immediate, so BT/BTS/BTR/BTC all come back a byte short.
    { b: [0x0f, 0xba, 0xe0, 0x01], len: 4, what: 'bt eax, imm8 — 0F BA /4' },
    { b: [0x0f, 0xba, 0xe8, 0x01], len: 4, what: 'bts eax, imm8 — 0F BA /5' },
    { b: [0x0f, 0xba, 0xf0, 0x01], len: 4, what: 'btr eax, imm8 — 0F BA /6' },
    { b: [0x0f, 0xba, 0xf8, 0x01], len: 4, what: 'btc eax, imm8 — 0F BA /7' },

    // --- moffs: a bare address, no ModRM
    { b: [0xa1, 1, 2, 3, 4, 5, 6, 7, 8], len: 9, what: 'mov eax, moffs64' },
    { b: [0xa0, 1, 2, 3, 4, 5, 6, 7, 8], len: 9, what: 'mov al, moffs64' },
    { b: [0x67, 0xa1, 1, 2, 3, 4], len: 6, what: 'mov eax, moffs32 — address-size prefix' },

    // --- prefixes
    { b: [0x66, 0x90], len: 2, what: 'operand-size prefix' },
    { b: [0x66, 0x8b, 0xc0], len: 3, what: 'operand-size prefix + ModRM' },
    { b: [0xf3, 0x90], len: 2, what: 'rep prefix' },
    // `ae` is one-byte `SAHF`, so `f2 ae` is 2 bytes with the `f2` counted. The
    // ModRM-bearing `fxsave`/`fxrstor` forms are `0F AE /0` and `/1`.
    { b: [0xf2, 0xae], len: 2, what: 'repnz prefix + SAHF (no ModRM)' },
    { b: [0x0f, 0xae, 0x00], len: 3, what: 'fxsave [rax] — 0F AE /0 has a ModRM' },
    { b: [0x0f, 0xae, 0xe8], len: 3, what: 'mfence — 0F AE /7 has a ModRM' },
    { b: [0xf3, 0x0f, 0xb6, 0xc0], len: 4, what: 'rep + two-byte escape + ModRM' },
    { b: [0x2e, 0x8b, 0xc0], len: 3, what: 'segment prefix + ModRM' },
    { b: [0x64, 0x8b, 0xc0], len: 3, what: 'fs prefix + ModRM' },
    { b: [0x65, 0x8b, 0xc0], len: 3, what: 'gs prefix + ModRM' },

    // --- operand size changes the immediate width
    // `66` makes an `iz` immediate 2 bytes rather than 4, and `b8+r` 2 rather
    // than 4. Treating `iz` as always 4 overstates every one of these by 2.
    { b: [0x66, 0x83, 0xc0, 0x01], len: 4, what: 'add ax, imm8 with 0x66 — the 66 is ignored here' },
    { b: [0x66, 0x81, 0xc0, 0x01, 0x00], len: 5, what: 'add ax, imm16 — 66 narrows the immediate' },
    { b: [0x66, 0xb8, 0x01, 0x00], len: 4, what: 'mov ax, imm16 — 66 narrows the immediate' },
    { b: [0x48, 0x83, 0xc0, 0x01], len: 4, what: 'add rax, imm8 — REX.W does not widen imm8' },
    { b: [0x48, 0x81, 0xc0, 0x01, 0x00, 0x00, 0x00], len: 7, what: 'add rax, imm32 — REX.W does not widen imm32' },

    // --- REX
    { b: [0x48, 0x89, 0xc0], len: 3, what: 'REX.W + ModRM' },
    { b: [0x41, 0x8b, 0xc0], len: 3, what: 'REX.B + ModRM' },
    { b: [0x44, 0x8b, 0xc0], len: 3, what: 'REX.R + ModRM' },
    { b: [0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], len: 10, what: 'REX.W makes mov imm64' },
    // REX must come *after* the legacy prefixes, or it is not a prefix at all
    // and the instruction is misparsed. `66 48 8b` is 66-then-REX; both are 4
    // bytes here, so this checks acceptance, and the `0x66` cases above pin the
    // operand-size effect that depends on the ordering.
    { b: [0x66, 0x48, 0x8b, 0xc0], len: 4, what: 'legacy prefix then REX' },
    // `40`-`4f` are REX in 64-bit mode, so `4f 8b c0` is `mov eax, r8d`.
    { b: [0x4f, 0x8b, 0xc0], len: 3, what: 'REX.WRB + ModRM' },

    // --- vector encodings
    //
    // Every VEX and EVEX instruction has a ModRM byte — there is no
    // ModRM-less form — so each vector below carries one. Omitting it, as the
    // first draft of this file did, makes the decoder read the *opcode* as a
    // ModRM and then a displacement it invents, so a 4-byte `vzeroupper` decodes
    // as 8. The failure looks like a VEX bug and is a missing byte.
    //
    // The 2-byte form (`0xc5`) has one payload byte; the 3-byte form (`0xc4`) has
    // three, because the five-bit opcode-map field is real rather than implied.
    // Consuming two puts the third payload byte where the opcode belongs, making
    // every 3-byte VEX instruction exactly one byte short — individually
    // plausible, which is why it survived every earlier run.
    { b: [0xc5, 0xf8, 0x77, 0xc0], len: 4, what: 'vzeroupper — VEX 2-byte' },
    { b: [0xc5, 0xf8, 0x29, 0xc0], len: 4, what: 'vmovaps xmm0, xmm0 — VEX 2-byte' },
    { b: [0xc5, 0xfc, 0x29, 0xc0], len: 4, what: 'vmovaps ymm0, ymm0 — VEX 2-byte, L=1' },
    { b: [0xc5, 0xfe, 0x10, 0x07], len: 4, what: 'vmovups ymm0, [rdi] — VEX 2-byte, mod=00' },
    { b: [0xc4, 0xe2, 0x7d, 0x78, 0xc6, 0x08], len: 6, what: 'vpbroadcastb ymm0, [rdi] — VEX 3-byte, 0F38' },
    { b: [0xc4, 0xe2, 0x7d, 0x58, 0xc6, 0x02], len: 6, what: 'vpbroadcastd ymm0, [rdi] — VEX 3-byte, 0F38' },
    { b: [0xc4, 0xe2, 0x7d, 0x18, 0x07, 0xc0], len: 6, what: 'vbroadcastss ymm0, xmm0 — VEX 3-byte, register form' },
    { b: [0xc4, 0xe3, 0x5b, 0x00, 0x0f, 0xc0, 0x01], len: 7, what: 'vpalignr ymm0, ymm1, ymm2, 1 — VEX 3-byte, 0F3A plus imm8' },
    { b: [0x62, 0xf1, 0x7c, 0x48, 0x6f, 0x00], len: 6, what: 'EVEX vmovdqu8 zmm0, [rax] — three payload bytes' },
  ];

  const bad = [];
  for (const c of CASES) {
    // Padded with nops so a length that overruns its own encoding is caught as a
    // wrong number rather than as a truncated read. Without this, a case whose
    // true length exceeds its byte list decodes as null and looks like a
    // completely different failure.
    const buf = Buffer.concat([Buffer.from(c.b), Buffer.alloc(16, 0x90)]);
    const got = x86_64Length(buf, 0);
    if (got !== c.len) {
      bad.push(`${c.what} [${c.b.map((x) => x.toString(16).padStart(2, '0')).join(' ')}]: ${got}, expected ${c.len}`);
    }
  }
  check(bad.length === 0, 'x86_64 lengths match the opcode map',
    bad.length ? bad.join('; ') : `${CASES.length} encodings spanning every length category`);

  // A buffer that ends inside an instruction is not an instruction of that
  // length. Returning a length anyway is how a sweep runs off the end of a
  // section and reads into the next one.
  const TRUNCATED = [
    { b: [0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7], what: 'mov rax, imm64, one byte short' },
    { b: [0xe8, 1, 2, 3], what: 'call rel32, one byte short' },
    { b: [0x8b, 0x84, 0x00, 0x00, 0x00], what: 'mov with disp32, one byte short' },
    { b: [0x8b, 0x04, 0x25, 0x10, 0x00, 0x00], what: 'mov fs:[disp32], one byte short' },
    { b: [0x0f, 0x3a, 0x0f, 0xc0], what: '0F 3A missing its imm8' },
    { b: [0x0f, 0xba, 0xe0], what: 'bt with imm8, missing the immediate' },
  ];
  const tbad = TRUNCATED.filter((c) => x86_64Length(Buffer.from(c.b), 0) !== null);
  check(tbad.length === 0, 'x86_64 an instruction cut off by the buffer end is null',
    tbad.length ? tbad.map((c) => c.what).join('; ') : `${TRUNCATED.length} truncations`);

  // The architecture caps an instruction at 15 bytes. A longer "instruction" is a
  // misparse and must be reported as such rather than handed to a caller that
  // will add it to an address.
  check(
    x86_64Length(Buffer.concat([Buffer.alloc(15, 0x2e), Buffer.from([0x90])]), 0) === null,
    'x86_64 an encoding longer than 15 bytes is rejected, not returned',
    '15 prefixes plus the opcode is 16 bytes',
  );

  // The boundary from the other side: 14 prefixes plus a 1-byte opcode is exactly
  // 15 and must decode. A loop capped at 15 *prefixes* rather than 15 bytes
  // total would pass the check above and fail this one.
  check(
    x86_64Length(Buffer.concat([Buffer.alloc(14, 0x2e), Buffer.from([0x90])]), 0) === 15,
    'x86_64 a 15-byte encoding of redundant prefixes is still accepted',
    'the cap is 15 bytes of instruction, not 15 prefixes',
  );

  // A buffer that ends *after* the prefixes and before the opcode is the shape a
  // sweep hands over at the very end of a section, when fewer bytes remain than
  // the decoder asked for. Reading the opcode there yields `undefined`, and
  // `ONE_BYTE[undefined][0]` throws — so the failure was a stack trace from
  // inside a sweep on a real binary, at the one place a caller least expects a
  // length error. Every plain-opcode fuzz missed it, because all of them pad.
  for (const [what, b] of [
    ['a bare legacy prefix', [0x2e]],
    ['two legacy prefixes', [0x2e, 0x66]],
    ['a legacy prefix then REX', [0x2e, 0x48]],
    ['fifteen prefixes', new Array(15).fill(0x2e)],
  ]) {
    let threw = false;
    let got = null;
    try { got = x86_64Length(Buffer.from(b), 0); } catch { threw = true; }
    check(!threw && got === null, `x86_64 a buffer ending after the prefixes is null: ${what}`,
      threw ? 'threw instead of returning null' : `${got}`);
  }

  // An unknown opcode must be null, not a guess. Reporting a length for a byte
  // that is not an opcode lets a sweep step into the middle of whatever it was
  // actually part of.
  check(x86_64Length(Buffer.from([0x0f, 0x0a]), 0) === null,
    'x86_64 an unknown two-byte opcode is null');
}

/* ------------------------------------------------------------------ *
 * 5. arch dispatch
 * ------------------------------------------------------------------ */

section('arch dispatch');

{
  // `arm64e` must reach the same decoder as `arm64`: it is A64 with pointer
  // authentication, and PAC instructions are fixed-width, so the lengths match.
  // Refusing `arm64e` would refuse most modern iOS binaries.
  //
  // The accepted spellings are exactly what `sliceArchName` produces, which is
  // the only thing that can reach this function from `disassemble()`: `arm64`,
  // `arm64e` and `x86_64`. Matching is case- and punctuation-sensitive because it
  // goes through the project's shared `archMatches`, so `ARM64`, `arm64-v8` and
  // `x86-64` are *not* accepted — asserted below rather than left as a surprise,
  // because a caller passing a string from some other tool would otherwise get a
  // silent null instead of a decode.
  for (const arch of ['arm64', 'arm64e']) {
    check(
      instructionLength(arch, word(0x94000030), 0) === 4,
      `instructionLength: ${arch} reaches the A64 decoder`,
    );
  }
  check(
    branchTarget('arm64e', word(0x94000030), 0x1000n, 0)?.target === 0x1000n + 0xc0n,
    'branchTarget: arm64e resolves a BL',
  );

  check(
    instructionLength('x86_64', Buffer.from([0x48, 0x89, 0xc0]), 0) === 3,
    'instructionLength: x86_64 reaches the x86 decoder',
  );
  for (const arch of ['ARM64', 'arm64-v8', 'x86-64']) {
    check(
      instructionLength(arch, Buffer.from([0x48, 0x89, 0xc0]), 0) === null,
      `instructionLength: ${arch} is not a name the reader produces, so it decodes nothing`,
    );
  }

  // An architecture with no decoder is a negative answer — not an exception, and
  // not a guess. Throwing here would force every caller to wrap a table lookup in
  // a try, and the CLI's error path exists precisely so they do not have to.
  for (const arch of ['ppc64', 'ppc', 'i386', 'arm64_32', 'unknown', '', null, undefined]) {
    check(
      instructionLength(arch, Buffer.from([0x90]), 0) === null
      && branchTarget(arch, Buffer.from([0x90]), 0n, 0) === null,
      `instructionLength/branchTarget: ${JSON.stringify(arch)} has no decoder and says so`,
    );
  }
  check(
    supportedArch('arm64') && supportedArch('arm64e') && supportedArch('x86_64')
    && !supportedArch('ppc64') && !supportedArch('i386') && !supportedArch('unknown'),
    'supportedArch agrees with what the decoders implement',
    'arm64, arm64e, x86_64 supported; ppc64 and i386 are not',
  );
}

/* ------------------------------------------------------------------ *
 * 6. the `__stubs` stride oracle, on the host's own binaries
 * ------------------------------------------------------------------ */

section('__stubs stride oracle');

{
  /**
   * Host binaries to try. `/usr/lib/dyld` first: on a stock macOS install it is
   * the largest multi-architecture Mach-O present, so it supplies both an x86_64
   * and an arm64 slice and tens of thousands of stubs. Everything is optional —
   * absence is a skip, never a failure, because otherwise this file would be a
   * test of one machine's `/usr/lib`.
   */
  const HOSTS = ['/usr/lib/dyld', '/bin/ls', '/usr/bin/true', '/usr/bin/ssh', '/usr/lib/libSystem.B.dylib'];

  /**
   * Sweep a whole section through `linearSweep`.
   *
   * `sliceBase` is the slice's own offset in the file, which is what the reader
   * adds to `sec.offset` to find the bytes. Getting it wrong reads a different
   * slice's section and every length below is then wrong for reasons that have
   * nothing to do with the decoder — which is why it is passed explicitly rather
   * than guessed at each call site.
   *
   * The sweep runs to the *section* end rather than the requested `end`, so an
   * instruction straddling the range boundary is length-decoded rather than
   * dropped. Without that, "every stub is 6 bytes" would be a statement about
   * the sweep's bookkeeping as much as about the decoder.
   */
  const sweepSection = (f, sec, arch, sliceBase) =>
    linearSweep(f, sec, arch, sliceBase, { start: 0, end: sec.size, max: 0 });

  /** Every (path, slice, section) triple on this host, across all HOSTS. */
  const sectionsOf = (archFilter) => {
    const out = [];
    for (const p of HOSTS) {
      if (!fs.existsSync(p) || !isMachOFile(p)) continue;
      const f = opener(p);
      try {
        for (const s of slicesOf(f)) {
          const thin = parseThin(f, s.offset);
          if (!thin) continue;
          const name = archFilter(thin);
          if (!name) continue;
          for (const sec of thin.sections) {
            if (sec.sectname === '__stubs' && sec.size > 0) out.push({ p, sec, base: s.offset, name });
          }
        }
      } finally { f.close(); }
    }
    return out;
  };

  /**
   * Every x86_64 entry in `__TEXT,__stubs` is `jmpq *disp(%rip)` — `ff 25
   * rel32` — exactly 6 bytes, and the section size is a multiple of 6 by
   * construction. So a correct decoder produces exactly `size / 6` instructions
   * there, every one 6 bytes, the last ending exactly on the boundary.
   *
   * This is the only check here that runs over thousands of *distinct*
   * instructions, and it is what a hand-written vector cannot do: a typo in an
   * opcode-map entry for an instruction nobody happened to choose shows up here
   * and nowhere else. It also cannot be satisfied by a decoder that is uniformly
   * wrong, because the stride is a property of the linker rather than of the
   * decoder.
   */
  const x64Sections = sectionsOf(() => 'x86_64');
  if (!x64Sections.length) {
    skip('x86_64 __stubs decodes as exactly size/6 six-byte instructions',
      'no x86_64 __stubs section found on this host');
  } else {
    const bad = [];
    let total = 0;
    for (const { p, sec, base } of x64Sections) {
      const f = opener(p);
      try {
        const insns = sweepSection(f, sec, 'x86_64', base);
        total += insns.length;
        const expected = sec.size / 6;
        if (insns.length !== expected) {
          bad.push(`${path.basename(p)}: ${insns.length} instructions, expected ${expected}`);
          continue;
        }
        const off = insns.filter((i) => i.length !== 6);
        if (off.length) {
          bad.push(`${path.basename(p)}: ${off.length} of ${insns.length} are not 6 bytes`
            + ` (first: ${off[0].length} at +${off[0].addr - sec.addr})`);
        }
      } finally { f.close(); }
    }
    check(bad.length === 0, 'x86_64 __stubs decodes as exactly size/6 six-byte instructions',
      bad.length ? bad.slice(0, 3).join('; ')
        : `${x64Sections.length} section(s), ${total} stubs, all fixed-stride`);
  }

  /**
   * The same idea for arm64 is *not* implemented as a `__stubs` oracle, and the
   * reason is worth recording: every A64 instruction is 4 bytes, so a "4-byte
   * stride" oracle is satisfied by any function that returns 4 — including one
   * that returns 4 unconditionally. It cannot fail, so it is not a check. The
   * check below covers the arm64 length path where a failure is visible.
   */

  /**
   * The per-symbol sweep, over the repo's own generated fixtures.
   *
   * This tests the property the tool's documentation rests on: *a sweep from a
   * trustworthy start decodes cleanly*. So each defined symbol is used as a
   * start, and the sweep from it must length-decode every instruction to the end
   * of the section — no null, no gap.
   *
   * The span comparison is what makes this a test rather than a smoke signal. A
   * null length makes `linearSweep` stop, and a sweep that stops early returns a
   * shorter list that looks perfectly reasonable; only comparing the covered
   * bytes against the span swept notices.
   *
   * `universal.macho` carries an arm64 slice, so this runs on an x86_64 host.
   * That matters: an oracle that silently covers only the host's own
   * architecture is how a whole decoder ends up tested on one of the two
   * architectures it implements. The architecture list is asserted below for
   * exactly that reason — the fixtures are generated, so a gap here is a gap in
   * the suite rather than in the machine.
   */
  const FIXTURES = ['populated.macho', 'universal.macho', 'thin-arm64.macho', 'thin-arm64e.macho'];
  let symChecked = 0, symInsts = 0;
  const symBad = [];
  const archSeen = new Set();

  for (const name of FIXTURES) {
    const p = path.join(ROOT, 'test', 'fixtures', name);
    if (!fs.existsSync(p)) {
      skip(`per-symbol sweep (${name})`, 'fixture missing — run npm run test:fixtures');
      continue;
    }
    const f = opener(p);
    try {
      for (const s of slicesOf(f)) {
        const thin = parseThin(f, s.offset);
        if (!thin) continue;
        const arch = sliceArchName(thin.cputype, thin.cpusubtype);
        if (!supportedArch(arch)) continue;
        archSeen.add(arch);
        const sec = thin.sections.find((x) => x.sectname === '__text' && x.size > 0);
        if (!sec) continue;

        const starts = readSymbols(f, s.offset, thin).entries
          .filter((e) => e.defined && e.addr >= sec.addr && e.addr < sec.addr + BigInt(sec.size))
          .map((e) => Number(e.addr - sec.addr));

        for (const start of starts) {
          const insns = linearSweep(f, sec, arch, s.offset, { start, end: sec.size, max: 0 });
          symChecked++;
          symInsts += insns.length;
          const span = sec.size - start;
          const covered = insns.reduce((a, i) => a + i.length, 0);
          if (!insns.length) {
            symBad.push(`${name} ${arch} +${start}: nothing decoded`);
          } else if (covered !== span) {
            // Named as "stopped early" rather than "wrong lengths": the length
            // decoder returned null somewhere, and the span is what shows it.
            symBad.push(`${name} ${arch} +${start}: covered ${covered} of ${span} bytes`
              + ` — the sweep stopped early on a null length`);
          }
        }
      }
    } finally { f.close(); }
  }

  if (!symChecked) {
    skip('a sweep from a defined symbol decodes to the end of its section', 'no fixture symbols found');
  } else {
    check(symBad.length === 0, 'a sweep from a defined symbol decodes to the end of its section',
      symBad.length ? symBad.slice(0, 3).join('; ')
        : `${symChecked} symbol sweep(s), ${symInsts} instructions, none stopped early`);

    check(archSeen.size >= 2, 'the per-symbol sweep covers more than one architecture',
      `${[...archSeen].join(', ')} — a suite that only ever decodes the host's own`
      + ' architecture leaves half the implementation untested');
  }
}

/* ------------------------------------------------------------------ *
 * 7. sweep coverage
 * ------------------------------------------------------------------ */

section('sweep coverage');

{
  // Every byte of the range must be claimed exactly once. A sweep that skips a
  // byte or overlaps one fails here even when its individual instruction lengths
  // were all correct, and nothing else in this file would notice.
  let checked = 0;
  const bad = [];
  for (const p of ['/usr/lib/dyld', '/bin/ls', '/usr/bin/true', '/usr/bin/ssh']) {
    if (!fs.existsSync(p) || !isMachOFile(p)) continue;
    const f = opener(p);
    try {
      for (const [arch, want] of [['x86_64', 'x86_64'], ['arm64', 'arm64']]) {
        const slice = preferredSlice(f, want);
        if (!slice) continue;
        const sec = slice.thin.sections.find((x) => x.sectname === '__text' && x.size > 0);
        if (!sec) continue;
        const end = Math.min(sec.size, 8192);
        const insns = linearSweep(f, sec, arch, slice.offset, { start: 0, end, max: 0 });
        if (!insns.length) continue;
        checked++;
        const total = insns.reduce((a, i) => a + i.length, 0);
        if (total !== end) {
          bad.push(`${path.basename(p)} ${arch}: lengths sum to ${total}, span was ${end}`);
          continue;
        }
        // And the instructions must be contiguous: each one starts exactly where
        // the previous ended. A sweep that reported the right total while
        // leaving a hole would pass the check above.
        let cursor = sec.addr;
        for (const i of insns) {
          if (i.addr !== cursor) { bad.push(`${path.basename(p)} ${arch}: gap or overlap at ${hex(i.addr)}`); break; }
          cursor += BigInt(i.length);
        }
      }
    } finally { f.close(); }
  }

  if (!checked) {
    skip('a sweep covers its range contiguously', 'no __text section found on this host');
  } else {
    check(bad.length === 0, 'a sweep covers its range contiguously',
      bad.length ? bad.slice(0, 3).join('; ')
        : `${checked} section-architecture pair(s), first 8 KiB, lengths sum to the span with no gaps`);
  }

  // Every instruction address in a sweep must lie inside the section it was read
  // from. A section whose `addr` is wrong, or a `sliceBase` that is, produces
  // addresses in a neighbouring section while every length stays correct — the
  // decoder cannot detect that, so the sweep's caller has to be checked for it.
  let addrChecked = 0;
  const abad = [];
  for (const p of ['/usr/lib/dyld', '/bin/ls']) {
    if (!fs.existsSync(p) || !isMachOFile(p)) continue;
    const f = opener(p);
    try {
      const slice = preferredSlice(f, 'x86_64');
      if (!slice) continue;
      const sec = slice.thin.sections.find((x) => x.sectname === '__stubs' && x.size > 0);
      if (!sec) continue;
      const insns = linearSweep(f, sec, 'x86_64', slice.offset, { start: 0, end: sec.size, max: 0 });
      addrChecked++;
      const last = insns[insns.length - 1];
      if (last && last.addr + BigInt(last.length) !== sec.addr + BigInt(sec.size)) {
        abad.push(`${path.basename(p)}: sweep ends at ${hex(last.addr + BigInt(last.length))},`
          + ` section ends at ${hex(sec.addr + BigInt(sec.size))}`);
      }
    } finally { f.close(); }
  }
  if (!addrChecked) {
    skip('a sweep ends exactly on the section boundary', 'no x86_64 __stubs section on this host');
  } else {
    check(abad.length === 0, 'a sweep ends exactly on the section boundary',
      abad.length ? abad.join('; ') : `${addrChecked} section(s)`);
  }
}

/* ------------------------------------------------------------------ *
 * report
 * ------------------------------------------------------------------ */

console.log(`\n${passed} passed, ${failures.length} failed, ${skipped.length} skipped.`);
if (failures.length) {
  console.log('failed:');
  for (const f of failures) console.log(`  ${f}`);
}
if (skipped.length) {
  console.log('skipped — absent on this host, which is not a failure:');
  for (const s of skipped) console.log(`  ${s}`);
}
process.exit(failures.length ? 1 : 0);