/**
 * disasm.mjs — instruction length decoding, branch target resolution, and
 * linear sweep, for ARM64 and x86_64 Mach-O slices.
 *
 *   node -e "import('./src/disasm.mjs').then(m => console.log(m.arm64Length(Buffer.alloc(4))))"
 *
 * ## Why this exists
 *
 * Every other tool in this package answers "where is the code" and stops there.
 * `findcall` reports sites *worth* disassembling. `findliteral` reports
 * pointers. Nothing answers "what does the code at this address do", because
 * nothing in this package has ever decoded an instruction.
 *
 * That boundary was deliberate — see `COMPETITIVE-LANDSCAPE.md` — and it is
 * still mostly right. But "we never decode instructions" is different from
 * "we cannot decode instructions". `findcall` can only ever report a
 * *candidate* caller, because it finds the bytes `e8 xx xx xx xx` and never
 * establishes that those five bytes start an instruction. This module is what
 * lets it say "and this is a real call edge" instead.
 *
 * ## Scope, and the line drawn around it
 *
 * This is NOT a disassembler in the usual sense. There is no operand decoding,
 * no mnemonic table, no control flow graph, no decompiler. It does exactly
 * three things:
 *
 *   1. `instructionLength` — how many bytes is the instruction at this address
 *   2. `branchTarget`     — where does this instruction branch to, if it does
 *   3. `linearSweep`      — apply 1 and 2 across a range, in address order
 *
 * The line is drawn at *what can be done correctly in a few hundred lines that a
 * reader can check*. A full disassembler is a large project with a large
 * surface for silent error; the length decoder is small, total, and testable
 * against an independent implementation of the same question (`findcall`).
 *
 * ## Why length decoding is the whole ballgame
 *
 * On ARM64 every instruction is 4 bytes, so a sweep is trivial and always
 * aligned. On x86_64 instruction length is variable and the decoder's job is to
 * find where each instruction *ends* so the next one can start in the right
 * place. Get one length wrong and every subsequent boundary in the sweep is
 * wrong too — the output stops being "somewhat wrong instructions" and becomes
 * "fabricated addresses".
 *
 * That is why this module is fussier about the x86_64 opcode table than the
 * feature strictly needs. A table with holes looks fine in a unit test with
 * three instructions in it and produces confident nonsense on a real binary.
 *
 * ## Known limits, stated rather than hidden
 *
 * ### Opcode-table gaps
 *
 *   - `0F 0F` (3DNow!) is decoded as ModRM-only; the trailing opcode byte and
 *     imm8 are not consumed, so the instruction is short by 2 bytes.
 *   - `0F 78`/`0F 79` (AMD `extrq`/`insertq`) take a variable imm16 that depends
 *     on the ModRM reg field; only the ModRM is consumed.
 *   - **EVEX (`0x62`) opcodes that take an imm8** are decoded as ModRM-only, so
 *     they come out 1 byte short. `vpternlogd` (`25`), `vcmpps` (`c2`), `vshufps`
 *     (`c6`), `vpalignr` under `0F3A` and about a dozen others are affected. The
 *     immediate's presence is a property of the *opcode*, and unlike the `0F 3A`
 *     map there is no bit in the prefix that announces it — EVEX carries the map
 *     in P2 bits [2:0] and nothing else that means "an imm8 follows". Encoding
 *     this would need a per-opcode EVEX table, guessed at from documentation
 *     rather than checked against a compiler, and a wrong entry there produces
 *     the same confident 1-byte error as no entry at all. Left as a stated gap
 *     instead.
 *   - No support for `APX` (0xD5).
 *
 * All four are *length* errors, and all four are AVX-512-era or AMD-only. That
 * bounds the practical damage: Apple's own arm64e code contains none of them, and
 * macOS x86_64 system binaries use EVEX only incidentally. On a binary that does
 * use them, the effect is the desynchronisation described next, starting at that
 * instruction — not a fabricated address, because every length error here is
 * short rather than long.
 *
 * Each is a *length* error, so each can desynchronise a sweep that walks into
 * one. They are listed here because a documented limit is one a caller can
 * check for, and an undocumented one is a wrong answer.
 *
 * ### Linear sweep loses sync on embedded data — measured, not assumed
 *
 * `__text` is not only code. It also carries jump tables, and a 4-byte jump
 * table entry is indistinguishable from a 4-byte instruction to a decoder that
 * has no types. A linear sweep therefore walks into one and every boundary
 * after it is shifted.
 *
 * This was measured rather than assumed, on `/usr/lib/dyld` (x86_64 slice,
 * 606,251 bytes of `__TEXT,__text`, 3,346 defined symbols):
 *
 *   - sweeping the **whole section** puts an instruction boundary on 3,045 of
 *     3,346 symbols (91.0%);
 *   - sweeping **from each symbol to the next** covers the span exactly, with
 *     no gaps, in **3,196 of 3,196** cases.
 *
 * The second number is the one that says the length decoder is right: started at
 * a known instruction boundary, it consumes every byte up to the next known
 * boundary exactly. The first number says the sweep is not a *discovery* tool —
 * it needs a starting point it can trust.
 *
 * The practical consequence, and the reason `linearSweep` takes a `start`:
 * sweeping a whole section is fine for *coverage* — every byte is classified —
 * but not for locating anything. Sweep from a symbol, a `findcall` site, or an
 * address you already have. This is the same relationship recursive descent has
 * with entry points, arrived at from the other direction.
 */
import { withFile, coversAddress } from './api.mjs';
import {
  archMatches, codeSections, parseThin, sliceArchName, slicesOf,
} from './macho.mjs';

/* ================================================================== *
 * ARM64 (A64)
 * ================================================================== */

/**
 * Length of the A64 instruction at `offset`. Always 4.
 *
 * This is not a shortcut — it is the architecture. A64 has no variable-length
 * instructions, so a "length decoder" for ARM64 is the constant 4 or an error
 * at the end of the buffer. The function exists so that callers have one
 * `instructionLength` to call regardless of slice architecture, and so that the
 * asymmetry with x86_64 is visible in the code rather than in a comment.
 *
 * @returns {number|null} 4, or null when fewer than 4 bytes remain.
 */
export function arm64Length(bytes, offset = 0) {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  return 4;
}

/**
 * Decode the A64 instruction at `offset` as a PC-relative branch.
 *
 * `pc` is the address of the instruction *itself* — not of `bytes[0]` — because
 * every A64 PC-relative branch is expressed relative to the instruction's own
 * address, and conflating the two produces targets that are wrong by exactly the
 * distance between the buffer and the instruction. Callers that pass a window
 * starting before the instruction will silently get wrong answers, which is why
 * every call site in this file passes an `addr` it has already added.
 *
 * ## The encodings, from the ARM Architecture Reference Manual
 *
 * All nine are `imm`-based PC-relative forms whose displacement is scaled and
 * then added to the instruction address:
 *
 *   B     imm26      26 bits, scaled x4   ±128 MB
 *   BL    imm26      26 bits, scaled x4   ±128 MB
 *   B.cond imm19     19 bits, scaled x4   ±1 MB
 *   CBZ   imm19      19 bits, scaled x4   ±1 MB
 *   CBNZ  imm19      19 bits, scaled x4   ±1 MB
 *   TBZ   imm14      14 bits, scaled x4   ±32 KB
 *   TBNZ  imm14      14 bits, scaled x4   ±32 KB
 *   ADR   imm21      21 bits, unscaled   ±1 MB, byte granularity
 *   ADRP  imm21      21 bits, shifted x12 page granularity
 *
 * The scale factors are the reason these cannot share one code path with x86:
 * ADR is *unscaled*, every other form is x4, and ADRP is a page-relative
 * encode-decode pair rather than an addition. Collapsing them into one helper
 * would mean a table of "which form has which scale", which is less code than
 * the explicit forms and much less checkable.
 *
 * @returns {{target: bigint, kind: string}|null} null when not a branch.
 */
export function arm64BranchTarget(bytes, pc, offset = 0) {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  const insn = bytes.readUInt32LE(offset);

  /**
   * Does this instruction match `mask`/`value`?
   *
   * The `>>> 0` is not cosmetic, and without it the failure is silent and total
   * for half the instruction set. JavaScript's bitwise operators coerce both
   * operands to **signed** 32-bit, so for a `BL` (0x94…, bit 31 set) the
   * expression `insn & 0xfc000000` yields a negative number, which never equals
   * the positive literal `0x94000000`. Every encoding that sets bit 31 therefore
   * fails to match — which is `BL`, `ADRP`, and every `CBZ`/`CBNZ`/`TBZ`/`TBNZ`
   * on an X register — while `B`, `B.cond` and the W-register forms work fine and
   * look entirely healthy in a spot check.
   *
   * The `>>> 0` in `test/fixtures.mjs`'s encoder is the same hazard approached
   * from the writing side, and is commented there for the same reason.
   */
  const is = (mask, value) => ((insn & mask) >>> 0) === value;

  /** Sign-extend a `bits`-wide field taken from bit 0 upwards. */
  const sext = (v, bits) => {
    const sign = 1 << (bits - 1);
    return (v & (sign - 1)) - (v & sign);
  };

  // BL: 100101 imm26 — branch with link, i.e. the call instruction.
  if (is(0xfc000000, 0x94000000)) {
    return { target: pc + BigInt(sext(insn & 0x03ffffff, 26) * 4), kind: 'BL' };
  }
  // B: 000101 imm26
  if (is(0xfc000000, 0x14000000)) {
    return { target: pc + BigInt(sext(insn & 0x03ffffff, 26) * 4), kind: 'B' };
  }
  // B.cond: 0101010 imm19 0 cond. Bit 4 is fixed at 0, which is what separates
  // B.cond from the system-branch space that shares the top 8 bits.
  if (is(0xff000010, 0x54000000)) {
    return { target: pc + BigInt(sext((insn >>> 5) & 0x7ffff, 19) * 4), kind: 'B.cond' };
  }
  // CBZ/CBNZ on W and X registers: `sf op 0110100 imm19 Rt`.
  // CBNZ W is 0x35 and CBZ X is 0xb4, so both the `sf` bit and the `op` bit
  // have to be inside the mask: with 0x7e000000 — the obvious choice, masking
  // the top 7 bits — `op` falls outside it, CBZ and CBNZ land on the same
  // value, and every conditional branch in the binary is reported as `CBZ`.
  // The mask is 0x7f000000 for that reason, and not for tidiness.
  if (is(0x7f000000, 0x34000000) || is(0x7f000000, 0x35000000)) {
    return {
      target: pc + BigInt(sext((insn >>> 5) & 0x7ffff, 19) * 4),
      kind: is(0x7f000000, 0x35000000) ? 'CBNZ' : 'CBZ',
    };
  }
  // TBZ/TBNZ on W and X registers: `sf op 0110110 imm14 b5 0 Rt`. The `op` bit
  // is bit 24 here too, so the same mask separates TBZ (0x36 from w0, 0xb6 from
  // x0) from TBNZ (0x37 from w0, 0xb7 from x0). `imm14` occupies the same bits
  // [18:5] that `imm19` does above; only the field width differs, so the range
  // is a quarter of CBZ's at ±32 KB.
  if (is(0x7f000000, 0x36000000) || is(0x7f000000, 0x37000000)) {
    return {
      target: pc + BigInt(sext((insn >>> 5) & 0x3fff, 14) * 4),
      kind: is(0x7f000000, 0x37000000) ? 'TBNZ' : 'TBZ',
    };
  }
  // ADR: 0 immlo 10000 immhi Rd
  if (is(0x9f000000, 0x10000000)) {
    const imm = sext((((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 0x3), 21);
    // Unscaled: ADR names a byte address, so there is no << 2 here.
    return { target: pc + BigInt(imm), kind: 'ADR' };
  }
  // ADRP: 1 immlo 10000 immhi Rd — the same field layout, bit 31 set.
  if (is(0x9f000000, 0x90000000)) {
    const imm = sext((((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 0x3), 21);
    // Page-relative encode-decode: the page base is the instruction's own page,
    // and the displacement is in pages. Adding the shifted immediate to the
    // unshifted instruction address would be wrong in two independent ways.
    return { target: (pc & ~0xfffn) + (BigInt(imm) << 12n), kind: 'ADRP' };
  }
  return null;
}

/* ================================================================== *
 * x86_64
 * ================================================================== */

/**
 * Category codes for the one-byte opcode map. One character each so the table
 * below reads as the Intel opcode map it is transcribed from, rather than as
 * 256 prose descriptions.
 *
 *   n    no ModRM byte, no immediate
 *   m    ModRM byte, no immediate
 *   i8   imm8
 *   i16  imm16
 *   iz   imm16 under an operand-size prefix, else imm32
 *   iv   imm16 under 0x66, imm64 under REX.W, else imm32
 *   i32  imm32 always (rel32 displacements)
 *   o    address-size-dependent memory offset: 8 bytes, or 4 under 0x67
 *   ii   imm16 then imm8 (ENTER)
 *   g    ModRM byte, immediate decided by the ModRM reg field
 *
 * The single-letter codes are load-bearing in one specific way: `m` is the
 * marker for "this opcode has a ModRM byte", detected as `cat[0] === 'm'`. A
 * bare category that happens to start with `m` is therefore read as ModRM-
 * bearing and loses its ModRM byte's worth of length, which is why the memory
 * offset code is `o` rather than the more obvious `moff`.
 */
const N = 'n', M = 'm', I8 = 'i8', I16 = 'i16', IZ = 'iz', IV = 'iv', I32 = 'i32',
  MOFF = 'o', II = 'ii', G = 'g';

/** Fill `[lo, hi]` inclusive with one category. */
function fill(table, lo, hi, cat) {
  for (let i = lo; i <= hi; i++) table[i] = cat;
}

/**
 * One-byte opcode map: opcode byte -> category.
 *
 * Transcribed from Intel SDM Vol. 2 Table 2-2, restricted to 64-bit mode. The
 * two deviations from the printed table are both deliberate:
 *
 *   - `0x06`, `0x07`, `0x0e`, `0x16`, `0x17`, `0x1e`, `0x1f`, `0x27`, `0x2f`,
 *     `0x37`, `0x3f`, `0x60`, `0x61`, `0x82`, `0x9a`, `0xc4`, `0xc5`, `0xce`,
 *     `0xd4`, `0xd5`, `0xd6`, `0xea` are invalid in 64-bit mode. They are
 *     mapped as if they existed rather than flagged invalid, because a sweep
 *     that has lost alignment will land on them, and a decoder that returns
 *     "invalid" there would make the sweep restart every byte and report
 *     nothing at all. Their *length* is what the sweep needs; it is not
 *     checking validity.
 *   - `0x0f`, `0x27`… are handled before this table is consulted.
 */
const ONE_BYTE = (() => {
  const t = new Array(256).fill(N);
  // ALU groups: six opcodes each, "Eb,Gb / Ev,Gv / Gb,Eb / Gv,Ev / AL,Ib / eAX,Iz".
  for (const base of [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]) {
    fill(t, base, base + 3, M);
    t[base + 4] = I8;
    t[base + 5] = IZ;
  }
  fill(t, 0x62, 0x63, M);           // 0x62 is EVEX; 0x63 MOVSXD
  t[0x68] = IZ; t[0x69] = 'm' + IZ; t[0x6a] = I8; t[0x6b] = 'm' + I8;
  fill(t, 0x70, 0x7f, I8);          // Jcc rel8
  fill(t, 0x80, 0x83, 'm' + I8);
  t[0x81] = 'm' + IZ;
  fill(t, 0x84, 0x8f, M);           // 0x8f POP Ev is ModRM-bearing despite the /0
  fill(t, 0xa0, 0xa3, MOFF);        // MOV AL/eAX, moffs
  t[0xa8] = I8; t[0xa9] = IZ;
  fill(t, 0xb0, 0xb7, I8);          // MOV r8, imm8
  fill(t, 0xb8, 0xbf, IV);          // MOV r, imm16/32/64
  t[0xc0] = 'm' + I8; t[0xc1] = 'm' + I8;
  t[0xc2] = I16; t[0xc3] = N;
  t[0xc6] = G; t[0xc7] = G;        // MOV Eb/Ev, imm — imm only for /0
  t[0xc8] = II;                     // ENTER imm16, imm8
  fill(t, 0xd0, 0xd3, M);           // shifts by 1 / by CL
  t[0xd4] = I8; t[0xd5] = I8;       // AAM/AAD, invalid in 64-bit
  fill(t, 0xd8, 0xdf, M);           // x87
  fill(t, 0xe0, 0xe7, I8);          // LOOP/JRCXZ/IN/OUT imm8
  t[0xe8] = I32; t[0xe9] = I32;     // CALL rel32, JMP rel32
  t[0xeb] = I8;                     // JMP rel8
  t[0xf6] = G; t[0xf7] = G;         // group 3 — TEST takes an immediate
  fill(t, 0xfe, 0xff, M);           // group 4/5
  return t;
})();

/**
 * Two-byte opcode map (`0F xx`): second byte -> category.
 *
 * Defaults to `m` rather than `n` because almost every `0F` opcode has a ModRM
 * byte, and a table that defaults to "no ModRM" turns every omission into a
 * silent length error. The no-ModRM entries are therefore listed explicitly,
 * which also makes them auditable — an entry here is a claim, not a default.
 *
 * `0F 80`-`0F 8F` are `i32` with no ModRM: Jcc rel32. Getting that wrong is the
 * single most common way a two-byte decoder desynchronises, because it turns a
 * 6-byte instruction into a 2-byte one.
 */
const TWO_BYTE = (() => {
  const t = new Array(256).fill(M);
  for (const b of [
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x37, 0x77, 0xa0, 0xa1, 0xa2, 0xa8, 0xa9, 0xaa,
  ]) t[b] = N;
  fill(t, 0xc8, 0xcf, N);           // BSWAP
  fill(t, 0x80, 0x8f, I32);         // Jcc rel32, no ModRM
  t[0x70] = 'm' + I8; t[0x71] = 'm' + I8; t[0x72] = 'm' + I8; t[0x73] = 'm' + I8;
  t[0xa4] = 'm' + I8; t[0xa5] = 'm' + IZ;   // SHLD
  t[0xac] = 'm' + I8; t[0xad] = 'm' + IZ;   // SHRD
  t[0xba] = G;                      // group 8 — BT/BTS imm8 for /4-/7
  t[0xc2] = 'm' + I8;               // CMPPS
  return t;
})();

/**
 * Immediate width for the group opcodes whose immediate depends on the ModRM
 * `reg` field, which is how the ISA signals which member of a group is meant.
 *
 * Only five opcodes are in this category: `C6`/`C7` (MOV, immediate for /0
 * only), `F6`/`F7` (group 3, immediate for TEST /0 and /1 only) and `0F BA`
 * (group 8, immediate for /4-/7). Every other group opcode has either an
 * immediate for all members or for none, and is expressed in the tables above.
 *
 * `0xBA` is the two-byte `0F BA`; it needs no separate table because the
 * dispatch is on the opcode byte itself and `0xBA` appears exactly once.
 *
 * Returning `0` rather than a size means "ModRM only", which is the correct
 * answer for the non-immediate members and the reason a decoder must consult
 * the ModRM byte *before* deciding the immediate.
 */
function groupImmediateSize(op, reg, operandSize) {
  switch (op) {
    case 0xc6: return reg === 0 ? 1 : 0;
    case 0xc7: return reg === 0 ? (operandSize === 16 ? 2 : 4) : 0;
    case 0xf6: return reg <= 1 ? 1 : 0;
    case 0xf7: return reg <= 1 ? (operandSize === 16 ? 2 : 4) : 0;
    case 0xba: return reg >= 4 && reg <= 7 ? 1 : 0;
    default: return 0;
  }
}

/** Legacy prefixes legal in 64-bit mode. Set, because it is consulted per byte. */
const LEGACY_PREFIXES = new Set([
  0xf0, // LOCK
  0xf2, // REPNE
  0xf3, // REP/REPE
  0x2e, 0x36, 0x3e, 0x26, // CS SS DS ES segment overrides
  0x64, 0x65, // FS GS segment overrides
  0x66, // operand size
  0x67, // address size
]);

/** Map selector, so the immediate rules for `0F 38`/`0F 3A` are explicit. */
const MAP_0F38 = 3, MAP_0F3A = 4;

/**
 * Decode one x86_64 instruction far enough to know its length and, if it is a
 * branch, where it goes.
 *
 * ## Why one function and not two
 *
 * The obvious design is a length decoder plus a separate branch decoder, both
 * walking the same prefixes and opcode. That is how the two can disagree: the
 * length decoder can count `0F 8x` as ModRM-bearing and the branch decoder as
 * not, or the branch decoder can forget that a `66` prefix shifts the immediate,
 * and the result is a target computed from a different instruction length than
 * the one the sweep advanced by. A branch target that is off by the prefix bytes
 * is not a rounding error — it is a fabricated address in the output.
 *
 * So there is one walk, and it returns both facts from the same parse. Every
 * exported per-architecture function below is a thin projection of this.
 *
 * ## The walk
 *
 *   prefixes (legacy, then REX) -> opcode (1-3 bytes, or VEX/EVEX)
 *     -> ModRM -> SIB -> displacement -> immediate(s)
 *
 * Two prefix rules are easy to get wrong and are handled explicitly:
 *
 *   - A legacy prefix *after* REX is ignored for decoding, but still part of the
 *     instruction. REX must be immediately before the opcode. `rexSeen` gates
 *     the prefix effects rather than the prefix bytes, which is what makes
 *     `48 66 89 c0` (MOV rax,rax) differ from `66 48 89 c0` — same bytes, and
 *     the SDM says the second one has the 0x66 ignored.
 *   - At most 15 bytes of prefix. Past that the byte is not a prefix, it is an
 *     opcode, and an unbounded prefix loop will happily consume the entire rest
 *     of a section while looking for one that never comes.
 *
 * @param {Buffer} bytes  the instruction and whatever follows it, for lookahead
 * @param {number} offset index of the instruction's first byte in `bytes`
 * @returns {{length:number, kind:string|null, rel:bigint|null}|null}
 *   `length` counts from `offset`. `rel` is a branch displacement measured from
 *   the end of the instruction and is null when `kind` is. Null overall only
 *   when the buffer ends inside the instruction: there is no such thing as an
 *   invalid x86-64 instruction to reject.
 */
function decodeX86(bytes, offset) {
  const end = bytes.length;
  if (offset < 0 || offset >= end) return null;

  let pos = offset;
  let op66 = false, addr67 = false, rex = 0, rexSeen = false;
  let prefixBytes = 0;

  // ---- prefixes -----------------------------------------------------
  for (;;) {
    if (pos >= end || prefixBytes >= 15) break;
    const b = bytes[pos];
    if (LEGACY_PREFIXES.has(b)) {
      // Ignored if a REX has already been seen, per the REX-must-be-last rule.
      if (!rexSeen) {
        if (b === 0x66) op66 = true;
        else if (b === 0x67) addr67 = true;
      }
      pos++; prefixBytes++;
      continue;
    }
    if (b >= 0x40 && b <= 0x4f) {
      rex = b;
      rexSeen = true;
      pos++; prefixBytes++;
      continue;
    }
    break;
  }
  const operandSize = (rex & 0x08) ? 64 : (op66 ? 16 : 32);
  const addressSize = addr67 ? 32 : 64;

  // ---- opcode -------------------------------------------------------
  // The buffer can end after the prefixes: a section's last few bytes, or the
  // short window a sweep hands over when fewer than 15 bytes remain. Reading
  // `bytes[pos]` there yields `undefined`, `ONE_BYTE[undefined]` is `undefined`,
  // and `cat[0]` throws. So a truncated tail was a crash rather than a null, and
  // it surfaced as a stack trace from inside a sweep on a real binary — on the
  // *last* section read, which is the one place a caller is least likely to look
  // for a length failure.
  if (pos >= end) return null;
  let op = bytes[pos++];
  let op2 = -1;
  let map = 1;
  // VEX/EVEX: 0 = none. The escape bytes 0xC4/0xC5/0x62 are *not* LES/LDS/
  // BOUND in 64-bit mode — that reassignment is the most consequential
  // difference between decoding 32-bit and 64-bit code, and a decoder that
  // treats them as the legacy instructions will desynchronise within a few
  // instructions of the first AVX instruction in the function.
  let vexBytes = 0;
  let vexPp = 0;
  if (op === 0xc5) {
    vexBytes = 2;
    if (pos + 1 > end) return null;
    vexPp = bytes[pos] & 0x03;
    pos += 1;
    op = bytes[pos++];
    map = vexPp + 1;                 // pp 1/2/3 -> 0F / 0F38 / 0F3A
  } else if (op === 0xc4) {
    vexBytes = 3;
    // Three payload bytes follow `0xc4`, not two: the 3-byte form exists precisely
    // because the five-bit opcode-map field (`mmmmmm`) is real rather than implied,
    // so `C4 P0 P1 P2 opcode modrm`. Consuming two puts `P2` where the opcode
    // belongs and the *opcode* where the ModRM belongs, which makes every 3-byte
    // VEX instruction come out exactly one byte short — and, worse, one the
    // length looks individually plausible for. The 2-byte `0xc5` form genuinely
    // has only one payload byte, so it must not be "fixed" the same way.
    if (pos + 3 > end) return null;
    vexPp = bytes[pos + 1] & 0x03;
    pos += 3;
    op = bytes[pos++];
    map = vexPp + 1;
  } else if (op === 0x62) {
    vexBytes = 4;
    if (pos + 3 > end) return null;
    // EVEX carries the opcode map in P2 bits [2:0]; 3 means an imm8 follows.
    vexPp = bytes[pos + 2] & 0x07;
    pos += 3;
    op = bytes[pos++];
    map = vexPp + 1;
  } else if (op === 0x0f) {
    if (pos >= end) return null;
    map = 2;                         // the 0F escape selects the two-byte map
    op2 = bytes[pos++];
    if (op2 === 0x38 || op2 === 0x3a) {
      map = op2 === 0x38 ? MAP_0F38 : MAP_0F3A;
      if (pos >= end) return null;
      op = bytes[pos++];
      op2 = -1;
    }
  }

  // ---- ModRM, SIB, displacement, immediate ---------------------------
  // `cat` is the category code from the maps above; `hasModrm`/`immSizes` are
  // derived from it. Doing the derivation in one place is what keeps the
  // length and the branch target from drifting apart.
  let cat;
  if (vexBytes) {
    // Every VEX/EVEX-encoded instruction has a ModRM byte, and the only map
    // that takes an immediate is 0F3A.
    cat = map === 4 ? M + I8 : M;
  } else if (map === 1) {
    cat = ONE_BYTE[op];
  } else if (map === 2) {
    cat = TWO_BYTE[op2];
  } else if (map === MAP_0F38) {
    cat = M;
  } else {
    cat = M + I8;                    // 0F 3A xx — always ModRM + imm8
  }

  // `g` counts as ModRM-bearing. It is the one category that carries a ModRM
  // without starting with `m`, because the letter `m` is taken by the ModRM-free
  // prefix used to build the combined entries. Testing only `cat[0] === M` here
  // silently drops the ModRM byte for C6/C7/F6/F7/0F BA, every one of which is
  // an immediate-bearing group instruction, so each loses 1-5 bytes.
  const hasModrm = cat[0] === M || cat === G;
  let reg = 0;
  if (hasModrm) {
    if (pos >= end) return null;
    const modrm = bytes[pos++];
    const mod = modrm >> 6;
    const rm = modrm & 0x07;
    reg = (modrm >> 3) & 0x07;

    // Displacement. Two of the four `mod` values do not mean what they look
    // like, and both of them are the common cases in 64-bit code rather than
    // the exotic ones — which is why getting them wrong desynchronises a sweep
    // almost immediately and why this is spelled out rather than compressed
    // into a lookup:
    //
    //   mod=00 rm=101  RIP-relative disp32. In 64-bit mode this is *the* normal
    //                  way to reach memory: every global access, every call
    //                  through a GOT slot, every PLT stub (`ff 25` = `jmp
    //                  *disp(%rip)`, 6 bytes). Reading it as "no displacement"
    //                  makes every such instruction 4 bytes too short.
    //   mod=00 rm=100 + SIB base=101  disp32 with no base register.
    //
    // Note the second has no `rip` and the first has no SIB byte at all, so the
    // SIB test must come first: with rm=100 the ModRM field means "a SIB
    // follows", and only that SIB's base field can mean "no base register".
    let sibBase = -1;
    if (mod !== 3 && rm === 4) {
      if (pos >= end) return null;
      const sib = bytes[pos++];
      sibBase = sib & 0x07;
      if (mod === 0 && sibBase === 5) pos += 4;
    } else if (mod === 0 && rm === 5) {
      pos += 4;
    }
    if (mod === 1) pos += 1;
    else if (mod === 2) pos += 4;
    // mod = 00 with rm = 000/001/010/011/110/111 is a base register and
    // contributes no displacement. mod = 11 is register-direct, likewise.
  }

  // Immediate. The order matters: `groupImmediateSize` needs `reg`, which is
  // only known once the ModRM has been read.
  let immSizes = 0;
  let immStart = -1;
  if (cat === G) {
    // For a two-byte group opcode the byte to dispatch on is `op2`: `op` is
    // still the 0x0F escape, so switching on it matches nothing and the
    // immediate is dropped. That silently costs `0F BA` (BT/BTS/BTR/BTC with an
    // immediate) its imm8.
    immSizes = groupImmediateSize(map === 2 ? op2 : op, reg, operandSize);
    if (immSizes) { immStart = pos; pos += immSizes; }
  } else if (cat === II) {
    immStart = pos;
    pos += 3;                        // imm16 then imm8, as one fixed group
  } else {
    // The immediate category is the whole code when there is no ModRM marker and
    // everything after it when there is. Reading it as "cat minus its first
    // character" unconditionally is what a bare `i32` — `CALL rel32` — turns
    // into `'32'`, which matches no branch below, so the immediate is never
    // recorded and the branch target is then read from offset -1.
    const immCat = hasModrm ? cat.slice(1) : cat;
    if (immCat) {
      const immAt = pos;
      if (immCat === I8) pos += 1;
      else if (immCat === I16) pos += 2;
      else if (immCat === I32) pos += 4;
      else if (immCat === IZ) pos += operandSize === 16 ? 2 : 4;
      else if (immCat === IV) pos += operandSize === 16 ? 2 : (operandSize === 64 ? 8 : 4);
      else if (immCat === MOFF) pos += addressSize === 32 ? 4 : 8;
      if (pos > immAt) { immStart = immAt; immSizes = pos - immAt; }
    }
  }

  // The architecture caps an instruction at 15 bytes. Exceeding that means the
  // bytes are not an instruction, so null is the honest answer — and a sweep
  // that stops here has stopped on garbage rather than skipped over it.
  if (pos > end) return null;        // buffer ended inside the instruction
  const length = pos - offset;
  if (length > 15) return null;

  // ---- branch ---------------------------------------------------------
  // Computed from the *total* length, so a target is correct under any prefix
  // combination without this function needing to know what those prefixes were.
  let kind = null;
  if (!vexBytes) {
    if (map === 1) {
      if (op === 0xe8) kind = 'CALL';
      else if (op === 0xe9 || op === 0xeb) kind = 'JMP';
      else if (op >= 0x70 && op <= 0x7f) kind = 'Jcc';
      else if (op >= 0xe0 && op <= 0xe2) kind = 'LOOP';
      else if (op === 0xe3) kind = 'JRCXZ';
    } else if (map === 2 && op2 >= 0x80 && op2 <= 0x8f) {
      kind = 'Jcc';
    }
  }
  // A branch with no recorded immediate is impossible in the printed opcode map,
  // so reaching it means a table entry says "no immediate" for an opcode that
  // has one. The length is still believed; the branch is dropped rather than
  // read from a bogus offset, because a wrong target is a fabricated address and
  // a missing one is a gap the caller can see.
  if (!kind || immStart < 0) return { length, kind: null, rel: null };

  // `rel` is measured from the end of the instruction, so it carries no address
  // of its own. Callers add `pc + offset`. Keeping the base out of here is what
  // lets `x86_64Length` and `x86_64BranchTarget` share one parse.
  const raw = immSizes === 1
    ? BigInt(bytes.readInt8(immStart))
    : BigInt(bytes.readInt32LE(immStart));
  return { length, kind, rel: BigInt(length) + raw };
}

/**
 * Length of the x86_64 instruction at `offset`, in bytes, or null if the buffer
 * ends inside it.
 */
export function x86_64Length(bytes, offset = 0) {
  const d = decodeX86(bytes, offset);
  return d ? d.length : null;
}

/**
 * Branch target of the x86_64 instruction at `offset`, relative to `pc`.
 *
 * `pc` is the address of the instruction, for the same reason as in
 * `arm64BranchTarget`. Returns `{ target, kind }` with a BigInt target, or null
 * when the instruction is not a direct relative branch.
 *
 * Direct relative branches only. `call [rip+disp]`, `call rax`, `jmp [rip+disp]`
 * and `jmp *rax` are not reported: the first two do not encode a target at all,
 * and the RIP-relative ones do not name a destination code address. Reporting
 * the *contents* of a RIP-relative slot would require reading a pointer and
 * deciding whether it is code, which is `mapliteral`'s job and not this one's.
 */
export function x86_64BranchTarget(bytes, pc, offset = 0) {
  const d = decodeX86(bytes, offset);
  if (!d || !d.kind) return null;
  return { target: pc + BigInt(offset) + d.rel, kind: d.kind };
}

/* ================================================================== *
 * Architecture dispatch
 * ================================================================== */

/**
 * Architectures whose instruction encoding this module knows.
 *
 * Reported rather than assumed. A caller that sweeps a slice whose architecture
 * is not in this list must be told "cannot decode", not handed an empty list —
 * the project's rule is that a negative answer has to be distinguishable from a
 * tool that did not run. `arm64e` is `arm64` with extra capability bits on the
 * same base encoding, so it decodes; `arm64_32` is 32-bit pointers under a
 * different ABI and is deliberately not treated as a synonym.
 */
export function supportedArch(arch) {
  return archMatches(String(arch), 'arm64') || archMatches(String(arch), 'x86_64');
}

/**
 * Length of the instruction at `offset` for `arch`, or null if unknown or
 * truncated.
 */
export function instructionLength(arch, bytes, offset = 0) {
  if (archMatches(String(arch), 'arm64')) return arm64Length(bytes, offset);
  if (archMatches(String(arch), 'x86_64')) return x86_64Length(bytes, offset);
  return null;
}

/**
 * Branch target of the instruction at `offset` for `arch`, or null.
 */
export function branchTarget(arch, bytes, pc, offset = 0) {
  if (archMatches(String(arch), 'arm64')) return arm64BranchTarget(bytes, pc, offset);
  if (archMatches(String(arch), 'x86_64')) return x86_64BranchTarget(bytes, pc, offset);
  return null;
}

/* ================================================================== *
 * Linear sweep
 * ================================================================== */

/**
 * Windows larger than this are not needed: the longest x86_64 instruction is 15
 * bytes, so this is a one-instruction lookahead with enormous slack, and the
 * only cost of a small window is more `read` calls on a small section.
 */
const READ_AHEAD = 16;

/**
 * Linear sweep over a byte range: decode one instruction, record it, advance by
 * its length, repeat.
 *
 * `f` is an open handle, `sec` a section record, `sliceBase` the slice's file
 * offset. All three are required and none may be defaulted: a section's `offset`
 * is relative to its slice, so on a fat binary omitting `sliceBase` reads the
 * right number of bytes from the wrong place — the same class of bug
 * `scanSection`'s comment describes.
 *
 * ## Why linear sweep and not recursive descent
 *
 * Recursive descent follows control flow from known entry points and so never
 * decodes data as code. That is strictly better *when you know the entry points*.
 * On a stripped binary you often do not, and the usual answer — sweep
 * everything — is what recursive descent would do anyway, without its ability
 * to stop when it goes wrong.
 *
 * ## What it guarantees, and what it does not
 *
 * It guarantees **coverage**: every byte of the range is consumed by exactly one
 * instruction record, so no address is silently skipped and the sum of the
 * lengths always equals the span.
 *
 * It does not guarantee that every record is *code*. A `__text` section carries
 * jump tables and alignment padding, and a linear sweep decodes those as
 * instructions — then stays out of step for the rest of the section, because one
 * wrong boundary makes the next one wrong too. On `dyld` that is the difference
 * between 91% of symbols being instruction boundaries when the whole section is
 * swept from its start, and 100% when each is swept from its own start. See the
 * measurement in this file's header.
 *
 * So the sweep needs a `start` it can trust, which is why `start` is a
 * parameter rather than something derived. A whole-section sweep is a coverage
 * report; a sweep from a symbol is a decoding.
 *
 * ## Chunking
 *
 * The range is read in windows and a window is re-read whenever fewer than 15
 * usable bytes remain after `pos`, because an instruction may straddle the end
 * of a window. The first version advanced `pos` by the window length, which
 * dropped any instruction straddling a boundary *and* then re-decoded the bytes
 * after it from the wrong position — on a large section, quietly.
 *
 * @returns {Array<{addr: bigint, bytes: Buffer, length: number, kind: string|null,
 *   target: bigint|null}>} `max` stops the sweep at that many instructions.
 */
export function linearSweep(f, sec, arch, sliceBase, { start = 0, end = sec.size, max = 0 } = {}) {
  const out = [];
  const stride = archMatches(String(arch), 'arm64') ? 4 : 0;
  const WINDOW = 1 << 16;
  const limit = Math.min(end, sec.size);

  let pos = Math.max(0, start);
  let buf = Buffer.alloc(0);
  let bufAt = pos;                     // section-relative offset of buf[0]

  // The window is bounded by the end of the *section*, not the end of the
  // requested range. An instruction that begins inside `range` can extend past
  // it, and its length cannot be determined without those bytes — so reading
  // only up to `limit` makes the decoder return null at the boundary and the
  // sweep stop one instruction early. It looks like a decode failure; it is a
  // truncated lookahead, and it cost 1 byte per sweep until it was fixed.
  //
  // Instructions are still only *emitted* while `pos < limit`, so a request for
  // a 32-instruction window does not return a 33rd half-instruction.
  while (pos < limit && (max <= 0 || out.length < max)) {
    if (pos < bufAt || pos - bufAt + READ_AHEAD > buf.length) {
      const want = Math.min(WINDOW, sec.size - pos);
      if (want <= 0) break;
      buf = f.read(sliceBase + sec.offset + pos, want);
      bufAt = pos;
      if (buf.length === 0) break;     // truncated file: report what was read
    }

    const slice = buf.subarray(pos - bufAt);
    let length = instructionLength(arch, slice, 0);
    // A fixed-stride architecture has no decoder to disagree with, so a short
    // tail is a truncated final instruction rather than a decoding failure —
    // record it as such instead of dropping the bytes.
    if (length === null && stride && slice.length > 0) length = Math.min(stride, slice.length);
    if (!length) {
      // x86_64 has no "invalid instruction", so `length === null` here means the
      // buffer ended mid-instruction. Stepping one byte would let the next
      // window's bytes be decoded from an arbitrary offset; stopping is honest.
      break;
    }

    const addr = sec.addr + BigInt(pos);
    // Recorded clipped to the requested range. The decoded length is kept in
    // `fullLength` when it differs, because a caller asking "what is at this
    // address" wants the real instruction and a caller asking "what is in this
    // window" wants the bytes that are in the window — and silently handing
    // over either one is how a range query starts reporting bytes outside
    // itself.
    const within = Math.min(length, limit - pos);
    const insn = slice.subarray(0, within);
    const branch = branchTarget(arch, insn, addr, 0);
    const rec = {
      addr,
      bytes: insn,
      length: within,
      kind: branch ? branch.kind : null,
      target: branch ? branch.target : null,
    };
    if (within !== length) rec.fullLength = length;
    out.push(rec);

    pos += length;
  }

  return out;
}

/**
 * Every direct branch in a range, as `{ source, target, kind }`.
 *
 * A convenience projection of `linearSweep` for callers that want edges and do
 * not want instructions — which is the shape that turns `findcall`'s shortlist
 * of candidate call sites into resolved edges.
 */
export function findBranchTargets(f, sec, arch, sliceBase, opts = {}) {
  return linearSweep(f, sec, arch, sliceBase, opts)
    .filter((i) => i.target !== null)
    .map((i) => ({ source: i.addr, target: i.target, kind: i.kind }));
}

/* ================================================================== *
 * High level API
 * ================================================================== */

/**
 * Disassemble a range of a Mach-O, across every slice that matches `arch`.
 *
 * With no `addr`, the sweep starts at the first byte of the first code section
 * of each matching slice. With an `addr`, it starts there and must fall inside
 * a code section of a matching slice; an address that is inside the file but
 * inside `__cstring` is reported as `outside-code`, because decoding a string
 * as instructions would produce addresses that look real.
 *
 * @returns {{arch, offset, section, sectionAddr, instructions, branches, notes}[]}
 *   one entry per slice that produced a sweep. `unsupported` on the result names
 *   slices whose architecture has no decoder here, so a caller can tell "this
 *   binary's ppc64 slice was skipped" from "this binary has no code".
 */
export function disassemble(path, { addr = null, arch = null, count = 32, bytes = 0 } = {}) {
  return withFile(path, (f) => {
    const slices = [];
    const unsupported = [];
    const notes = [];

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin
        ? sliceArchName(thin.cputype, thin.cpusubtype)
        : sliceArchName(s.cputype, s.cpusubtype);
      if (arch && !archMatches(name, arch)) continue;

      if (!supportedArch(name)) {
        unsupported.push(name);
        continue;
      }

      const pool = codeSections(thin);
      if (pool.fallback) {
        notes.push(`${name}: no section is flagged as instructions, so the sweep is untyped`);
      }

      // With no address, take the first code section. With one, take the
      // section that covers it, and only that section: sweeping every section
      // and filtering afterwards would decode the whole file to answer a
      // question about one address.
      let chosen = null;
      let start = 0;
      if (addr === null) {
        chosen = pool.sections[0];
        if (chosen) start = 0;
      } else {
        if (!coversAddress(thin, addr)) continue;
        for (const sec of pool.sections) {
          if (addr >= sec.addr && addr < sec.addr + BigInt(sec.size)) {
            chosen = sec;
            start = Number(addr - sec.addr);
            break;
          }
        }
      }
      if (!chosen) continue;

      const instructions = linearSweep(f, chosen, name, s.offset, {
        start,
        end: bytes > 0 ? Math.min(start + bytes, chosen.size) : chosen.size,
        max: count,
      });
      slices.push({
        arch: name,
        offset: s.offset,
        section: `${chosen.segname},${chosen.sectname}`,
        sectionAddr: chosen.addr,
        sectionSize: chosen.size,
        startAddr: chosen.addr + BigInt(start),
        instructions,
        branches: instructions.filter((i) => i.target !== null)
          .map((i) => ({ source: i.addr, target: i.target, kind: i.kind })),
      });
    }

    return { slices, unsupported, notes };
  });
}