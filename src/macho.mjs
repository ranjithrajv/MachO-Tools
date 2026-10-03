/**
 * macho.mjs — a Mach-O reader.
 *
 * Fat-header parsing, load commands, symbol tables, `__TEXT` literal search and
 * file-offset-to-vaddr mapping. It knows nothing about any application; it knows
 * about the file format.
 *
 * ## Why this is one module
 *
 * These tools were written one at a time and each grew its own reader. They
 * diverged, and the divergence produced bugs that no amount of testing on the
 * binary the tools were written for would have found:
 *
 *   - one tool hardcoded `const SLICE = 0x4000` — one binary's x86_64 slice
 *     offset inside its own fat header, correct for exactly one file on earth.
 *     Against any other universal binary it read load commands out of the middle
 *     of a data section and returned a confident, wrong answer.
 *   - another read the architecture list at a fixed offset, which is only right
 *     for a *thin* Mach-O, so on a universal binary its section walk silently
 *     failed and it scanned a default window containing nothing.
 *   - a third treated an absent architecture as fatal rather than a preference,
 *     so it failed outright on an arm64-only binary.
 *
 * Every one of those is a *parse* bug, and they were only reachable by pointing
 * a tool at a binary it was not written for. Centralising the parsing is what
 * makes them fixable once.
 *
 * ## Why the fat header is parsed rather than assumed
 *
 * A universal binary's slices sit at offsets given by the fat header, and those
 * offsets depend on the order and number of architectures in the build. There
 * is no default, and the numbers vary far enough to matter: in one measured
 * pair the slices sat at 0x4000 and 0xf16c000. A reader that assumed 0x4000
 * would work on that binary and nowhere else.
 *
 * ## Which slice to use
 *
 * Not "the first one". A universal binary can be stripped on one architecture
 * and not the other, so `richestSlice` takes the one with the most symbols and
 * `preferredSlice` treats a requested architecture as a preference that falls
 * back to the richest rather than a requirement that returns null.
 */

import { openSync, closeSync, readSync, fstatSync } from 'node:fs';

/** Mach-O and fat-header magics, big- and little-endian. */
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_MAGIC_32 = 0xfeedface;
export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;

export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_SEGMENT_64 = 0x19;
export const LC_UUID_CMD = 0x1b;
export const LC_RPATH_CMD = 0x1c;
export const LC_MAIN_CMD = 0x29;
export const LC_SOURCE_VERSION_CMD = 0x2b;

/**
 * Load-command names, for `describe --loads`.
 *
 * A *description* table, deliberately. It exists so `parseThin` can print what a
 * binary declares without this reader having to understand what any of it means
 * — the line between "this file says it links libSystem" and "this reader can
 * resolve libSystem" is the project's own "will not do" boundary, and naming the
 * commands does not cross it. `LC_ENCRYPTION_INFO` is in here for the same
 * reason: knowing a binary is encrypted is a fact about it.
 *
 * Keys are the numeric commands; the `0x80000000` bit is stripped first, because
 * `LC_REQ_DYLD` only ever *adds* to a base command and every consumer here wants
 * the base name. An unmapped command is reported by number rather than dropped,
 * so an unrecognised load command is visible instead of silently absent.
 */
export const LOAD_COMMANDS = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0x3: 'LC_SYMSEG',
  0x4: 'LC_THREAD',
  0x5: 'LC_UNIXTHREAD',
  0x6: 'LC_LOADFVMLIB',
  0x7: 'LC_IDFVMLIB',
  0x8: 'LC_IDENT',
  0x9: 'LC_FVMFILE',
  0xa: 'LC_PREPAGE',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB',
  0xd: 'LC_ID_DYLIB',
  0xe: 'LC_LOAD_DYLINKER',
  0xf: 'LC_ID_DYLINKER',
  0x10: 'LC_PREBOUND_DYLIB',
  0x11: 'LC_ROUTINES',
  0x12: 'LC_SUB_FRAMEWORK',
  0x13: 'LC_SUB_UMBRELLA',
  0x14: 'LC_SUB_CLIENT',
  0x15: 'LC_SUB_LIBRARY',
  0x16: 'LC_TWOLEVEL_HINTS',
  0x17: 'LC_PREBIND_CKSUM',
  0x18: 'LC_LOAD_WEAK_DYLIB',
  0x19: 'LC_SEGMENT_64',
  0x1a: 'LC_ROUTINES_64',
  0x1b: 'LC_UUID',
  0x1c: 'LC_RPATH',
  0x1d: 'LC_CODE_SIGNATURE',
  0x1e: 'LC_SEGMENT_SPLIT_INFO',
  0x1f: 'LC_REEXPORT_DYLIB',
  0x20: 'LC_LAZY_LOAD_DYLIB',
  0x21: 'LC_ENCRYPTION_INFO',
  0x22: 'LC_DYLD_INFO',
  0x23: 'LC_DYLD_INFO_ONLY',
  0x24: 'LC_LOAD_UPWARD_DYLIB',
  0x25: 'LC_VERSION_MIN_MACOSX',
  0x26: 'LC_VERSION_MIN_IPHONEOS',
  0x27: 'LC_FUNCTION_STARTS',
  0x28: 'LC_DYLD_ENVIRONMENT',
  0x29: 'LC_MAIN',
  0x2a: 'LC_DATA_IN_CODE',
  0x2b: 'LC_SOURCE_VERSION',
  0x2c: 'LC_DYLIB_CODE_SIGN_DRS',
  0x2d: 'LC_ENCRYPTION_INFO_64',
  0x2e: 'LC_LINKER_OPTION',
  0x2f: 'LC_LINKER_OPTIMIZATION_HINT',
  0x30: 'LC_VERSION_MIN_TVOS',
  0x31: 'LC_VERSION_MIN_WATCHOS',
  0x32: 'LC_BUILD_VERSION',
  0x33: 'LC_DYLD_EXPORTS_TRIE',
  0x34: 'LC_DYLD_CHAINED_FIXUPS',
  0x35: 'LC_FILESET_ENTRY',
  0x36: 'LC_ATOM_INFO',
  0x37: 'LC_FUNCTION_VARIANTS',
  0x38: 'LC_FUNCTION_VARIANT_FIXUPS',
  0x39: 'LC_TARGET_TRIPLE',
};

/** Name a load command, or report its number when this table has no entry. */
export function loadCommandName(cmd) {
  // LC_REQ_DYLD is 0x80000000 and is *added* to a base command, so stripping it
  // finds LC_RPATH for 0x8000001c. It is never a command on its own.
  return LOAD_COMMANDS[cmd & 0x7fffffff] || `0x${(cmd >>> 0).toString(16)}`;
}

/** nlist_64 type field: N_STAB and N_TYPE masks. */
export const N_STAB = 0xe0;
export const N_TYPE = 0x0e;
export const N_SECT = 0x0e;

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;
export const CPU_ARM64_32 = 0x0200000c;
export const CPU_POWERPC = 0x00000012;
export const CPU_POWERPC64 = 0x01000012;

/**
 * Section attribute bits that mark a section as containing instructions.
 *
 * These are the flags a linker sets on `__text` and `__stubs`, and *only* on
 * those. They are what makes a scan typed: everything else in `__TEXT` is data
 * or literals, and a byte pattern that happens to decode as a call inside
 * `__cstring` is not a call site no matter how plausible it looks.
 */
export const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
export const S_ATTR_SOME_INSTRUCTIONS = 0x00000400;

/* ------------------------------------------------------------------ *
 * header flags
 * ------------------------------------------------------------------ */

/**
 * The `flags` word of `mach_header`/`mach_header_64`, byte 24, as `[bit, name]`.
 *
 * Transcribed from `<mach-o/loader.h>` in the macOS SDK rather than from memory,
 * and the header is a worse source of assumptions than it looks. Four of these
 * are newer than the "28 flags" usually quoted for `MH_*`: `MH_NLIST_OUTOFSYNC_
 * WITH_DYLDINFO`, `MH_SIM_SUPPORT`, `MH_IMPLICIT_PAGEZERO` and `MH_DYLIB_IN_CACHE`.
 * A table that stopped at `MH_APP_EXTENSION_SAFE` would report those four as
 * unknown bits on real binaries — which is precisely the false alarm the
 * abnormality check in {@link detectAbnormalities} must not be able to raise.
 *
 * The bits are *not* contiguous: 0x20000000 has no name in the header at all,
 * so a binary that sets it produces a genuinely unknown bit. That gap is the
 * reason {@link decodeHeaderFlags} reports `unknown` bits separately from
 * undecoded ones rather than folding them together.
 */
export const MH_FLAGS = [
  [0x00000001, 'MH_NOUNDEFS'],
  [0x00000002, 'MH_INCRLINK'],
  [0x00000004, 'MH_DYLDLINK'],
  [0x00000008, 'MH_BINDATLOAD'],
  [0x00000010, 'MH_PREBOUND'],
  [0x00000020, 'MH_SPLIT_SEGS'],
  [0x00000040, 'MH_LAZY_INIT'],
  [0x00000080, 'MH_TWOLEVEL'],
  [0x00000100, 'MH_FORCE_FLAT'],
  [0x00000200, 'MH_NOMULTIDEFS'],
  [0x00000400, 'MH_NOFIXPREBINDING'],
  [0x00000800, 'MH_PREBINDABLE'],
  [0x00001000, 'MH_ALLMODSBOUND'],
  [0x00002000, 'MH_SUBSECTIONS_VIA_SYMBOLS'],
  [0x00004000, 'MH_CANONICAL'],
  [0x00008000, 'MH_WEAK_DEFINES'],
  [0x00010000, 'MH_BINDS_TO_WEAK'],
  [0x00020000, 'MH_ALLOW_STACK_EXECUTION'],
  [0x00040000, 'MH_ROOT_SAFE'],
  [0x00080000, 'MH_SETUID_SAFE'],
  [0x00100000, 'MH_NO_REEXPORTED_DYLIBS'],
  [0x00200000, 'MH_PIE'],
  [0x00400000, 'MH_DEAD_STRIPPABLE_DYLIB'],
  [0x00800000, 'MH_HAS_TLV_DESCRIPTORS'],
  [0x01000000, 'MH_NO_HEAP_EXECUTION'],
  // `0x02000000`, not `0x00200000` — the bit above `MH_NO_HEAP_EXECUTION`, with a
  // leading zero in the header. Reading it as 24 would report a real flag as
  // unknown and invent a different one alongside it.
  [0x02000000, 'MH_APP_EXTENSION_SAFE'],
  [0x04000000, 'MH_NLIST_OUTOFSYNC_WITH_DYLDINFO'],
  [0x08000000, 'MH_SIM_SUPPORT'],
  [0x10000000, 'MH_IMPLICIT_PAGEZERO'],
  [0x80000000, 'MH_DYLIB_IN_CACHE'],
];

/** Every named header-flag bit, as one mask. The complement is what may be unknown. */
const MH_FLAG_MASK = MH_FLAGS.reduce((a, [bit]) => a | bit, 0);

/**
 * Decode a header `flags` word into names, plus any bits this table cannot name.
 *
 * `unknown` is the whole point of the return value. A flag bit that is set and
 * unnamed is either a format newer than this reader or a corrupted header, and
 * those two deserve very different reactions — so it is reported rather than
 * dropped. Dropping it would make a file that declares something unfamiliar look
 * exactly like one that does not, which is the shape of a wrong answer.
 *
 * @param {number} flags the `flags` word, as read unsigned
 * @returns {{flags: number, names: string[], unknown: number}}
 */
export function decodeHeaderFlags(flags) {
  const names = [];
  for (const [bit, name] of MH_FLAGS) {
    if ((flags & bit) !== 0) names.push(name);
  }
  // `~MH_FLAG_MASK` is negative in two's complement, so it is masked back to 32
  // bits before use. `flags` is already unsigned, so this cannot go negative.
  const unknown = (flags & ~MH_FLAG_MASK) >>> 0;
  return { flags, names, unknown };
}

/* ------------------------------------------------------------------ *
 * section types and attributes
 * ------------------------------------------------------------------ */

/** `SECTION_TYPE`, the low byte of a section's `flags`. */
export const SECTION_TYPE_MASK = 0x000000ff;

/**
 * Section types, the low byte of a section's `flags`.
 *
 * Transcribed from `<mach-o/loader.h>`, and complete through
 * `S_INIT_FUNC_OFFSETS` (0x16) — including the five thread-local types, which a
 * 22-entry table copied from an older header omits, and which appear on any
 * binary built with C++ static destructors or `thread_local` variables.
 */
export const SECTION_TYPES = {
  0x00: 'S_REGULAR',
  0x01: 'S_ZEROFILL',
  0x02: 'S_CSTRING_LITERALS',
  0x03: 'S_4BYTE_LITERALS',
  0x04: 'S_8BYTE_LITERALS',
  0x05: 'S_LITERAL_POINTERS',
  0x06: 'S_NON_LAZY_SYMBOL_POINTERS',
  0x07: 'S_LAZY_SYMBOL_POINTERS',
  0x08: 'S_SYMBOL_STUBS',
  0x09: 'S_MOD_INIT_FUNC_POINTERS',
  0x0a: 'S_MOD_TERM_FUNC_POINTERS',
  0x0b: 'S_COALESCED',
  0x0c: 'S_GB_ZEROFILL',
  0x0d: 'S_INTERPOSING',
  0x0e: 'S_16BYTE_LITERALS',
  0x0f: 'S_DTRACE_DOF',
  0x10: 'S_LAZY_DYLIB_SYMBOL_POINTERS',
  0x11: 'S_THREAD_LOCAL_REGULAR',
  0x12: 'S_THREAD_LOCAL_ZEROFILL',
  0x13: 'S_THREAD_LOCAL_VARIABLES',
  0x14: 'S_THREAD_LOCAL_VARIABLE_POINTERS',
  0x15: 'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS',
  0x16: 'S_INIT_FUNC_OFFSETS',
};

/**
 * Section attributes, the top 24 bits of a section's `flags`, as `[bit, name]`.
 *
 * `S_ATTR_PURE_INSTRUCTIONS` and `S_ATTR_SOME_INSTRUCTIONS` are here as entries
 * rather than kept only as the two constants {@link isCodeSection} tests, because
 * a section's attributes are now *reported* and the two lists must not be able
 * to disagree about which bits those are. {@link isCodeSection} still tests the
 * constants — the single source of truth for the code/data decision — and this
 * table is the single source of truth for the names.
 *
 * Note the hole in the numbering: `S_ATTR_DEBUG` is 0x02000000 and the bits below
 * it are 0x00000400 downward, so 0x01000000 through 0x00800000 and 0x00008000
 * downward have no name. Those become `attributesUnknown`, and are reported.
 */
export const SECTION_ATTRIBUTES = [
  [0x80000000, 'S_ATTR_PURE_INSTRUCTIONS'],
  [0x40000000, 'S_ATTR_NO_TOC'],
  [0x20000000, 'S_ATTR_STRIP_STATIC_SYMS'],
  [0x10000000, 'S_ATTR_NO_DEAD_STRIP'],
  [0x08000000, 'S_ATTR_LIVE_SUPPORT'],
  [0x04000000, 'S_ATTR_SELF_MODIFYING_CODE'],
  [0x02000000, 'S_ATTR_DEBUG'],
  [0x00000400, 'S_ATTR_SOME_INSTRUCTIONS'],
  [0x00000200, 'S_ATTR_EXT_RELOC'],
  [0x00000100, 'S_ATTR_LOC_RELOC'],
];

const SECTION_ATTRIBUTE_MASK = SECTION_ATTRIBUTES.reduce((a, [bit]) => a | bit, 0);

/**
 * The attribute *region* of a section's `flags`: `SECTION_ATTRIBUTES`, the top 24.
 *
 * Separate from {@link SECTION_ATTRIBUTE_MASK}, which is only the bits this table
 * can name — and the two are not interchangeable. Masking with the complement of
 * the named bits and calling the remainder "unknown attributes" also catches the
 * section *type* in the low byte, so every `S_CSTRING_LITERALS` section reported
 * `0x2` as an unknown attribute and every real binary came back with a wall of
 * spurious warnings. The region has to be bounded first, and only then compared
 * against the names.
 */
const SECTION_ATTRIBUTE_REGION = 0xffffff00;

/**
 * Split a section's `flags` word into its type and its attributes.
 *
 * The two occupy disjoint parts of one word — `SECTION_TYPE` is the low 8 bits,
 * `SECTION_ATTRIBUTES` the top 24 — and they answer different questions. Type
 * says what the bytes are (`S_CSTRING_LITERALS`, `S_SYMBOL_STUBS`);
 * attributes say how the linker may treat them (`S_ATTR_PURE_INSTRUCTIONS`,
 * `S_ATTR_NO_DEAD_STRIP`). `code`/`data` in the section listing comes from the
 * attributes, and the type is printed beside it, so a section can be read as
 * "code" and `S_REGULAR` at once — which is what `__text` is.
 *
 * @param {number} flags the section's `flags` word, as read unsigned
 * @returns {{type: string, typeRaw: number, attributes: string[], attributesUnknown: number}}
 */
export function decodeSectionFlags(flags) {
  const typeRaw = flags & SECTION_TYPE_MASK;
  const attributes = [];
  for (const [bit, name] of SECTION_ATTRIBUTES) {
    if ((flags & bit) !== 0) attributes.push(name);
  }
  const attributesUnknown = (flags & SECTION_ATTRIBUTE_REGION & ~SECTION_ATTRIBUTE_MASK) >>> 0;
  return {
    type: SECTION_TYPES[typeRaw] || `S_UNKNOWN_0x${typeRaw.toString(16)}`,
    typeRaw,
    attributes,
    attributesUnknown,
  };
}

/* ------------------------------------------------------------------ *
 * LC_SOURCE_VERSION
 * ------------------------------------------------------------------ */

/**
 * Decode an `LC_SOURCE_VERSION` word into its five components.
 *
 * The header documents this as `A.B.C.D.E packed as a24.b10.c10.d10.e10`, which
 * is not five equal fields — `A` is 24 bits and the rest are 10. Decoding it as
 * five 10-bit fields, which is the obvious reading and the one most tools get
 * wrong, silently mangles every component: a real `A` of 0x1000000 would lose its
 * high bits and the whole version would come out as `0.0.0.x.y`. So the shifts
 * are taken from that comment rather than derived.
 *
 * @param {bigint} v the packed `version` word
 * @returns {{raw: bigint, a: bigint, b: bigint, c: bigint, d: bigint, e: bigint, text: string}}
 */
export function decodeSourceVersion(v) {
  const a = (v >> 40n) & 0xffffffn;
  const b = (v >> 30n) & 0x3ffn;
  const c = (v >> 20n) & 0x3ffn;
  const d = (v >> 10n) & 0x3ffn;
  const e = v & 0x3ffn;
  return { raw: v, a, b, c, d, e, text: `${a}.${b}.${c}.${d}.${e}` };
}

/**
 * Mach-O and fat-header magics, as raw byte sequences.
 *
 * Compared as bytes rather than as integers, and that is not fussiness. A thin
 * little-endian Mach-O begins `cf fa ed fe`; read as a big-endian integer that
 * is 0xcffaedfe, which is in neither the fat nor the 64-bit-thin list, so a
 * reader written the obvious way accepts every universal binary and silently
 * rejects every thin one. Two copies of that check existed in this project at
 * one point and the test suite carried the correct version while the library
 * carried the broken one — so the check now lives here, once, and everything
 * imports it.
 */
export const MACHO_MAGICS = [
  Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // fat
  Buffer.from([0xbe, 0xba, 0xfe, 0xca]), // fat, byte-swapped
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), // 64-bit thin
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // 32-bit thin
];

/** True when `p` is a readable file whose first four bytes are a Mach-O magic. */
export function isMachOFile(p) {
  let fd;
  try {
    fd = openSync(p, 'r');
    const head = Buffer.alloc(4);
    if (readSync(fd, head, 0, 4, 0) !== 4) return false;
    return MACHO_MAGICS.some((m) => head.equals(m));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * A human name for a CPU type, falling back to its raw value.
 *
 * The fallback is a real fallback and not a placeholder: `sliceName` is the
 * only place an architecture is turned into text, so an unmapped cputype still
 * *reports* correctly — as `cputype=0x12` — where a name guessed from the magic
 * would report something false.
 *
 * Coverage is ordered by who actually hands us these files, not by whether the
 * Darwin headers list them. `ppc` is here because GameCube and Wii binaries
 * are Mach-O and a large, expert user base analyses them weekly; `ppc64` is one
 * more line for the same ecosystem. `arm64_32` is here because watchOS ships it,
 * and it is emphatically *not* a subtype of arm64 — see {@link archMatches}.
 */
export function sliceName(cputype) {
  if (cputype === CPU_X86_64) return 'x86_64';
  if (cputype === CPU_ARM64) return 'arm64';
  if (cputype === CPU_ARM64_32) return 'arm64_32';
  if (cputype === CPU_POWERPC64) return 'ppc64';
  if (cputype === CPU_POWERPC) return 'ppc';
  if (cputype === 0x0000000c) return 'arm';
  if (cputype === 0x00000007) return 'i386';
  if (cputype == null) return 'thin';
  return `cputype=0x${cputype.toString(16)}`;
}

/**
 * The subtypes that distinguish an architecture without changing its cputype.
 *
 * `arm64e` is not a separate `cputype` — it is `CPU_TYPE_ARM64` with a
 * different *subtype* — so {@link sliceName} cannot see it, and every arm64e
 * slice was reported as plain `arm64`. On iOS that is the difference between a
 * binary that uses pointer authentication and one that does not, which is the
 * first question anything PAC-related asks.
 *
 * Masked before comparison because the high byte carries capability flags
 * rather than subtype: `CPU_SUBTYPE_LIB64` is `0x80000000` and
 * `CPU_SUBTYPE_PTRAUTH_ABI` reuses the same bit, so a raw compare works on the
 * binaries seen so far and fails on one that set a flag — the kind of bug that
 * only appears on someone else's machine.
 */
export const CPU_SUBTYPE_ARM64E = 2;
/** `CPU_SUBTYPE_ARM64E | 8`, the arm64e variant advertising the v8 ISA. */
export const CPU_SUBTYPE_ARM64E_V8 = 10;

/**
 * A slice's architecture name, including the arm64e distinction.
 *
 * Takes the subtype and degrades to {@link sliceName} when it is absent, which
 * is a real case rather than a hypothetical: a thin slice's subtype may not have
 * been read, and `arm64` is a better answer than a fabricated `arm64e`. Every
 * call site therefore passes whatever it has, and an unknown subtype falls back
 * to the plain name rather than guessing.
 */
export function sliceArchName(cputype, cpusubtype) {
  if (cputype === CPU_ARM64) {
    const st = cpusubtype == null ? null : cpusubtype & 0x00ffffff;
    if (st === CPU_SUBTYPE_ARM64E || st === CPU_SUBTYPE_ARM64E_V8) return 'arm64e';
  }
  return sliceName(cputype);
}

/**
 * Open a file and return a bounded reader with a small read cache.
 *
 * The cache matters: walking load commands and the symbol table re-reads the
 * same few pages many times, and without it a 476 MB universal binary turns
 * into hundreds of thousands of syscalls.
 */
export function opener(p) {
  const fd = openSync(p, 'r');
  const size = fstatSync(fd).size;
  const cache = new Map();
  return {
    fd,
    size,
    path: p,
    /** Read `len` bytes at `off`. Short reads are returned as-is, never padded. */
    read(off, len) {
      if (off < 0 || len <= 0) return Buffer.alloc(0);
      if (off >= size) return Buffer.alloc(0);
      const want = Math.min(len, size - off);
      const key = `${off}:${want}`;
      const hit = cache.get(key);
      if (hit) return hit;
      const b = Buffer.alloc(want);
      const n = readSync(fd, b, 0, want, off);
      const out = b.subarray(0, n);
      // Bounded rather than unbounded: the pointer-hunting tools sweep the
      // whole file and would otherwise pin hundreds of MB.
      if (cache.size > 4096) cache.clear();
      cache.set(key, out);
      return out;
    },
    close() {
      closeSync(fd);
    },
  };
}

/**
 * Parse a fat header into its slices, or null when this is not a fat binary.
 *
 * Returns `[]` rather than null for a fat file with no readable slice table,
 * so callers can tell "not fat" from "fat but unreadable".
 */
export function parseFat(f) {
  const head = f.read(0, 8);
  if (head.length < 8) return null;
  const magic = head.readUInt32BE(0);
  if (magic !== FAT_MAGIC && magic !== FAT_CIGAM) return null;
  const n = head.readUInt32BE(4);
  const slices = [];
  for (let i = 0; i < n; i++) {
    const o = f.read(8 + i * 20, 20);
    if (o.length < 20) break;
    slices.push({
      cputype: o.readUInt32BE(0),
      // Byte 4 of the 20-byte `fat_arch`. Skipped until arm64e needed it, which
      // is the shape of most gaps here: the subtype is only meaningful for a few
      // architectures, but a reader that does not carry it cannot name them at
      // all, and naming is what `--arch` matches on.
      cpusubtype: o.readUInt32BE(4),
      offset: o.readUInt32BE(8),
      size: o.readUInt32BE(12),
    });
  }
  return slices;
}

/**
 * Parse the load commands of the thin Mach-O at `base`.
 *
 * Returns null when there is no Mach-O header there, which is the normal
 * result for a non-binary file and must not throw.
 */
export function parseThin(f, base = 0) {
  const hdr = f.read(base, 32);
  if (hdr.length < 28) return null;
  const magic = hdr.readUInt32LE(0);
  const is64 = magic === MH_MAGIC_64;
  if (!is64 && magic !== MH_MAGIC_32) return null;

  const cputype = hdr.readUInt32LE(4);
  const cpusubtype = hdr.readUInt32LE(8);
  const filetype = hdr.readUInt32LE(12);
  const ncmds = hdr.readUInt32LE(16);
  const sizeofcmds = hdr.readUInt32LE(20);
  // Byte 24 in both header forms. `mach_header` and `mach_header_64` agree here
  // because the field precedes `reserved` and the only difference between the two
  // is that trailing 4 bytes plus the wider `n_value`s further in — so this one
  // is *not* a place the 32-bit/64-bit offset trap applies, and it is read
  // before `is64` is ever consulted rather than inside a `wide ?` ternary.
  const flags = hdr.readUInt32LE(24);
  let off = base + (is64 ? 32 : 28);
  const segments = [];
  const sections = [];
  const loadCommands = [];
  let symtab = null;
  let uuid = null;
  let entryPoint = null;
  let sourceVersion = null;
  const rpaths = [];

  for (let i = 0; i < ncmds; i++) {
    const lc = f.read(off, 8);
    if (lc.length < 8) break;
    const cmd = lc.readUInt32LE(0);
    const cmdsize = lc.readUInt32LE(4);
    if (cmdsize < 8) break; // a zero cmdsize would loop forever

    // Recorded before any decoding, so every command appears even when nothing
    // here knows what it means. A reader that silently dropped the ones it did
    // not recognise would make an unfamiliar binary look simpler than it is,
    // which is the shape of a wrong answer rather than a partial one.
    loadCommands.push({ cmd, name: loadCommandName(cmd), cmdsize, offset: off - base });

    if (cmd === LC_UUID_CMD) {
      // 16 bytes at offset 8. A UUID is a value rather than an interpretation,
      // which is why it is read here and `LC_CODE_SIGNATURE` is not: reading the
      // bytes of an identifier is the same class of act as reading a section's
      // size, whereas following a code signature is decoding a structure. The
      // two differ by whether answering correctly requires understanding
      // something else's format.
      const s = f.read(off, 24);
      if (s.length >= 24) {
        uuid = s.toString('hex', 8, 24).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
      }
    } else if (cmd === LC_SYMTAB) {
      const s = f.read(off, 24);
      if (s.length >= 24) {
        symtab = {
          symoff: s.readUInt32LE(8),
          nsyms: s.readUInt32LE(12),
          stroff: s.readUInt32LE(16),
          strsize: s.readUInt32LE(20),
        };
      }
    } else if (cmd === LC_MAIN_CMD) {
      // `struct entry_point_command`. The header documents `cmdsize` 24, with
      // `entryoff` and `stacksize` as `uint64_t` — and that is the case the
      // header describes, but it is not the case that ships.
      //
      // Every LC_MAIN measured on this machine's own binaries — 672 slices across
      // /bin, /usr/bin and system frameworks — declares `cmdsize` **16**, i.e.
      // `entryoff` with no `stacksize` after it. Reading a fixed 24 bytes here
      // does not merely read one field too many: it reads 8 bytes *past the end of
      // this command*, which is the next load command's header. The result is a
      // plausible-looking `stacksize`, and on an `x86_64` slice an `entryoff`
      // whose high half is the following command's `cmdsize` — the kind of value
      // that reads as a real offset and is not one.
      //
      // So the command's own `cmdsize` bounds the read, and `stacksize` is taken
      // only when there are bytes for it. `entryoff` stays a BigInt either way:
      // narrowing a genuine 64-bit offset to a Number would lose precision above
      // 2^53, and a caller has no way to tell a truncated one from a small one.
      const want = Math.min(cmdsize, 24);
      const s = f.read(off, want);
      if (s.length >= 16) {
        // The eight bytes the header calls a `uint64_t`. Taken whole, because the
        // two forms of this command are not the same width in practice — see
        // `rawHigh32` and `value` below.
        const raw = s.readBigUInt64LE(8);
        const high32 = Number((raw >> 32n) & 0xffffffffn);
        // In the 16-byte form the upper half of this field is **uninitialised**,
        // not data. Measured across 672 LC_MAINs on this machine: the upper 32
        // bits are zero on every arm64/arm64e slice and non-zero on the x86_64
        // shared-cache stubs (0x8, 0x10, 0x18 — values with no relationship to
        // anything else in the file). Reading those eight bytes as a uint64
        // therefore reports 103,079,241,432 as `/bin/ls`'s entry offset, which is
        // not an offset and looks entirely like one.
        //
        // So the width is chosen from `cmdsize`: the documented 24-byte command
        // carries a real uint64, and the 16-byte command that actually ships
        // carries a 32-bit value in the low half. `rawHigh32` is reported
        // regardless, so the raw bytes stay visible and nothing is hidden.
        const wide = cmdsize >= 24;
        entryPoint = {
          entryoff: wide ? raw : (raw & 0xffffffffn),
          rawHigh32: high32,
          // Absent in the 16-byte form. `null`, not 0: "this command declared no
          // stack size" and "this command declared a stack size of zero" are
          // different claims, and only one of them is true here.
          stacksize: wide ? s.readBigUInt64LE(16) : null,
          cmdsize,
          valueBasis: wide
            ? 'LC_MAIN.entryoff read as uint64 — this command declares the documented 24-byte layout'
            : `LC_MAIN.entryoff read as its low 32 bits — this command declares cmdsize ${cmdsize}, ` +
              'the 16-byte form that actually ships; the upper 32 bits are uninitialised' +
              (high32 !== 0 ? ` and are non-zero here (0x${high32.toString(16)})` : ''),
        };
      }
    } else if (cmd === LC_RPATH_CMD) {
      // `struct rpath_command` ends in `union lc_str path`, which is an *offset*
      // — measured from the start of this load command — not a string stored
      // inline. Reading eight bytes in as if it were the first characters of the
      // path yields a string that looks like a path: a little-endian length-like
      // value, and it will pass a "does it look sane" check while naming a
      // directory that does not exist. The offset is taken literally, and
      // bounds-checked against this command's own `cmdsize`.
      const s = f.read(off, 12);
      if (s.length >= 12) {
        const rel = s.readUInt32LE(8);
        if (rel >= 12 && rel < cmdsize) {
          const body = f.read(off + rel, cmdsize - rel);
          const z = body.indexOf(0);
          const path = body.toString('latin1', 0, z < 0 ? body.length : z);
          if (path) rpaths.push(path);
        }
      }
    } else if (cmd === LC_SOURCE_VERSION_CMD) {
      // `struct source_version_command`, `cmdsize` 16. The packing is
      // `a24.b10.c10.d10.e10`; see {@link decodeSourceVersion}.
      const s = f.read(off, 16);
      if (s.length >= 16) sourceVersion = decodeSourceVersion(s.readBigUInt64LE(8));
    } else if (cmd === LC_SEGMENT_64 || cmd === LC_SEGMENT) {
      const wide = cmd === LC_SEGMENT_64;
      const need = wide ? 72 : 56;
      const s = f.read(off, need);
      if (s.length >= need) {
        const segname = s.toString('latin1', 8, 24).replace(/\0.*$/, '');
        segments.push({
          segname,
          vmaddr: wide ? s.readBigUInt64LE(24) : BigInt(s.readUInt32LE(24)),
          vmsize: wide ? s.readBigUInt64LE(32) : BigInt(s.readUInt32LE(28)),
          fileoff: wide ? s.readBigUInt64LE(40) : BigInt(s.readUInt32LE(32)),
          filesize: wide ? s.readBigUInt64LE(48) : BigInt(s.readUInt32LE(36)),
        });
        // Section entries follow the segment command. Both forms carry them —
        // this used to read only the 64-bit one, which meant a 32-bit slice
        // reported zero sections and every address lookup in it came back "not
        // in a section".
        //
        // The offsets below are transcribed from `<mach-o/loader.h>` in the macOS
        // SDK rather than derived from the 64-bit form, because the two layouts
        // are not related by a scale factor:
        //
        //   field       section_64   section
        //   addr            32          32
        //   size            40          36
        //   offset          48          40
        //   flags           64          56
        //   entry size      80          68
        //
        // `addr` is the only field at the same offset in both, because the two
        // 16-byte name fields above it are the same size in both. Every 32-bit
        // field after it shifts the next one 4 bytes earlier, so `flags` ends up
        // 8 bytes apart and the entries differ in length by 12 rather than by a
        // factor. Scaling 48 by 68/80 happens to give 40 — the right answer by
        // luck, and the wrong way to arrive at one.
        const sectsAt = wide ? 64 : 48;          // nsects, in the segment command
        const sectSize = wide ? 80 : 68;
        const sectBase = off + (wide ? 72 : 56);  // the segment command's own size
        const nsects = s.readUInt32LE(sectsAt);
        for (let k = 0; k < nsects; k++) {
          const sc = f.read(sectBase + k * sectSize, sectSize);
          if (sc.length < sectSize) break;
          const secFlags = sc.readUInt32LE(wide ? 64 : 56);
          sections.push({
            sectname: sc.toString('latin1', 0, 16).replace(/\0.*$/, ''),
            segname: sc.toString('latin1', 16, 32).replace(/\0.*$/, ''),
            addr: wide ? sc.readBigUInt64LE(32) : BigInt(sc.readUInt32LE(32)),
            size: Number(wide ? sc.readBigUInt64LE(40) : sc.readUInt32LE(36)),
            offset: sc.readUInt32LE(wide ? 48 : 40),
            // Section attributes. Read because S_ATTR_*_INSTRUCTIONS is the only
            // in-file signal that separates code from data, and a byte scanner
            // that cannot tell them apart reports data as call sites — see
            // `instructionSections`. Offset 64 in `section_64`, 56 in `section`.
            //
            // `flags` stays the raw word and stays authoritative; the decoded
            // `type`/`attributes` are spread in beside it rather than replacing
            // it, so a caller that needs the undecoded value — and the abnormality
            // check does, to notice attribute bits this table cannot name — does
            // not have to recompute it.
            flags: secFlags,
            ...decodeSectionFlags(secFlags),
          });
        }
      }
    }
    off += cmdsize;
  }
  return {
    is64, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags,
    segments, sections, loadCommands, symtab, uuid,
    entryPoint, sourceVersion, rpaths,
  };
}

/**
 * Every slice of a binary, as `{ cputype, offset, size, thin }`.
 *
 * A thin binary comes back as a single slice with `thin: true` and a null
 * cputype, so callers can treat both shapes identically.
 */
export function slicesOf(f) {
  const fat = parseFat(f);
  if (fat) return fat.map((s) => ({ ...s, thin: false }));
  return [{ cputype: null, cpusubtype: null, offset: 0, size: f.size, thin: true }];
}

/** The `__TEXT` section of a parsed slice, which is where literals live. */
export function textSection(thin) {
  return (
    thin.sections.find((s) => s.segname === '__TEXT' && s.size > 0) ||
    thin.sections.find((s) => s.segname === '__TEXT') ||
    null
  );
}

/** True when a section's attributes say it contains instructions. */
export function isCodeSection(sec) {
  return (sec.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) !== 0;
}

/**
 * The sections of a slice that hold code, ordered as they appear in the file.
 *
 * This is what turns an untyped byte scan into a typed one. The previous
 * approach scanned `__text` end to end, and `__text` is not entirely code: it
 * also carries the `__cstring`/`__const`/`__literal*` sections, jump tables and
 * alignment padding. Any of those can contain bytes that decode as a `call
 * rel32` pointing at the address you asked about, and each such byte was
 * reported as a call site. The output looked like a list of callers and was
 * partly fiction.
 *
 * `__stubs` is included deliberately: PLT stubs are code and do contain direct
 * `jmp rel32` and `call rel32` instructions, so they are legitimate results and
 * filtering them out would hide real edges.
 *
 * Falls back to every non-empty section when the slice carries no
 * instruction-flagged section at all. That is a rare and slightly worrying
 * input — a hand-built or unusual binary — and the alternative (report zero
 * call sites) would be the confident-wrong-answer failure this project has
 * already produced several of. `fallback: true` in the result tells the caller
 * which answer it got.
 */
export function codeSections(thin) {
  const code = thin.sections.filter((s) => s.size > 0 && isCodeSection(s));
  if (code.length) return { sections: code, fallback: false };
  return {
    sections: thin.sections.filter((s) => s.size > 0),
    fallback: true,
  };
}

/**
 * Read every symbol name in a slice.
 *
 * Both defined symbols (N_SECT) and imported ones are kept and counted apart:
 * a family satisfied only by an import is weaker evidence than one satisfied
 * by the engine's own definition, so `entries` exposes the distinction rather
 * than flattening it. Debugging entries (N_STAB) are skipped — they are not
 * symbols.
 *
 * `names` is the convenient form for substring matching. `entries` carries
 * each symbol's vaddr and defined/imported flag, which the address-oriented
 * tools (`sym`, `symlookup`) need and which a name-only
 * projection would throw away.
 */
export function readSymbols(f, base, thin) {
  const { symtab } = thin;
  // Every return path carries the same keys. The two early ones used to omit
  // `entries`, so a caller that destructured uniformly — which is what the test
  // suite did — got `undefined` and threw on a binary with no symbol table. That
  // is the worst shape for a reader whose whole job is to handle binaries that
  // lack things: the case where the fields are missing is exactly the case
  // nobody exercises until they hit it in the wild.
  if (!symtab || symtab.nsyms === 0) {
    return {
      names: [], entries: [], defined: 0,
      total: symtab ? symtab.nsyms : 0,
      note: symtab ? 'empty symbol table' : 'no LC_SYMTAB',
    };
  }

  const str = f.read(base + symtab.stroff, symtab.strsize);
  if (str.length === 0) {
    return { names: [], entries: [], defined: 0, total: symtab.nsyms, note: 'empty string table' };
  }

  const nameAt = (x) => {
    if (x >= str.length) return '';
    const z = str.indexOf(0, x);
    return str.toString('latin1', x, z < 0 ? str.length : z);
  };

  const names = [];
  const entries = [];
  let defined = 0;
  const BATCH = 20000;
  // `nlist` is 16 bytes in the 64-bit form and 12 in the 32-bit one, and its
  // `n_value` is a `uint64_t` in the first and a `uint32_t` in the second. This
  // used to read 16-byte entries with a 64-bit value unconditionally, so every
  // symbol in a 32-bit slice was read at the wrong stride: names came from the
  // wrong place in the string table, `n_type` from what was actually another
  // entry's `n_strx`, and the address from bytes that were never an address. The
  // symptom was not an error — it was plausible-looking wrong symbols, which is
  // why the stride is taken from the parse rather than written as a constant.
  const nlistSize = thin.is64 ? 16 : 12;
  for (let b = 0; b < symtab.nsyms; b += BATCH) {
    const cnt = Math.min(BATCH, symtab.nsyms - b);
    const blk = f.read(base + symtab.symoff + b * nlistSize, cnt * nlistSize);
    if (blk.length < cnt * nlistSize) break;
    for (let i = 0; i < cnt; i++) {
      const at = i * nlistSize;
      const info = blk[at + 4];
      if (info & N_STAB) continue;
      const strx = blk.readUInt32LE(at);
      if (strx >= str.length) continue;
      const isDefined = (info & N_TYPE) === N_SECT;
      if (isDefined) defined++;
      const nm = nameAt(strx);
      if (!nm) continue;
      names.push(nm);
      entries.push({
        name: nm,
        addr: thin.is64 ? blk.readBigUInt64LE(at + 8) : BigInt(blk.readUInt32LE(at + 8)),
        defined: isDefined,
      });
    }
  }
  return { names, entries, defined, total: symtab.nsyms, note: null };
}

/**
 * Pick the slice most worth probing: the one with the most symbols.
 *
 * A universal binary can be stripped on one architecture and not the other, so
 * "first slice" is the wrong rule. Falls back to the first parseable slice so
 * a fully stripped binary still gets its string scan run.
 */
export function richestSlice(f) {
  let best = null;
  for (const s of slicesOf(f)) {
    const thin = parseThin(f, s.offset);
    if (!thin) continue;
    const syms = readSymbols(f, s.offset, thin);
    const entry = {
      ...s,
      arch: s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype),
      thin,
      names: syms.names,
      nsyms: syms.total,
      ndefined: syms.defined,
      stripped: syms.note || syms.total === 0,
      symNote: syms.note,
    };
    if (!best || entry.names.length > best.names.length) best = entry;
  }
  return best;
}

/**
 * The byte offset of the slice a tool should read.
 *
 * This is the one number the old tools got wrong by hardcoding. It reads only
 * the load commands and the symbol *count*, not the symbol names, so it is
 * cheap enough to call before deciding what else to do — the address-oriented
 * tools need the offset and then walk the symtab themselves.
 *
 * @param {object} f        an `opener()` handle
 * @param {string} [prefer] architecture to prefer, e.g. 'x86_64'
 * @returns {{offset:number, arch:string, nsyms:number, thin:object}|null}
 *
 * `prefer` is a preference, not a requirement. The first version treated it as
 * a requirement and returned null whenever the named slice was absent, which
 * made every caller fail outright on an arm64-only binary — including on a
 * thin arm64 Go toolchain, where there is no x86_64 slice to find. The right
 * behaviour is "use this one if it exists, otherwise take the richest", and
 * reporting which slice was actually chosen is the caller's job.
 */
export function preferredSlice(f, prefer) {
  let best = null;
  for (const s of slicesOf(f)) {
    const thin = parseThin(f, s.offset);
    if (!thin) continue;
    const arch = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
    const nsyms = thin.symtab ? thin.symtab.nsyms : 0;
    const entry = { offset: s.offset, arch, nsyms, thin, size: s.size };
    // `archMatches`, not `===`. Naming arm64e as its own architecture turned this
    // comparison into a real bug: on an Apple-silicon system binary whose slice
    // is `arm64e`, `--arch=arm64` stopped matching, the preference was ignored,
    // and the caller got whichever slice happened to be richest — silently the
    // wrong answer to a question that had been asked precisely.
    if (prefer && archMatches(arch, prefer)) return entry;
    if (!best || nsyms > best.nsyms) best = entry;
  }
  return best;
}

/**
 * True when a slice's architecture name satisfies a requested one.
 *
 * The comparison is by name because that is what `--arch` takes, and names are
 * what every tool already reports. A caller asking for `arm64` against an
 * `arm64e` slice is asking for the same instruction set, so the `e` suffix is
 * ignored — otherwise `--arch=arm64` would read nothing from an Apple-silicon
 * system binary whose slice is named `arm64e`, and report the file as empty.
 *
 * The suffix rule is deliberately narrow, and the names added since say why it
 * has to stay that way. `arm64e` differs from `arm64` only in capability bits on
 * the same 64-bit instruction set, so collapsing them is safe. `arm64_32` and
 * `ppc`/`ppc64` are a different thing entirely: `arm64_32` is 32-bit pointers
 * under a distinct ABI, and the two PowerPC types differ in pointer width. None
 * of them ends in `e`, so none of them collapse, and that is the property worth
 * asserting rather than assuming — a name that later gained a trailing `e`
 * would silently start matching an architecture it is not.
 */
export function archMatches(sliceArch, want) {
  if (!want) return true;
  if (sliceArch === want) return true;
  return String(sliceArch).replace(/e$/, '') === String(want).replace(/e$/, '');
}

/**
 * True when a section occupies bytes in the file, as opposed to being zero-fill.
 *
 * `__bss` and `__noptrbss` have a real `addr` and a real `size` but no bytes
 * anywhere: the loader supplies zeros. The linker records their file `offset` as
 * 0, and their address range usually extends past the end of the segment's
 * `filesize`, so a `size > 0` test does not exclude them.
 *
 * This distinction decides whether an address can be read from the file at all,
 * and getting it wrong is not a small error. In `go`, `__DATA,__bss` covers
 * file offsets 0 through 180,760 — which are the Mach-O header and its load
 * commands. A `o2a` that treated it as backed by the file reported file offset
 * 0x1000 as being inside `__bss`, when it is the first byte of `__text`.
 *
 * The test is containment in the owning segment's file range rather than a
 * comparison against the section's own `offset`, because `offset` is the field
 * that is *not* meaningful for these sections.
 */
export function isBackedByFile(thin, sec) {
  if (sec.size === 0) return false;
  const seg = thin.segments.find((g) => g.segname === sec.segname);
  if (!seg) return sec.offset !== 0;
  // A section's file range is only real if it lies within the segment's.
  return sec.offset >= Number(seg.fileoff)
    && sec.offset + sec.size <= Number(seg.fileoff) + Number(seg.filesize);
}

/**
 * An `LC_MAIN` entry point, resolved only as far as the bytes actually support.
 *
 * ## Why there is no address here
 *
 * `<mach-o/loader.h>` calls `entryoff` the "file (__TEXT) offset of main()", and
 * the obvious implementation is `__TEXT.vmaddr + entryoff`. Measured against real
 * binaries, that arithmetic does not produce the entry point:
 *
 *   - On a 113 MB, fully-symbolled arm64 `node`, `entryoff` is 88,241,840 while
 *     `__TEXT` spans file bytes 0..85,082,112. The offset is *past the end of
 *     `__TEXT`*, and as a slice-relative file offset it resolves into
 *     `__LINKEDIT` — the link-edit region holding the symbol table. It matches no
 *     defined symbol under any of the three plausible bases.
 *   - On dyld shared-cache stubs (`/bin/ls`, `/bin/cat`, and most of /bin), the
 *     same is true and expected: the stub has no code of its own, so the offset
 *     refers to something the file does not contain.
 *
 * So `vaddr` is `null` and stays null. Emitting `__TEXT.vmaddr + entryoff` would
 * produce an address of exactly the shape a caller then feeds to `symlookup` and
 * `findcall` — and it would be wrong on essentially every binary, in a way that
 * looks like a measurement. A missing answer is recoverable; a fabricated address
 * is not, which is the rule `lookupAddress` and `toFileOffset` already follow.
 *
 * What *is* reported is the raw value, the declared `cmdsize` that determines how
 * it should be read, and the derived address only when it can be checked — see
 * `entryoffLandsIn`.
 *
 * @param {object} thin a `parseThin()` result
 * @returns {null|{entryoff: bigint, stacksize: bigint|null, cmdsize: number,
 *   vaddr: null, note: string}}
 */
export function resolveEntryPoint(thin) {
  if (!thin.entryPoint) return null;
  const { entryoff, stacksize, cmdsize, rawHigh32, valueBasis } = thin.entryPoint;
  const text = thin.segments.find((g) => g.segname === '__TEXT') || null;
  const inText = text
    ? entryoff >= text.fileoff && entryoff < text.fileoff + text.filesize
    : null;
  return {
    entryoff,
    stacksize,
    cmdsize,
    rawHigh32,
    valueBasis,
    vaddr: null,
    // Disclosed rather than acted on. `false` here is the normal case for a
    // shared-cache stub and is also true of a fully-symbolled `node`, so it is
    // not by itself evidence of damage — which is why it is not an abnormality.
    entryoffLandsInText: inText,
    note: 'raw file offset; no address is derived from it, because the header\'s ' +
      '"__TEXT offset" description does not hold on the binaries measured'
      + (inText === false ? ', and this one falls outside __TEXT' : ''),
  };
}

/**
 * Shannon entropy of a buffer, in bits per byte (0..8).
 *
 * Sampled over at most `maxBytes` rather than the whole buffer. The only consumer
 * is the packing heuristic in {@link detectAbnormalities}, and "is this blob
 * compressed" is answered by its first megabyte as reliably as by its last —
 * whereas a 200 MB string table read in full on every `describe` would make the
 * cheapest tool in the package the slowest one. Sampling a prefix also keeps the
 * measurement cheap for the fixture-sized files the suite runs on.
 */
export function shannonEntropy(f, offset, length, maxBytes = 1 << 20) {
  const n = Math.min(length, maxBytes);
  if (n <= 0) return 0;
  const buf = f.read(offset, n);
  if (buf.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (const b of buf) freq[b]++;
  let h = 0;
  for (const c of freq) {
    if (c === 0) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Above this many bits per byte, a string table is treated as probably packed. */
const PACKED_ENTROPY = 6.4;

/**
 * Structural problems in one slice, reported rather than thrown.
 *
 * ## Why this exists
 *
 * Every other function in this reader answers a question about a well-formed
 * binary. This one answers a question about a *malformed* one, which is the
 * case where the confident-wrong-answer failure this project keeps fighting is
 * most likely: a truncated file, a hand-patched header or a packed binary all
 * produce bytes that parse without error and describe as something real.
 *
 * It is deliberately separate from parsing. A reader that reported a problem by
 * returning null would make "this binary is damaged" indistinguishable from "this
 * binary does not have that", which is the same conflation `a2o` was fixed for.
 * So parsing stays permissive and this reports alongside it.
 *
 * ## What is checked, and what is not
 *
 * Only things that can be decided from the bytes alone, and only where being
 * wrong would change a tool's answer:
 *
 *   - header flag bits with no name in `loader.h`;
 *   - fewer readable load commands than the header's `ncmds` claims, which means
 *     the walk was cut short and the section and symbol tables may be incomplete;
 *   - a section or segment claiming bytes past the end of its slice;
 *   - a symbol or string table reaching past the slice;
 *   - the symbol and string tables overlapping each other, which no legitimate
 *     linker output does;
 *   - a string table whose byte distribution is too flat to be text.
 *
 * Deliberately not checked: an `LC_MAIN` entry point outside `__TEXT`. That is the
 * normal state of a dyld shared-cache stub and, measured, also true of a
 * fully-symbolled 113 MB `node` — so the check fired on essentially every correct
 * binary this package is pointed at. A warning that is always true teaches a
 * reader to skip warnings; the raw offset is reported in `entryPoint` instead, and
 * whether it lands in `__TEXT` is disclosed there as a fact rather than a verdict.
 *
 * Deliberately *not* checked: unknown load commands. Those are already surfaced
 * by `loadCommandName` as a number rather than a name, which is this project's
 * chosen line for "present but not understood", and listing them a second time
 * as abnormalities would grade an unfamiliar-but-valid command as damage.
 *
 * ## On the packing heuristic
 *
 * Entropy is a heuristic and is labelled as one. Printable text sits around
 * 4.5-5.2 bits per byte and compressed or encrypted data near 8, so the
 * threshold sits in the empty gap between them — but obfuscated-but-not-compressed
 * data lands above it, and a legitimately compressed string table would land
 * above it too. It says "look at this", never "this is packed".
 *
 * @param {object} f an `opener()` handle
 * @param {object} thin a `parseThin()` result
 * @param {object} [opts]
 * @param {number} [opts.sliceOffset=0] the slice's offset within the file
 * @param {number} [opts.sliceSize] the slice's size; defaults to the rest of the file
 * @returns {Array<{kind: string, detail: string}>}
 */
export function detectAbnormalities(f, thin, { sliceOffset = 0, sliceSize = null } = {}) {
  const out = [];
  const sliceEnd = sliceSize == null ? f.size - sliceOffset : sliceSize;
  const add = (kind, detail) => out.push({ kind, detail });

  // Header flags this table cannot name. A real binary can set a bit added after
  // this reader was written, so the detail says "unrecognised" rather than
  // "corrupt" — it is a claim about the names, not about the file.
  const hdr = decodeHeaderFlags(thin.flags);
  if (hdr.unknown !== 0) {
    add(
      'unknown-header-flags',
      `header sets flag bits with no name in <mach-o/loader.h>: 0x${hdr.unknown.toString(16)}`,
    );
  }

  if (thin.loadCommands.length < thin.ncmds) {
    add(
      'load-commands-truncated',
      `header declares ${thin.ncmds} load command(s), only ${thin.loadCommands.length} were readable — ` +
        'the segment, section and symbol tables below may be incomplete',
    );
  }

  // Sections past the slice. Gated on `isBackedByFile`, which is what separates
  // "claims bytes that are not there" from "__bss legitimately occupies no bytes":
  // a zero-fill section carries a real address range and a `size` that can easily
  // exceed the file, and flagging it would be flagging every ordinary binary.
  for (const sec of thin.sections) {
    if (sec.size === 0) continue;
    if (!isBackedByFile(thin, sec)) continue;
    if (sec.offset + sec.size > sliceEnd) {
      add(
        'section-past-slice-end',
        `${sec.segname},${sec.sectname} claims bytes ${sec.offset}..${sec.offset + sec.size}, ` +
          `past the end of the slice at ${sliceEnd}`,
      );
    }
    if (sec.attributesUnknown !== 0) {
      add(
        'unknown-section-attributes',
        `${sec.segname},${sec.sectname} sets attribute bits with no name in <mach-o/loader.h>: ` +
          `0x${sec.attributesUnknown.toString(16)}`,
      );
    }
    if (sec.type.startsWith('S_UNKNOWN_')) {
      add(
        'unknown-section-type',
        `${sec.segname},${sec.sectname} has section type 0x${sec.typeRaw.toString(16)}, ` +
          'which <mach-o/loader.h> does not define',
      );
    }
  }

  for (const seg of thin.segments) {
    const hi = seg.fileoff + seg.filesize;
    if (hi > sliceEnd) {
      add(
        'segment-past-slice-end',
        `${seg.segname} claims file bytes ${seg.fileoff}..${hi}, past the end of the slice at ${sliceEnd}`,
      );
    }
  }

  const st = thin.symtab;
  if (st) {
    // The stride differs between `nlist` (12) and `nlist_64` (16), so it is taken
    // from the parse rather than written as a constant — the same trap that once
    // read every symbol in a 32-bit slice one entry off.
    const stride = thin.is64 ? 16 : 12;
    const symEnd = st.symoff + st.nsyms * stride;
    if (st.nsyms > 0 && symEnd > sliceEnd) {
      add(
        'symtab-past-slice-end',
        `LC_SYMTAB claims ${st.nsyms} symbol(s) in bytes ${st.symoff}..${symEnd}, ` +
          `past the end of the slice at ${sliceEnd}`,
      );
    }
    const strEnd = st.stroff + st.strsize;
    if (st.strsize > 0 && strEnd > sliceEnd) {
      add(
        'strtab-past-slice-end',
        `LC_SYMTAB claims a string table in bytes ${st.stroff}..${strEnd}, ` +
          `past the end of the slice at ${sliceEnd}`,
      );
    }
    if (st.nsyms > 0 && st.strsize > 0
      && st.symoff < strEnd && st.stroff < symEnd) {
      add(
        'symtab-strtab-overlap',
        `the symbol table (${st.symoff}..${symEnd}) and the string table (${st.stroff}..${strEnd}) ` +
          'overlap — no linker emits this, and a reader cannot trust either extent',
      );
    }
    if (st.strsize > 0) {
      const h = shannonEntropy(f, sliceOffset + st.stroff, st.strsize);
      if (h > PACKED_ENTROPY) {
        add(
          'strtab-high-entropy',
          `the string table averages ${h.toFixed(2)} bits/byte over its first ` +
            `${Math.min(st.strsize, 1 << 20)} bytes — above the ~6.4 threshold, ` +
            'so it may be compressed or obfuscated rather than plain text',
        );
      }
    }
  }

  return out;
}

/**
 * Map a file offset to a vaddr within a parsed slice, or null if unmapped.
 * Used to turn a literal's file offset into the address a tool must cite.
 *
 * Zero-fill sections are skipped. They are listed first-and-foremost as sections
 * but have no bytes, so a file offset inside one belongs to whatever actually
 * occupies that range — usually the header. See `isBackedByFile`.
 */
export function toVaddr(thin, fileOff) {
  for (const s of thin.sections) {
    if (!isBackedByFile(thin, s)) continue;
    if (fileOff >= s.offset && fileOff < s.offset + s.size) {
      return {
        vaddr: s.addr + BigInt(fileOff - s.offset),
        section: `${s.segname},${s.sectname}`,
      };
    }
  }
  for (const s of thin.segments) {
    if (fileOff >= Number(s.fileoff) && fileOff < Number(s.fileoff) + Number(s.filesize)) {
      return {
        vaddr: s.vmaddr + BigInt(fileOff - Number(s.fileoff)),
        section: `${s.segname} (segment)`,
      };
    }
  }
  return null;
}

/**
 * Map a vaddr to a file offset within a parsed slice, or null.
 *
 * The inverse of `toVaddr`, and the half that needs the zero-fill check more
 * urgently: `__bss` has an address and a size, so a vaddr inside it *looks*
 * mappable, but no byte of it exists in the file. Returned as
 * `{ zerofill: true }` rather than null, because "this address exists but is not
 * in the file" and "this address is not in this binary" are different answers
 * and a caller patching a file needs to tell them apart.
 *
 * Sections first, then segments, mirroring `toVaddr`: a section is the tighter
 * answer, and the segment range is what covers the padding between them.
 */
export function toFileOffset(thin, vaddr) {
  for (const s of thin.sections) {
    if (vaddr < s.addr || vaddr >= s.addr + BigInt(s.size)) continue;
    if (!isBackedByFile(thin, s)) {
      return {
        offset: null,
        zerofill: true,
        section: `${s.segname},${s.sectname}`,
        segname: s.segname,
      };
    }
    return {
      offset: s.offset + Number(vaddr - s.addr),
      zerofill: false,
      section: `${s.segname},${s.sectname}`,
      segname: s.segname,
    };
  }
  for (const s of thin.segments) {
    if (vaddr < s.vmaddr || vaddr >= s.vmaddr + s.vmsize) continue;
    const delta = vaddr - s.vmaddr;
    // Past `filesize` the segment is mapped but absent from the file: the tail of
    // a `__DATA` that runs into `__bss`, or all of `__PAGEZERO`.
    if (delta >= s.filesize) {
      return {
        offset: null,
        zerofill: true,
        section: `${s.segname} (segment)`,
        segname: s.segname,
      };
    }
    return {
      offset: Number(s.fileoff) + Number(delta),
      zerofill: false,
      section: `${s.segname} (segment)`,
      segname: s.segname,
    };
  }
  return null;
}

/** The section containing a file offset, or null. */
export function sectionOf(thin, fileOff) {
  return thin.sections.find(
    (s) => isBackedByFile(thin, s) && fileOff >= s.offset && fileOff < s.offset + s.size,
  ) || null;
}

/**
 * Find a byte string inside a section, stopping early per needle.
 *
 * Scoped to `__TEXT` rather than the whole file: literals live there, and a
 * whole-file sweep of a 476 MB universal binary is slow enough that tools end
 * up not being run. The `overlap` window carries a match that straddles a
 * chunk boundary, which a naive chunked scan silently drops.
 *
 * `sliceBase` is the slice's file offset within the file. A section's `offset`
 * is slice-relative, so on a universal binary this reads the wrong bytes without
 * it — see `scanSection` in `api.mjs` for the full account of how that stayed
 * hidden. Returns absolute file offsets and vaddrs.
 */
export function findInSection(
  f,
  sec,
  needles,
  { perNeedle = 4, chunk = 1 << 24, overlap = 64, sliceBase = 0 } = {},
) {
  const found = new Map();
  if (!sec || sec.size === 0) return { hits: found, scanned: 0, available: false };
  const enc = needles.map((n) => Buffer.from(n, 'latin1'));
  const start = sliceBase + sec.offset;
  const end = start + sec.size;
  let pos = start;
  let carry = Buffer.alloc(0);
  let carryBase = start;
  let scanned = 0;

  while (pos < end) {
    const buf = f.read(pos, Math.min(chunk, end - pos));
    if (buf.length === 0) break;
    scanned += buf.length;
    const hay = Buffer.concat([carry, buf]);
    const base = carryBase;

    for (let i = 0; i < enc.length; i++) {
      const key = needles[i];
      const list = found.get(key) || [];
      if (list.length >= perNeedle) continue;
      let from = 0;
      while (list.length < perNeedle) {
        const at = hay.indexOf(enc[i], from);
        if (at < 0) break;
        const abs = base + at;
        const pre = hay.subarray(Math.max(0, at - 16), at);
        list.push({
          off: abs,
          vaddr: sec.addr + BigInt(abs - start),
          section: sec.sectname,
          ctx: pre.toString('latin1').replace(/[^\x20-\x7e]/g, '.').slice(-16),
        });
        from = at + 1;
      }
      found.set(key, list);
    }

    if (needles.every((n) => (found.get(n) || []).length >= perNeedle)) break;
    carry = hay.subarray(Math.max(0, hay.length - overlap));
    carryBase = base + hay.length - carry.length;
    pos += buf.length;
  }
  return { hits: found, scanned, available: true };
}

