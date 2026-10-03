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
  let off = base + (is64 ? 32 : 28);
  const segments = [];
  const sections = [];
  const loadCommands = [];
  let symtab = null;
  let uuid = null;

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
            flags: sc.readUInt32LE(wide ? 64 : 56),
          });
        }
      }
    }
    off += cmdsize;
  }
  return { is64, cputype, cpusubtype, filetype, ncmds, sizeofcmds, segments, sections, loadCommands, symtab, uuid };
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

