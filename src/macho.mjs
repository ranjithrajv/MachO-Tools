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

/** nlist_64 type field: N_STAB and N_TYPE masks. */
export const N_STAB = 0xe0;
export const N_TYPE = 0x0e;
export const N_SECT = 0x0e;

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;

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

/** A human name for a CPU type, falling back to its raw value. */
export function sliceName(cputype) {
  if (cputype === CPU_X86_64) return 'x86_64';
  if (cputype === CPU_ARM64) return 'arm64';
  if (cputype === 0x0000000c) return 'arm';
  if (cputype === 0x00000007) return 'i386';
  if (cputype == null) return 'thin';
  return `cputype=0x${cputype.toString(16)}`;
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
  const ncmds = hdr.readUInt32LE(16);
  let off = base + (is64 ? 32 : 28);
  const segments = [];
  const sections = [];
  let symtab = null;

  for (let i = 0; i < ncmds; i++) {
    const lc = f.read(off, 8);
    if (lc.length < 8) break;
    const cmd = lc.readUInt32LE(0);
    const cmdsize = lc.readUInt32LE(4);
    if (cmdsize < 8) break; // a zero cmdsize would loop forever

    if (cmd === LC_SYMTAB) {
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
        // Section entries are 80 bytes each and exist only in the 64-bit form.
        if (wide) {
          const nsects = s.readUInt32LE(64);
          for (let k = 0; k < nsects; k++) {
            const sc = f.read(off + 72 + k * 80, 80);
            if (sc.length < 80) break;
            sections.push({
              sectname: sc.toString('latin1', 0, 16).replace(/\0.*$/, ''),
              segname: sc.toString('latin1', 16, 32).replace(/\0.*$/, ''),
              addr: sc.readBigUInt64LE(32),
              size: Number(sc.readBigUInt64LE(40)),
              offset: sc.readUInt32LE(48),
              // Section attributes (offset 64 in `section_64`). Read because
              // S_ATTR_*_INSTRUCTIONS is the only in-file signal that separates
              // code from data, and a byte scanner that cannot tell them apart
              // reports data as call sites — see `instructionSections`.
              flags: sc.readUInt32LE(64),
            });
          }
        }
      }
    }
    off += cmdsize;
  }
  return { is64, cputype, segments, sections, symtab };
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
  return [{ cputype: null, offset: 0, size: f.size, thin: true }];
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
  for (let b = 0; b < symtab.nsyms; b += BATCH) {
    const cnt = Math.min(BATCH, symtab.nsyms - b);
    const blk = f.read(base + symtab.symoff + b * 16, cnt * 16);
    if (blk.length < cnt * 16) break;
    for (let i = 0; i < cnt; i++) {
      const info = blk[i * 16 + 4];
      if (info & N_STAB) continue;
      const strx = blk.readUInt32LE(i * 16);
      if (strx >= str.length) continue;
      const isDefined = (info & N_TYPE) === N_SECT;
      if (isDefined) defined++;
      const nm = nameAt(strx);
      if (!nm) continue;
      names.push(nm);
      entries.push({ name: nm, addr: blk.readBigUInt64LE(i * 16 + 8), defined: isDefined });
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
      arch: s.thin ? sliceName(thin.cputype) : sliceName(s.cputype),
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
    const arch = s.thin ? sliceName(thin.cputype) : sliceName(s.cputype);
    const nsyms = thin.symtab ? thin.symtab.nsyms : 0;
    const entry = { offset: s.offset, arch, nsyms, thin, size: s.size };
    if (prefer && arch === prefer) return entry; // a named request wins outright
    if (!best || nsyms > best.nsyms) best = entry;
  }
  return best;
}

/**
 * Map a file offset to a vaddr within a parsed slice, or null if unmapped.
 * Used to turn a literal's file offset into the address a tool must cite.
 */
export function toVaddr(thin, fileOff) {
  for (const s of thin.sections) {
    if (fileOff >= s.offset && fileOff < s.offset + s.size) {
      return { vaddr: s.addr + BigInt(fileOff - s.offset), section: `${s.segname},${s.sectname}` };
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

/** The section containing a file offset, or null. */
export function sectionOf(thin, fileOff) {
  return thin.sections.find((s) => fileOff >= s.offset && fileOff < s.offset + s.size) || null;
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

