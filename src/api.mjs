/**
 * api.mjs — the supported programmatic interface.
 *
 * ## Why this exists
 *
 * The six CLIs were the only interface. Each reimplemented what it needed from
 * the file format, and they diverged in ways that were not merely inelegant:
 *
 *   - `symfind.mjs` and `symlookup.mjs` each parsed `LC_SYMTAB` by hand rather
 *     than calling `readSymbols`, so `symgrep` filtered to defined symbols while
 *     they reported imports alongside them.
 *   - `mapliteral.mjs` reimplemented the fat-header walk *and* hardcoded
 *     `if (cputype === 0x01000007)`, then threw `'x86_64 slice not found'` on an
 *     arm64-only binary — the exact "absent architecture is fatal" defect the
 *     rest of the project fixed and the smoke test guards against. It escaped
 *     because it did not share the reader, which is precisely the argument for
 *     sharing it.
 *
 * The README has always said this reader is meant to be imported or vendored,
 * and LGPL-3.0 §4d1 exists so that embedding it does not infect the embedding
 * application. None of that is usable while the only way in is to spawn a
 * subprocess and parse English. This module makes the licence rationale and the
 * "it is a reader, not a script" claim the same thing.
 *
 * ## Shape of every result
 *
 * Each function returns a plain object and throws nothing for ordinary
 * negative answers: no match is `{ matches: [] }`, not an exception. A caller
 * asking "does this binary call X" wants `false`, not a stack trace. Genuine
 * I/O failures do throw, because a caller that cannot distinguish "no result"
 * from "could not look" has the problem this project keeps fixing.
 *
 * Addresses come back as BigInt, matching `macho.mjs`. They do not fit in a
 * JSON number and must not be silently truncated; `output.mjs` renders them as
 * hex strings when a caller asks for JSON.
 *
 * ## Stability
 *
 * The exports here are the package's public surface and follow semver.
 * `macho.mjs` is also importable, but new format support lands there first, so
 * it is treated as lower-level: stable within a major version, more likely to
 * grow.
 */

import {
  opener, isMachOFile, slicesOf, parseThin, readSymbols, preferredSlice,
  richestSlice, sliceName, textSection, codeSections, sectionOf, toVaddr,
} from './macho.mjs';

/* ------------------------------------------------------------------ *
 * opening
 * ------------------------------------------------------------------ */

/**
 * Open a binary, hand it to `fn`, close it afterwards.
 *
 * A handle per call is the whole lifecycle. The alternative — an object with an
 * explicit `close()` — is a handle that leaks whenever a caller forgets, and
 * every consumer of this package is a short script. Callers that genuinely want
 * one open can use `macho.mjs`'s `opener` directly.
 *
 * @param {string} path
 * @param {(f: object) => T} fn
 * @returns {T} whatever `fn` returns
 * @throws if the path cannot be opened or is not a Mach-O
 */
export function withFile(path, fn) {
  if (typeof path !== 'string' || !path) throw new TypeError('withFile: a path is required');
  if (!isMachOFile(path)) throw new Error(`${path}: not a Mach-O binary`);
  const f = opener(path);
  try {
    return fn(f);
  } finally {
    f.close();
  }
}

/**
 * What is in this file: every slice, with architecture, extent and symbol
 * counts. The first thing to call on an unknown binary.
 *
 * `thin` means "this file is a single-architecture Mach-O", which is a different
 * statement from "this slice has one architecture". The two are routinely
 * confused, and confusing them is how the fixed-offset reader bug happened.
 */
export function describe(path) {
  return withFile(path, (f) => {
    const slices = [];
    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      const arch = s.thin ? sliceName(thin?.cputype) : sliceName(s.cputype);
      if (!thin) {
        slices.push({
          arch, offset: s.offset, size: s.size, thin: s.thin, readable: false,
          nsyms: 0, defined: 0, codeSections: 0, textAddr: null, textSize: 0,
          note: 'no Mach-O header at this offset',
        });
        continue;
      }
      const syms = readSymbols(f, s.offset, thin);
      const text = textSection(thin);
      slices.push({
        arch,
        offset: s.offset,
        size: s.size,
        thin: s.thin,
        readable: true,
        bits: thin.is64 ? 64 : 32,
        nsyms: syms.total,
        defined: syms.defined,
        note: syms.note,
        textAddr: text ? text.addr : null,
        textSize: text ? text.size : 0,
        codeSections: codeSections(thin).sections.length,
      });
    }
    return {
      path,
      size: f.size,
      fat: slices.length > 1 || slices.every((s) => !s.thin),
      slices,
    };
  });
}

/* ------------------------------------------------------------------ *
 * symbols
 * ------------------------------------------------------------------ */

/** Which slice a symbol query should read: a named arch, else the richest. */
function symbolSlice(f, arch) {
  if (arch) {
    const named = preferredSlice(f, arch);
    if (named) return named;
    // A preference, not a requirement: falling through to the richest is the
    // behaviour that stopped an arm64-only binary from failing outright.
  }
  const rich = richestSlice(f);
  if (!rich) throw new Error('no Mach-O slice could be parsed');
  return { offset: rich.offset, arch: rich.arch, thin: rich.thin, size: rich.size };
}

/**
 * Regex over a slice's symbol table.
 *
 * `definedOnly` defaults to true, matching `symgrep`: an imported name carries
 * neither an address nor an implementation, so this answers "where is this
 * implemented" rather than "what does this link against". Turn it off when
 * imports are the actual question.
 */
export function grepSymbols(path, pattern, { arch, flags = 'i', definedOnly = true } = {}) {
  const re = new RegExp(pattern, flags);
  return withFile(path, (f) => {
    const slice = symbolSlice(f, arch);
    const syms = readSymbols(f, slice.offset, slice.thin);
    const matches = syms.entries
      .filter((e) => (definedOnly ? e.defined : true) && re.test(e.name))
      .sort(byAddr);
    return { arch: slice.arch, pattern, flags, matches, defined: syms.defined, total: syms.total, note: syms.note };
  });
}

/**
 * Substring over a symbol table, deduplicated and address-ordered.
 *
 * Deduplicated because a symbol table routinely carries one name at several
 * addresses — aliases, thunks, per-architecture copies — and a list where
 * `memcpy` appears nine times is harder to read than one where it appears once.
 * `unique: false` restores the raw per-entry form.
 */
export function findSymbols(path, substring, { arch, max = 4000, unique = true } = {}) {
  return withFile(path, (f) => {
    const slice = symbolSlice(f, arch);
    const syms = readSymbols(f, slice.offset, slice.thin);
    const hits = syms.entries.filter((e) => e.name.includes(substring));
    const matches = unique
      ? [...new Map(hits.map((e) => [e.name, e])).values()].sort(byAddr).slice(0, max)
      : hits.slice(0, max);
    return {
      arch: slice.arch, substring, matches,
      count: hits.length,
      uniqueCount: new Set(hits.map((e) => e.name)).size,
      truncated: unique && hits.length > max,
      defined: syms.defined, total: syms.total, note: syms.note,
    };
  });
}

/**
 * Which function contains a virtual address.
 *
 * Only defined, address-bearing symbols are considered. Imported symbols carry
 * `n_value == 0`, so including them makes any low address resolve to an import
 * sitting at zero — a confident, plausible, wrong answer, and the single worst
 * failure mode this project has produced.
 */
export function lookupAddress(path, vaddr, { arch } = {}) {
  const target = typeof vaddr === 'bigint' ? vaddr : BigInt(vaddr);
  return withFile(path, (f) => {
    const slice = symbolSlice(f, arch);
    const syms = readSymbols(f, slice.offset, slice.thin);
    const defs = syms.entries.filter((e) => e.defined && e.addr !== 0n).sort(byAddr);

    if (defs.length === 0) {
      return {
        arch: slice.arch, vaddr: target, function: null, start: null, next: null,
        offset: null, size: null,
        note: 'no defined symbols in this slice — stripped, or a dyld-cache stub',
      };
    }

    // Last defined symbol at or below the target.
    let lo = 0;
    let hi = defs.length - 1;
    let best = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (defs[mid].addr <= target) { best = mid; lo = mid + 1; } else hi = mid - 1;
    }
    if (best < 0) {
      return {
        arch: slice.arch, vaddr: target, function: null, start: null, next: null,
        offset: null, size: null,
        note: 'no defined symbol at or below this address',
      };
    }

    // Walk back over aliases sharing this name, so the reported start is the
    // real function entry rather than whichever alias the table ordered first.
    let at = best;
    while (at > 0 && defs[at - 1].name === defs[best].name) at--;
    const start = defs[at].addr;
    const next = defs[best + 1] ? defs[best + 1].addr : null;
    return {
      arch: slice.arch, vaddr: target, function: defs[at].name, start, next,
      offset: target - start, size: next === null ? null : next - start, note: null,
    };
  });
}

const byAddr = (a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0);

/* ------------------------------------------------------------------ *
 * call sites
 * ------------------------------------------------------------------ */

/** The direct-call encoding for an architecture, or null if unknown. */
export function callEncoding(arch) {
  if (arch.startsWith('x86_64') || arch.startsWith('i386')) return 'x86 rel32';
  if (arch.startsWith('arm64') || arch === 'arm') return 'arm64 BL';
  return null;
}

/**
 * Direct `call`/`jmp` sites resolving to `target`, across every slice.
 *
 * ## Typed by default, and that is the whole point
 *
 * The scan covers only sections whose attributes mark them as instructions. The
 * earlier version swept all of `__text`, which is not entirely code — it also
 * carries `__cstring`, `__const`, `__literal4`, jump tables and padding. Any of
 * those can hold four bytes that decode as a `call rel32` aimed at the address
 * you asked about, and each was reported as a call site. The output read as a
 * caller list and was partly fiction.
 *
 * `includeData: true` restores the old sweep, for when the data sections are
 * exactly what you are hunting. `typed` in the result says which you got, and
 * `untypedFallback` says the slice marked no section as instructions at all —
 * a rare and slightly worrying input, where reporting zero call sites would be
 * the confident-wrong-answer failure this project keeps producing.
 *
 * ## What is still not found
 *
 * Indirect calls, register calls and jumps through a PLT stub do not encode
 * their target in the instruction, so they cannot appear here. Every hit is a
 * site *worth disassembling*, not a proven call-graph edge.
 */
export function findCalls(path, target, { arch, includeData = false, max = 0 } = {}) {
  const want = typeof target === 'bigint' ? target : BigInt(target);
  return withFile(path, (f) => {
    const hits = [];
    const slices = [];
    const unsupported = [];
    let scanned = 0;

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceName(thin.cputype) : sliceName(s.cputype);
      if (arch && name !== arch) continue;

      const enc = callEncoding(name);
      if (!enc) { unsupported.push(name); continue; }

      const pool = sectionPool(thin, includeData);
      const record = {
        arch: name,
        encoding: enc,
        typed: !pool.widened,
        untypedFallback: pool.fallback,
        sections: [],
        scanned: 0,
        skipped: null,
      };

      // Whether the *target* is in this slice at all — a slice that cannot
      // contain the destination cannot hold a call to it, and saying so is not
      // the same as scanning and finding nothing.
      //
      // Note what this check is NOT: filtering the scanning sections by whether
      // they contain the target. A caller and its callee usually live in
      // different places, so that reading skips every section that could hold a
      // real call site and reports zero for a function that is demonstrably
      // called thousands of times.
      if (!coversAddress(thin, want)) {
        record.skipped =
          `target 0x${want.toString(16)} is not mapped in this slice — skipped`;
        slices.push(record);
        continue;
      }

      for (const sec of pool.sections) {
        record.sections.push({
          name: `${sec.segname},${sec.sectname}`, addr: sec.addr, size: sec.size,
        });
        record.scanned += scanSection(f, sec, name, enc, want, hits, s.offset);
      }
      scanned += record.scanned;
      if (record.sections.length === 0) {
        record.skipped = 'this slice has no non-empty code section to scan';
      }
      slices.push(record);
    }

    hits.sort(byAddr);
    return {
      target: want,
      hits: max > 0 ? hits.slice(0, max) : hits,
      count: hits.length,
      truncated: max > 0 && hits.length > max,
      scanned,
      slices,
      unsupported,
      typed: !includeData,
    };
  });
}

/**
 * The distinct addresses a binary calls or jumps to directly.
 *
 * This inverts `findCalls`, and it is also the only honest way to tell a working
 * scanner from a dead one: a broken scanner and a scanner that legitimately
 * found no caller of *one* address look identical, but only one of them
 * produces an empty *target* list for a whole binary.
 */
export function listCallTargets(path, { arch, includeData = false, minSites = 0 } = {}) {
  return withFile(path, (f) => {
    const counts = new Map();
    const slices = [];
    const unsupported = [];
    let scanned = 0;

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceName(thin.cputype) : sliceName(s.cputype);
      if (arch && name !== arch) continue;
      const enc = callEncoding(name);
      if (!enc) { unsupported.push(name); continue; }

      const pool = sectionPool(thin, includeData);
      let sliceScanned = 0;
      // The same mapped-range gate `findCalls` applies. A `rel32` is signed, so
      // from a high address it can decode to a destination that falls in no
      // section and no segment at all — pure arithmetic on bytes that were never
      // an instruction. Counting those makes the target list look busy and
      // disagrees with what `findCalls` reports for the same binary, which is
      // the kind of disagreement a caller cannot reason about.
      const mapped = (v) => coversAddress(thin, v);
      for (const sec of pool.sections) sliceScanned += tallySection(f, sec, enc, counts, s.offset, mapped);
      scanned += sliceScanned;
      slices.push({
        arch: name, encoding: enc, typed: !pool.widened,
        untypedFallback: pool.fallback, scanned: sliceScanned,
      });
    }

    const targets = [...counts.entries()]
      .filter(([, n]) => n >= minSites)
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .map(([dest, sites]) => ({ dest, sites }));
    return { targets, total: targets.length, scanned, slices, unsupported, typed: !includeData };
  });
}

/**
 * The sections a call scan should cover.
 *
 * `includeData` deliberately widens to *every* non-empty section, data included.
 * That is the old behaviour and it is available on request, not on by default.
 */
function sectionPool(thin, includeData) {
  if (includeData) {
    return { sections: thin.sections.filter((s) => s.size > 0), fallback: false, widened: true };
  }
  return codeSections(thin);
}

/**
 * True when `vaddr` falls inside anything this slice maps.
 *
 * Sections first, then segments, because a section is a subset of a segment and
 * the segment is what covers the gaps — `__PAGEZERO`, and the tail of a segment
 * past its last section. A target in the former is unreachable by a direct
 * branch; one in the latter might be.
 */
export function coversAddress(thin, vaddr) {
  for (const s of thin.sections) {
    if (vaddr >= s.addr && vaddr < s.addr + BigInt(s.size)) return true;
  }
  for (const s of thin.segments) {
    if (vaddr >= s.vmaddr && vaddr < s.vmaddr + s.vmsize) return true;
  }
  return false;
}

/**
 * Scan one section for direct calls to `want`. Returns bytes scanned.
 *
 * `sliceBase` is the slice's file offset, and it is required. A `section_64`'s
 * `offset` is relative to the start of its *slice*, not to the start of the
 * file — so on a universal binary every read has to add the slice base. Omitting
 * it does not crash and does not return nothing: it reads the right *number* of
 * bytes from the wrong place, and finds whatever call encodings happen to sit
 * there. The system binaries this project was tested against were thin or had
 * their first slice near enough to the file start to make the mistake hard to
 * notice, which is why a generated fat fixture with slices at known offsets
 * found it and `/usr/bin/true` never did.
 */
function scanSection(f, sec, arch, enc, want, hits, sliceBase) {
  const CHUNK = 1 << 24;
  const label = `${sec.segname},${sec.sectname}`;
  let scanned = 0;
  let pos = 0;

  while (pos < sec.size) {
    const buf = f.read(sliceBase + sec.offset + pos, Math.min(CHUNK, sec.size - pos));
    if (buf.length === 0) break;
    scanned += buf.length;
    const base = sec.addr + BigInt(pos);

    if (enc === 'x86 rel32') {
      for (const op of [0xe8, 0xe9]) {
        let i = buf.indexOf(op);
        while (i !== -1 && i + 5 <= buf.length) {
          const rel = BigInt(buf.readInt32LE(i + 1));
          if (base + BigInt(i) + 5n + rel === want) {
            hits.push({ addr: base + BigInt(i), kind: op === 0xe8 ? 'call' : 'jmp', arch, section: label });
          }
          i = buf.indexOf(op, i + 1);
        }
      }
    } else {
      // 4 bytes at a time, so only aligned `BL`s are considered.
      for (let i = 0; i + 4 <= buf.length; i += 4) {
        const insn = buf.readUInt32LE(i);
        // `>>> 0`: `&` alone yields a *signed* int32 and 0x94000000 is above 2^31,
        // so both sides go negative and the mask never matches. That bug kept
        // the arm64 path a confident zero for its entire life.
        if (((insn & 0xfc000000) >>> 0) !== 0x94000000) continue;
        let imm = insn & 0x03ffffff;
        if (imm & 0x02000000) imm -= 0x04000000; // sign-extend from 26 bits
        const site = base + BigInt(i);
        if (site + (BigInt(imm) << 2n) === want) {
          // `BL` is branch-with-link: it *calls*, unlike the x86 `jmp` sharing
          // its opcode byte.
          hits.push({ addr: site, kind: 'BL', arch, section: label });
        }
      }
    }

    // Four displacement bytes follow the opcode, so a 4-byte overlap catches a
    // straddling instruction. Unlike `len - 5` this cannot exceed `len`, so it
    // cannot stop advancing on a short final chunk and hang the tool.
    const advance = buf.length - 4;
    pos += advance > 0 ? advance : buf.length;
    if (advance <= 0) break;
  }
  return scanned;
}

/**
 * Tally every direct-call destination in one section. Returns bytes scanned.
 *
 * `sliceBase` for the same reason as `scanSection`: a section's file offset is
 * slice-relative, and reading without the base reads the wrong bytes while
 * looking like it worked.
 *
 * `mapped` is the predicate deciding whether a decoded destination is an address
 * this slice maps at all.
 */
function tallySection(f, sec, enc, counts, sliceBase, mapped) {
  const CHUNK = 1 << 24;
  let scanned = 0;
  let pos = 0;
  while (pos < sec.size) {
    const buf = f.read(sliceBase + sec.offset + pos, Math.min(CHUNK, sec.size - pos));
    if (buf.length === 0) break;
    scanned += buf.length;
    const base = sec.addr + BigInt(pos);
    if (enc === 'x86 rel32') {
      for (const op of [0xe8, 0xe9]) {
        let i = buf.indexOf(op);
        while (i !== -1 && i + 5 <= buf.length) {
          const dest = base + BigInt(i) + 5n + BigInt(buf.readInt32LE(i + 1));
          if (mapped(dest)) counts.set(dest, (counts.get(dest) || 0) + 1);
          i = buf.indexOf(op, i + 1);
        }
      }
    } else {
      for (let i = 0; i + 4 <= buf.length; i += 4) {
        const insn = buf.readUInt32LE(i);
        if (((insn & 0xfc000000) >>> 0) !== 0x94000000) continue;
        let imm = insn & 0x03ffffff;
        if (imm & 0x02000000) imm -= 0x04000000;
        const dest = base + BigInt(i) + (BigInt(imm) << 2n);
        if (mapped(dest)) counts.set(dest, (counts.get(dest) || 0) + 1);
      }
    }
    const advance = buf.length - 4;
    pos += advance > 0 ? advance : buf.length;
    if (advance <= 0) break;
  }
  return scanned;
}

/* ------------------------------------------------------------------ *
 * literals
 * ------------------------------------------------------------------ */

/**
 * Find a byte literal, in the whole file by default.
 *
 * The whole file, not `__TEXT`: a format magic can just as easily sit in
 * `__DATA` or be embedded in code, and can exist in one slice of a universal
 * binary but not the other. `textOnly: true` restricts the sweep to `__TEXT`,
 * which is far cheaper when you already know it is there.
 *
 * Each hit carries its slice, its vaddr where the slice maps one, its section
 * and the bytes around it. That combination usually distinguishes a string from
 * a pointer table from bytes that happen to sit inside an instruction, without
 * opening a disassembler.
 */
export function findLiteral(path, literal, { textOnly = false, max = 0 } = {}) {
  const needle = Buffer.isBuffer(literal) ? literal : Buffer.from(String(literal), 'latin1');
  return withFile(path, (f) => {
    const slices = [];
    const hits = [];
    let scanned = 0;

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceName(thin.cputype) : sliceName(s.cputype);
      const text = textSection(thin);
      const textLo = text ? s.offset + text.offset : 0;
      const textHi = text ? textLo + text.size : 0;

      const from = textOnly && text ? textLo : s.offset;
      const to = textOnly && text ? textHi : s.offset + s.size;
      const found = searchRange(f, needle, from, to);
      scanned += to - from;
      slices.push({ arch: name, offset: s.offset, size: s.size, from, to, hits: found.length });

      for (const off of found) {
        const inText = text && off >= textLo && off < textHi;
        const sec = sectionOf(thin, off - s.offset);
        hits.push({
          off,
          slice: name,
          inText,
          vaddr: inText
            ? text.addr + BigInt(off - textLo)
            : toVaddr(thin, off - s.offset)?.vaddr ?? null,
          section: sec ? `${sec.segname},${sec.sectname}` : null,
          context: contextAround(f, off, 16, 8),
        });
      }
    }
    hits.sort((a, b) => a.off - b.off);
    return {
      literal: needle.toString('latin1'),
      hex: needle.toString('hex'),
      hits: max > 0 ? hits.slice(0, max) : hits,
      count: hits.length,
      truncated: max > 0 && hits.length > max,
      scanned,
      slices,
      textOnly,
    };
  });
}

/**
 * Map a literal to its addresses, then find what *points at* those addresses.
 *
 * This is the tool with a purpose rather than a mechanism. A magic in read-only
 * data is only a label; the pointer tables hanging off it are the handler
 * table, and locating those is how you find the code that dispatches on a
 * format without disassembling anything.
 *
 * `offsets` overrides the literal search, for when the magic is assembled at
 * runtime and so never appears contiguously — the same reason `findCalls`
 * cannot see indirect calls. Slice choice is by symbol richness or `arch`, and
 * an absent architecture is a preference rather than a requirement, so this no
 * longer fails outright on an arm64-only binary.
 */
export function mapLiteral(path, literal, { arch, offsets = null, maxPointers = 40 } = {}) {
  const needle = Buffer.from(String(literal), 'latin1');
  return withFile(path, (f) => {
    const parsed = [];
    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceName(thin.cputype) : sliceName(s.cputype);
      if (arch && name !== arch) continue;
      const text = textSection(thin);
      const inText = text
        ? searchRange(f, needle, s.offset + text.offset, s.offset + text.offset + text.size)
        : [];
      const syms = readSymbols(f, s.offset, thin);
      parsed.push({
        name, s, thin, text, nsyms: syms.total, inText,
        report: { arch: name, offset: s.offset, size: s.size, inText: inText.length, nsyms: syms.total },
      });
    }
    if (parsed.length === 0) throw new Error('no Mach-O slice could be parsed');

    let best = parsed[0];
    for (const p of parsed) if (p.nsyms > best.nsyms) best = p;

    const given = offsets && offsets.length ? offsets.map(Number) : null;
    let abs;
    if (given) {
      // Offsets are file-absolute. Someone recording one by hand from
      // `findliteral` output has an absolute offset, and normalising a relative
      // one here would be a guess about which they meant.
      abs = given;
    } else if (best.text) {
      const lo = best.s.offset + best.text.offset;
      abs = searchRange(f, needle, lo, lo + best.text.size);
    } else {
      abs = [];
    }

    const locations = abs.map((o) => mapOne(best, o, f));
    const mapped = locations.filter((l) => l.vaddr !== null);
    for (const m of mapped) {
      const ptr = Buffer.alloc(8);
      ptr.writeBigUInt64LE(m.vaddr);
      m.pointers = [];
      // The pointer search is whole-file while the literal search is per-slice,
      // so a pointer has to be attributed through *its own* slice's section
      // table. Resolving it against the chosen slice instead makes every pointer
      // in another slice unmapped — which is what an early version of this did,
      // and it reported the universal fixture's second descriptor table as
      // having no location at all.
      for (const off of searchRange(f, ptr, 0, f.size)) {
        const owner = parsed.find((p) => off >= p.s.offset && off < p.s.offset + p.s.size);
        const rel = off - (owner ? owner.s.offset : best.s.offset);
        const sec = (owner || best).thin.sections.find(
          (x) => rel >= x.offset && rel < x.offset + x.size,
        );
        m.pointers.push({
          off,
          slice: owner ? owner.name : null,
          vaddr: (owner || best).thin.segments.length
            ? toVaddr((owner || best).thin, rel)?.vaddr ?? null
            : null,
          section: sec ? `${sec.segname},${sec.sectname}` : null,
        });
        if (m.pointers.length >= maxPointers) break;
      }
      m.pointerCount = m.pointers.length;
      m.pointersTruncated = m.pointerCount >= maxPointers;
    }

    return {
      literal: needle.toString('latin1'),
      hex: needle.toString('hex'),
      arch: best.name,
      sliceOffset: best.s.offset,
      explicit: Boolean(given),
      locations: mapped,
      unmapped: locations.filter((l) => l.vaddr === null),
      slices: parsed.map((p) => p.report),
    };
  });
}

/** One literal occurrence resolved to a vaddr and its section. */
function mapOne(best, abs, f) {
  const sec = sectionOf(best.thin, abs - best.s.offset);
  const m = toVaddr(best.thin, abs - best.s.offset);
  return {
    off: abs,
    vaddr: m ? m.vaddr : null,
    section: m ? m.section : null,
    context: contextAround(f, abs, 64, 24),
    fileExtent: sec ? { offset: sec.offset, size: sec.size } : null,
    pointers: null,
  };
}

/* ------------------------------------------------------------------ *
 * byte helpers
 * ------------------------------------------------------------------ */

/**
 * Find every occurrence of `needle` in `[from, to)`.
 *
 * Chunked with a carry window, because these literals get searched inside
 * multi-hundred-megabyte binaries and slurping a whole slice is how the tools
 * became too slow for anyone to run. The overlap is at least 64 bytes and
 * always longer than the needle, so a match straddling a chunk boundary is not
 * dropped — a naive chunked scan loses exactly those, silently.
 */
export function searchRange(f, needle, from, to) {
  if (to <= from || needle.length === 0) return [];
  const CHUNK = 1 << 24;
  const OVERLAP = Math.max(64, needle.length * 2);
  const found = [];
  let pos = from;
  let carry = Buffer.alloc(0);
  let carryBase = from;

  while (pos < to) {
    const buf = f.read(pos, Math.min(CHUNK, to - pos));
    if (buf.length === 0) break;
    const hay = Buffer.concat([carry, buf]);
    let i = 0;
    while (true) {
      const at = hay.indexOf(needle, i);
      if (at < 0) break;
      // `>= from` drops the duplicate a hit inside the carry produces twice.
      if (carryBase + at >= from) found.push(carryBase + at);
      i = at + 1;
    }
    carry = hay.subarray(Math.max(0, hay.length - OVERLAP));
    carryBase = carryBase + hay.length - carry.length;
    pos += buf.length;
  }
  return found;
}

/** Printable context around a file offset, as `pre` and `hit`. */
export function contextAround(f, off, preLen = 16, hitLen = 8) {
  const printable = (b) => b.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
  const lo = Math.max(0, off - preLen);
  const pre = f.read(lo, off - lo);
  return { pre: printable(pre), preFrom: lo, hit: printable(f.read(off, hitLen)) };
}

export { isMachOFile, sliceName, textSection, codeSections };
