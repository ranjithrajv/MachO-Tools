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

import fs from 'node:fs';
import {
  opener, isMachOFile, slicesOf, parseThin, readSymbols, preferredSlice,
  richestSlice, sliceName, sliceArchName, textSection, codeSections, sectionOf, toVaddr,
  toFileOffset, isBackedByFile, archMatches,
  decodeHeaderFlags, decodeSectionFlags, decodeSourceVersion, detectAbnormalities,
  resolveEntryPoint,
} from './macho.mjs';

/* ------------------------------------------------------------------ *
 * opening
 * ------------------------------------------------------------------ */

/**
 * An error that names its reason code, so a caller does not have to read it.
 *
 * These are the same codes the JSON envelope publishes as `errors`, which is
 * what makes the contract usable from a program rather than a person: an agent
 * asking for `/nope` and for `/etc/hosts` gets two different codes and can act
 * on that, where before both arrived as `io` with the message "not a Mach-O
 * binary" — two unrelated problems reported as one, sending a caller looking in
 * the wrong place.
 *
 * @param {string} path
 * @returns {Error & { code: string }}
 */
function readerError(path) {
  // `statSync` rather than `existsSync` because the interesting case is a path
  // that is *there* and still unreadable — a directory, a dangling symlink, a
  // permissions problem — which `existsSync` reports as simply absent and so
  // would mislabel as a missing file rather than an unreadable one.
  let readable = true;
  try {
    if (fs.statSync(path).isDirectory()) readable = false;
  } catch {
    readable = false;
  }
  return Object.assign(
    new Error(
      readable
        ? `${path}: not a Mach-O binary`
        : `${path}: cannot be read (no such file, not a regular file, or not permitted)`,
    ),
    { code: readable ? 'unknown-encoding' : 'io' },
  );
}

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
 * @throws if the path cannot be opened or is not a Mach-O. The thrown error
 *   carries `.code`, one of the reason codes the JSON envelope documents —
 *   `io` for a path that cannot be read, `unknown-encoding` for a file that
 *   reads fine but is not Mach-O — so a caller can branch without matching
 *   English.
 */
export function withFile(path, fn) {
  if (typeof path !== 'string' || !path) throw new TypeError('withFile: a path is required');
  if (!isMachOFile(path)) throw readerError(path);
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
      const arch = s.thin ? sliceArchName(thin?.cputype, thin?.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
      if (!thin) {
        slices.push({
          arch, offset: s.offset, size: s.size, thin: s.thin, readable: false,
          nsyms: 0, defined: 0, codeSections: 0, textAddr: null, textSize: 0,
          uuid: null, segments: [], sections: [], loadCommands: [],
          flags: 0, flagsNamed: [], flagsUnknown: 0,
          entryPoint: null, rpaths: [], sourceVersion: null, abnormalities: [],
          note: 'no Mach-O header at this offset',
        });
        continue;
      }
      const syms = readSymbols(f, s.offset, thin);
      const text = textSection(thin);
      const hdr = decodeHeaderFlags(thin.flags);
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
        // The three lists the reader already parsed and nothing surfaced. A
        // caller asking "what is in this file" wants the sections, not a count
        // of how many are code — and `ipsw macho info --section` answers the
        // same question, so leaving these out meant being unable to do something
        // a competitor's dump does in one line.
        segments: thin.segments,
        sections: thin.sections,
        loadCommands: thin.loadCommands,
        uuid: thin.uuid,
        // The header `flags` word, its decoded names, and — kept separate — any
        // bits this reader cannot name. Folding "unrecognised" into "not set"
        // would let a newer binary describe as an ordinary one, which is the
        // quiet wrong answer this package exists to avoid.
        flags: thin.flags,
        flagsNamed: hdr.names,
        flagsUnknown: hdr.unknown,
        // `entryPoint` carries the resolved vaddr plus the segment it was derived
        // from, so a caller can see the arithmetic rather than trust a bare
        // number. `null` when the slice has no LC_MAIN.
        entryPoint: resolveEntryPoint(thin),
        // Runtime search paths, in the order the binary declares them. Order is
        // load order, and `@rpath` resolution depends on it.
        rpaths: thin.rpaths,
        // The five-part source version, or null when the binary declares none.
        sourceVersion: thin.sourceVersion,
        // Structural problems, reported alongside the parse rather than instead
        // of it. Empty on a healthy binary, which is the common case.
        abnormalities: detectAbnormalities(f, thin, { sliceOffset: s.offset, sliceSize: s.size }),
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
 * address <-> file offset
 * ------------------------------------------------------------------ */

/** A file position or address as a hex string, for the wire. */
const hex = (v) => `0x${v.toString(16)}`;

/**
 * Which slice an address or offset query should read.
 *
 * `symbolSlice` is the wrong choice here even though the fallback logic matches:
 * it picks the slice with the most *symbols*, and a stripped slice can be the one
 * whose layout you are asking about. An address is a question about a
 * particular slice's mapping, so `--arch` selects it when given and otherwise the
 * first slice that parses — the order the fat header lists, which is the order
 * the file itself declares. For a thin binary both agree.
 */
function layoutSlice(f, arch) {
  return layoutSlices(f, arch)[0];
}

/**
 * Every slice an address or offset query should consider.
 *
 * `symbolSlice` is the wrong choice here even though the fallback logic looks
 * similar: it picks the slice with the most *symbols*, and a stripped slice can
 * be the one whose layout you are asking about. Layout is a question about a
 * particular slice, so all of them are returned and the caller reports a single
 * answer only when exactly one slice agrees.
 */
function layoutSlices(f, arch) {
  if (arch) {
    const named = preferredSlice(f, arch);
    // A preference, not a requirement, matching every other tool here: an absent
    // architecture falls through to the whole file rather than failing.
    if (named) return [named];
  }
  const out = [];
  for (const s of slicesOf(f)) {
    const thin = parseThin(f, s.offset);
    if (thin) {
      out.push({
        offset: s.offset,
        arch: s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype),
        thin,
        size: s.size,
      });
    }
  }
  if (out.length === 0) throw new Error('no Mach-O slice could be parsed');
  return out;
}

/**
 * The shape both directions report, so one row means the same thing either way.
 *
 * `query`, `vaddr` and `offset` are hex strings, not numbers. A 64-bit file
 * position does not survive a `Number` and a BigInt does not survive
 * `JSON.stringify`, so a caller reading the envelope would otherwise get either a
 * thrown error or a silent precision loss — and this package already emits every
 * other address this way for the same reason.
 */
function mappingRow(slice, query, m) {
  return {
    arch: slice.arch,
    query: hex(query),
    // Taken from the mapping rather than echoed from the query: in one direction
    // the query *is* the vaddr and in the other it is a file offset, and a row
    // whose `vaddr` silently reported whichever was asked about would be wrong
    // half the time.
    vaddr: m.vaddr === null || m.vaddr === undefined ? hex(query) : hex(m.vaddr),
    offset: m.offset ?? null,
    // Absolute, for a file with more than one slice: a section's `offset` is
    // relative to its slice, so reporting it unqualified would send a reader to
    // the wrong bytes in every slice but the first.
    absoluteOffset: m.offset === null || m.offset === undefined ? null : slice.offset + m.offset,
    section: m.section,
    zerofill: m.zerofill === true,
    mapped: true,
    note: null,
  };
}

function unmappedRow(slice, query, note) {
  return {
    arch: slice.arch, query: hex(query), vaddr: null, offset: null, absoluteOffset: null,
    section: null, zerofill: false, mapped: false, note,
  };
}

/**
 * Virtual address to file offset: which byte of the file is this address?
 *
 * `offset` is slice-relative — the same basis the section table uses — and
 * `absoluteOffset` adds the slice's own position in the file. Both are reported
 * because a reader patching a file needs the absolute one and a reader
 * comparing against `otool -l` output needs the relative one, and guessing which
 * was meant is how the wrong bytes get edited.
 *
 * `zerofill` is true for an address that is mapped but has no bytes: `__bss`,
 * `__noptrbss`, `__PAGEZERO`, and the tail of a segment past `filesize`. Those
 * are separate answers from `mapped: false`, and a caller that wants to read or
 * write the byte has to treat them differently.
 */
export function addressToOffset(path, vaddr, { arch } = {}) {
  const want = typeof vaddr === 'bigint' ? vaddr : BigInt(vaddr);
  return withFile(path, (f) => {
    const slices = layoutSlices(f, arch);
    const per = [];
    for (const slice of slices) {
      const m = toFileOffset(slice.thin, want);
      if (!m) {
        per.push(unmappedRow(slice, want, 'address is not mapped by this slice'));
        continue;
      }
      const row = mappingRow(slice, want, m);
      row.note = m.zerofill
        ? `${m.section} is zero-fill — mapped at this address, but no byte of it exists in the file`
        : null;
      per.push(row);
    }

    const mapped = per.filter((r) => r.mapped);
    if (mapped.length === 1) return mapped[0];

    // More than one slice maps the address, or none does. Both are reported
    // rather than resolved, because picking a slice is a choice about which
    // binary you meant, and a fat binary's slices share an address space by
    // construction — `__TEXT` starts at 0x100000000 in every one of them.
    if (mapped.length === 0) {
      return {
        ...unmappedRow(per[0], want, 'address is not mapped by any slice'),
        slices: per,
      };
    }
    return {
      arch: null,
      query: hex(want),
      vaddr: hex(want),
      offset: null,
      absoluteOffset: null,
      section: null,
      zerofill: false,
      mapped: true,
      ambiguous: true,
      slices: per,
      note: `${mapped.length} slices map this address — pass --arch to choose one`,
    };
  });
}

/**
 * File offset to virtual address: which address does this byte have?
 *
 * `query` is reported as the slice-relative offset, since that is the basis
 * `toVaddr` uses; an absolute offset is accepted and converted when it falls in
 * this slice. Offsets in no slice are reported per slice rather than rejected, so
 * a fat binary answers for all of them in one call.
 *
 * A file offset can belong to more than one slice's *layout* only if the slices
 * overlap, which a well-formed fat binary does not do. Where they do, every
 * slice that maps the offset is reported, because picking one would be a guess.
 */
export function offsetToAddress(path, offsets, { arch } = {}) {
  const list = Array.isArray(offsets) ? offsets : [offsets];
  return withFile(path, (f) => {
    const candidates = layoutSlices(f, arch);

    const queries = list.map((raw) => {
      const abs = typeof raw === 'bigint' ? raw : BigInt(raw);
      // Offsets are absolute positions in the file. Each slice's row also carries
      // its own slice-relative offset, because a `section_64`'s `offset` is
      // relative to the slice and the two differ on every slice but the first.
      const per = [];
      for (const s of candidates) {
        // `s.offset` is a Number (a file position) and `abs` a BigInt (an
        // address-shaped quantity), so the subtraction is done in BigInt and
        // narrowed after. Mixing them directly throws.
        const rel = abs >= BigInt(s.offset) ? Number(abs - BigInt(s.offset)) : null;
        if (rel === null) {
          per.push(unmappedRow(s, abs, 'offset is before this slice in the file'));
          continue;
        }
        const m = toVaddr(s.thin, rel);
        if (!m) {
          per.push(unmappedRow(s, abs, 'no section or segment in this slice maps that offset'));
          continue;
        }
        // `m.vaddr` is the address this offset resolves to; `query` is the offset
        // that was asked about. Both are carried, and they differ on every slice
        // but the first.
        per.push(mappingRow(s, abs, { ...m, offset: rel }));
      }
      const mapped = per.filter((r) => r.mapped);
      return {
        query: hex(abs),
        basis: 'absolute',
        slices: per,
        // The one mapping, when there is exactly one. More than one is reported
        // rather than picked, and so is none.
        vaddr: mapped.length === 1 ? mapped[0].vaddr : null,
        ambiguous: mapped.length > 1,
      };
    });

    return { path, queries, slices: candidates.map((s) => ({ arch: s.arch, offset: s.offset })) };
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

/** The chosen slice plus its symbols, read once. Shared by every symbol query. */
function symbolsFor(f, arch) {
  const slice = symbolSlice(f, arch);
  return { slice, syms: readSymbols(f, slice.offset, slice.thin) };
}

/**
 * Search a symbol table by substring or regex, with one coherent set of rules.
 *
 * This is the primitive behind the `macho-sym` CLI, which replaced `symgrep`
 * and `symfind` — two tools that answered the same question with different
 * defaults. `symgrep` matched regexes, defaulted to defined symbols and returned
 * one row per table entry; `symfind` matched substrings, included imports and
 * deduplicated by name. Neither default was a mistake, and a tool with two
 * contradictory notions of "a symbol" is the kind of thing this project has been
 * deleting bugs out of — so the rules are now stated once:
 *
 *   - `mode: 'substring'` (default) matches literally; `'regex'` matches
 *     `/pattern/i`. Substring is the default because the name is usually known
 *     but not its exact spelling, and a pattern that accidentally compiles as a
 *     bad regex is a worse failure than one that matches too much.
 *   - `definedOnly` defaults to true: an imported name carries no address and no
 *     implementation, so it is not an answer to "where is this implemented".
 *   - `dedupe` defaults to true: one name is one row, because a symbol table
 *     routinely carries a name at several addresses (aliases, thunks, per-arch
 *     copies) and nine rows saying `memcpy` is harder to read than one.
 *
 * The two narrower functions this absorbed were removed rather than kept as
 * aliases: at 0.1.0 there are no external consumers to strand, and leaving two
 * superseded exports would recreate the ambiguity the merge exists to end.
 *
 * @param {string} path
 * @param {string} pattern
 * @param {object} [opts]
 * @param {string} [opts.arch] preferred architecture; falls back to the richest
 * @param {'substring'|'regex'} [opts.mode='substring']
 * @param {string} [opts.flags='i'] regex flags, ignored in substring mode
 * @param {boolean} [opts.definedOnly=true] exclude imported (N_EXT) names
 * @param {boolean} [opts.dedupe=true] one row per distinct name
 * @param {number} [opts.max=4000] row cap; only applied when deduplicating
 * @returns {object}
 * @throws if the pattern is not a valid regex, or the file is not a Mach-O
 */
export function searchSymbols(path, pattern, {
  arch, mode = 'substring', flags = 'i', definedOnly = true, dedupe = true, max = 4000,
} = {}) {
  if (typeof pattern !== 'string' || !pattern) throw new TypeError('searchSymbols: a pattern is required');
  // Built before the file is opened so an invalid regex is a usage error about
  // the pattern, not a confusing failure from deep inside a read.
  const re = mode === 'regex' ? new RegExp(pattern, flags) : null;

  return withFile(path, (f) => {
    const { slice, syms } = symbolsFor(f, arch);
    const hits = syms.entries.filter(
      (e) => (definedOnly ? e.defined : true) && (re ? re.test(e.name) : e.name.includes(pattern)),
    );
    const matches = dedupe
      ? [...new Map(hits.map((e) => [e.name, e])).values()].sort(byAddr).slice(0, max)
      : hits.slice(0, max);
    return {
      arch: slice.arch,
      pattern,
      mode,
      flags: mode === 'regex' ? flags : null,
      matches,
      count: hits.length,
      uniqueCount: new Set(hits.map((e) => e.name)).size,
      truncated: hits.length > matches.length,
      deduped: dedupe,
      definedOnly,
      defined: syms.defined,
      total: syms.total,
      note: syms.note,
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
        offset: null, size: null, aliases: null,
        note: 'no defined symbols in this slice — stripped, or a dyld-cache stub',
      };
    }

    // Last defined symbol at or below the target. Note that this alone cannot tell
    // a real answer from a fabricated one; the coverage guard below is what makes
    // the result trustworthy outside the mapped range.
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
        offset: null, size: null, aliases: null,
        note: 'no defined symbol at or below this address',
      };
    }

    // Walk back over aliases sharing this name, so the reported start is the
    // real function entry rather than whichever alias the table ordered first.
    let at = best;
    while (at > 0 && defs[at - 1].name === defs[best].name) at--;
    const start = defs[at].addr;
    const next = defs[best + 1] ? defs[best + 1].addr : null;

    // Whether this slice maps the target at all — checked here, after the
    // search, because the search alone cannot tell a real answer from a
    // fabricated one.
    //
    // A symbol table records where code *starts*, not where the slice *ends*, so
    // "the last symbol at or below the target" is a real answer only while the
    // target is inside the mapped range. Past the end it is a guess: every
    // address above the last symbol resolved to that last symbol, so
    // `0xffffffffffffffff` came back as `_runtime.enoptrbss` at an offset of
    // `0xfffffffefd35fc3f`. A wrong offset is worse than a missing one, because
    // it looks like a measurement. `findCalls` and `mapLiteral` already ask this
    // question, so skipping it here made the three disagree about one address in
    // one binary.
    //
    // `target === start` is exempt, and the exemption is load-bearing. A BSS
    // symbol can sit exactly at the end of its segment — in Go's `go`,
    // `_runtime.enoptrbss` is at `0x102ca03c0`, which is precisely
    // `__DATA.vmaddr + __DATA.vmsize` and therefore one past the last mapped
    // byte. That address is a real function entry and must still resolve;
    // guarding before the search rejected it and turned a correct answer into a
    // negative one. So: a symbol's own entry point always resolves, and coverage
    // only decides the addresses *between* and *beyond* symbols.
    if (target !== start && !coversAddress(slice.thin, target)) {
      return {
        arch: slice.arch, vaddr: target, function: null, start: null, next: null,
        offset: null, size: null, aliases: null,
        note: 'address is not mapped by this slice — nothing here to resolve',
      };
    }

    // Other symbols starting at exactly this address, when the answer is not the
    // only one.
    const aliases = symbolsStartingAt(defs, target, defs[at].name);

    return {
      arch: slice.arch, vaddr: target, function: defs[at].name, start, next,
      offset: target - start, size: next === null ? null : next - start,
      aliases: aliases.length ? aliases : null, note: null,
    };
  });
}

/**
 * Distinct names, other than `chosen`, that start at exactly `target`.
 *
 * Several symbols sharing one address is ordinary, not exotic. Go's linker
 * writes zero-size region markers next to real symbols — in `go`,
 * `_go:buildid` and `_runtime.text` both sit at `0x100001000`, and four symbols
 * share `0x10091ac0`-style addresses — and a C library may alias an implementation
 * under several names.
 *
 * `nlist_64` carries no size field, so nothing in the symbol table distinguishes
 * a zero-size marker from a real function. Picking one name and reporting a
 * `size` derived from the next unrelated symbol therefore presents a linker
 * bookkeeping entry as a function of 112 bytes. That is the same defect as a
 * fabricated offset: a number shaped like a measurement that no one measured.
 * So the answer keeps its choice — deterministic, and a symbol that genuinely
 * starts here — and discloses the alternatives rather than implying it is the
 * only one.
 *
 * `defs` is sorted by address, so equal addresses are contiguous and the run is
 * found by a lower-bound search plus a walk. Bounded by the size of the run, not
 * by the table.
 */
function symbolsStartingAt(defs, target, chosen) {
  let lo = 0;
  let hi = defs.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (defs[mid].addr < target) lo = mid + 1;
    else hi = mid;
  }
  const names = [];
  for (let i = lo; i < defs.length && defs[i].addr === target; i++) {
    const name = defs[i].name;
    if (name !== chosen && names[names.length - 1] !== name) names.push(name);
  }
  return names;
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
      const name = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
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
      const name = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
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
export function findLiteral(path, literal, { textOnly = false, arch, max = 0 } = {}) {
  const needle = Buffer.isBuffer(literal) ? literal : Buffer.from(String(literal), 'latin1');
  return withFile(path, (f) => {
    const slices = [];
    const hits = [];
    let scanned = 0;
    // `--arch` bookkeeping. `matched` is whether any slice satisfied the request;
    // `fallback` is the first slice that did not, kept so an unsatisfiable
    // request still produces a real answer. Both are needed and they are
    // different questions — a universal binary with `--arch=arm64` has one
    // matching and one non-matching slice, and recording "wanted = true" for the
    // second would report the request as unsatisfied.
    let matched = false;
    let fallback = null;

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
      // `arch` is a preference, not a filter, and this tool now matches the
      // other five: a named slice wins if present, otherwise the richest slice is
      // read anyway. Filtering instead would report a usage mistake — an absent
      // architecture — as "the magic is not in this file", which is a claim
      // about the bytes that happens to be false. Verified: `--arch=riscv`
      // against /bin/ls searches a slice, and says which.
      if (arch && !archMatches(name, arch)) {
        if (!fallback) fallback = { s, thin, name }; // first non-matching slice
        continue;
      }
      if (arch) matched = true;
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
    // No slice matched `--arch`: read one anyway rather than report nothing, and
    // say so. Refusing would turn a mistyped architecture into "the magic is not
    // in this file", which is a statement about the bytes and is false.
    if (arch && !matched && fallback && !slices.length) {
      const { s, thin, name } = fallback;
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
          off, slice: name, inText,
          vaddr: inText ? text.addr + BigInt(off - textLo) : toVaddr(thin, off - s.offset)?.vaddr ?? null,
          section: sec ? `${sec.segname},${sec.sectname}` : null,
          context: contextAround(f, off, 16, 8),
        });
      }
      hits.sort((a, b) => a.off - b.off);
    }
    return {
      literal: needle.toString('latin1'),
      hex: needle.toString('hex'),
      hits: max > 0 ? hits.slice(0, max) : hits,
      count: hits.length,
      truncated: max > 0 && hits.length > max,
      scanned,
      slices,
      textOnly,
      // `arch` is what was asked for. `archHonoured` is that value when a slice
      // satisfied it and `null` when none did — so a caller can tell "you got the
      // slice you asked for" from "you got a slice anyway, and it was not this
      // one" without re-deriving it from `archRead`. `archRead` is the ground
      // truth: what actually answered.
      arch: arch ?? null,
      archHonoured: arch && matched ? arch : null,
      archRead: slices.map((x) => x.arch),
    };
  });
}

/**
 * NUL-terminated strings in the C-string sections, with where each one loads.
 *
 * ## Why this is not `findLiteral` with a different argument
 *
 * `findliteral` searches for bytes the caller already knows. This finds strings
 * nobody has to know in advance, which is the other direction: the __cstring
 * section of a binary is a table of things it says, and reading it needs no
 * prior hypothesis. `ipsw macho info --strings` prints cstrings too, so this is
 * not a capability it lacks — the difference is that every string here carries
 * its **file offset, virtual address and owning section**, which is what makes a
 * string actionable rather than merely visible. A string you cannot address is
 * a string you cannot hand to `symlookup` or `mapliteral`.
 *
 * ## What counts as a string
 *
 * A run of at least `min` printable bytes terminated by NUL. Deliberately not
 * UTF-8 validation: a C string is a byte sequence between NULs, and rejecting
 * anything that is not valid UTF-8 would silently drop the Swift and ObjC
 * material that lives in `__cstring` and is full of non-ASCII.
 *
 * @param {string} path
 * @param {object}  [opts]
 * @param {string}  [opts.arch]    prefer this slice of a universal binary
 * @param {number}  [opts.min]     shortest string to report (default 4)
 * @param {number}  [opts.max]     cap on results (default unlimited)
 * @param {string}  [opts.filter]  substring a string must contain
 */
export function findStrings(path, { arch, min = 4, max = 0, filter = null } = {}) {
  return withFile(path, (f) => {
    const slices = [];
    const strings = [];
    let scanned = 0;
    // Whether some slice satisfied `arch`, and the first slice that did not.
    // Both are needed and they are different questions — a universal binary with
    // `--arch=arm64` has one matching and one non-matching slice, and recording
    // "wanted = true" for the second would report the request as unsatisfied.
    // `fallback` is what makes an absent architecture a preference rather than
    // a filter: read one slice anyway rather than report nothing.
    let matched = false;
    let fallback = null;

    // One slice's C-string sections, walked for NUL-delimited runs. A function
    // rather than inline because the `--arch` fallback below has to run exactly
    // this over a slice the loop skipped, and two copies of a 30-line walk is
    // how the two paths come to disagree.
    const scan = (s, thin, name) => {
      // The C-string sections. `__cstring` is the real one; `__cfstring` is
      // CFString literals, whose pointers are 32 bytes of structure rather than
      // text, so including it would report addresses as if they were strings.
      // `__objc_methname` and `__swift5_reflstr` *are* NUL-terminated text and
      // are exactly what someone reversing a binary wants, so they are included
      // and labelled, not filtered out.
      const wanted = CSTRING_SECTIONS.filter((n) => thin.sections.some((x) => x.sectname === n));
      if (!wanted.length) {
        slices.push({ arch: name, offset: s.offset, size: s.size, sections: [], strings: 0, scanned: 0 });
        return;
      }

      let found = 0;
      for (const sec of thin.sections) {
        if (!CSTRING_SECTIONS.includes(sec.sectname) || sec.size === 0) continue;
        const lo = s.offset + sec.offset;
        // A section's bytes can run past the end of the file when the linker
        // recorded a size it did not write — zero-fill tail, or a truncated
        // binary. Clamped rather than trusted, because reading past the end
        // here would throw in the middle of an otherwise good answer.
        const hi = Math.min(lo + sec.size, f.size);
        if (hi <= lo) continue;
        const buf = f.read(lo, hi - lo);
        scanned += buf.length;

        const label = `${sec.segname},${sec.sectname}`;
        // Walk NUL-delimited runs rather than regexing the whole buffer, so the
        // offset of each string is known exactly instead of inferred from a
        // match index plus the preceding terminator.
        let start = 0;
        while (start < buf.length) {
          const end = buf.indexOf(0, start);
          const stop = end === -1 ? buf.length : end;
          if (stop - start >= min) {
            const raw = buf.subarray(start, stop);
            const text = raw.toString('latin1');
            if (printable(raw) && (!filter || text.includes(filter))) {
              strings.push({
                off: lo + start,
                slice: name,
                vaddr: sec.addr + BigInt(start),
                section: label,
                length: stop - start,
                text,
              });
              found++;
            }
          }
          if (end === -1) break;
          start = end + 1;
        }
        slices.push({ arch: name, offset: s.offset, size: s.size, sections: wanted, strings: found, scanned: buf.length });
      }
    };

    for (const s of slicesOf(f)) {
      const thin = parseThin(f, s.offset);
      if (!thin) continue;
      const name = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
      // `arch` is a preference, not a filter, and this must match what
      // `findLiteral` does: a named slice wins if present, otherwise the first
      // slice is read anyway. Two tools that report the same `archRead` field
      // cannot mean different things by `--arch`.
      if (arch && !archMatches(name, arch)) {
        if (!fallback) fallback = { s, thin, name }; // first non-matching slice
        continue;
      }
      if (arch) matched = true;
      scan(s, thin, name);
    }

    // No slice matched `--arch`: read one anyway rather than report nothing, and
    // say so via `archHonoured: null`. Refusing would turn a mistyped
    // architecture into "there are no strings in this file", which is a claim
    // about the bytes and is false.
    if (arch && !matched && fallback) scan(fallback.s, fallback.thin, fallback.name);

    strings.sort((a, b) => a.off - b.off);
    const capped = max > 0 ? strings.slice(0, max) : strings;
    return {
      arch: arch ?? null,
      min,
      count: strings.length,
      truncated: capped.length < strings.length,
      strings: capped,
      scanned,
      slices,
      sections: CSTRING_SECTIONS,
      // Same three fields `findLiteral` returns, for the same reason: `arch` is
      // what was asked for, `archHonoured` is that value when a slice satisfied
      // it and `null` when none did, and `archRead` is the ground truth of what
      // actually answered. A string search that reads a slice the caller did
      // not ask for is the failure this makes visible rather than silent.
      archHonoured: arch && matched ? arch : null,
      archRead: slices.map((x) => x.arch),
    };
  });
}

/**
 * Section names whose contents are NUL-terminated text.
 *
 * A list rather than a hardcoded `__cstring` check because a Go binary keeps
 * its strings in `__cstring` but Swift and Objective-C put method names and
 * reflection records in their own named sections, and a tool that only looked at
 * `__cstring` would report an ObjC binary as having no strings in it — which is
 * the kind of wrong-looking-right answer this project keeps refusing to give.
 */
const CSTRING_SECTIONS = ['__cstring', '__objc_methname', '__swift5_reflstr', '__objc_classname'];

/** Every byte printable or tab/newline — the check that keeps binary noise out. */
function printable(b) {
  for (const c of b) {
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 0x20 || c > 0x7e) return false;
  }
  return b.length > 0;
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
      const name = s.thin ? sliceArchName(thin.cputype, thin.cpusubtype) : sliceArchName(s.cputype, s.cpusubtype);
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

export { isMachOFile, sliceName, sliceArchName, textSection, codeSections };

/**
 * Instruction decoding, re-exported from `instruction.mjs`.
 *
 * Exported rather than left behind a CLI because the question these answer —
 * "how long is the instruction at this address, and where does it branch" — is
 * the same *kind* of question as `addressToOffset` and `findCalls`, and a caller
 * holding a buffer should not have to spawn a process to get the answer.
 *
 * What they deliberately do not do is decode *operands* or print mnemonics. They
 * answer "where are the boundaries, and where do the direct edges go", which is a
 * fact about the byte stream; anything past that is a claim about what the program
 * does. The sweep's limits and the opcode table's documented gaps carry over
 * unchanged.
 */
export {
  disassemble,
  instructionLength,
  branchTarget,
  supportedArch,
} from './instruction.mjs';
