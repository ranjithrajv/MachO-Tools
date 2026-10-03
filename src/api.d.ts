/**
 * Type declarations for MachO-Tools.
 *
 * Hand-written rather than generated, and deliberately small.
 *
 * `allowJs` + `checkJs` would infer most of this, but inference for a library is
 * a liability: it describes what the code happens to do rather than what it
 * promises, so an internal refactor silently changes the public types and every
 * consumer's build breaks without anyone editing a `.d.ts`. These declarations
 * are the contract, and they are allowed to be narrower than the implementation.
 *
 * Addresses are `bigint` throughout. A 64-bit virtual address does not survive a
 * JavaScript `number` — anything above 2^53 loses its low bits — and a type that
 * said `number` would push every caller into a silent precision loss. JSON output
 * renders them as `"0x..."` strings for the same reason.
 */

/** A 64-bit virtual address or file offset. */
export type Vaddr = bigint;

/** Mach-O and fat-header magic numbers. */
export const MH_MAGIC_64: number;
export const MH_MAGIC_32: number;
export const FAT_MAGIC: number;
export const FAT_CIGAM: number;

/** CPU types this reader names. */
export const CPU_X86_64: number;
export const CPU_ARM64: number;

/** Load commands and symbol-type masks the reader inspects. */
export const LC_SEGMENT: number;
export const LC_SEGMENT_64: number;
export const LC_SYMTAB: number;
export const N_STAB: number;
export const N_TYPE: number;
export const N_SECT: number;

/** Section attribute bits that mark a section as containing instructions. */
export const S_ATTR_PURE_INSTRUCTIONS: number;
export const S_ATTR_SOME_INSTRUCTIONS: number;

/** The four Mach-O magic byte sequences, compared as bytes. */
export const MACHO_MAGICS: Buffer[];

/** Standard exit codes, matching `EXIT` in the implementation. */
export declare const EXIT: {
  readonly ok: 0;
  /** The tool ran and found nothing — deliberately not an error. */
  readonly empty: 1;
  readonly usage: 2;
  readonly fail: 3;
};

/** A bounded, cached reader over an open file. */
export interface Opener {
  /** The underlying file descriptor. */
  fd: number;
  /** File size in bytes. */
  size: number;
  /** The path this handle was opened from. */
  path: string;
  /**
   * Read `len` bytes at absolute file offset `off`. Short reads are returned
   * as-is and never padded, so a read past the end is a zero-length buffer
   * rather than an error.
   */
  read(off: number, len: number): Buffer;
  close(): void;
}

/** Open a file and return a bounded reader with a small read cache. */
export declare function opener(path: string): Opener;

/** True when `p` is a readable file whose first four bytes are a Mach-O magic. */
export declare function isMachOFile(p: string): boolean;

/** A human name for a CPU type, falling back to its raw value. */
export declare function sliceName(cputype: number | null): string;

/**
 * A slice's architecture name, including the `arm64e` distinction.
 *
 * `arm64e` shares `CPU_TYPE_ARM64` with `arm64` and differs only in subtype, so
 * {@link sliceName} cannot see it. When `cpusubtype` is null or unread, this
 * falls back to the plain cputype name.
 */
export declare function sliceArchName(
  cputype: number | null,
  cpusubtype?: number | null,
): string;

/** `CPU_SUBTYPE_ARM64E`, masked past the capability bits in the high byte. */
export declare const CPU_SUBTYPE_ARM64E: number;
/** `CPU_SUBTYPE_ARM64E_V8` — arm64e advertising the v8 ISA. */
export declare const CPU_SUBTYPE_ARM64E_V8: number;

/** One entry of a fat header. */
export interface FatSlice {
  cputype: number;
  /**
   * The subtype field, byte 4 of the 20-byte `fat_arch`.
   *
   * Only meaningful for architectures that use it — chiefly `arm64e`, which is
   * an `arm64` subtype rather than a cputype of its own.
   */
  cpusubtype: number;
  /** Byte offset of this slice within the *file*. */
  offset: number;
  size: number;
}

/** A slice with its parse result attached. */
export interface Slice extends FatSlice {
  /** True when the file is a single-architecture Mach-O rather than fat. */
  thin: boolean;
}

/** A parsed segment. `vmaddr`/`vmsize` are BigInt because they are 64-bit. */
export interface Segment {
  segname: string;
  vmaddr: bigint;
  vmsize: bigint;
  fileoff: bigint;
  filesize: bigint;
}

/**
 * A parsed section.
 *
 * `offset` is relative to the start of its **slice**, not the start of the file.
 * Reading a section therefore requires the slice's file offset as well; see
 * `codeSections` and the API functions, which handle that.
 */
export interface Section {
  sectname: string;
  segname: string;
  addr: bigint;
  size: number;
  offset: number;
  /** Section attributes, as of `section_64`. */
  flags: number;
}

/** A parsed `LC_SYMTAB`. */
export interface Symtab {
  symoff: number;
  nsyms: number;
  stroff: number;
  strsize: number;
}

/** One load command, as recorded before any decoding. */
export interface LoadCommand {
  cmd: number;
  name: string;
  cmdsize: number;
  /** Offset from the start of the slice, not of the file. */
  offset: number;
}

/** A parsed thin Mach-O header plus its load-command tables. */
export interface Thin {
  is64: boolean;
  cputype: number;
  /** The subtype from the header, byte 8. See {@link FatSlice.cpusubtype}. */
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
  segments: Segment[];
  sections: Section[];
  loadCommands: LoadCommand[];
  symtab: Symtab | null;
  uuid: string | null;
}

/** One symbol-table entry. */
export interface SymbolEntry {
  name: string;
  addr: bigint;
  /** True for `N_SECT` symbols — defined here, as opposed to imported. */
  defined: boolean;
}

/** The result of reading a symbol table. Every key is always present. */
export interface Symbols {
  names: string[];
  entries: SymbolEntry[];
  /** How many entries are defined in this slice. */
  defined: number;
  total: number;
  /** Why the list is empty, when it is. `null` when it is not. */
  note: string | null;
}

/** Parse a fat header into its slices, or `null` when this is not a fat binary. */
export declare function parseFat(f: Opener): FatSlice[] | null;

/** Parse the load commands of the thin Mach-O at `base`. */
export declare function parseThin(f: Opener, base?: number): Thin | null;

/** Every slice of a binary, fat or thin. */
export declare function slicesOf(f: Opener): Slice[];

/** The `__TEXT` section of a parsed slice, which is where literals live. */
export declare function textSection(thin: Thin): Section | null;

/** True when a section's attributes mark it as containing instructions. */
export declare function isCodeSection(sec: Section): boolean;

/**
 * The sections of a slice that hold code.
 *
 * `fallback` is true when the slice marked no section as instructions, in which
 * case every non-empty section is returned — an unusual input where reporting
 * zero call sites would be worse than an untyped scan.
 */
export declare function codeSections(thin: Thin): {
  sections: Section[];
  fallback: boolean;
};

/** Read every symbol in a slice, defined and imported, counted apart. */
export declare function readSymbols(f: Opener, base: number, thin: Thin): Symbols;

/** The slice with the most symbols — the one most worth probing. */
export declare function richestSlice(f: Opener): (Slice & {
  arch: string;
  thin: Thin;
  names: string[];
  nsyms: number;
  ndefined: number;
  stripped: boolean | string;
  symNote: string | null;
}) | null;

/**
 * The byte offset of the slice a tool should read.
 *
 * `prefer` is a preference, not a requirement: a named architecture that is
 * absent falls back to the richest slice rather than returning null.
 */
export declare function preferredSlice(
  f: Opener,
  prefer?: string,
): { offset: number; arch: string; nsyms: number; thin: Thin; size: number } | null;

/**
 * Map a file offset to a vaddr within a parsed slice, or null if unmapped.
 *
 * Zero-fill sections are skipped: they have no bytes in the file, so an offset
 * inside one belongs to whatever actually occupies that range.
 */
export declare function toVaddr(
  thin: Thin,
  fileOff: number,
): { vaddr: bigint; section: string } | null;

/**
 * Map a vaddr to a slice-relative file offset within a parsed slice, or null.
 *
 * `zerofill: true` means the address is mapped but has no byte in the file —
 * `__bss`, `__PAGEZERO`, or a segment tail past `filesize`. That is a different
 * answer from `null`, which means the address is not in this slice at all.
 */
export declare function toFileOffset(
  thin: Thin,
  vaddr: Vaddr,
): { offset: number | null; zerofill: boolean; section: string; segname: string } | null;

/** True when a section occupies bytes in the file rather than being zero-fill. */
export declare function isBackedByFile(thin: Thin, sec: Section): boolean;

/** The section containing a slice-relative file offset, or null. */
export declare function sectionOf(thin: Thin, fileOff: number): Section | null;

/** True when `vaddr` falls inside anything this slice maps. */
export declare function coversAddress(thin: Thin, vaddr: Vaddr): boolean;

/** Find a byte string inside a section, stopping early per needle. */
export declare function findInSection(
  f: Opener,
  sec: Section,
  needles: string[],
  opts?: { perNeedle?: number; chunk?: number; overlap?: number; sliceBase?: number },
): { hits: Map<string, Array<{ off: number; vaddr: bigint; section: string; ctx: string }>>; scanned: number; available: boolean };

/* ------------------------------------------------------------------ *
 * the supported API
 * ------------------------------------------------------------------ */

/** Open a binary, hand it to `fn`, close it afterwards. */
export declare function withFile<T>(path: string, fn: (f: Opener) => T): T;

/** What is in this file: every slice, with architecture, extent and symbol counts. */
export declare function describe(path: string): {
  path: string;
  size: number;
  /** True when the file holds more than one slice. */
  fat: boolean;
  slices: Array<{
    arch: string;
    offset: number;
    size: number;
    thin: boolean;
    readable: boolean;
    bits: 64 | 32 | undefined;
    nsyms: number;
    defined: number;
    note: string | null;
    textAddr: bigint | null;
    textSize: number;
    codeSections: number;
    /** The slice's segments, as `{ segname, vmaddr, vmsize, fileoff, filesize }`. */
    segments: Segment[];
    sections: Section[];
    loadCommands: LoadCommand[];
    /** Lowercase RFC-4122, or null when the slice carries no `LC_UUID`. */
    uuid: string | null;
  }>;
};

/**
 * One address/offset mapping. Three outcomes, kept apart on purpose.
 *
 * `query` and `vaddr` are hex strings. A 64-bit vaddr does not survive a `Number`
 * and a BigInt does not survive `JSON.stringify`, so a numeric field here would
 * either throw or lose precision silently. Offsets stay numeric because a file
 * position is far below 2^53 in practice and is arithmetic rather than identity.
 */
export interface OffsetRow {
  arch: string | null;
  /** What was asked: a vaddr for `a2o`, a file offset for `o2a`. */
  query: string;
  /** The address this row maps to, as `0x…`. Null only when unmapped. */
  vaddr: string | null;
  /** Slice-relative, matching the section table. Null when zero-fill or unmapped. */
  offset: number | null;
  /** `offset` plus the slice's position in the file. Null when there is no byte. */
  absoluteOffset: number | null;
  /** `__TEXT,__text`, or `__DATA (segment)` for a range no section covers. */
  section: string | null;
  /** Mapped in memory but absent from the file: `__bss`, `__PAGEZERO`. */
  zerofill: boolean;
  /** False when no slice maps the address at all. */
  mapped: boolean;
  /** True when several slices map it — a universal binary maps 0x100000000 in each. */
  ambiguous?: boolean;
  /** Per-slice detail, present when `ambiguous` or `mapped` is false. */
  slices?: OffsetRow[];
  note: string | null;
}

/**
 * Virtual address to file offset.
 *
 * Returns one row when exactly one slice maps the address. On a universal binary
 * without `arch`, every slice maps `0x100000000` by construction, so the row
 * comes back `ambiguous` with `slices` filled in rather than guessing which
 * binary was meant.
 */
export declare function addressToOffset(
  path: string,
  vaddr: Vaddr,
  opts?: { arch?: string },
): OffsetRow;

/**
 * File offset to virtual address, for one or more offsets.
 *
 * Offsets are absolute positions in the file; each slice's row also carries its
 * own slice-relative offset. Every slice is examined, because the same offset
 * means a different address in each.
 */
export declare function offsetToAddress(
  path: string,
  offsets: Vaddr | Vaddr[],
  opts?: { arch?: string },
): {
  path: string;
  queries: Array<{
    /** The absolute file offset asked about, as `0x…`. */
    query: string;
    basis: 'absolute';
    slices: OffsetRow[];
    /** The single mapping as `0x…`, or null when none or more than one. */
    vaddr: string | null;
    ambiguous: boolean;
  }>;
  slices: Array<{ arch: string; offset: number }>;
};

/**
 * Search a symbol table by substring or regex, with one coherent set of rules.
 *
 * This replaced two narrower functions: `grepSymbols` (regex, defined-only, one
 * row per entry) and `findSymbols` (substring, imports included, deduplicated by
 * name). Both were removed rather than aliased — the merged rules above are the
 * only symbol-search contract, which is the point of the merge.
 */
export declare function searchSymbols(
  path: string,
  pattern: string,
  opts?: {
    arch?: string;
    mode?: 'substring' | 'regex';
    flags?: string;
    definedOnly?: boolean;
    dedupe?: boolean;
    max?: number;
  },
): {
  arch: string;
  pattern: string;
  mode: 'substring' | 'regex';
  /** Regex flags actually applied; `null` in substring mode, where none are. */
  flags: string | null;
  matches: SymbolEntry[];
  /** Matches before deduplication and the row cap. */
  count: number;
  /** Distinct names among the matches. */
  uniqueCount: number;
  /** True when `max` dropped rows. */
  truncated: boolean;
  deduped: boolean;
  definedOnly: boolean;
  defined: number;
  total: number;
  note: string | null;
};

/**
 * Which function contains a virtual address.
 *
 * Only defined, address-bearing symbols are considered. `function` is null with
 * a `note` when nothing resolves — a negative answer, not an error.
 *
 * An address the slice does not map resolves to null, with a note saying so,
 * rather than to the last symbol below it. A symbol's own entry point always
 * resolves even where it sits one past the last mapped byte, which is where a
 * BSS symbol can land.
 *
 * `aliases` lists the other names starting at the same address, or is null when
 * the answer is the only one. `nlist_64` has no size field, so a zero-size
 * linker region marker is indistinguishable from a real function here; where
 * `aliases` is set, treat `size` as a bound rather than a measurement.
 */
export declare function lookupAddress(
  path: string,
  vaddr: Vaddr,
  opts?: { arch?: string },
): {
  arch: string;
  vaddr: bigint;
  function: string | null;
  start: bigint | null;
  next: bigint | null;
  offset: bigint | null;
  size: bigint | null;
  aliases: string[] | null;
  note: string | null;
};

/** The direct-call encoding for an architecture, or null if unknown. */
export declare function callEncoding(arch: string): 'x86 rel32' | 'arm64 BL' | null;

/** One direct call or jump that resolves to a target address. */
export interface CallSite {
  addr: bigint;
  kind: 'call' | 'jmp' | 'BL';
  arch: string;
  /** The section the instruction was found in. */
  section: string;
}

/** Per-slice accounting for a call scan. */
export interface CallSliceReport {
  arch: string;
  encoding: 'x86 rel32' | 'arm64 BL';
  /** True when only instruction-flagged sections were scanned. */
  typed: boolean;
  /** True when the slice flagged no section as instructions at all. */
  untypedFallback: boolean;
  sections: Array<{ name: string; addr: bigint; size: number }>;
  scanned: number;
  skipped: string | null;
}

/**
 * Direct `call`/`jmp` sites resolving to `target`, across every slice.
 *
 * Typed by default: only sections whose attributes mark them as instructions
 * are scanned. `includeData` widens to every non-empty section. Either way,
 * indirect calls are invisible — they do not encode their target.
 */
export declare function findCalls(
  path: string,
  target: Vaddr,
  opts?: { arch?: string; includeData?: boolean; max?: number },
): {
  target: bigint;
  hits: CallSite[];
  count: number;
  truncated: boolean;
  scanned: number;
  slices: CallSliceReport[];
  /** Architectures whose call encoding is not implemented. */
  unsupported: string[];
  typed: boolean;
};

/**
 * The distinct addresses a binary calls or jumps to directly.
 *
 * The inversion of `findCalls`, and the only way to tell a working scanner from
 * a dead one: both produce an empty caller list for one address, but only one
 * produces an empty target list for a whole binary.
 */
export declare function listCallTargets(
  path: string,
  opts?: { arch?: string; includeData?: boolean; minSites?: number },
): {
  targets: Array<{ dest: bigint; sites: number }>;
  total: number;
  scanned: number;
  slices: Array<{
    arch: string;
    encoding: 'x86 rel32' | 'arm64 BL';
    typed: boolean;
    untypedFallback: boolean;
    scanned: number;
  }>;
  unsupported: string[];
  typed: boolean;
};

/** Printable context around a file offset. */
export interface Context {
  pre: string;
  /** The file offset `pre` starts at. */
  preFrom: number;
  hit: string;
}

/**
 * Find a byte literal.
 *
 * The whole file by default; `textOnly` restricts to `__TEXT`, which is much
 * cheaper when you already know it is there.
 */
export declare function findLiteral(
  path: string,
  literal: string | Buffer,
  opts?: { textOnly?: boolean; max?: number },
): {
  literal: string;
  hex: string;
  hits: Array<{
    off: number;
    slice: string;
    inText: boolean;
    vaddr: bigint | null;
    section: string | null;
    context: Context;
  }>;
  count: number;
  truncated: boolean;
  scanned: number;
  slices: Array<{
    arch: string; offset: number; size: number;
    from: number; to: number; hits: number;
  }>;
  textOnly: boolean;
};

/**
 * Map a literal to its addresses, then find what points at those addresses.
 *
 * The literal search is per-slice; the pointer search is whole-file, so a
 * pointer can be reported in a slice other than the one whose literal was mapped.
 * `offsets` overrides the literal search, for magics assembled at runtime.
 */
export declare function mapLiteral(
  path: string,
  literal: string,
  opts?: { arch?: string; offsets?: number[] | null; maxPointers?: number },
): {
  literal: string;
  hex: string;
  arch: string;
  sliceOffset: number;
  /** True when `offsets` was supplied rather than searching for the literal. */
  explicit: boolean;
  locations: Array<{
    off: number;
    vaddr: bigint;
    section: string | null;
    context: Context;
    fileExtent: { offset: number; size: number } | null;
    pointers: Array<{
      off: number;
      slice: string | null;
      vaddr: bigint | null;
      section: string | null;
    }> | null;
    pointerCount: number;
    pointersTruncated: boolean;
  }>;
  unmapped: Array<{ off: number }>;
  slices: Array<{
    arch: string; offset: number; size: number; inText: number; nsyms: number;
  }>;
};

/**
 * NUL-terminated strings in the C-string sections, with where each one loads.
 *
 * `arch` is what was asked for, `archHonoured` is that value when a slice
 * satisfied it and `null` when none did, and `archRead` is the ground truth of
 * what actually answered — the same three fields `findLiteral` returns, because
 * an absent architecture is a preference rather than a filter and a search that
 * reads a slice the caller did not ask for has to say so.
 */
export declare function findStrings(
  path: string,
  opts?: {
    arch?: string;
    min?: number;
    max?: number;
    filter?: string | null;
  },
): {
  arch: string | null;
  min: number;
  count: number;
  truncated: boolean;
  strings: Array<{
    off: number;
    slice: string;
    vaddr: bigint;
    section: string;
    length: number;
    text: string;
  }>;
  scanned: number;
  slices: Array<{
    arch: string;
    offset: number;
    size: number;
    sections: string[];
    strings: number;
    scanned: number;
  }>;
  sections: string[];
  archHonoured: string | null;
  archRead: string[];
};

/**
 * Find every occurrence of `needle` in the absolute file range `[from, to)`.
 *
 * Chunked with a carry window, so a match straddling a chunk boundary is not
 * dropped.
 */
export declare function searchRange(f: Opener, needle: Buffer, from: number, to: number): number[];

/** Printable context around an absolute file offset. */
export declare function contextAround(f: Opener, off: number, preLen?: number, hitLen?: number): Context;
