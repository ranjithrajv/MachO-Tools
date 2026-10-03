---
name: macho-explorer
description: Reads Apple Mach-O binaries without otool, nm or a disassembler. Answers what is in a binary, which function contains an address, what directly calls a given address, where a byte literal or file-format magic lives in the file, and which code points at it. Works on macOS, Linux and Windows, including universal binaries and stripped ones. Use when inspecting a Mach-O, a .app bundle, an iOS binary, a dylib, a Go/Rust/Swift/ObjC executable, or when handed a crash-log address, a "what is this binary" question, or a magic number to trace back to its handler — even when MachO-explorer/MachO-explorer is not named.
license: LGPL-3.0-or-later
metadata:
  version: "1.0.0"
  macho-explorer-version: "0.1.0"
---

# MachO-explorer

Mach-O introspection in pure JavaScript. No dependencies, no build step, no
install: Node ≥ 22.15 and either the CLI or an MCP server.

**It is a reader, not a disassembler.** Every answer is a fact about the file
format or the bytes. Hand the addresses it produces to a disassembler; do not
try to make it decode code.

## Reading the file's structure

`macho-describe` is also the only tool here that shows you the map: every
segment, every section with its address and size, every load command by name,
the build's UUID — the one field that says *which* build this is rather than
what is in it — and the platform and filetype, which say whether you are holding
an iOS binary, a framework or a command-line tool.

```sh
macho-describe --sections /path/to/binary   # segment,section  addr..end  size  code|data
macho-describe --segments /path/to/binary   # name  vm range  file range
macho-describe --loads    /path/to/binary   # LC_SEGMENT_64, LC_LOAD_DYLIB, LC_UUID, ...
macho-describe --arch=arm64 /path/to/binary # one slice of a universal binary
```

The `code`/`data` marking is the same signal `macho-findcall` types its scan by,
so the two can be checked against each other.

Load commands are **named, not interpreted**. Knowing a binary declares
`LC_LOAD_DYLIB` or `LC_CODE_SIGNATURE` is a fact about it; following the
dependency or parsing the signature is not something these tools do.

Three commands are interpreted rather than merely named, because their values are
plain fields rather than another format: `LC_RPATH` (the `@rpath` search paths, in
declaration order), `LC_SOURCE_VERSION` (the five-part `A.B.C.D.E` source version),
and `LC_MAIN` (the entry point). Each is in `--json` as `rpaths`, `sourceVersion`
and `entryPoint`.

**`entryPoint.vaddr` is always `null`.** The header calls `LC_MAIN`'s `entryoff` a
`__TEXT` offset and measurement does not bear that out — on a real 113 MB binary it
resolves into `__LINKEDIT`, and on a dyld shared-cache stub it points at code the
file does not contain. Do not compute `__TEXT.vmaddr + entryoff` yourself; use the
raw `entryoff` and treat `vaddr: null` as the honest answer.

Header `flags` are decoded into names (`MH_PIE`, `MH_TWOLEVEL`, `MH_NOUNDEFS`, …),
and a bit the reader cannot name is reported separately as `flagsUnknown` rather
than dropped. Each section's `flags` are split into `type` (`S_CSTRING_LITERALS`,
`S_SYMBOL_STUBS`, …) and `attributes` (`S_ATTR_PURE_INSTRUCTIONS`, …) — two
disjoint halves of one word, so a section is routinely `code` *and* `S_REGULAR`.

### When `abnormalities` is non-empty

`describe` reports structural problems **alongside** a successful parse, never
instead of one: a damaged file still answers every other question, and the result
still carries the sections and symbols that could genuinely be read. So a
non-empty `abnormalities` means "this header disagrees with this file", not "nothing
here is trustworthy" — read what was recovered, and treat the named parts as
suspect:

| `kind` | what it means |
|---|---|
| `unknown-header-flags` | a flag bit `<mach-o/loader.h>` gives no name to — a newer toolchain, or a patched header |
| `load-commands-truncated` | the header claims more load commands than the file contains, so the section and symbol tables may be incomplete |
| `strtab-past-slice-end`, `symtab-past-slice-end` | the symbol or string table reaches past the end of the slice |
| `section-past-slice-end`, `segment-past-slice-end` | a section or segment claims bytes the slice does not have |
| `symtab-strtab-overlap` | the two tables overlap, which no linker emits |
| `strtab-high-entropy` | the string table's bytes are too uniform to be text — possibly compressed or obfuscated. A heuristic; it invites a look, it does not conclude |

An **unknown load command is not an abnormality** — those are named by number by
`--loads` on purpose, so an unfamiliar-but-valid command is not graded as damage.

## Listing what a binary already contains

To see its strings without knowing one in advance:

```sh
macho-findliteral --strings /path/to/binary
macho-findliteral --strings --min=8 --filter=error /path/to/binary
```

Each string carries its address and its section, so it can be handed straight to
`macho-symlookup`. This reads `__cstring`, `__objc_methname`, `__swift5_reflstr`
and `__objc_classname`.

**It finds nothing in a Go binary.** Go keeps its strings length-prefixed inside
`__gopclntab`, not NUL-terminated, so there is no terminator to scan for and zero
is the correct answer. Use `macho-sym` on a Go symbol, or `macho-findliteral`
with a substring you already know, instead.

## Three ways in, in order of preference

**1. The MCP server**, if one is configured — the tools are already there and
return structured answers:

```
macho-describe  macho-sym  macho-symlookup  macho-findcall
macho-findliteral  macho-mapliteral  macho-a2o  macho-o2a
```

**2. The CLI**, which needs nothing configured:

```sh
macho-describe    /path/to/binary
macho-sym         'runtime.main' /path/to/binary
macho-symlookup   0x100085c30 -b /path/to/binary
macho-findcall    0x100085c30 /path/to/binary
macho-findliteral LZ4 "/path/to/Some App.app"
macho-mapliteral  LZ4 /path/to/binary
macho-a2o         0x100085c30 -b /path/to/binary     # address  → file offset
macho-o2a         0x85c30 -b /path/to/binary          # file offset → address
macho-disasm      0x100085c30 /path/to/binary         # where instructions start, and where they branch
```

**3. The library**, when you are writing code:

```js
import { describe, searchSymbols, lookupAddress, findCalls,
         listCallTargets, findLiteral, mapLiteral } from 'macho-explorer';
```

From a checkout with nothing installed, `node src/describe.mjs <binary>` works —
and `src/macho.mjs` alone is one auditable file that imports nothing but
`node:fs`, so it can be copied into a project outright.

### Reading a `.app`

Pass the bundle; the executable inside is found automatically. Anywhere a binary
is accepted, a bundle is too.

## The workflow that actually works

Reverse-engineering a binary is a loop, and skipping the first step is how you
end up reading addresses that were never in that slice.

1. **`macho-describe`** first, always. It tells you how many slices there are,
   which architecture each is, whether there is a symbol table to search at all,
   where `__TEXT` starts, and the build's UUID. On a universal binary everything
   after this needs `--arch` or it silently reads one arbitrary slice.
2. **`macho-sym`** to turn a name into an address.
3. **`macho-symlookup`** to turn an address back into a function — the way to
   make sense of an address from a crash log.
4. **`macho-findcall`** for who calls it.
5. **`macho-findliteral`** for where a format magic sits, then
   **`macho-mapliteral`** for which code points at it. This pair is the one with
   no equivalent in `ipsw`, Ghidra or `otool`.

To go the other way — from an address to the file position to read bytes —
`macho-a2o` then `macho-o2a`.

## Five things that will otherwise waste your time

**Addresses are hex strings.** `"0x100085c30"`, never a JSON number. A 64-bit
virtual address does not survive a JavaScript `Number` — everything above 2^53
loses its low bits, and the resulting address points at real, wrong code rather
than failing. Over MCP the schema rejects a number; in the shell, quote it.

**An empty result is an answer, not a failure.** No matches returns an empty
list and exit status 1. Do not retry it with variations. Distinguish it from a
real failure by the status: **1 means "ran, found nothing"**, 2 is a usage
error, 3 means the file could not be read. `ok:false` with
`errors:["io"]` means the binary is missing; `errors:["unknown-encoding"]` means
it is there and is not a Mach-O. Those are different problems and the codes tell
them apart.

**`macho-findcall` sees direct calls only.** A call through a register, or
through a PLT stub, does not encode its target in the instruction, so it does not
appear. Every hit is a site *worth* opening in a disassembler, not a proven
call-graph edge, and **an empty result does not mean nothing calls the target.**
On x86_64 the scan is typed by section rather than by instruction, so it can also
match a byte inside the middle of a multi-byte instruction. On arm64 it steps 4
bytes and sees only aligned `BL`s.

**A stripped binary has no symbols.** `macho-sym` and `macho-symlookup` return
nothing at all rather than guessing — which means a missing `.dSYM` makes those
two useless, while `macho-findcall` and `macho-findliteral` keep working, because
they read bytes rather than names. When symbols are missing, go straight to
`findliteral`/`mapliteral` or to the byte-oriented tools.

**System dylibs are not on disk any more.** Since macOS 11 there is no
`/usr/lib/libSystem.B.dylib` to point at; the real libraries live inside the dyld
shared cache, which this does not read. If a path under `/usr/lib` turns out not
to exist, that is why — it is not a broken install. Use a real binary instead.

## What it will not do, so you do not have to try

No decompilation, no mnemonics, no operand decoding, no control flow graph. No
indirect or PLT call resolution. No dSYM or
DWARF. No code signature, entitlements, chained fixups, export tries, or
Objective-C and Swift metadata — `describe --loads` *names* those load commands
but does not interpret them. Not ELF, not PE. **Little-endian only** — big-endian
Mach-O (NeXTSTEP on m68k/SPARC, classic Mac OS on PowerPC) is refused as
`unknown-encoding`; a `ppc` slice is named and reported `readable: false`.

`macho-disasm` does decode instruction lengths and resolve **direct** branches
(`x86_64` for `x86_64`, and `BL`/`B`/`B.cond`/`CBZ`/`CBNZ`/`TBZ`/`TBNZ`/`ADR`/`ADRP`
for `arm64`/`arm64e`) — that is what it is for, and it is not a disassembler:
instructions come back as bytes, not as text. Read it as a linear sweep from a
*known-good* address such as a symbol. Sweeping a whole code section decodes
interleaved jump tables and string literals as instructions, and on `x86_64` one
wrong length shifts every boundary after it.

All twelve `MH_*` filetypes are named, but only the loaded-image ones
(`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`, `MH_DYLINKER`, `MH_KEXT_BUNDLE`, …)
behave as you would expect. **Do not trust addresses from a `MH_OBJECT`**: an
object file is relocatable, so it has no load address — `textAddr` is `0x0` and
symbol values are section-relative offsets. `MH_FILESET` (kernelcache) is named
but its nested Mach-Os are not walked, and `MH_DSYM`/`MH_CORE` carry no code.

Every Apple platform is covered, because they all ship Mach-O: **macOS**
(`x86_64`, `arm64`, `i386`), **iOS and iPadOS** (`arm64`, `arm64e`, `armv7`),
**tvOS** (`arm64`), **watchOS** (`arm64_32`, `armv7k`) and **visionOS**
(`arm64`) — 32- and 64-bit, thin and universal. iPadOS reports as `ios` because
Apple has no separate platform constant for it, and `armv7k` reports as `arm`,
so the platform command is what identifies a watch build rather than the
architecture name.

`macho-describe` reports the platform (`ios`, `macos`, `tvos`, `watchos`, the
simulators), the filetype, and whether an App Store binary's `__TEXT` is
encrypted — which is the one thing that makes a zero result from
`macho-findcall` mean "could not look" rather than "nothing calls this".

When you need to know what the code *does* rather than where it is, use Ghidra
(free, no licence server) or Hopper. That is the intended division: this produces
the shortlist of addresses worth opening, and hands them over — `macho-disasm`
narrows that shortlist to instruction boundaries and direct branch edges, which is
the last step before a real disassembler takes over.

## Scripting notes

- Every tool takes `--json` and emits one envelope: `{tool, ok, binary, errors,
  messages?, notes?, data}`, with stdout carrying only JSON and all prose on
  stderr.
- Addresses come back as `"0x…"` strings, deliberately — see above.
- The binary comes from an explicit argument, then `$MACHO_BINARY`, then
  `$MACHO_APP`. `macho-symlookup`, `macho-a2o` and `macho-o2a` take only queries
  as positionals, so their binary must come from `-b` or the environment.
- `--arch=<x86_64|arm64>` is a preference, not a requirement: if that slice is
  absent, another is read and a note says which. Check the note rather than
  assuming you got the slice you asked for.
- **An unknown flag is a usage error, exit 2**, with a suggestion when the name is
  a near miss. If a tool exits 2 and says "did you mean", the answer is in the
  message. Nothing here ignores a flag — that used to be the behaviour on several
  tools and it turned a typo into a confident wrong answer.

## Verifying it works

No install, no network, no fixtures to download:

```sh
node test/fixtures.mjs --check   # the corpus matches its generator
node test/smoke.mjs              # the tools against binaries they were not written for
node test/mcp.mjs                # the protocol, over a real pipe
```

## Registering the MCP server

```sh
claude mcp add macho -- node /absolute/path/to/src/mcp.mjs
```

or in `.mcp.json`:

```json
{ "mcpServers": { "macho": {
    "command": "node",
    "args": ["/absolute/path/to/src/mcp.mjs"],
    "env": { "MACHO_BINARY": "/path/to/a/binary" } } } }
```

`MACHO_BINARY` saves passing a path on every call. It speaks both the modern
`2026-07-28` protocol (per-request `_meta`, no handshake) and the legacy
`initialize` handshake, because clients in the wild still use both.

## Licence

LGPL-3.0-or-later. It has no opinion about, and no access to, the contents of the
files it is pointed at.
