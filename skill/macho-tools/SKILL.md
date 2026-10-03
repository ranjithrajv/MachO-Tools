---
name: macho-tools
description: Reads Apple Mach-O binaries without otool, nm or a disassembler. Answers what is in a binary, which function contains an address, what directly calls a given address, where a byte literal or file-format magic lives in the file, and which code points at it. Works on macOS, Linux and Windows, including universal binaries and stripped ones. Use when inspecting a Mach-O, a .app bundle, an iOS binary, a dylib, a Go/Rust/Swift/ObjC executable, or when handed a crash-log address, a "what is this binary" question, or a magic number to trace back to its handler — even when MachO-Tools is not named.
license: LGPL-3.0-or-later
metadata:
  version: "1.0.0"
  macho-tools-version: "0.1.0"
---

# MachO-Tools

Mach-O introspection in pure JavaScript. No dependencies, no build step, no
install: Node ≥ 22.15 and either the CLI or an MCP server.

**It is a reader, not a disassembler.** Every answer is a fact about the file
format or the bytes. Hand the addresses it produces to a disassembler; do not
try to make it decode code.

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
```

**3. The library**, when you are writing code:

```js
import { describe, searchSymbols, lookupAddress, findCalls,
         listCallTargets, findLiteral, mapLiteral } from 'MachO-Tools';
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
   and where `__TEXT` starts. On a universal binary everything after this needs
   `--arch` or it silently reads one arbitrary slice.
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

No disassembly, no decompilation. No indirect or PLT call resolution. No dSYM or
DWARF. No load-command dump, code signature, entitlements, chained fixups, export
tries, or Objective-C and Swift metadata. Not ELF, not PE.

When you need to know what the code *does* rather than where it is, use Ghidra
(free, no licence server) or Hopper. That is the intended division: this produces
the shortlist of addresses worth opening, and hands them over.

## Scripting notes

- Every tool takes `--json` and emits one envelope: `{tool, ok, binary, errors,
  messages?, notes?, data}`, with stdout carrying only JSON and all prose on
  stderr.
- Addresses come back as `"0x…"` strings, deliberately — see above.
- The binary comes from an explicit argument, then `$MACHO_BINARY`, then
  `$MACHO_APP`. `macho-symlookup`, `macho-a2o` and `macho-o2a` take only queries
  as positionals, so their binary must come from `-b` or the environment.
- `--arch=<x86_64|arm64>` is a preference, not a requirement: if that slice is
  absent, the richest one is read instead.
- Unknown flags are **silently ignored** on several tools. If a result looks
  wrong, check you spelled the flag as documented before doubting the answer.

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
