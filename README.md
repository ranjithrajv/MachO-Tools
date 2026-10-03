# MachO-Tools

[![test](https://github.com/ranjithrajv/MachO-Tools/actions/workflows/test.yml/badge.svg)](https://github.com/ranjithrajv/MachO-Tools/actions/workflows/test.yml)

Mach-O binary introspection. Reads fat headers, symbol tables, sections and
`__text`, and answers questions about an executable you know nothing about.
**It knows nothing about any application** — no formats, no products, no save
files. Every answer is a fact about the file format or about the bytes.

**Mach-O is the whole scope, chosen.** This is a tool built around one format,
not a toolkit that happens to include one, and that focus is what pays for the
depth. It does not disassemble, and it will not grow to.

```sh
node src/describe.mjs /usr/local/go/bin/go       # what is in this file?
node src/describe.mjs --sections /usr/local/go/bin/go   # every section, and which are code
node src/describe.mjs --loads /usr/local/go/bin/go      # every load command, by name
node src/sym.mjs 'runtime.main' /usr/local/go/bin/go
node src/symlookup.mjs 0x100085c30 -b /usr/local/go/bin/go
node src/findcall.mjs --list /usr/local/go/bin/go 20
node src/findliteral.mjs LZ4 "/Applications/Some App.app"
node src/findliteral.mjs --strings --filter=error /usr/local/go/bin/go
node src/a2o.mjs 0x100085c30 -b /usr/local/go/bin/go
node src/o2a.mjs 0x85c30 -b /usr/local/go/bin/go
node src/findcall.mjs --json 0x100085c30 /usr/local/go/bin/go | jq '.count'
```

No dependencies, no build step, no install, no network. Node ≥ 22.15.

## The tools

| | |
|---|---|
| `describe.mjs` | What is in this file? Every slice, architecture, extent, symbol counts, where `__TEXT` starts, the build's **UUID** — and with `--sections`, `--segments` or `--loads`, every section, segment and load command by name |
| `sym.mjs` | Search a symbol table by substring, or by regex with `--regex`. Imports marked rather than shown as `0x0` |
| `symlookup.mjs` | Which function contains this vaddr? Reads symbols directly, because `nm` on a large universal binary is unusable |
| `findcall.mjs` | Direct `call`/`jmp` xrefs to an address — or `--list` for the distinct targets a binary calls |
| `findliteral.mjs` | Find a byte literal anywhere in a file, per slice, with context — or `--strings` to list what the binary already contains |
| `mapliteral.mjs` | Map a literal to vaddrs, then find the pointers to them — which is how you find the code that handles a format |
| `a2o.mjs` | Which byte of the file is this vaddr? Both the slice-relative and the absolute offset, and zero-fill as its own answer |
| `o2a.mjs` | Which vaddr does this file offset have? Every slice's answer, since one offset means a different address in each |

Eight tools; there were seven until `symgrep.mjs` and `symfind.mjs` merged into
`sym.mjs`, which now covers both conventions with `--regex` and `--all-imp`.

### Installing

```sh
npm install -g macho-tools          # macho-describe, macho-sym, ...
man macho-sym
```

Or vendor `src/`. Or copy **`src/macho.mjs` alone** — it imports nothing but
`node:fs`, so the whole raw reader is one auditable file with no `node_modules`,
no lockfile and no install step. Man pages ship in `man/man1/`, completions in
`completions/` (bash and zsh).

### Pointing it at a binary

1. an explicit argument, where the tool accepts one
2. `$MACHO_BINARY` — a path to an executable
3. `$MACHO_APP` — a `.app` bundle; the executable is found inside it
4. a documented fallback system binary, so a bare invocation is not a dead end
   (`null` on Windows, where a bare invocation says what to pass instead)

```sh
node src/sym.mjs 'someSymbol' /path/to/binary
MACHO_APP="/Applications/Some App.app" node src/sym.mjs 'someSymbol'
```

`symlookup` takes only addresses as positionals, so its binary comes from `-b`
or the environment rather than from a position — a path told apart from an
address by *looking* like one turns a typo into a confident wrong answer.

| Flag | Meaning |
|---|---|
| `--json` | Emit one JSON object on stdout; diagnostics go to stderr |
| `-b`, `--binary <path>` | The binary, for tools where every positional is a query |
| `--arch=<name>` | Restrict to one architecture. A preference, not a requirement: if the slice is absent another is read, and the note says which |
| `--sections`, `--segments`, `--loads` | `describe`: list sections, segments, or load commands by name |
| `--strings`, `--min`, `--filter` | `findliteral`: list the strings already in the binary instead of searching for one |
| `--include-data` | `findcall`: widen the scan from code sections to every section |
| `-h`, `--help` | Print usage |

**An unrecognised flag is a usage error**, exit 2, with a suggestion when the
name is a near miss:

```sh
$ node src/sym.mjs --regexx 'runtime\.main' /path/to/binary
unknown flag: --regexx

  did you mean --regex?
```

This is not cosmetic. It used to be the other way round on every tool but
`describe`: `parseArgs` dropped anything it did not recognise, so a typo'd
`--regex` silently became a substring search and answered a *different question*
with exit 1 — "found nothing" — which is a confident wrong answer wearing a
successful exit status.

`a2o` and `o2a` take only addresses or offsets as positionals, so their binary
comes from `-b` like `symlookup`'s does.

### A lone path is the binary, not a pattern

`sym` takes a pattern and *then* a binary, so a single positional that names a
Mach-O used to be read as the pattern. The binary then defaulted, and the tool
answered about `/bin/ls` while saying nothing about the file that was never
opened:

```sh
$ node src/sym.mjs /Applications/Developer.app/Contents/MacOS/Developer
no symbol matched; a stripped binary has none to match against   # about /bin/ls
exit=1
```

Exit 1 — "found nothing" — about a file nobody asked about. It is now a usage
error that names what it read and what to type instead, and `--json` reports it
as `missing-pattern` with the path in `binary`:

```
test/fixtures/populated.macho names a Mach-O, and sym takes a pattern and then a binary.

  Read as a pattern it would search /bin/ls instead — a different
  file — so this is refused rather than answered.

    search it:          node src/sym.mjs <pattern> "…/populated.macho"
```

The fallback was never the defect — falling back is correct when no binary is
given at all. It is wrong while *holding* an argument that is a binary, because
the answer is then about a file the caller never named.

**Deliberately narrow.** It fires only on a lone Mach-O or `.app` path. A pattern
that merely looks like a path is still searched, which is why `findliteral` and
`mapliteral` do not do this: for those a literal that is also a real file is a
legitimate search, not a mistake. `findcall` needs no such rule — it already
requires a hex address first.

### Zero-fill is a third answer

`a2o` distinguishes three outcomes, because they are three different facts and
conflating any two of them puts a patch script in the wrong place:

| | |
|---|---|
| `offset: 0x85c30` | mapped, and there is a byte at that position |
| `zerofill: true` | mapped, and there is **no byte** — `__bss`, `__noptrbss`, `__PAGEZERO` |
| `mapped: false` | not in this binary at all |

`__bss` has an address and a size, and the linker records its file offset as `0`,
so a reader that walks sections without asking whether they occupy bytes resolves
the Mach-O header into `__bss` — in `go`, a prefix of the file measured in
  hundred-odd kilobytes. The `zerofill` fixture exists to keep that fixed, and
  reverting the fix fails the suite against it.

## When to use this, and when not to

Mach-O tooling splits cleanly into two kinds of thing, and this is only one of
them. MachO-Tools is a **reader**: facts about the file, in milliseconds, not a
disassembler. What it does is get you from "I have a binary and no idea what is
in it" to "here are the four addresses worth opening in a disassembler" in about
a second.

Reach for **this** when:

- you want **one dependency-free file** you can vendor, or read end to end;
- you are on **Linux or Windows** pointing at a Mac binary. The reader is pure
  buffer arithmetic, and `nm` and `otool` do not run off macOS at all;
- the binary is **large and universal**. `nm` on a 476 MB universal binary takes
  minutes; this reads the symbol table directly and answers in milliseconds;
- you want **scriptable, composable queries** rather than a GUI — every tool
  takes `--json`, and `src/api.mjs` is importable;
- you need **literal-level triage**: where is this format magic, what addresses
  does it map to, and what points at them.

Reach for **something else** when:

- you want **Mach-O and everything around it**. [`blacktop/ipsw`](https://github.com/blacktop/ipsw)
  is the closest thing to a superset of this package: 17 `macho` commands and 34
  `dyld` commands as of `ipsw` 3.1.730, covering load commands, chained fixups,
  code signing, entitlements, FairPlay decryption, Objective-C and Swift
  metadata, ARM64 disassembly, and firmware images and dyld shared caches this
  package never looks at. It is MIT, installs from Homebrew, and is the better
  choice for almost every question *except* the two in the table below;
- you want a **complete, general Mach-O parser**.
  [`p-x9/MachOKit`](https://github.com/p-x9/MachOKit) (Swift, the most complete)
  or [`pstirparo/machofile`](https://github.com/pstirparo/machofile) (Python,
  self-contained, malware-analysis lineage) parse load commands, code signing,
  fixups, export tries and Objective-C/Swift metadata;
- you want **several file formats**. LIEF covers ELF, PE and Mach-O in one
  dependency. Mach-O being this project's whole scope is the reason it is not
  here;
- you want to **know what the code does**. Ghidra is free and needs no licence
  server, and these tools are built to hand work *to* one, not to replace one.

### The comparison, concretely

| | MachO-Tools | `ipsw` | MachOKit / machofile | LIEF | `nm` / `otool` | Ghidra / IDA |
|---|---|---|---|---|---|---|
| Dependencies | none | none (~40 MB binary) | none (Swift) / none (Python) | native library | none | large |
| Build step | none | no (prebuilt) | SwiftPM / none | yes | — | no |
| Runs on Linux/Windows | yes | yes (static binary) | Swift: no / Python: yes | yes | no | yes |
| Universal binaries | every slice | every slice | every slice | every slice | `lipo` first | per slice |
| Regex over symbols | yes | yes | no | no | partial | yes |
| vaddr → function | yes | yes (`macho a2s`) | partial | no | no | yes |
| vaddr → file offset | yes | yes (`macho a2o`) | no | no | no | by hand |
| file offset → vaddr | yes | yes (`macho o2a`) | no | no | no | by hand |
| Zero-fill reported as its own case | yes | no ¶ | no | no | no | no |
| Direct-call xrefs | yes | **no** † | no | no | no | yes |
| Indirect / PLT xrefs | **no** | no | no | no | no | yes |
| Literal → vaddr → pointers | yes | **no** † | no | no | no | by hand |
| Scan restricted to code sections | yes | **no** † | no | no | n/a | yes |
| Objective-C / Swift metadata | **no** | yes | yes | partial | no | yes |
| Code signing / fixups | **no** | yes | yes | yes | `codesign` | partial |
| Disassembly | **no** | ARM64 only ‡ | no | no | no | yes |
| JSON output | yes | partial § | manual | yes | no | yes |
| Importable as a library | yes | yes (Go, `ipswd`) | yes | yes | no | limited |
| Reproducible offline test gate | **yes** | no | partial | n/a | n/a | partial |

The four bolded gaps in the MachO-Tools column are deliberate. They are the ones
where a general parser or a disassembler is strictly better, and closing them
here would mean becoming one of those projects instead of this one.

`a2o` and `o2a` close a gap `ipsw` also has, and the reason it is worth saying
is that the obvious implementation of both is wrong in the same direction. A
section's file `offset` is relative to its slice, and `__bss` records an offset
of 0 while having a non-zero size — so a reader that walks sections without
asking whether they occupy bytes resolves the Mach-O header into `__bss`. In
`go` that is a prefix of the file measured in hundred-odd kilobytes. `a2o`
reports both the slice-relative and the absolute offset, and treats zero-fill as
its own answer.

`ipsw` wins almost every row above, and that is the honest shape of the
landscape: it is the superset, this is the subset. The three rows marked † are
the ones where it has no answer at all, and they are the reason this package
still exists:

- **`ipsw` has no cross-reference command for a standalone Mach-O.** Its only
  one is `dyld xref <cache> <addr>`, scoped to a dyld shared cache rather than a
  file, and marked `🚧 [WIP]` by its own author. `findcall` works on a single
  binary, covers arm64 `BL` and x86_64 `rel32`, and can be restricted to code
  sections so a data coincidence does not read as a call.
- **Nothing in `ipsw` searches for an arbitrary byte literal and then follows
  the pointers to it.** `macho info --strings` prints `__cstring`;
  `findliteral` scans any byte sequence anywhere in the file, and `mapliteral`
  turns each hit into a vaddr and finds what references it.

‡ Its disassembler is ARM64-only and says so in the source — `macho_disass.go`
returns `can only disassemble arm64 binaries` on any other CPU — so on x86_64,
`findcall` covers ground `ipsw` does not reach at all.

¶ `macho a2o` and `macho o2a` return an offset for any address, including one
inside `__bss` — which has an address, a size, and no bytes in the file, because
the loader supplies zeros. The offset it reports there is arithmetic that does not
correspond to a readable byte. `a2o` reports that case as `zerofill: true` with
no offset, because "mapped, and there is a byte" and "mapped, and there is none"
are different facts and a patch script needs to tell them apart.

§ `--json` is on `macho info` and `macho disass` but absent from `macho a2s`,
`macho a2o`, `macho o2a` and `macho dump`, so a pipeline cannot rely on it
uniformly. Every tool here has it, and the envelope shape is the same across all
of them.

The full row-by-row comparison, taken from `ipsw`'s source tree rather than its
README, is in [`FEATURE-PARITY-IPSW.md`](FEATURE-PARITY-IPSW.md).

## What it will not do

Worth stating as a decision, because a gap and a refusal read the same in a
table and only one of them survives a contributor with good intentions and too
much time:

| Will not | Because |
|---|---|
| **Disassemble** | Handing off to a disassembler is the design. `findcall` output is a shortlist of sites *worth* disassembling; a built-in disassembler would make that shortlist unnecessary and this package redundant |
| **Resolve indirect / PLT calls** | The target is not in the instruction, so producing it means decoding the stream — the disassembler again. A wrong edge here would be worse than a missing one: it would look like a call graph |
| **Read dSYM / DWARF** | A different file format and a large amount of code for the minority of binaries whose symbols are in a sidecar |
| **Parse ObjC/Swift metadata** | MachOKit does this properly and is better at it. Duplicating it is the clearest possible way to become a worse MachOKit |
| **ELF or PE** | Mach-O is the focus, not the first of four. Depth in one format beats breadth across several |
| **Code signing, fixups, export tries** | LIEF and `codesign` cover them, and none of them changes which function a vaddr lands in |

The test for anything on that list is not "is it hard" — indirect call
resolution is genuinely hard, which is why it stays out. The test is whether
closing the gap would make this package *worse at the thing it is for*. A
package that answers 40% of a question is useful; one that answers all of a
question it was never built for is not.

## Limits

- **One format, on purpose.** Mach-O is what this package is for, not the only
  format it has not got round to yet. Android APKs, iOS bundles and Windows PE
  need a different reader, and always will.
- **Direct calls only.** Indirect calls, register calls and jumps through a PLT
  stub do not encode their target in the instruction, so they do not appear in
  `findcall`. Every hit is a site *worth disassembling*, not a proven call-graph
  edge.
- **The x86_64 scan is typed by *section*, not by instruction.** It restricts
  itself to sections the linker flagged as code, which removes data false
  positives, but it will still match a byte inside a multi-byte instruction
  rather than at an instruction boundary. Alignment is not something the file
  format records, so this cannot be fixed without a disassembler. The arm64 path
  steps 4 bytes at a time and does see only aligned `BL`s.
- **Stripped binaries have no symbols** to grep. `sym` and `symlookup` report
  nothing rather than guess; `findcall` and `findliteral` read bytes rather than
  names and are unaffected. There is no dSYM support, so a shipped build with
  its symbols in a sidecar is out of reach.
- **Not a general Mach-O parser.** `describe --loads` names every load command but
  interprets none of them: no code signing, no fixups, no export trie, no
  ObjC/Swift metadata, no FAT32, and no following a `LC_LOAD_DYLIB` to the library
  it names.
- **Verified on macOS and Linux.** The reader is portable buffer arithmetic; on
  Windows only the generated half of the suite runs.

## Scripting it

Every tool takes `--json`, with two guarantees so a consumer does not have to
learn one dialect: **stdout is JSON only** (progress lines, per-slice narration
and "none found" prose all go to stderr), and **one envelope, always** —
`{ tool, ok, binary, errors, messages?, notes?, data }`, where `errors` holds
machine-readable reason codes (`bad-arguments`, `bad-address`, `bad-pattern`,
`no-match`, `no-call-sites`, `no-symbols`, `unknown-encoding`, `io`) rather than
prose.

`io` and `unknown-encoding` are deliberately distinct, because the two are
different problems: one is a file that cannot be read, the other a file that
reads fine and is not a Mach-O. Told "not a Mach-O binary" about a path that
does not exist, a caller goes looking for the wrong file entirely.

Addresses are emitted as `"0x..."` strings, never JSON numbers: a 64-bit vaddr
does not survive a `Number`, and a silent precision loss would be
indistinguishable from a correct answer.

| Code | Meaning |
|---|---|
| 0 | Ran, found something |
| 1 | **Ran, found nothing.** Deliberately distinct from an error |
| 2 | Usage error — bad or missing arguments |
| 3 | Could not do the job — unreadable file, unparseable Mach-O |

A caller that cannot tell "found nothing" from "could not look" has the problem
this project keeps fixing, so it is encoded in the exit status. The status is
the same with and without `--json`: the flag changes the format of the answer,
not the answer, and a tool whose text mode and JSON mode disagree about whether
something was found is worse than one with no contract at all. The suite asserts
that parity across tools rather than listing expected values per tool, so a tool
added later fails the same check.

### For coding agents

Two doorways, and they are not redundant.

**An MCP server**, so an agent that speaks the protocol finds these tools at
all:

```sh
claude mcp add macho -- node /absolute/path/to/src/mcp.mjs
```

```json
{ "mcpServers": { "macho": {
    "command": "node",
    "args": ["/absolute/path/to/src/mcp.mjs"],
    "env": { "MACHO_BINARY": "/path/to/a/binary" } } } }
```

Eight tools — `macho-describe`, `macho-sym`, `macho-symlookup`,
`macho-findcall`, `macho-findliteral`, `macho-mapliteral`, `macho-a2o`,
`macho-o2a` — each returning the **same envelope** the CLIs emit under `--json`,
plus a short text block. Nothing new to learn depending on how you arrived.

It speaks both protocol eras, because clients in the wild still use both: the
modern `2026-07-28` revision (per-request `_meta`, no handshake) and the legacy
`initialize` handshake back to `2024-11-05`.

**An [Agent Skill](skill/)**, for agents that drive the CLI or the library
instead. It carries the three things that produce confidently wrong answers —
addresses are hex *strings*, an empty result is not an error, `findcall` sees
direct calls only — plus the workflow and the fallbacks. It is plain
`SKILL.md` in an open format, so it works in Claude Code, Codex, Cursor, VS Code,
Copilot and Gemini CLI by copying one directory.

```sh
mkdir -p .claude/skills && cp -r skill/macho-tools .claude/skills/
```

Be clear-eyed about what this is: Hopper, Binary Ninja and `ipsw` all ship an MCP
server, so **this is distribution, not differentiation**. An MCP server is how an
agent discovers a capability exists; without one this package is invisible to
every agent-driven workflow while being well suited to it. See
[`COMPETITIVE-LANDSCAPE.md`](COMPETITIVE-LANDSCAPE.md).

```js
import { describe, findCalls, lookupAddress, mapLiteral } from 'macho-tools';

const { slices } = describe('/path/to/binary');
const fn = lookupAddress('/path/to/binary', 0x100085c30n);
const callers = findCalls('/path/to/binary', fn.start);
const tables = mapLiteral('/path/to/binary', 'LZ4');
```

The specifier is `macho-tools`, exactly as `"name"` spells it in `package.json` —
package names are case-sensitive when Node resolves them.

The name is lowercase because npm will not accept a capital letter in a name
published for the first time. That was not a style choice: this package shipped
as `MachO-Tools`, and `npm publish --dry-run` reported `+ MachO-Tools@0.1.0` and
exited 0 on it, because a dry run never asks the registry whether a name is
acceptable. `npm view` returned E404 with the reason spelled out — *"name can no
longer contain capital letters"* — and npm's own validator reported
`validForNewPackages: false`. The command that looks like the check was not one.

| Export | Returns |
|---|---|
| `describe(path)` | Every slice: architecture, extent, symbol counts, `__TEXT` bounds, **`uuid`**, and the full `segments` / `sections` / `loadCommands` lists |
| `searchSymbols(path, pattern, opts)` | Symbol search. `mode: 'substring'` (default) or `'regex'`; `definedOnly` and `dedupe` default true |
| `lookupAddress(path, vaddr, opts)` | The function containing an address |
| `findCalls(path, vaddr, opts)` | Direct call/jmp sites targeting an address |
| `listCallTargets(path, opts)` | The distinct addresses a binary calls |
| `findLiteral(path, lit, opts)` | Byte-literal occurrences, per slice, with context |
| `mapLiteral(path, lit, opts)` | Literal → vaddr → the pointers to it |
| `addressToOffset(path, vaddr, opts)` | vaddr → file offset, both bases, or `zerofill` |
| `offsetToAddress(path, offsets, opts)` | File offset → vaddr, one row per slice |
| `withFile(path, fn)` | Open, hand to a callback, close |
| `coversAddress(thin, vaddr)` | Is this address mapped by this slice? |

Two conventions worth knowing: **a negative answer is a value, not an
exception** (`{ matches: [] }`, `{ function: null }` — genuine I/O failures still
throw, so "no result" and "could not look" stay distinguishable), and
**addresses are `bigint`** in, `"0x…"` out.

`lookupAddress` returns `{ function: null }` for an address the slice does not
map, rather than for the last symbol below it. A symbol table records where code
*starts*, not where the slice *ends*, so without that check every address above
the last symbol would resolve to that symbol with an offset of billions of bytes
— a wrong answer shaped like a measurement. A symbol's own entry point still
resolves even where it sits one past the last mapped byte, which is where a BSS
symbol can land. `findCalls` and `mapLiteral` have always asked the same
question, so the three agree about any address in any binary.

`aliases` carries a second caveat: when several symbols start at the same
address, the answer names the alternatives rather than implying it is the only
one. This is ordinary, not exotic — Go's linker writes zero-size region markers
beside real symbols, so in `go` both `_go:buildid` and `_runtime.text` sit at
`0x100001000`. `nlist_64` has no size field, so nothing in the table separates a
marker from a function, and a `size` derived from the next unrelated symbol is a
bound rather than a measurement. `aliases: null` means the answer stands alone.

`addressToOffset` and `offsetToAddress` report `query` and `vaddr` as `"0x…"`
strings for the same reason every other address here is: a 64-bit position does not
survive a JSON number. Offsets stay numeric — they are arithmetic, and a file
position is far below 2^53 in practice.

`src/macho.mjs` — the raw reader — is also importable and is where new format
support lands first. It is stable within a major version but lower-level and more
likely to grow than `api.mjs`.

## Configuration

`config.json` holds the two things that are facts about the world rather than
about the format: the bundle convention (`.app`, `Contents/MacOS`) and the scan
chunking. Both are overridable with `$MACHO_CONFIG`, and a malformed override
falls back to the shipped values rather than failing — a typo should not stop a
tool you handed an explicit binary.

```sh
echo '{"bundle":{"ext":".bundle","macosDir":["bin","exec"]}}' > /tmp/alt.json
MACHO_CONFIG=/tmp/alt.json node src/sym.mjs 'someSymbol'
```

## Verify it yourself, in about five seconds

Every correctness claim in this README is reproducible on a clean checkout,
offline, with nothing installed — no `npm install`, no fixture download, no
network:

```sh
git clone https://github.com/ranjithrajv/MachO-Tools && cd MachO-Tools

node test/fixtures.mjs --check    #  ~0.1s   the corpus matches its generator
node test/smoke.mjs               #  ~4s     the tools, on binaries they were not written for
node test/mcp.mjs                 #  ~15s    the protocol, driven over a real pipe
node test/skill.mjs               #  ~3s     the agent instructions match the tools
node test/mutation-check.mjs      #  ~2m     the historical defects are still caught
```

The four fast numbers are wall-clock on an M-series laptop and are there to set
expectations, not to be asserted. The counts and verdicts are the claim.

Each is a different kind of evidence: `--check` re-derives every byte of the
generated corpus, so a hand-edited or stale fixture cannot pass as a test;
`smoke.mjs` runs the tools against binaries they were not written for and
asserts its own coverage; `mcp.mjs` drives a real subprocess over a real pipe
and parses **every** line of stdout, so a stray write on any code path turns a
test red rather than a user's session green; `skill.mjs` holds the agent-facing
prose to the tree, so an instruction cannot name a flag that does nothing or an
exit code that means something else. `mutation-check.mjs` reintroduces one real
historical bug at a time and requires the suite to fail, with an inconclusive
mutation failing the run rather than counting as caught.

**A green `npm run test:all` is also a complete rot check** — the fixtures pin
exact addresses and counts, so a new toolchain release cannot silently change
what the readers do. CI runs four jobs, with the reader suite on macOS, Linux and
Windows.

Two of them also run before you commit. Clone once and enable the versioned
hooks:

```sh
git config core.hooksPath .githooks
```

`pre-commit` runs the corpus check and the reader suite; `pre-push` adds the
protocol and skill suites. The mutation check is in neither, because ~2m on every
commit is how a fast gate stops being run — it stays in CI and in `test:all`.
Both hooks **refuse rather than pass** when they cannot run, so a clone without
`node` on `PATH` is told so instead of reporting a green it did not earn.

`CONTRIBUTING.md` has the detail: what each check establishes, why the suite runs
against two corpora, and the four defects in this project's own history that a
test suite reported green.

## Contributing

Pull requests welcome, with one thing to read first: the scope above is a
decision, not a backlog. [`CONTRIBUTING.md`](CONTRIBUTING.md) covers the test
for anything that would join the "will not do" list, the no-application-knowledge
boundary, the gate a change has to pass, and what a new tool owes the rest of the
package.

## Licence

**LGPL-3.0-or-later.** See [`LICENSE`](LICENSE) for the GNU Lesser General Public
License v3, and [`COPYING`](COPYING) for the GNU General Public License v3 that it
incorporates — both are required, since LGPLv3 is defined in terms of GPLv3.

It has no opinion about, and no access to, the contents of the files it is
pointed at.

### Provenance

This reader was written while reversing a commercial product, and it is
published from a workspace whose disclosure for those projects lives in the
sibling project's `NOTICE.md` — reach it from the repository root rather than by
link here, because this package is published to npm on its own. **Nothing
proprietary ships here**: no key material, no game data, no disassembly, no asset
bytes, and the only inputs it ever reads are the Mach-O files a user points it
at. That is enforced rather than reviewed — four `boundary:` checks scan `src/`,
`test/` and the published tarball and fail on a publisher, a title or its
container format appearing in any of them.

**The licence does not extend to that product.** LGPL covers this code. It does
not license anyone else's intellectual property, and reading a file format out of
a binary does not make the binary yours to redistribute.