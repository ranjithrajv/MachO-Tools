# MachO-Tools

Mach-O binary introspection. Reads fat headers, symbol tables, sections and
`__text`, and answers questions about an executable you have no other knowledge
of. **It knows nothing about any application** — no formats, no products, no
save files. Everything here is a fact about the file format or about the bytes.

```sh
node src/describe.mjs /usr/local/go/bin/go       # what is in this file?
node src/symgrep.mjs 'runtime.main' /usr/local/go/bin/go
node src/symlookup.mjs 0x100085c30 -b /usr/local/go/bin/go
node src/findcall.mjs --list /usr/local/go/bin/go 20
node src/findliteral.mjs LZ4 "/Applications/Some App.app"

node src/findcall.mjs --json 0x100085c30 /usr/local/go/bin/go | jq '.count'

npm test                  # run the tools against binaries they were not written for
npm run test:fixtures     # rebuild the generated test corpus
npm run test:mutation     # prove those tests would notice if the tools broke
```

No dependencies, no build step, no key material, no game install. Node ≥ 22.15.

## When to use this, and when not to

Mach-O tooling splits cleanly into two kinds of thing, and this is only one of
them. Both columns are real projects; neither is a strawman.

| | A **reader** | A **disassembler** |
|---|---|---|
| What it gives you | facts about the file | the code |
| Examples | MachOKit, macholibre, machofile, LIEF | Ghidra, IDA, Hopper, Binary Ninja |
| Answers | "what are this binary's slices, sections and symbols" | "what does this function do" |
| Time to first answer | milliseconds | minutes to hours |

MachO-Tools is a **reader**, with one thing readers usually lack: a query
interface. It does not disassemble, and it will not grow to. What it does is get
you from "I have a binary and no idea what is in it" to "here are the four
addresses worth opening in a disassembler" in about a second.

Concretely, reach for something else when:

- you want to **read a Mach-O from code** and want a complete, general parser —
  use [`p-x9/MachOKit`](https://github.com/p-x9/MachOKit) (Swift, the most
  complete) or [`pstirparo/machofile`](https://github.com/pstirparo/machofile)
  (Python, self-contained, malware-analysis lineage). They parse load commands,
  code signing, fixups, export tries and Objective-C/Swift metadata; this reads
  fat headers, sections, symbols and code bytes, and knows nothing else;
- you want **several file formats** — LIEF covers ELF, PE and Mach-O in one
  dependency. This is Mach-O only, and adding ELF would make it worse at the one
  thing it is for;
- you want to **know what code does** — Ghidra is free and needs no licence
  server. Nothing here replaces a decompiler, and the tools are built to hand
  work *to* one;
- the binary is **stripped and you have no dSYM** — then symbols are gone and
  `symgrep`, `symfind` and `symlookup` have nothing to work with. `findcall` and
  `findliteral` read bytes rather than names and are unaffected.

Reach for **this** when:

- you want **one dependency-free file** you can vendor, or read end to end. It
  is a few hundred lines of plain JavaScript with no build step;
- you are on **Linux or Windows** pointing at a Mac binary. The reader is pure
  buffer arithmetic and does not care what platform you are on;
- the binary is **large and universal**. `nm` on a 476 MB universal binary takes
  minutes; this reads the symbol table directly and answers in milliseconds;
- you want **scriptable, composable queries** rather than a GUI. Every tool takes
  `--json`, and `src/api.mjs` is importable, so the answers go into a pipeline
  instead of a terminal;
- you need **literal-level triage**: where is this format magic, what addresses
  does it map to, and what points at them.

### The comparison, concretely

What this does that the alternatives do not, and what it does not do:

| | MachO-Tools | MachOKit / machofile | LIEF | `nm` / `otool` | Ghidra / IDA |
|---|---|---|---|---|---|
| Dependencies | none | none (Swift) / none (Python) | native library | none | large |
| Build step | none | SwiftPM / none | yes | — | no |
| Runs on Linux/Windows | yes | Swift: no / Python: yes | yes | no | yes |
| Universal binaries | every slice | every slice | every slice | `lipo` first | per slice |
| Regex over symbols | yes | no | no | partial | yes |
| vaddr → function | yes | partial | no | no | yes |
| Direct-call xrefs | yes | no | no | no | yes |
| Indirect / PLT xrefs | **no** | no | no | no | yes |
| Literal → vaddr → pointers | yes | no | no | no | by hand |
| Scan restricted to code sections | yes | no | no | n/a | yes |
| Objective-C / Swift metadata | **no** | yes | partial | no | yes |
| Code signing / fixups | **no** | yes | yes | `codesign` | partial |
| Disassembly | **no** | no | no | no | yes |
| JSON output | yes | manual | yes | no | yes |
| Importable as a library | yes | yes | yes | no | limited |
| Tests pinned to known inputs | yes | partial | n/a | n/a | yes |

The four bolded gaps are deliberate. They are the ones where a general parser or
a disassembler is strictly better, and closing them here would mean becoming one
of those projects instead of this one. Each one is stated in **Limits** below
rather than left to be discovered.

## Why it is a separate project

These tools were originally written alongside application-specific scripts, and
the boundary between the two was invisible: a file that searched a binary for
arbitrary byte strings, sitting next to one that decoded a particular
application's asset formats. Only one of them was about the format.

Separating them made the question sharper and found bugs that could not have
been found otherwise. Every tool here had at some point been run against exactly
one binary — the one it was written for — and that is the worst possible way to
test code that has to work on any binary. Each of the following produced a clean
exit code and a plausible, wrong answer:

| Bug | What you saw instead of an error |
|---|---|
| Matched *imported* symbols as enclosing functions | imports carry `n_value == 0`, so any low address "resolved" to an import at `0x0` |
| Never parsed a fat header | on a universal binary the section walk silently failed and it scanned a default window containing nothing, reporting "0 call sites" |
| Read sections at their slice-relative offset | correct on a thin binary, and on any universal binary whose first slice is near the file start — so it read the right *number* of bytes from the wrong place on every other |
| Chunk loop could not terminate | `pos += len - 5` stops advancing once the final chunk is under 5 bytes |
| Dead arm64 path | only the x86 `rel32` encoding was known, and its mask compared a *signed* int32 against a constant above 2³¹, so arm64 returned a confident zero |
| Treated an absent architecture as fatal | returned null on an arm64-only binary, failing outright rather than using the slice it had |
| Its own copy of the fat-header reader | `mapliteral` hardcoded `cputype === 0x01000007` and threw on any Apple-silicon-native build, surviving only because it did not share the reader |

None of those is reachable from a single input. All of them are reachable from a
second, unrelated one — which is what `test/smoke.mjs` and the generated
fixtures exist to provide.

The slice-relative offset bug is the instructive one. It was invisible for the
life of the project because every binary it was tested against was either thin
(where slice-relative and absolute offsets coincide) or had its first slice near
the file start. It took a *generated* fat binary with slices at known offsets to
surface it, which is the argument for the corpus described below.

## The tools

| | |
|---|---|
| `describe.mjs` | What is in this file? Every slice, its architecture, extent, symbol counts, where `__TEXT` starts. |
| `symgrep.mjs` | Regex over a symbol table. `<regex> [binary]` |
| `symfind.mjs` | Substring over a symbol table, deduplicated and address-ordered. |
| `symlookup.mjs` | Which function contains this vaddr? Reads symbols directly, because `nm` on a large universal binary is unusable. |
| `findcall.mjs` | Direct `call`/`jmp` xrefs to an address — or `--list` for the distinct targets a binary calls. |
| `findliteral.mjs` | Find a byte literal anywhere in a file, per slice, with context. |
| `mapliteral.mjs` | Map a literal to vaddrs, then find the pointers to them — which is how you find the code that handles a format. |

### Common flags

| Flag | Meaning |
|---|---|
| `--json` | Emit one JSON object on stdout; diagnostics go to stderr. See below. |
| `-b`, `--binary <path>` | The binary, for tools where every positional is a query. |
| `--arch=<name>` | Restrict to one architecture. A preference, not a requirement. |
| `--include-data` | `findcall`: widen the scan from code sections to every section. |

### Pointing it at a binary

1. an explicit argument, where the tool accepts one
2. `$MACHO_BINARY` — a path to an executable
3. `$MACHO_APP` — a `.app` bundle; the executable is found inside it
4. a documented fallback, so a bare invocation is not a dead end

```sh
node src/symgrep.mjs 'someSymbol' /path/to/binary
MACHO_APP="/Applications/Some App.app" node src/symgrep.mjs 'someSymbol'
node src/symlookup.mjs 0x100085c30 -b /path/to/binary
```

`symlookup` takes only addresses as positionals, so its binary comes from `-b`
or the environment rather than from a position — a path told apart from an
address by *looking* like one is the kind of inference that turns a typo into a
confident wrong answer.

The fallback is a system binary that exists on every machine this runs on, so a
bare invocation is not a dead end. It is a fallback rather than a default target —
nothing here is *meant* to be pointed at it. It is `null` on Windows, where no
such guarantee holds, so a bare invocation says what to pass instead of reporting
a missing file.

## JSON output

Every tool takes `--json`, with two guarantees so that a consumer does not have
to learn seven dialects:

1. **stdout is JSON only.** Progress lines, per-slice narration and the "none
   found" prose all go to stderr. `tool --json | jq` works.
2. **One envelope, always** — `{ tool, ok, binary, errors, messages?, notes?, data }`.
   `errors` holds machine-readable reason codes (`no-call-sites`,
   `no-symbols`, `unknown-encoding`, `io`), not prose, so a consumer can branch
   on `code` instead of pattern-matching an English sentence.

```sh
node src/findcall.mjs --json 0x100085c30 /usr/local/go/bin/go | jq '.count'
node src/describe.mjs --json /usr/local/go/bin/go | jq '.data.slices[].arch'
```

Addresses are emitted as `"0x..."` strings, never JSON numbers. A 64-bit vaddr
does not survive a `Number` — anything above 2⁵³ loses its low bits — and a
silent precision loss in the output would be indistinguishable from a correct
answer.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Ran, found something |
| 1 | **Ran, found nothing.** Deliberately distinct from an error. |
| 2 | Usage error — bad or missing arguments |
| 3 | Could not do the job — unreadable file, unparseable Mach-O |

A caller that cannot tell "found nothing" from "could not look" has the problem
this project keeps fixing, so it is encoded in the exit status.

## Using it as a library

`src/api.mjs` is the supported programmatic interface and the package entry
point. The CLIs are thin wrappers over it — there is no behaviour reachable from
the command line that is not available to an importer, and no second copy of the
reader to be wrong in a different way.

```js
import { describe, findCalls, lookupAddress, mapLiteral } from 'mach-o-tools';

const { slices } = describe('/path/to/binary');
const fn = lookupAddress('/path/to/binary', 0x100085c30n);
const callers = findCalls('/path/to/binary', fn.start);
const tables = mapLiteral('/path/to/binary', 'LZ4');
```

| Export | Returns |
|---|---|
| `describe(path)` | Every slice: architecture, extent, symbol counts, `__TEXT` bounds |
| `grepSymbols(path, re, opts)` | Regex over a symbol table, defined-only by default |
| `findSymbols(path, sub, opts)` | Substring search, deduplicated |
| `lookupAddress(path, vaddr, opts)` | The function containing an address |
| `findCalls(path, vaddr, opts)` | Direct call/jmp sites targeting an address |
| `listCallTargets(path, opts)` | The distinct addresses a binary calls |
| `findLiteral(path, lit, opts)` | Byte-literal occurrences, per slice, with context |
| `mapLiteral(path, lit, opts)` | Literal → vaddr → the pointers to it |
| `withFile(path, fn)` | Open, hand to a callback, close |
| `coversAddress(thin, vaddr)` | Is this address mapped by this slice? |

Two conventions worth knowing:

- **A negative answer is a value, not an exception.** No match is
  `{ matches: [] }` or `{ function: null, note: ... }`. A caller asking "does
  this binary call X" wants `false`, not a stack trace. Genuine I/O failures do
  throw, so "no result" and "could not look" stay distinguishable.
- **Addresses are `bigint`.** They do not fit in a JSON number and must not be
  silently truncated. `src/api.d.ts` declares them as `bigint` for the same
  reason — a `number` there would invite the loss into every consumer.

`src/macho.mjs` — the raw reader — is also importable and is where new format
support lands first. It is stable within a major version but lower-level and more
likely to grow than `api.mjs`.

## The call scan is typed

`findcall` scans only sections whose attributes mark them as instructions —
`__text`, `__stubs`, `__stub_helper`, and whatever else the linker flagged
`S_ATTR_PURE_INSTRUCTIONS`. `__stubs` is included deliberately: PLT stubs are
code and do contain direct `jmp rel32` and `call rel32`, so they are legitimate
results.

This matters because `__TEXT` is not all code. It also carries `__cstring`,
`__const`, `__literal4`, jump tables and alignment padding, and any of those can
hold four bytes that decode as a `call rel32`. An untyped sweep reports every one
of them as a call site, so its output reads as a caller list and is partly
fiction — which is worse than useless, because it is indistinguishable from a
real one.

Measured on the x86_64 slice of `/usr/bin/ssh`, tallying every direct call and
jump in the binary:

| | sites found | bytes scanned |
|---|---|---|
| typed (default) | 12,776 | 478,464 |
| `--include-data` | 12,900 | 710,896 |

124 of the untyped sites — 1.0%, spread over 124 of 2,935 distinct targets —
are in data sections. A typical one is `0x8108215d`, which lives in
`__TEXT,__const` and is reported once as "called". Nothing calls it; four bytes
of a constant happen to decode that way. The error rate is low, which is exactly
what makes it a problem: a 1% false-positive rate spread across a long list is
not something a reader can spot by looking, and every false entry has to be
discarded by hand.

`--include-data` restores the old sweep for when the data sections are exactly
what you are hunting, and `typed` in the output says which you got. If a slice
flags no section as instructions at all, the scan falls back to untyped and says
so in `untypedFallback` — reporting zero call sites there would be the
confident-wrong-answer failure this project keeps producing.

The `decoy.macho` fixture makes the distinction testable rather than a matter of
trust: it plants five bytes in a data section that decode as a call to a function
the code really does call, so the typed and untyped answers differ by exactly one
and the difference is attributable.

## Configuration

`config.json` holds the two things that are facts about the world rather than
about the format: the bundle convention (`.app`, `Contents/MacOS`) and the scan
chunking. Both are overridable with `$MACHO_CONFIG`, which names a file to read
instead:

```sh
echo '{"bundle":{"ext":".bundle","macosDir":["bin","exec"]}}' > /tmp/alt.json
MACHO_CONFIG=/tmp/alt.json node src/symgrep.mjs 'someSymbol'
```

`macosDir` is a list of bare path segments rather than a joined string, because
`path.join` is how it gets composed — hardcoding a separator here is what makes a
path wrong on Windows in a way `path.join` would have fixed.

A malformed override falls back to the shipped values rather than failing: these
are convenience paths, and a typo should not stop a tool you handed an explicit
binary.

## Verifying the tools, and verifying the verification

The suite runs against **two corpora**, and the distinction is the point.

**Generated fixtures** (`test/fixtures.mjs`) are Mach-O binaries written from
scratch by code in the repository. They exist on every machine, they cover the
shapes that are hard to find by hand, and their answers are known because the
generator is right there to read:

| Fixture | Shape it provides |
|---|---|
| `universal.macho` | Fat binary, both architectures, slices at known offsets |
| `arm64-only.macho` | No x86_64 slice to fall back to |
| `decoy.macho` | Code and data in one segment, with a planted decoy call in the data |
| `stripped.macho` | No symbol table at all |
| `thin-x86_64.macho`, `thin-arm64.macho` | Single-architecture, for the thin path |

For fixtures the suite asserts **exact counts and exact addresses**, because the
generator is versioned and its answers are stable by construction.

**System binaries** — `/usr/bin/true`, `/usr/bin/ssh`, a Go toolchain, ffmpeg —
are whatever the machine has. They are the breadth: real linkers, real compilers,
real sizes. For these the suite asserts only invariants that hold for *any*
Mach-O, pinning no counts and no addresses, because those move with a compiler
release and a test that pins them fails for the wrong reason.

This is the reverse of how the suite used to work. It ran **only** on system
binaries, so on a bare CI runner it discovered nothing, exited 2, and "checked
nothing" was indistinguishable from "failed to run". The mutation check was
worse: it copies the tree and re-runs the suite inside the copy, so on a machine
without ffmpeg a mutation was never exercised and the run reported it as caught.
Every verdict about the tools depended on what happened to be installed. The
slice-relative-offset bug above survived for exactly that reason — it needs a fat
binary whose second slice is far from the file start, and no system binary on the
author's machine happened to be one.

The suite leans on the **negative** paths, where a wrong answer and a right
answer are equally quiet and only the wrong one is dangerous, and it asserts its
own coverage: that a symbol-less binary and a populated one were both tested,
that both architectures were exercised, and that every input shape the known
defects need was actually present. A test that quietly skips half the input space
and reports success is worse than no test.

`test/mutation-check.mjs` then reintroduces each bug in the table above and
asserts that `smoke.mjs` notices. A test that passes proves nothing unless it
fails when the thing it guards is broken.

Both of those had to be fixed after they were first written, and the way they
failed is worth recording:

- The smoke test's **positive control** was missing. It only checked that the
  call finder *reported* an encoding, which it did even with its arm64
  comparison inverted — so a dead scanner passed. It now uses `findcall --list`
  to prove the matcher resolves real targets, then cross-checks the top one
  against the symbol reader, so two independent parsers have to agree. When the
  per-slice narration moved to stderr, `execFileSync` silently dropped it and
  the control reported `[undefined]` while asserting nothing; the suite now uses
  `spawnSync` and *asserts* the encoding it verified is a known one. A check
  that cannot fail is worse than a missing one, because it reports success.
- The mutation check's **expectation matched the check *name***, which appears on
  PASS lines as well, so a wholly broken tool still "matched" and the run
  reported green. It now only accepts a `FAIL` line.
- An **incomplete mutation** reported a confident green: removing only the
  `N_SECT` filter left the other guard (`value === 0n`) blocking the imported
  symbols, so the suite passed while establishing nothing. Each mutation now
  restores the actual original defect rather than approximating it.

## Limits

These are the ones that matter, stated rather than discovered:

- **Mach-O only.** Android APKs, iOS bundles and Windows PE need a different
  reader; nothing here will parse them. This is a scope decision, not a gap to
  be closed later.
- **Direct calls only.** Indirect calls, register calls and jumps through a PLT
  stub do not encode their target in the instruction, so they do not appear in
  `findcall`. Every hit is a site *worth disassembling*, not a proven call-graph
  edge. This is the largest gap against Ghidra/IDA and the reason the tools hand
  off rather than replace.
- **The x86_64 scan is not typed by *instruction*.** It restricts itself to code
  sections, which removes data false positives, but it does not decode the
  instruction stream: it will still match a byte inside a multi-byte instruction
  rather than at an instruction boundary. Alignment is not something the file
  format records, so this cannot be fixed without a disassembler. The arm64 path
  steps 4 bytes at a time and so does see only aligned `BL`s.
- **Stripped binaries have no symbols** to grep. `symgrep`, `symfind` and
  `symlookup` will report nothing rather than guess; `findcall` and `findliteral`
  still work, since they read bytes rather than names. There is no dSYM support,
  so a shipped build with its symbols in a sidecar is out of reach.
- **Not a general Mach-O parser.** No load-command dump, no code signing, no
  fixups, no export trie, no Objective-C or Swift runtime metadata, no
  disassembly, no FAT32. See the comparison table above for what to use instead.
- **Verified on macOS and Linux.** The reader is portable buffer arithmetic, but
  the test corpus runs on POSIX; on Windows the system-binary half is skipped and
  only the generated fixtures are exercised.

## Licence

**LGPL-3.0-or-later.** See [`LICENSE`](LICENSE) for the GNU Lesser General Public
License v3, and [`COPYING`](COPYING) for the GNU General Public License v3 that it
incorporates — both are required, since LGPLv3 is defined in terms of GPLv3.

This is a format reader. It has no opinion about, and no access to, the contents
of the files it is pointed at.

On why LGPL rather than MIT: the reader is meant to be *used* by other tools —
imported, or vendored — without those tools becoming copyleft. LGPL keeps the
improvement path open for anyone who extends the reader while staying permissive
toward the applications built on top of it. If you only want to run these as
commands, the distinction costs you nothing; if you want to embed the reader in
a larger tool, LGPL-3.0 section 4d1 lets you link against a modified version
without relicensing your application.
