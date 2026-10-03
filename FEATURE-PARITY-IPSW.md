# Feature parity — `MachO-Tools` vs `blacktop/ipsw`

Researched 2026-10-03, re-verified after the MCP/skill work. The `ipsw` column
is taken from the source tree, not its README: `cmd/ipsw/cmd/macho/` (17 files)
and `cmd/ipsw/cmd/dyld/` (44 files), enumerated via the GitHub API, with each
command's cobra flag registrations extracted directly from source. The
`MachO-Tools` column is taken from the code and from running every tool, not
from `README.md`.

**Re-verification result: `ipsw` has not moved.** Same 17 files in `macho/`,
same `pushed_at` (2026-10-02), still 3,769 stars, still MIT. So the comparison
below is a like-for-like diff of one side changing and the other not.

**Verdict up front, after the MCP, `a2o`/`o2a` and describe work:** `ipsw` is
still a strict superset on format coverage and still wins every capability
contest that involves *decoding* something. MachO-Tools now wins **eleven**
rows, up from five, and **four of the new ones are capabilities rather than
properties** — the load-command listing, the section enumeration, the UUID and
`__cstring` with addresses. The feature race over format coverage is over; the
remaining contest is on footprint, auditability, contract and agent integration.

---

## 1. The `ipsw` surface, for reference

```
ipsw macho info       arch header loads json sig ent objc swift symbols strings
                      starts fixups split-seg fileset-entry extract-fileset-entry
                      all-fileset-entries bit-code demangle dump-cert output
ipsw macho search     load-command launch-const import section uuid sym protocol
                      class category sel ivar          (regex, over a FOLDER or IPSW)
ipsw macho disass     entry symbol section demangle slide cache quiet force
                      dec dec-lang dec-model dec-retry-backoff json
ipsw macho dump       arch addr bytes output entry segment section
ipsw macho a2o        vaddr -> file offset
ipsw macho o2a        file offset -> vaddr
ipsw macho a2s / s2a  vaddr <-> symbol
ipsw macho lipo       extract one slice from a fat binary
ipsw macho diff       diff two Mach-Os
ipsw macho patch      patch add / mod / rm
ipsw macho sign       code signing
ipsw macho decrypt    FairPlay decryption
ipsw macho bbl        boot blob loader

ipsw dyld             34 commands: xref (WIP) search symaddr str objc swift
                      extract disass info emu ida imports patches slide split
                      stubs tbd webkit mg prewarm softlinks uniq split-slide
```

`ipsw macho info` alone has **19 feature flags**. MachO-Tools' entire tool
count is 8 — and `describe` alone now answers three of `info`'s flags
(`--loads`, `--section`, `--uuid`) plus most of a fourth.

---

## 2. Parity matrix

`ipsw` only · **both** · `MachO-Tools` only

### 2.1 Container and format

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Fat header, per-slice listing | ✅ | ✅ `describe` |
| Mach header dump | ✅ `--header` | ⚠️ the fields it reports, not a byte dump |
| **Load-command dump** | ✅ `--loads` | ✅ `describe --loads`, **17 in a Go binary** |
| Segment / section enumeration | ✅ `--section`, `--section` on `dump` | ✅ **`describe --sections`, per section** |
| UUID value | ✅ `--uuid` | ✅ **`describe`, every slice** |
| Architecture selection on fat | ✅ `--arch` | ✅ **all 8 tools**, as a preference |
| Split segments (`__DATA_CONST`, `__TEXT_EXEC`) | ✅ `--split-seg` | ❌ |
| Chained fixups | ✅ `--fixups` | ❌ |
| Embedded LLVM bitcode | ✅ `--bit-code` | ❌ |
| Fileset entries (`MH_FILESET`) | ✅ 3 flags | ❌ |
| **Extract a slice from fat** | ✅ `macho lipo` | ❌ **no equivalent** |
| Diff two binaries | ✅ `macho diff` | ❌ |
| arm64 + x86_64 | ✅ | ✅ |

### 2.2 Symbols

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Substring symbol search | ✅ `--sym` regex | ✅ `sym` |
| Regex symbol search | ✅ | ✅ `--regex` |
| Import-only / defined-only split | ✅ `--import` | ✅ `--all-imp` |
| Name **demangling** (Swift / C++) | ✅ `--demangle` | ❌ |
| cstrings listing (`__cstring`) | ✅ `--strings` | ✅ `findliteral --strings`, **with addresses** |
| Function-start listing (LC_FUNCTION_STARTS) | ✅ `--starts` | ❌ |
| Search **ObjC** classes / selectors / categories / ivars / protocols | ✅ 5 flags | ❌ |
| Search **Swift** metadata | ✅ `--swift`, `--swift-all`, `dyld search --swift` | ❌ |
| Multi-symbol batch lookup | ✅ `dyld symaddr --in <json>` | ❌ one pattern per run |

### 2.3 Addresses

The `a2o`/`o2a` rows changed, so they are worth reading closely rather than
ticking off. Both tools now answer the same question `ipsw macho a2o` and
`ipsw macho o2a` do, and both take `--arch`. Three things differ, and all three
are the same species of thing this project exists to avoid:

**Zero-fill is a third answer, not an error or a wrong offset.** An address in
`__bss` is mapped, has a section, and has *no byte in the file*. Verified
against `zerofill.macho`:

```json
{ "vaddr": "0x100001000", "offset": null, "section": "__TEXT,__bss",
  "zerofill": true, "mapped": true,
  "note": "__TEXT,__bss is zero-fill — mapped at this address, but no byte of it exists in the file" }
```

`ipsw`'s `macho a2o` has no `zerofill` concept — no match in `pkg/macho`, and
neither conversion file mentions it. A script that takes an offset from `a2o`
and `dd`s the file gets nothing for a `__bss` address. Conflating that with
"not in this binary" sends it to the wrong place; that is the specific failure
`a2o`'s own description says it exists to prevent.

**An ambiguous fat binary is reported, not resolved by coin toss.** Every slice
maps `__TEXT` at `0x100000000`, so an address is genuinely in all of them.
Verified on `universal.macho`:

```json
{ "arch": null, "vaddr": "0x100000120", "mapped": true, "ambiguous": true,
  "slices": [ { "arch": "x86_64", "offset": 288, "absoluteOffset": 16672 },
              { "arch": "arm64",  ... } ] }
```

`arch: null` and every per-slice answer, rather than one slice chosen silently.
Pass `--arch` to pick.

**Both emit JSON.** Neither `ipsw macho a2o` nor `ipsw macho o2a` has a `--json`
flag — verified by reading both files, which are 117 lines each and register only
`--arch` and `--debug`. So the two commands that exist to feed a *script* are the
two that cannot be scripted, and a caller has to scrape the human-formatted
table.

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| vaddr → containing function | ✅ `a2s` | ✅ `symlookup` |
| vaddr → file offset | ✅ `a2o` | ✅ **`a2o`** |
| file offset → vaddr | ✅ `o2a` | ✅ **`o2a`** |
| **Zero-fill as a distinct answer** | ❌ not modelled | ✅ **`zerofill:true`** |
| **Slice ambiguity reported, not guessed** | ❌ | ✅ **`ambiguous:true`** |
| Batch address lookup | ✅ `symaddr --in <json>` | ✅ multiple positionals |
| **Direct call/jmp xrefs in a standalone Mach-O** | ❌ **none** | ✅ **`findcall`** |
| List distinct call targets | ❌ | ✅ `findcall --list` |
| **JSON on the offset conversions** | ❌ neither has `--json` | ✅ **both do** |
| **Scan restricted to code sections** | ❌ | ✅ **`--include-data` to widen** |

This is the most important block in the document.

`ipsw` has no `macho xref`. Its only cross-reference command is
`dyld xref <DSC> <ADDR>` — scoped to a **dyld shared cache**, not a standalone
Mach-O, and its own help string is:

```
Short: "🚧 [WIP] Find all cross references to an address"
```

It is marked work-in-progress by its author. MachO-Tools' `findcall` works on a
standalone file, handles both arm64 `BL` and x86_64 `rel32`, and is explicitly
typed by section. **`findcall` has no competitor in `ipsw` at all.**

Note the converse: `ipsw macho disass` is documented "Disassemble **ARM64**
MachO". On x86_64, MachO-Tools' `findcall` covers ground `ipsw`'s disassembler
does not.

### 2.4 Bytes and literals

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Hex/bytes dump at a vaddr | ✅ `macho dump --bytes --section` | ⚠️ context bytes only |
| Dump a whole segment/section | ✅ `macho dump --segment/--section` | ❌ |
| **Arbitrary byte-literal search in a Mach-O** | ❌ | ✅ **`findliteral`** |
| **literal → vaddr → pointers to it** | ❌ | ✅ **`mapliteral`** |
| `__cstring` dump | ✅ `info --strings` | ✅ `--strings`, each with an **address** |
| Regex over strings in a dyld cache | ✅ `dyld str --pattern` | n/a (cache-scoped) |
| Decoy rejection (data vs code) | n/a | ✅ `decoy.macho` fixture |

`ipsw macho info --strings` prints `__cstring` — NUL-terminated strings from a
named section. MachO-Tools' `findliteral` scans **any byte sequence anywhere in
the file**, including inside code, and `mapliteral` then resolves each
occurrence to a vaddr and finds the pointers that reference it. Nothing in
`ipsw` does this. It is the single most distinctive thing in the package, and
the README undersells it as "literal-level triage".

The `--strings` row was a genuine gap and is now closed, with one difference
that matters more than the feature: every entry carries its file offset, virtual
address and owning section, so it can be fed straight into `symlookup` or
`mapliteral`. A string you cannot address is a string you cannot act on. The
limits are stated rather than left to be discovered — it reads the Objective-C
and Swift name sections too, skips `__cfstring` because those are structures
rather than text, and finds nothing in a Go binary, whose strings are
length-prefixed in `__gopclntab` and have no terminator to scan for (§4.6).

### 2.5 Corpus scale

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| One binary at a time | ✅ | ✅ |
| Search a **directory** of binaries | ✅ `macho search <FOLDER>` | ❌ |
| Search an entire **IPSW firmware image** | ✅ | ❌ |
| dyld shared cache (44 commands) | ✅ | ❌ |
| Firmware: img3 / img4 / OTA / kernelcache / KDK | ✅ | ❌ |
| Connected-device inspection (`idev`) | ✅ | ❌ |
| Firmware download | ✅ | ❌ |

`ipsw macho search --import 'CCCrypt' /path/to/binaries` answering "which of
these 4,000 binaries import this" is a genuinely different product. MachO-Tools
processes one file per invocation.

### 2.6 Mutation

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Patch bytes / add / remove | ✅ `patch add/mod/rm` | ❌ |
| Code signing | ✅ `macho sign` | ❌ |
| FairPlay decryption | ✅ `macho decrypt` | ❌ |
| Entitlements read | ✅ `--ent`, `--ent-der`, `--dump-cert` | ❌ |
| Code signature read | ✅ `--sig` | ❌ |
| ObjC / Swift metadata read | ✅ | ❌ |

All six are on MachO-Tools' own "What it will not do" list, and the project's
own test for that list — *would closing this gap make the package worse at the
thing it is for?* — is the right test. **But the honest reading of that list is
that it is a list of everything `ipsw` does and MachO-Tools does not.** It is a
scope statement, not a competitive strength.

### 2.7 Output contract — the strongest row, and it widened

| Property | `ipsw` | MachO-Tools |
|---|---|---|
| `--json` | ⚠️ `info`, `search`, `disass` — **verified absent** from `a2o`, `o2a`, `dump` | ✅ **all 9 CLIs + the MCP server** |
| One envelope shape across tools | ❌ per-command | ✅ `{tool, ok, binary, errors, messages, notes, data}` |
| Exit-code taxonomy | ❌ | ✅ 0 / 1 / 2 / 3 |
| "Found nothing" ≠ "could not look" | ❌ | ✅ by design |
| Addresses never lose precision | ⚠️ | ✅ `"0x…"` strings, `bigint` in |
| stdout is data only | ❌ mixed | ✅ prose to stderr |
| Negative answer is a value | ❌ | ✅ `{matches: []}`, `{function: null}` |
| **Same shape over MCP and CLI** | ❌ n/a | ✅ **one envelope, two doors** |
| A misspelled option is rejected | ❌ | ✅ **both surfaces, exit 2** |
| A mistyped `--arch` is reported | ❌ | ✅ `archHonoured: null`, `archRead` |

`ipsw` has `--json` on three of its Mach-O commands and none on `a2o`, `o2a` or
`dump` — verified from source, not inferred. A pipeline cannot rely on it
uniformly.

Three things widened this row since the last version of this document. The new
`a2o`/`o2a` CLIs both take `--json`, so the two commands `ipsw` cannot script
are the two this one can. And the MCP server returns **the same envelope** as
`--json` — verified in `test/mcp.mjs`, which asserts `structuredContent` carries
`tool`, `ok`, `errors` and `data`. A consumer learns one contract and uses it
whether it arrived by pipe or by agent.

The third is the one worth having. An option that is silently ignored does not
just lose a feature — it *answers a different question*, which is the worst
failure mode available to a tool that exists to be trusted. Both surfaces now
reject an unknown key and name a near miss (§4.1), and `--arch` that matches no
slice says so instead of returning nothing (§4.2). Both properties are asserted
on the CLIs *and* over a real MCP pipe, because a contract held by one door and
not the other is not a contract.

### 2.8 Distribution and adoption

| | `ipsw` | MachO-Tools |
|---|---|---|
| Stars | **3,769** | 0 |
| Licence | **MIT** | LGPL-3.0 |
| Install | Homebrew (own tap + core), snap, scoop, releases | `npm i -g` → **valid name, not yet published** |
| Language runtime | Go 1.26 static binary | Node ≥ 22.15 |
| Runtime dependencies | none, but ~40 MB binary | none, and **zero** |
| Docs site | ✅ + Discord + DeepWiki | README only |
| **MCP server** | ❌ **none** — 0 matches for `modelcontextprotocol` in the tree | ✅ **dual-era stdio, `macho-mcp`** |
| Agent skill | ✅ `ipsw-skill` (90★, Claude Code / Codex / Gemini) | ✅ `skill/` |
| Programmatic surface | REST daemon (`ipswd`) | ✅ `src/api.mjs` + CLI + **MCP** |
| Shell completion | ✅ | ✅ |
| Man pages | ✅ | ✅ |
| Tests | Go suite | **243 smoke + 138 MCP + 30 skill + 7/7 mutation** |
| Offline reproducible gate | ❌ | ✅ |
| **Auditable in one file** | ❌ 6,173 commits of Go | ✅ **`macho.mjs`, one file** |

The MCP row is new and it is a genuine flip. `ipsw` has an *agent skill* — a
documented workflow an agent follows — but no server, so an agent that does not
read prose still cannot call anything. MachO-Tables now has both doors. Be clear
about what that is worth: it is **distribution, not differentiation**, since
Hopper, Binary Ninja 6.0 and `ipsw` all now sit in the same conversation. It
means the tools are reachable, not that they are better.

---

## 3. Score

| | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Capability rows won | ~46 | **9** (was 5) |
| MachO format coverage | complete | partial |
| Multi-arch disassembly | ARM64 | — (by design) |
| x86_64 direct-call xrefs | ❌ | ✅ |
| Byte-literal → pointer analysis | ❌ | ✅ |
| vaddr ⇄ file offset | ✅ no JSON | ✅ **JSON + zerofill + ambiguity** |
| Corpus / firmware scale | ✅ | ❌ |
| Output contract consistency | partial | ✅ **and shared with MCP** |
| Agent integration | skill only | ✅ **skill + MCP server** |
| Zero runtime footprint | partial | ✅ |
| Single-file auditability | ❌ | ✅ |
| MCP server | ❌ | ✅ |
| Agent skill | ✅ | ✅ |
| Installable today | ✅ | ❌ **still E404** |
| Momentum | 3,769★, 8 yrs | 0★, 2 days |

**Nine rows, four of which are capabilities.** Up from five. The four
capabilities are: `findcall` (direct xrefs in a standalone file), byte-literal
search, literal → pointer analysis, and the `a2o`/`o2a` pair with its zero-fill
and ambiguity answers. The other five are properties: the output contract, zero
runtime footprint, single-file auditability, the MCP server, and x86_64 xref
coverage.

Two things this does **not** change. `ipsw` is still a strict superset on format
coverage — load commands, code signing, ObjC/Swift, disassembly, dyld caches and
firmware are all still theirs alone. And MachO-Tools is still **not published**.

That second one has changed *why*, which is worth recording because the reason
was invisible. `npm view MachO-Tools` returned E404, and the obvious reading was
"not published yet". In fact it could not have been published at all: npm refuses
a capital letter in a name published for the first time, and `validate-npm-package-name`
reported `validForNewPackages: false`. `npm publish --dry-run` packed the tarball
and printed `+ MachO-Tools@0.1.0` with exit 0, so the command a maintainer reaches
for to check readiness reported success on the one thing that was broken. The name
is now `macho-tools`, and `test/publish.mjs` asserts the property in CI.

---

## 4. Defects found while building this comparison

### 4.1 Unknown flags were silently ignored by the CLIs — **fixed**

`describe` rejected an unknown flag with exit 2 while every other tool **dropped
it and continued**:

```sh
$ node src/sym.mjs --regexx '^pop_0[0-3]$' test/fixtures/populated.macho
substring "^pop_0[0-3]$": 0 matches, 0 unique
exit=1                                    # 1 = "found nothing", not 2 = usage error

$ node src/symlookup.mjs 0x100000120 --nope -b test/fixtures/populated.macho
exit=0                                    # confident success, flag silently dropped
```

A typo'd `--regex` did not fail — it **silently changed the question being
asked** and reported a negative answer to the wrong one, contradicting the rule
the README states for positional arguments:

> a path told apart from an address by *looking* like one turns a typo into a
> confident wrong answer.

The reasoning was correct and was applied to positionals but not to flags. The
inconsistency was the worse half: one tool exited 2 and the rest exited 0 or 1,
in a package whose pitch is one envelope and one dialect.

**Now closed on both surfaces, and they agree.** `rejectUnknownFlags()` in
`src/output.mjs` takes each tool's own known-flag set, so the rule lives beside
the parser that used to violate it, and a near miss is corrected by name:

```sh
$ node src/sym.mjs --regexx '^pop_0[0-3]$' test/fixtures/populated.macho
unknown flag: --regexx

  did you mean --regex?
exit=2
```

Every one of the eight tools is asserted, plus a check that all sixteen
documented flag combinations still parse — because stopping working commands to
prevent silent no-ops is a trade that has to be paid deliberately.
`test/skill.mjs` also asserts the converse: **no** tool accepts `--check`, the
flag that belongs to `fixtures.mjs`.

The MCP surface had rejected unknown keys from the start, and that behaviour is
now the CLI's rather than a divergence between them:

```json
{ "regx": true }
→ isError: true
  "regx: unknown argument. This tool accepts: binary, pattern, regex,
   case_sensitive, include_imports, dedupe, max, arch."
```

A wrong *type* is caught the same way (`regex: "yes"` → "expected true or
false"). The validator rejects unknown keys outright rather than ignoring them,
precisely because a model that misspells an option and is told "ok" will build
its next step on the answer.

### 4.2 `--arch` was missing from `describe` and `findliteral` — **fixed**

The README's flag table presented `--arch` as a general option. It existed on
`sym`, `symlookup` and `findcall` only, and `describe --arch=arm64` exited 2 —
correct, but it meant **`ipsw macho info --arch` was a capability MachO-Tools did
not have on its own primary describe tool.** Given that fat binaries are the
stated reason the project exists, `describe` being unable to scope to a slice was
the wrong gap to have.

Both tools now take it, and both treat it as a **preference rather than a
requirement**, which is the rule the other five already followed. The difference
matters: filtering would turn a mistyped architecture into "the magic is not in
this file", a claim about the bytes that happens to be false.

```sh
$ node src/describe.mjs --arch=arm64 test/fixtures/universal.macho
  arm64  file 0..799  64-bit  4 defined / 6 symbols  1 code section(s)
  note: --arch=arm64: showing 1 of 2 slices — drop the flag for all
```

`fat: true` survives the narrowing, because "this is a universal binary, here is
the arm64 half" is a different and more useful answer than pretending it is
thin. An architecture that matches nothing shows every slice and says so.
`findliteral` reports `arch`, `archHonoured` (null when the request was not met)
and `archRead` — the ground truth — so a caller can tell "you got the slice you
asked for" from "you got a slice anyway" without re-deriving it.

### 4.3 The reason-code conflation — **fixed**

This was the finding that mattered most, because it sat under the project's
central claim. It is now closed:

```sh
$ node src/describe.mjs --json /nope        # missing file      → io
$ node src/describe.mjs --json /etc/hosts   # wrong format      → unknown-encoding
$ node src/describe.mjs --json /tmp         # a directory       → io
```

`readerError()` in `src/api.mjs` distinguishes them with `statSync`, and the code
travels on the thrown error as `.code` so every CLI and the MCP server branch on
one value. `sym` also gained the `try`/`catch` it never had — an unhandled
rejection under `--json` meant the envelope contract held only for binaries that
happened to be readable — and `symlookup` no longer reports an unreadable binary
as `bad-address`. Both were verified and are covered by `test/skill.mjs`, which
runs the CLIs and asserts the codes rather than trusting the prose.

### 4.4 `describe` reported a count of code sections and nothing else

**Fixed.** `parseThin` had always built `segments[]` and `sections[]` — 5 and 15
respectively for a stock Go binary — and `describe` reported only
`codeSections: 2`, a count. So the reader knew the whole map and the tool
discarded it, and **`ipsw macho info --section` was a capability MachO-Tools
lacked on the tool whose entire job is answering "what is in this file".**

`describe` now carries all three lists, and adds three flags to print them in
text, because the default view is the "what is this file" answer and a wall of
section names buries it:

```sh
$ node src/describe.mjs --sections /usr/local/go/bin/go
  __TEXT,__text                      0x100001000..0x10059caf4  5,880,564  code
  __TEXT,__symbol_stub1              0x10059cb00..0x10059d124      1,572  code
  __TEXT,__rodata                    0x10059d140..0x100602219    413,913  data
$ node src/describe.mjs --loads /usr/local/go/bin/go
load commands in arm64: 17
  LC_SEGMENT_64                   72 bytes  at 0x20
  LC_LOAD_DYLIB                   56 bytes  at 0x71c
  LC_UUID                         24 bytes  at 0x850
```

Load commands are **named, not interpreted**, which is a deliberate line:
knowing a binary declares `LC_LOAD_DYLIB` is a fact about it, and following the
dependency is not something this package does. An unrecognised command is
reported by number rather than dropped, so an unfamiliar load command is visible
instead of silently absent.

The `code`/`data` marking calls the reader's own `isCodeSection` rather than
re-testing the attribute bits inline. That is not tidiness: the first version of
this did re-test them, and a second copy of that predicate is a second thing to
keep correct — which is how the project shipped a bug from exactly that before.

### 4.5 The 32-bit reader path had three defects and no fixture

**Found and fixed while adding 32-bit coverage.** Every one of the eight original
fixtures was 64-bit, so the `if (wide)` gate on section parsing meant the 32-bit
branch of a reader that claims to handle both had never been executed by
anything. Building a 32-bit fixture surfaced three defects, all the same mistake
— a 32-bit field read at the 64-bit offset:

| field | 64-bit offset | 32-bit offset | was |
|---|---|---|---|
| `section.offset` | 48 | **40** | 44 (which is `align`) |
| `section.flags` | 64 | **56** | 56 ✓ |
| `nlist` stride | 16 | **12** | 16 |

The stride was the one that mattered. It did not throw, did not reduce the
symbol count, and produced names that looked like names — every symbol read one
entry off. Verified by mutation:

```
- bits32: resolves target_fn through a 12-byte nlist (got "__mh_execute_header")
- bits32: the symbol's own address is exact, not truncated (got 134512884)
```

`test/fixtures/bits32.macho` now pins all three, with the expected values
transcribed from `<mach-o/loader.h>` rather than derived from the 64-bit form.
That is not pedantry: scaling 48 by 68/80 gives 40, so the right answer was
reachable by luck, and the offsets do **not** scale — each 32-bit field shifts the
next one 4 bytes earlier, so `flags` ends 8 bytes from where it was and the
entries differ in length by 12 rather than by a factor. All three defects are
also mutations in `test/mutation-check.mjs`, so the 32-bit branch cannot rot the
way it did.

The fixture's addresses are genuinely 32-bit (`0x8048000`), so a value that
overflowed truncates rather than quietly staying large.

### 4.6 `--strings` over `__cstring`

`ipsw macho info --strings` prints C strings. MachO-Tools had nothing, and the gap
was worth closing because a string you cannot address is a string you cannot hand
to `symlookup` or `mapliteral` — every entry carries its file offset, virtual
address and owning section.

Two things about it that are worth stating plainly rather than leaving to be
discovered:

- **It finds nothing in a Go binary, and zero is the correct answer.** Go keeps
  its strings length-prefixed inside `__gopclntab`, not NUL-terminated, so there
  is no terminator to scan for. Both the CLI and the MCP tool say so in a note
  when the count is zero, because "0 strings" otherwise reads as "this binary has
  nothing to say".
- It reads `__cstring`, `__objc_methname`, `__swift5_reflstr` and
  `__objc_classname`. `__cfstring` is excluded on purpose: those are 32-byte
  structures, so including it would report addresses as if they were strings.
  The rest are included and labelled rather than filtered out, because a tool that
  only looked at `__cstring` would report an Objective-C binary as having no
  strings in it.

### 4.7 The UUID was named but not read — **fixed**

A smaller instance of the same rule as §4.4, found while writing §4.4's
`--loads` output: the load-command table said `LC_UUID`, and the 16 bytes
immediately after the command header were not parsed. `ipsw macho info --uuid`
prints them.

This one was worth closing rather than documenting, and the reason is the line
the load-command table already draws. A UUID is read, and `LC_CODE_SIGNATURE` is
not, because **reading the bytes of an identifier is the same class of act as
reading a section's size, while following a code signature means decoding a
structure someone else defined.** The distinction is not "small fields yes, big
fields no" — it is whether answering correctly requires understanding a format
this package has no other business knowing.

```
$ node src/describe.mjs /usr/local/go/bin/go
  arm64    file 0..14516816  64-bit  19,526 defined / 19,657 symbols  2 code section(s) __text 0x100001000+5,880,564
           uuid e5f29a7e-46cd-3735-c21f-ed044a7e5c86
```

A UUID is the only field in the file that identifies *which build* this is rather
than describing what is in it. Two binaries can have identical sizes, symbol
counts and section layouts and still be different builds.

The fixture places its `LC_UUID` **last of three** commands, which is what makes
the test worth having: the bytes sit at offset 8 of that command, and a reader
pointing at offset 0 gets `cmd` and `cmdsize` — which format into a perfectly
plausible identifier. Verified:

```
- stripped: reads its LC_UUID (got 1b000000-1800-0000-a1b2-c3d4e5f64708)
```

`0x1b` is `LC_UUID` and `0x18` is 24, its size. Both correct, neither a UUID.

---

## 5. The one-paragraph honest summary

If a user needs to know what is in a Mach-O and has Node and nothing else,
MachO-Tools is a better choice than `ipsw`: nothing to install, one file to
read, and a machine contract `ipsw` does not have — the same contract whether
the caller arrived by pipe or by MCP. If a user needs to know anything *else* —
code signing, entitlements, chained fixups, export tries, Objective-C or Swift
metadata, a disassembly, a firmware image, a directory of binaries, or the
literal's callers in a shared cache — `ipsw` answers it and MachO-Tools does not.
The load-command *listing* is now closed; the load-command *interpretation* is
not, and is not planned to be.

Three things MachO-Tools is now alone on, and all three are the same idea
applied at different depths: **direct call xrefs in a standalone file**, with no
`ipsw` equivalent at all; **byte-literal → vaddr → pointers**, which no `ipsw`
command does; and **vaddr ⇄ file offset that admits "mapped but there is no byte
there" and "this address is in every slice" as answers** rather than collapsing
them into a wrong offset. The first is a capability `ipsw` lacks. The other two
are capabilities `ipsw` has and answers less honestly.

The parity table is not a roadmap argument for closing rows. It is a scoping
argument for **stopping**: the ~46 lost rows are all on the "What it will not do"
list, by decision, and the project's own test for that list still comes out
right. Nothing in the MCP or skill work moved that line, and nothing should.

Two things are worth saying out loud rather than leaving in a table where they
lose. **The MCP server and the skill are distribution, not differentiation** —
`ipsw` has a skill today, Hopper and Binary Ninja have servers, and by the time
this was written that made all three table stakes. And **none of it counts while
the package is unpublished**: `npm view macho-tools` still returns E404, which is
worth more than every row in this document combined. The name is now valid and the
check is in CI, so this is the last blocker rather than a permanent one.

The one row worth defending loudest is still `findcall`, because `ipsw` has no
answer for it at all — and the second is now the zero-fill and ambiguity
handling in `a2o`/`o2a`, because that is a capability `ipsw` ships and answers
with a number that is sometimes wrong.
