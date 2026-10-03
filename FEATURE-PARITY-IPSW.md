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

**Verdict up front, after the MCP and `a2o`/`o2a` work:** `ipsw` is still a
strict superset on format coverage and still wins every capability contest that
involves *decoding* something. MachO-Tools now wins **nine** rows, up from five,
and **two of the new ones are capabilities rather than properties**. The feature
race over format coverage is over; the remaining contest is on footprint,
auditability, contract and agent integration.

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
count is 6.

---

## 2. Parity matrix

`ipsw` only · **both** · `MachO-Tools` only

### 2.1 Container and format

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Fat header, per-slice listing | ✅ | ✅ `describe` |
| Mach header dump | ✅ `--header` | ❌ |
| **Load-command dump** | ✅ `--loads` | ❌ **none** |
| Segment / section enumeration | ✅ `--section`, `--section` on `dump` | ⚠️ count only (`codeSections: 2`) |
| UUID | ✅ `--uuid` | ❌ |
| Architecture selection on fat | ✅ `--arch` | ⚠️ 3 of 6 tools only |
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
| cstrings listing (`__cstring`) | ✅ `--strings` | ❌ *(has raw byte scan instead)* |
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
| Regex over strings in a dyld cache | ✅ `dyld str --pattern` | n/a (cache-scoped) |
| Decoy rejection (data vs code) | n/a | ✅ `decoy.macho` fixture |

`ipsw macho info --strings` prints `__cstring` — NUL-terminated strings from a
named section. MachO-Tools' `findliteral` scans **any byte sequence anywhere in
the file**, including inside code, and `mapliteral` then resolves each
occurrence to a vaddr and finds the pointers that reference it. Nothing in
`ipsw` does this. It is the single most distinctive thing in the package, and
the README undersells it as "literal-level triage".

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

`ipsw` has `--json` on three of its Mach-O commands and none on `a2o`, `o2a` or
`dump` — verified from source, not inferred. A pipeline cannot rely on it
uniformly.

Two things widened this row since the last version of this document. The new
`a2o`/`o2a` CLIs both take `--json`, so the two commands `ipsw` cannot script
are the two this one can. And the MCP server returns **the same envelope** as
`--json` — verified in `test/mcp.mjs`, which asserts `structuredContent` carries
`tool`, `ok`, `errors` and `data`. A consumer learns one contract and uses it
whether it arrived by pipe or by agent.

### 2.8 Distribution and adoption

| | `ipsw` | MachO-Tools |
|---|---|---|
| Stars | **3,769** | 0 |
| Licence | **MIT** | LGPL-3.0 |
| Install | Homebrew (own tap + core), snap, scoop, releases | `npm i -g` → **E404, unpublished** |
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
firmware are all still theirs alone. And MachO-Tools is still **not
installable**: `npm view MachO-Tools` returns E404, which is worth more than any
row in this table and has not been addressed.

---

## 4. Defects found while building this comparison

### 4.1 Unknown flags are silently ignored by the CLIs — and `--regex` silently downgrades

**Still open on the CLI.** `describe` rejects an unknown flag with exit 2. The
tools that share the flag parser **drop it and continue**:

```sh
$ node src/sym.mjs --regexx '^pop_0[0-3]$' test/fixtures/populated.macho
substring "^pop_0[0-3]$": 0 matches, 0 unique
exit=1                                    # 1 = "found nothing", not 2 = usage error

$ node src/symlookup.mjs 0x100000120 --nope -b test/fixtures/populated.macho
exit=0                                    # confident success, flag silently dropped
```

A typo'd `--regex` does not fail — it **silently changes the question being
asked** and reports a negative answer to the wrong one. `README.md` states the
principle this violates:

> a path told apart from an address by *looking* like one turns a typo into a
> confident wrong answer.

That reasoning is correct, and it is applied to positional arguments but not to
flags.

**Mitigating factor, and it is a real one:** the JSON envelope records
`"mode": "substring"` vs `"mode": "regex"`, so the contract is self-describing
and a caller *can* detect the downgrade by inspecting `data.mode`. This is the
same discipline the package applies to 64-bit addresses. So this is a
**moderate** defect, not a critical one — but the exit-code layer, which the
README sells as the primary guarantee, does not catch it.

Worse than the typo case is the inconsistency: **`describe` exits 2 and the rest
exit 0 or 1.** For a package whose pitch is "one envelope, always" and "six
tools, one dialect", the flag surface should not behave differently per tool.

**Closed on the MCP surface**, which is where an agent actually meets this. The
same typo, as an argument:

```json
{ "regx": true }
→ isError: true
  "regx: unknown argument. This tool accepts: binary, pattern, regex,
   case_sensitive, include_imports, dedupe, max, arch."
```

A wrong *type* is caught the same way (`regex: "yes"` → "expected true or
false"). The MCP validator rejects unknown keys outright rather than ignoring
them, precisely because a model that misspells an option and is told "ok" will
build its next step on the answer. This is the one place the two surfaces differ
in a way that is worth calling a bug in the CLI rather than a design difference.

### 4.2 `--arch` is missing from `describe` and `findliteral`

The README's flag table presents `--arch` as a general option. It exists on
`sym`, `symlookup` and `findcall` only. `describe --arch=arm64` exits 2 with a
usage message — correct, but it means **`ipsw macho info --arch` is a capability
MachO-Tools does not have on its own primary describe tool.** Given that fat
binaries are the stated reason the project exists, `describe` being unable to
scope to a slice is the wrong gap to have.

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

### 4.4 `--arch` is still missing from `describe` and `findliteral`

The README's flag table presents `--arch` as a general option. It exists on
`sym`, `symlookup`, `findcall`, `a2o` and `o2a`, and:

```sh
$ node src/describe.mjs --arch=arm64 test/fixtures/universal.macho   # exit 2, usage
$ node src/findliteral.mjs pop --arch=arm64 test/fixtures/universal.macho   # exit 1, flag ignored
```

`describe` at least refuses; `findliteral` silently ignores it, which is §4.1's
bug wearing a different hat. Either way, **`ipsw macho info --arch` remains a
capability MachO-Tools does not have on its own primary describe tool.** Given
that fat binaries are the stated reason the project exists, `describe` being
unable to scope to a slice is the wrong gap to have — and it is now the largest
remaining one on this list that is cheap to close.

---

## 5. The one-paragraph honest summary

If a user needs to know what is in a Mach-O and has Node and nothing else,
MachO-Tools is a better choice than `ipsw`: nothing to install, one file to
read, and a machine contract `ipsw` does not have — the same contract whether
the caller arrived by pipe or by MCP. If a user needs to know anything *else* —
load commands, code signature, entitlements, Objective-C, Swift, a disassembly, a
firmware image, a directory of binaries, or the literal's callers in a shared
cache — `ipsw` answers it and MachO-Tools does not.

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
this was written that made all three table stakes. And **none of it counts if
the package is not installable**: `npm view MachO-Tools` still returns E404,
which is worth more than every row in this document combined.

The one row worth defending loudest is still `findcall`, because `ipsw` has no
answer for it at all — and the second is now the zero-fill and ambiguity
handling in `a2o`/`o2a`, because that is a capability `ipsw` ships and answers
with a number that is sometimes wrong.
