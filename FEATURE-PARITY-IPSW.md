# Feature parity — `MachO-Tools` vs `blacktop/ipsw`

Researched 2026-10-03. The `ipsw` column is taken from the source tree, not its
README: `cmd/ipsw/cmd/macho/` (17 files) and `cmd/ipsw/cmd/dyld/` (34 files),
enumerated via the GitHub API, with each command's cobra flag registrations
extracted directly from source. The `MachO-Tools` column is taken from the code
and from running every tool, not from `README.md`.

**Verdict up front:** `ipsw` is a strict superset on format coverage and wins
every capability contest. MachO-Tools wins exactly **five** rows, and only one
of them is a capability rather than a property. The feature race is over; the
remaining contest is on footprint, auditability and contract.

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

| Capability | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| vaddr → containing function | ✅ `a2s` | ✅ `symlookup` |
| vaddr → file offset | ✅ `a2o` | ❌ **no primitive** |
| file offset → vaddr | ✅ `o2a` | ⚠️ only inside `mapliteral` |
| Batch address lookup | ✅ `symaddr --in <json>` | ✅ multiple positionals |
| **Direct call/jmp xrefs in a standalone Mach-O** | ❌ **none** | ✅ **`findcall`** |
| List distinct call targets | ❌ | ✅ `findcall --list` |
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
| dyld shared cache (34 commands) | ✅ | ❌ |
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

### 2.7 Output contract — the one clean win

| Property | `ipsw` | MachO-Tools |
|---|---|---|
| `--json` | ⚠️ `info`, `search`, `disass` — **verified absent** from `a2o`, `o2a`, `dump` | ✅ all 6 |
| One envelope shape across tools | ❌ per-command | ✅ `{tool, ok, binary, errors, messages, notes, data}` |
| Exit-code taxonomy | ❌ | ✅ 0 / 1 / 2 / 3 |
| "Found nothing" ≠ "could not look" | ❌ | ✅ by design |
| Addresses never lose precision | ⚠️ | ✅ `"0x…"` strings, `bigint` in |
| stdout is data only | ❌ mixed | ✅ prose to stderr |
| Negative answer is a value | ❌ | ✅ `{matches: []}`, `{function: null}` |

This is the strongest row in the table. `ipsw` has `--json` on three of its
Mach-O commands and none on `a2o`/`o2a`/`dump` — verified from the source, not
inferred. A pipeline cannot rely on it uniformly. MachO-Tools' contract is
genuinely better and is worth saying out loud.

### 2.8 Distribution and adoption

| | `ipsw` | MachO-Tools |
|---|---|---|
| Stars | **3,769** | 0 |
| Licence | **MIT** | LGPL-3.0 |
| Install | Homebrew (own tap + core), snap, scoop, releases | `npm i -g` → **E404, unpublished** |
| Language runtime | Go 1.26 static binary | Node ≥ 22.15 |
| Runtime dependencies | none, but ~40 MB binary | none, and **zero** |
| Docs site | ✅ + Discord + DeepWiki | README only |
| Agent/AI integration | `ipsw-skill` (Claude Code, Codex, Gemini) | none |
| Programmatic surface | REST daemon (`ipswd`) | `src/api.mjs` + CLI |
| Shell completion | ✅ | ✅ |
| Man pages | ✅ | ✅ |
| Tests | Go suite | 213 checks + 7/7 mutation gate |
| Offline reproducible gate | ❌ | ✅ |
| **Auditable in one file** | ❌ 6,173 commits of Go | ✅ **`macho.mjs`, one file** |

---

## 3. Score

| | `ipsw` | MachO-Tools |
|---|:--:|:--:|
| Capability rows won | ~46 | **5** |
| MachO format coverage | complete | partial |
| Multi-arch disassembly | ARM64 | — (by design) |
| x86_64 direct-call xrefs | ❌ | ✅ |
| Byte-literal → pointer analysis | ❌ | ✅ |
| Corpus / firmware scale | ✅ | ❌ |
| Output contract consistency | partial | ✅ |
| Zero runtime footprint | partial | ✅ |
| Single-file auditability | ❌ | ✅ |
| Installable today | ✅ | ❌ |
| Momentum | 3,769★, 8 yrs | 0★, 1 day |

**Five rows, one of which is a capability.** The four that are not capabilities
are: the output contract, zero runtime footprint, single-file auditability, and
x86_64 xref coverage. Three of those four are properties rather than features,
and none of them is currently in the README's marketing.

---

## 4. Defects found while building this comparison

### 4.1 Unknown flags are silently ignored by 3 of 6 tools — and `--regex` silently downgrades

`describe` rejects an unknown flag with exit 2. The other three tools that share
the flag parser **drop it and continue**:

```sh
$ node src/sym.mjs --regexx '^runtime\.main$' /usr/local/go/bin/go
substring "^runtime\.main$": 0 matches, 0 unique
exit=1                                    # 1 = "found nothing", not 2 = usage error

$ node src/symlookup.mjs 0x100001000 --nope -b /usr/local/go/bin/go
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

### 4.2 `--arch` is missing from `describe` and `findliteral`

The README's flag table presents `--arch` as a general option. It exists on
`sym`, `symlookup` and `findcall` only. `describe --arch=arm64` exits 2 with a
usage message — correct, but it means **`ipsw macho info --arch` is a capability
MachO-Tools does not have on its own primary describe tool.** Given that fat
binaries are the stated reason the project exists, `describe` being unable to
scope to a slice is the wrong gap to have.

### 4.3 The reason-code conflation (carried over)

```sh
$ node src/describe.mjs --json /nope        # missing file
$ node src/describe.mjs --json /etc/hosts   # wrong format
$ node src/describe.mjs --json /tmp         # a directory
```
All three → `errors: ["io"]`, message `"not a Mach-O binary"`. `unknown-encoding`
is never emitted. Full detail in `COMPETITIVE-LANDSCAPE.md` §5.

---

## 5. The one-paragraph honest summary

If a user needs to know what is in a Mach-O and has Node and nothing else,
MachO-Tools is a better choice than `ipsw`: nothing to install, one file to
read, and a machine contract `ipsw` does not have. If a user needs to know
anything *else* — load commands, code signature, entitlements, Objective-C,
Swift, a disassembly, a firmware image, a directory of binaries, or the literal's
callers in a shared cache — `ipsw` answers it and MachO-Tools does not, except
for direct call/jmp xrefs in a standalone file, where MachO-Tools is alone.

The parity table is not a roadmap argument for closing rows. It is a scoping
argument for **stopping**: the 46 lost rows are all on the "What it will not do"
list, by decision, and the project's own test for that list still comes out
right. The one row worth defending — `findcall` — should be defended *loudly*,
because `ipsw` has no answer for it at all, and the README currently buries it
in a comparison table where it loses.
