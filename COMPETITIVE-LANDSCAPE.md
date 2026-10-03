# Competitive landscape — `MachO-Tools`

Researched 2026-10-03. Every number is from the GitHub REST API or the npm
registry on that date; every behavioural claim was run against this tree, not
inferred from the README. Where I could not verify something, it says so.

The sibling `TOWS.md` is an *internal* assessment — strengths, weaknesses, and
what to do about them. It is not a competitive study, and in three places it
reaches conclusions this one contradicts.

---

## 0. The finding that reframes everything else

**This project does not exist yet, competitively.** Not "is early" — does not
exist.

| | |
|---|---|
| GitHub repo created | 2026-10-02 (yesterday) |
| Stars / forks / watchers | 0 / 0 / 0 |
| Published on npm | **No.** `npm view macho-tools` → `E404` |
| `api.npmjs.org/downloads` | 404, package not found |
| Publishable? | **Yes, since 2026-10-03.** It was not: the name was `MachO-Tools`, and npm refuses a capital letter in a name published for the first time. `npm publish --dry-run` hid this by printing `+ MachO-Tools@0.1.0` and exiting 0. |

The README's first install instruction is:

```sh
npm install -g MachO-Tools          # macho-describe, macho-sym, ...
```

That command fails today. `TOWS.md` §Strengths lists "Publishable as
configured — nothing blocking an `npm publish`" and treats distribution as
solved, because the manifest *is* complete. Complete metadata is not
publication. Every distribution advantage the project claims — `npm i -g`, man
pages after install, shell completions, `$MACHO_BINARY` defaults — is currently
unreachable by anyone but the author.

So this is a **positioning study, not a market-share study.** Nobody has
competed with this tool yet because nobody has received it.

---

## 1. The competitor set

### Tier 0 — already on the machine

The default competitor is not a project, it is `/usr/bin`.

| | |
|---|---|
| `otool`, `nm`, `lipo`, `codesign` | Ship with macOS. macOS only. One question per invocation. No JSON. |
| `llvm-objdump`, `llvm-nm`, `llvm-readobj` | Ship with Xcode CLT, Homebrew LLVM **and every Linux distro**. `llvm-objdump --macho` is a documented flag ("Use Mach-O specific object file parser"). |

The `llvm-*` row matters and the README does not mention it. `TOWS.md` lists
"Linux/Windows against Mac binaries — `nm` and `otool` do not run off macOS at
all" as an *opportunity*. The observation is true and the conclusion is wrong:
LLVM fills that gap on the same machines, is free, is Apache-2.0-with LLVM
exceptions, and is often already installed. The real gap is narrower than
stated — it is not "cross-platform Mach-O reading", it is "cross-platform Mach-O
reading **with no toolchain to install**".

### Tier 1 — the "just use X" objection

| Project | Stars | Licence | Last push | What it costs you |
|---|---|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 80,325 | Apache-2.0 | 2026-09-30 | JDK 25 + ~2 GB install. But: "run in both user-interactive and **automated** modes", and PyGhidra now ships in the box |
| [radare2](https://github.com/radareorg/radare2) | 24,911 | NOASSERTION | 2026-10-02 | Steep learning curve, dated feel |
| [rizin](https://github.com/rizinorg/rizin) | 3,926 | LGPL-3.0 | 2026-10-01 | `rz-bin` has a `mach0` plugin *and* a `bin_xtr_fatmach0` extractor; JSON output |
| [LIEF](https://github.com/LIEF-project/LIEF) | 5,579 | Apache-2.0 | 2026-09-28 | Native library + bindings |
| [RetDec](https://github.com/avast/retdec) | 8,636 | MIT | 2026-05-26 | Retargetable decompiler, LLVM-based |

Ghidra is the answer this project will be handed, and it is a genuinely
reasonable answer: free, no licence server, headless, Python-scriptable. The
README's response — "these tools are built to hand work *to* one, not to replace
one" — is the right response. It is also, on its own, an argument that the tool
is a *pre-step to Ghidra*, which is a small market.

### Tier 2 — complete Mach-O parsers (libraries, not tools)

| Project | Stars | Language | Last push |
|---|---|---|---|
| [p-x9/MachOKit](https://github.com/p-x9/MachOKit) | 278 | Swift | 2026-10-02 |
| [blacktop/go-macho](https://github.com/blacktop/go-macho) | 258 | Go | 2026-09-27 |
| [pstirparo/machofile](https://github.com/pstirparo/machofile) | 99 | Python | 2026-02-10 |
| Go stdlib `debug/macho` | — (golang/go: 139,123) | Go | stdlib, ships with the toolchain |

`debug/macho` deserves attention because it is the sharpest form of the "why
not just…" objection: it is a **complete, correct, zero-dependency Mach-O
parser that ships inside the Go toolchain**, in every language's opinion the
right way to do this. It is not cross-*toolchain* free — you need Go — but for
a Go shop it is the zero-cost answer, and it parses strictly more than this
project does.

MachOKit and machofile are correctly characterised in the README. Both are
genuinely smaller in reach than this project.

### Tier 3 — the Mach-O specialist CLI. **This is the one that matters.**

| Project | Stars | Licence | Last push | Commits |
|---|---|---|---|---|
| [blacktop/ipsw](https://github.com/blacktop/ipsw) | **3,769** | MIT | **2026-10-02** | 6,173 |

`ipsw` is absent from the README's comparison table, from `TOWS.md`, and from
every strategic claim in the project. It is the closest competitor and it is a
**strict superset**. From its own README:

| Capability | `ipsw` |
|---|---|
| Describe a binary | `ipsw macho info /path/to/binary --arch arm64e` |
| Symbol / import search | `ipsw macho search /path/to/binaries --import 'CCCrypt'` — **across a directory of binaries** |
| Disassembly | `ipsw macho disass /path/to/binary --symbol _main` |
| Xrefs | `ipsw dyld` — "find symbols and cross-references" |
| JSON | "Commands that support `--json` document it in their help" |
| Programmatic access | `ipswd` daemon with a **REST API** |
| macOS / Linux / Windows | Homebrew tap, **snap**, **scoop**, GitHub releases, goreleaser |
| ObjC / Swift / signing / entitlements / kernelcaches / dyld shared caches | all yes |
| AI-agent integration | ships **`ipsw-skill`** for Claude Code, Codex, Gemini |
| Licence | **MIT** (this project: LGPL-3.0) |

Every row of the README's "Reach for this when" list is a row `ipsw` wins on
volume, and every row of the "What it will not do" list is a row `ipsw` already
does. The single maintainer disadvantage is real but smaller than it looks:
eight years of momentum, a docs site, a Discord, DeepWiki indexing, sponsor
buttons, cross-platform packaging, and an agent skill.

### Tier 4 — the JS/npm niche this project actually lives in

| Package | Stars | Downloads/mo | Published | Licence |
|---|---|---|---|---|
| [`macho`](https://www.npmjs.com/package/macho) (indutny) | 27 | 31,061 | 2023-08 | **none declared** |
| [`fatmacho`](https://www.npmjs.com/package/fatmacho) (NowSecure) | 9 | 27,676 | 2019-08 | MIT |
| [`node-lief`](https://www.npmjs.com/package/node-lief) | 10 | 24,361 | 2026-07 | Apache-2.0 |
| [`macho-ts`](https://www.npmjs.com/package/macho-ts) | 1 | 710 | 2023-10 | MIT |
| [`macho-unsign`](https://www.npmjs.com/package/macho-unsign) | — | 19,395 | 2024-08 | MIT |
| [`libjsmacho`](https://github.com/ArmorixTeam/libjsmacho) | 2 | — | 2026-01 | — |
| [`@ebowwa/mcp-nm`](https://www.npmjs.com/package/@ebowwa/mcp-nm) | — | 58 | 2026-02 | — |
| **`MachO-Tools`** | **0** | **0** | **never** | LGPL-3.0 |

Two things to read here.

**The niche is real but shallow.** ~103,000 downloads/month flow through
adjacent Mach-O npm packages. Almost all of it is transitive — `fatmacho` via
React Native CLI, `macho` via tooling — not a user asking for Mach-O
introspection. Nobody is searching npm for this. That is a warning as much as
an opportunity: **the audience does not arrive looking, it has to be met.**

**The JS field is genuinely abandoned.** `indutny/macho` is 12 years old and
last published in 2023 with no licence. `fatmacho` is a fat-header-only parser
from 2019. `macho-ts` has 710 monthly downloads and one star. `MachO-Tools` is
the most capable *and* the most recently maintained Mach-O reader in
JavaScript — and it is also the only one with a test suite, an importable API,
man pages, and a mutation gate. On the merits of the artefact, it wins its own
niche. It has simply never been in a position to be chosen.

### Tier 5 — commercial

| | |
|---|---|
| **Hopper** | macOS-native disassembler/decompiler. Python scripting, LLDB/GDB debugger, ObjC + Swift demangling, and — new — an **integrated MCP server**. Also an **Extensible SDK for writing custom file-format parsers**. |
| **Binary Ninja 6.0** | C++/Python/Rust APIs inside and outside the UI, cooperative multi-user, and **MCP** in the 6.0 headline. |

---

## 2. Competitive claims in the docs that do not survive contact

These are the specific statements that a competitor or a reviewer will check,
and which currently fail.

| Claim | Where | Reality |
|---|---|---|
| "A query interface is the gap readers have. MachOKit and machofile parse far more; neither lets you *ask*." | `TOWS.md` Opportunities | `ipsw macho` is a query interface with `--json` and a REST daemon. `rizin`'s `rz-bin` has JSON. Ghidra is "automated modes". |
| The five-way comparison table | `README.md` | Omits `ipsw` (3.8k★), `llvm-objdump`, Go `debug/macho`, `rizin`, and `capa` (6,209★ — byte-level triage with JSON, the closest thing to `findliteral` at scale). |
| "`nm` and `otool` do not run off macOS at all" → cross-platform is the opportunity | `TOWS.md` | True but incomplete. LLVM, `ipsw`, and `rizin` all run everywhere. The defensible gap is *no toolchain*, not *no macOS*. |
| "AI and automated analysis — `--json` on every tool and an importable API is shaped for pipeline use" | `TOWS.md` Opportunities | Hopper ships an MCP server. Binary Ninja 6.0 ships MCP. `ipsw` ships an agent skill for Claude Code/Codex/Gemini. `@ebowwa/mcp-nm` exists on npm. The angle is now table stakes, not differentiation. |
| "Publishable as configured — nothing blocking an `npm publish`" | `TOWS.md` Strengths | **Wrong in the way that mattered.** The manifest was complete; the *name* was not. npm refuses a capital letter in a name published for the first time, so `MachO-Tools` could never ship — and `npm publish --dry-run` printed `+ MachO-Tools@0.1.0` and exited 0, so the command that looks like the check reported success. Corrected to `macho-tools`, with `test/publish.mjs` asserting it. |
| "202 passed, 1 skipped" | `README.md` | The suite now reports **213 passed, 1 skipped**. |
| "The reader is portable buffer arithmetic, and `nm` and `otool` do not run off macOS at all" | `README.md` | Accurate, and the strongest true claim in the document. It just needs to name what it is competing *against* — which is not `nm`. |

---

## 3. Where the moat genuinely is

Four defensible things, in descending order of how hard they are to copy.

**1. Zero *runtime* footprint — not "few dependencies", none.**
`src/macho.mjs` imports `node:fs` and nothing else. No Go toolchain, no Python
interpreter, no native library, no LLVM install, no build step. Every competitor
in Tiers 1–5 requires at least one of: a ~40 MB Go binary, a JVM, a Python
environment, a native extension, or an Apple SDK. `node-lief` at 24k
downloads/month is the sharpest illustration — it is the *same audience* choosing
to take a native dependency rather than write the parser.

**2. Auditable in one file, by reading it.**
This is the real moat and it is not about features. `ipsw` is 6,173 commits of
Go you will not read. Ghidra is a research institution. LIEF is a C++ library
with bindings. MachO-Tools is one file a security reviewer can verify end to
end, in an afternoon, with no build. For the buyer who wants to *vendor* a
parser into a product they are legally responsible for — the actual buyer for a
game studio, given the provenance in `README.md` §Provenance — that is worth
more than any row in the comparison table. It is also, notably, the one
property the project has never once claimed in its own marketing.

**3. An honest machine contract.**
Four exit codes distinguishing *found something* / *found nothing* / *usage error*
/ *could not look*. One JSON envelope on every tool. Addresses as `"0x…"`
strings because a 64-bit vaddr does not survive a `Number`. Negative answers as
values, not exceptions. No competitor does this. `ipsw` documents `--json`
per-command; Ghidra's output formats are per-script; `rz-bin` has its own.

**4. It is not an iOS-research tool.**
`ipsw`'s centre of gravity is firmware, dyld caches, kernelcaches and devices.
Ghidra's is general reverse engineering. MachO-Tools is generic Mach-O
introspection with no domain. For a team that wants to look at *their own*
shipping binaries and has no interest in firmware research, that neutrality is
the feature.

### And the honest weakness underneath all of them

**Every one of those four is a reason to choose it as a dependency. None of them
is a reason to prefer it as a tool.** The audience that picks a *tool* wants
answers; the audience that picks a *dependency* wants a guarantee. This project
has been built and documented entirely as the second, and competes for
attention as the first.

---

## 4. Structural losses

**`ipsw` is a strict superset with 3.8k stars and an MIT licence.** There is no
feature row where MachO-Tools wins and `ipsw` loses. The fight over features is
already over. The only fight available is on the axes in §3 — footprint,
auditability, contract honesty, neutrality — and those are not in the README.

**Licence friction is a real adoption tax, and it is separate from provenance.**
`TOWS.md` correctly identifies provenance/IP optics as the only
project-ending threat. It misses the mundane one: "copy one file into my repo"
is the exact use case, and LGPL-3.0's copy-on-modification is precisely what a
corporate reviewer will flag in review. `ipsw` is MIT. `retdec` is MIT. The
sibling packages in this workspace are MIT. Whatever the licensing rationale
was, it should be stated as a *choice* with a *reason*, the way
`README.md` §Provenance states its position — not left to be inferred.

**No dyld shared cache, no `.tbd`. On modern macOS the system libraries are not
on disk as Mach-O at all.** Verified on this machine:

```
$ ls /usr/lib/libSystem.B.dylib
ls: /usr/lib/libSystem.B.dylib: No such file or directory
```

Since Big Sur the real dylibs live inside
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` — on this box,
`aot_shared_cache.0` alone is 880 MB. So `macho-findliteral /usr/lib/libSystem.B.dylib`
cannot work, and neither can `nm` or `otool`. `ipsw dyld` is an entire product
surface built for exactly this, and the README's Limits section does not
mention it. This is a **new** competitive dimension that did not exist when the
tool was designed and that is closing.

**One maintainer, no institutional home** — `TOWS.md` already names this as the
most likely failure mode and is right.

---

## 5. Defects found while studying

Both are small. Both are in the product's *core differentiator* — honest error
semantics — which is why they are worth naming.

**5.1 The JSON contract cannot distinguish "missing file" from "wrong format".**
The README promises machine-readable reason codes — `no-call-sites`,
`no-symbols`, `unknown-encoding`, `io` — and states that "a caller that cannot
tell *found nothing* from *could not look* has the problem this project keeps
fixing." Verified:

```
$ node src/describe.mjs --json /nope          $ node src/describe.mjs --json /etc/hosts
"errors": ["io"]                             "errors": ["io"]
"messages": ["/nope: not a Mach-O binary"]    "messages": ["/etc/hosts: not a Mach-O binary"]
```

Byte-identical apart from the path. A directory (`/tmp`) produces the same. The
exit code 3 is the right *category*, so the four-code contract holds — but
`unknown-encoding` is never emitted for an unparseable file, and `io` is emitted
for a format problem. A machine consumer — precisely the audience the envelope
exists for — gets one bit where the documentation promises two.

**5.2 Three unrelated conditions are reported as one.**
Missing file, non-Mach-O file, and directory all print `not a Mach-O binary`.
"This path does not exist" is a different, more actionable message than "these
bytes are not Mach-O", and conflating them is the human-facing version of 5.1.

---

## 6. What to do, in order

1. **Publish to npm.** Nothing else on this list matters until someone can
   `npm install -g macho-tools`. The blocker was the name, not the manifest: npm
   refuses a capital letter in a name published for the first time, so
   `MachO-Tools` could never have shipped — and `npm publish --dry-run` reported
   success on it anyway. Fixed to `macho-tools` on 2026-10-03, with
   `test/publish.mjs` now asserting it in CI, since a dry run cannot. Then cut a
   release, and `brew` if the man pages are real.

2. **Add the missing names to the comparison table**, and put `ipsw` in it
   honestly as the superset it is. A table that names the strongest competitor
   and explains why you still want this one is the single highest-credibility
   asset available, and it is the opposite of what the current table does.
   `ipsw`, `llvm-objdump`, Go `debug/macho`, `rizin`, `capa`.

3. **Lead with auditability, not with features.** §3.2 is the only genuinely
   uncopyable property in the project and it appears nowhere in the README.
   There is already a verified demonstration of it (`TOWS.md` S3 — `macho.mjs`
   copied alone into an empty directory, used to parse real binaries with no
   `node_modules` and no `package.json` present). That demo *is* the
   differentiation. Publish it.

4. **Fix 5.1 and 5.2.** Emit `unknown-encoding` for an unparseable file and
   reserve `io` for I/O failure; distinguish missing-file from wrong-format in
   the human message. Small change, and it is the claim the whole JSON envelope
   exists to support.

5. **Correct the stale count** (202 → 213) and the "publishable" framing in
   `TOWS.md`.

6. **Decide and state the licence.** If LGPL-3.0 is right for the vendoring
   story this project is built around, say why in the README. If it is
   inherited rather than chosen, it is currently costing adoption for no
   benefit.

7. **Treat `.tbd` and dyld shared caches as a competitive clock, not a feature
   request.** They are out of scope by the project's own stated test — and that
   test is correct — but they are also the reason a macOS-adjacent user reaches
   for `ipsw` instead of this. Worth knowing which side of that line you are on.

8. **Do not build a disassembler, and do not build an MCP server to lead with.**
   The first is already the project's stated decision and remains correct. The
   second would be chasing a slot Hopper, Binary Ninja and `ipsw` occupy with
   far more capability behind it.

---

## Appendix — how to re-verify this

```sh
# competitive set
gh api repos/blacktop/ipsw            --jq '{stars:.stargazers_count,pushed:.pushed_at,license:.license.spdx_id}'
gh api repos/p-x9/MachOKit           --jq '{stars:.stargazers_count,pushed:.pushed_at}'
gh api repos/pstirparo/machofile     --jq '{stars:.stargazers_count,pushed:.pushed_at}'
gh api repos/NationalSecurityAgency/ghidra --jq .stargazers_count
gh api repos/rizinorg/rizin          --jq .stargazers_count
gh api repos/mandiant/capa           --jq .stargazers_count

# the project itself
gh api repos/ranjithrajv/MachO-Tools --jq '{stars:.stargazers_count,created:.created_at}'
npm view macho-tools version          # E404 as of 2026-10-03 — valid name, not yet published

# npm demand in the niche
npm view macho      # 31,061 downloads/mo
npm view fatmacho   # 27,676
npm view node-lief  # 24,361

# defects 5.1 and 5.2
node src/describe.mjs --json /nope
node src/describe.mjs --json /etc/hosts
node src/describe.mjs --json /tmp

# the modern-macOS dyld problem
ls /usr/lib/libSystem.B.dylib         # No such file or directory
ls -la /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/
```
