# TOWS analysis — `macho-tools`

A strategic view of the project, derived from what the code and test suite
actually do today rather than from an aspirational description. Every claim
below is checkable against the repository, and the numbers were re-derived by
running the suites on 2026-10-02.

TOWS is SWOT with the action step: the four factor lists are the inputs, and the
matrix is the output — pairing each internal factor with each external one to
generate a strategy, rather than leaving four disconnected lists that tell you
nothing about what to do on Monday.

## Corrections to the previous version

This document previously contradicted the tree on six points. All are fixed
below, and each is worth naming because the stale version was more confident
than it was correct.

| Stale claim | Reality |
|---|---|
| MIT, no CLA | **LGPL-3.0-or-later** (`package.json`, `README.md` §Licence). The three *sibling* packages are MIT; this one deliberately is not. |
| "Two tests do not bite"; of four mutations two were inconclusive | **7 mutations, 7 caught.** The three harness defects were fixed. |
| "62 checks" over five system binaries including Ollama | **202 checks.** The corpus is 7 generated fixtures plus 5 system-binary *candidates* (`/usr/bin/true`, `/usr/bin/ssh`, `/bin/ls`, a Go toolchain, ffmpeg), of which whichever exist are used. Ollama is still referenced, but as an optional **`.app` bundle** probe, not a binary. |
| "Not publishable as configured": `private: true`, no `repository`/`author` | Metadata is complete — repository, bugs, homepage, author, `exports`, `types`, `files`. No `private`. |
| "macOS only" | **Verified on macOS and Linux**; Windows exercises the fixtures half only. |
| "Publish provenance deliberately — every claim in `NOTICE.md`" | **Resolved as a `README.md` §Provenance, not a `NOTICE.md`, and the reason is now written down rather than left as a mismatch against three siblings.** The correction holds: there is still no `NOTICE.md` here. What changed is that this is now a decision with a stated rationale instead of an unclaimed gap — see S5. |

### Corrections, second pass

Recorded rather than quietly deleted, because a strategic document that is only
ever right about the present is indistinguishable from one that was never
checked.

**The "No CI" weakness was false, and it had inverted the agenda.** The
workflow exists and passes. §Reading named `W1` as *the agenda* on the premise
that "everything strategic is gated on the suite running unattended" — sound
reasoning aimed at a premise that was not true. The suite does run unattended.
What remained was the half of `W1` that had not landed, which is now in.

**The document also contradicted itself on the corpus size** — "5 system-binary
candidates" in the corrections table and "4 system binaries" in Strengths, two
sections apart. There are five candidates; how many are *used* is machine-
dependent, which is itself the point of `W3`.

**Two real defects surfaced while implementing `W1`, both in the verification
path rather than in the readers** — which is where the risk actually was:

1. *The shipped-file list was hardcoded.* The boundary check guarded "no
   application is named in what the package ships" using a literal three-file
   list, while `files` shipped nine entries. It was scanning **16 files where 31
   ship** — including all six man pages, both completion sets and `COPYING`. This
   is the project's central claim, and the check guarding it had quietly stopped
   matching, which is the precise failure it exists to prevent. Found while
   shipping the fixture corpus, because that change made the drift visible.
2. *A symlinked invocation ran nothing and exited 0.* Making the generator
   importable introduced an `import.meta.url` entry-point guard. npm installs a
   local dependency as a symlink, and Node resolves `import.meta.url` while
   `argv[1]` still holds the linked path — so the guard concluded "imported",
   the work never ran, and `--check` on a **drifted corpus passed without reading
   a byte**. Fixed by realpathing both sides; verified to exit 1 on drift through
   a symlink, and verified that a genuine import is still silent.

Both are the same shape as the three the README already records. That is four
distinct routes to a confident green, and the reason the rule is stated as a rule
rather than as a habit: **a verification that cannot fail is worse than a missing
one, because it reports success.**

The old document also recommended DWARF as the single highest-value next step.
That contradicts this project's stated strategy — see `W-note` in the matrix.

---

## Inputs

### Strengths — internal, helpful

| | Evidence |
|---|---|
| **Zero dependencies, zero build step** | Node builtins only; `npm test` works on a clean clone with no install. `.gitignore` goes further and treats a `node_modules/` directory as a bug. |
| **No product knowledge** | No game, publisher, save file or proprietary format in `src/` or `test/`. Now **enforced**, not merely verified — see W5. The only product-adjacent string is `LZ4`, used as an illustrative needle in the `findliteral` usage text and the same way in a test — a generic compression library, not a product fact. |
| **One reader, not seven** | `src/macho.mjs` owns fat headers, load commands, `LC_SYMTAB` and sections. Duplication was the root cause of a real defect: `mapliteral` hardcoded `cputype === 0x01000007` and threw on any Apple-silicon-native build. |
| **Two corpora with opposite assertion policies** | 7 generated fixtures (39,568 bytes, built by `test/fixtures.mjs`, asserted with *exact* counts and addresses) plus 4 system binaries (asserted against *invariants* only, pinning no counts because they move with a compiler release). This is the fix for "every verdict depended on what happened to be installed". |
| **Mutation testing, and it bites** | `test/mutation-check.mjs` reintroduces each historical defect into a copy of the tree. Latest run: **7 mutations, 7 caught.** Six of the seven are detected by the fixture generator's own self-check, independent of `smoke.mjs`. An *inconclusive* mutation now fails the run — a stale anchor previously exited 0 and shrank the count in silence. |
| **The suite verifies its own coverage** | It asserts that both architectures were exercised, that a symbol-less and a populated binary were both tested, and that every input shape a known defect needs was present. A test that silently skips half the input space and reports success is worse than no test. |
| **Both architectures decoded** | x86_64 `rel32` and arm64 `BL`, with an explicit `unsupported` list rather than a silent zero. |
| **Typed call scanning** | Code-sections-only by default, `--include-data` to widen, and `decoy.macho` plants a decoy call in data specifically so the filter is proven rather than asserted. |
| **A real public surface** | Every tool takes `--json`; `src/api.mjs` is importable; `api.d.ts` is hand-written and deliberately *narrower* than the implementation, because inferred types describe what the code happens to do rather than what it promises. Addresses are `bigint` end to end. |
| **Honest about itself** | A table of its own seven historical bugs, a comparison table against five named alternatives, and a Limits section that states the gaps rather than leaving them to be discovered. |
| **Publishable as configured** | Complete manifest metadata; nothing blocking an `npm publish`. |
| **Installable, not just vendorable** | Six man pages and shell completions for bash and zsh, all in `files`. `man macho-sym` works after `npm i -g`. |

### Weaknesses — internal, harmful

| | Evidence |
|---|---|
| ~~**No CI, and not in the existing local gate**~~ — **both false, and the CI half was the load-bearing error** | **There is CI.** `.github/workflows/test.yml` is three jobs: `fixtures --check` on ubuntu, `test` on a **macos/ubuntu/windows** matrix, `mutation` on ubuntu. This weakness was stated as fact, and §Reading built the whole agenda on it — which is how a document ends up confident and wrong about the thing it exists to assess. Corrected below. |
| **The local gate omitted this package** — **LANDED** | `.githooks/pre-commit` now runs `fixtures.mjs --check` (~0.1s) and `smoke.mjs` (~4s), with the mutation check deliberately excluded at ~2m and CI named as its home. Verified to *block* on a hand-edited fixture and on a failing suite, not merely to run. |
| **Indirect calls are invisible** | Register calls, jumps through a PLT stub, and any indirect call do not encode their target. Largest gap against Ghidra/IDA. |
| **No dSYM / DWARF** | 2 of 6 tools go blind on a stripped binary, and a shipped build whose symbols live in a sidecar is out of reach entirely. |
| **No disassembly, no load-command dump, no fixups/export trie/ObjC-Swift metadata** | Deliberate, and documented as deliberate — see `W-note` and `W8`. Now also stated as a **decision** in the README ("What this will not do") rather than only as a gap in a table. |
| **arm64 scan steps 4 bytes at a time** | Sees aligned `BL`s only; an instruction at an unaligned address is missed. |
| **No `NOTICE.md`** — **partly addressed** | The three sibling packages each carry one. Still no standalone `NOTICE.md` here, which is the right shape: this package redistributes nothing derived from the product, so there is no asset list to publish. What it needed instead was a statement of *position*, and `README.md` §Provenance now carries one — origin, what does not ship, and that the licence does not extend to the publisher's IP. A sibling `NOTICE.md` would be a shorter restatement of that. |
| **An absent corpus member is silent** | `smoke.mjs` prints every skipped *check* loudly (`N skipped: ...` / "a skip means the input was unavailable"), and its coverage receipt asserts the generated corpus is complete. But `discover()` drops an absent *system binary* from the candidate list without a word, so "202 passed" and "150 passed, no ffmpeg on this box" differ only in the number. The check-level honesty is in place; the corpus-level half is not. |
| **The shipped-file list was hardcoded — LANDED** | The boundary check's "in what the package ships" group was a literal three-file list while `files` also carried `man/`, `completions/`, `LICENSE` and `COPYING`: **16 files scanned where 31 ship.** Now derived from `package.json`'s own `files`, with a check that the derivation succeeded. Found while shipping the fixture corpus, which is the sort of change that finds it. |
| **A symlinked invocation ran nothing and exited 0 — LANDED** | The `import.meta.url` guard added to make the generator importable compared `argv[1]` to a path Node had already realpath-resolved. npm links a local dependency, so through a symlink `--check` on a **drifted corpus passed without looking at anything**. Fixed by realpathing both sides; verified to exit 1 on drift via symlink and still silent on a real import. The fourth confident-green in this project's history — see *Corrections, second pass*. |
| **Bundle ergonomics are macOS-shaped** | `bundle.mjs` assumes `.app` / `Contents/MacOS`. Fine — that is the target — but the cross-platform story is thinner than the tests suggest. |

### Opportunities — external, helpful

| | |
|---|---|
| **Stable format, thin tooling** | Mach-O has barely changed in 30 years. `otool`/`nm` ship in the box but need `lipo` first, emit no JSON, and answer one question per invocation. |
| **A query interface is the gap readers have** | MachOKit and machofile parse far more; neither lets you *ask*. This project's one differentiator. |
| **Linux/Windows against Mac binaries** | `nm` and `otool` do not run off macOS at all. CI and server-side triage are unserved by the in-box tools. |
| **Large universal binaries** | `nm` on a 476 MB universal binary takes minutes; this reads the symbol table directly. |
| **The fixture generator is independently useful** | A deterministic, in-repo Mach-O corpus with known answers is a contribution to *other* projects' parser tests, not just to this one. |
| **Security and malware triage** | Incident response wants byte-level facts, not a GUI, and the README already names `machofile`'s malware-analysis lineage. |
| **The bug table is publishable on its own** | "Seven ways to read a fat binary wrong" stands as a write-up regardless of which toolkit reads them. |
| **AI and automated analysis** | A dependency-free parser with `--json` on every tool and an importable API is shaped for pipeline use. |

### Threats — external, harmful

| | |
|---|---|
| **Provenance and IP optics** | Extracted from reverse-engineering a commercial product. The code is clean of it; the lineage is knowable. **LGPL does not license the publisher's IP.** This is the only threat that can end the project. |
| **The workspace's provenance apparatus does not cover this package** — **partly addressed** | The sibling projects exclude key material by four enforced boundaries — gitignored, `prepack`-excluded, `NEVER_VENDOR`, and untracked-stripped-from-history — with a secret-scan and a pre-push hook. **Much of that machinery does not apply here, and saying so is stronger than copying it:** this package has no decoder, reads no key file, writes no derived data, and has nothing to exclude. What it needed was a claim it could *prove*, and W5 is that — the no-product-knowledge boundary is now a test, not a review habit. The position is stated in `README.md` §Provenance. The root `LICENSE` no longer implies the MIT grant reaches this directory. |
| **Better-funded incumbents** | Ghidra is free with no licence server, which removes the usual objection to it. Hopper, Binary Ninja, LIEF, MachOKit. |
| **Abandonment** | One maintainer, no institutional home. The most likely way this ends is by not being continued. |
| **Silent rot against toolchain releases** | The invariant-only policy for system binaries is *correct* and also means nothing forces an update. **Mostly retired:** CI runs the `fixtures --check` job, which re-derives all 39,568 bytes of the corpus, so a toolchain change that alters the readers fails the run rather than passing quietly. |
| **No discoverability** | **Partly addressed:** a CI badge is now in the README. Still no docs site, and six flat binaries. |
| **Conflation with the sibling `tools/` package** | The workspace-level "no product knowledge" guarantee is true of this package in isolation and easy to overstate. |

---

## The TOWS matrix

|  | **Opportunities** | **Threats** |
|---|---|---|
| **Strengths** | **SO — build** | **ST — defend** |
| Two corpora, 202 checks, 7/7 mutations | **S1. LANDED.** The verification claim is now the README's second section, above "when to use this": a `git clone` and three commands, with each number labelled by *what kind of evidence it is* — corpus integrity, working on unknown binaries, and tests that would notice. Wall-clock timings are given as approximate on purpose, because they are machine-dependent and a suite that pins them fails for the wrong reason. A CI badge sits above it. | **S5. LANDED, in the shape this package needs.** No `NOTICE.md`: there is no derived asset to publish here, so the sibling's shape does not fit. `README.md` §Provenance instead states origin, what does not ship (nothing — and now *enforced*, see W5), and that LGPL does not license the publisher's IP. The root `LICENSE` says the same, so neither reader is misled about which grant applies. |
| One tested reader, no product knowledge | **S2. LANDED.** `test/fixtures.mjs` is now `MachO-Tools/fixtures`, exporting `buildFixtures({ out, check })`, with `test/fixtures.mjs` and the six `.macho` files added to `files`. Verified from a real `npm install`: the subpath resolves, the corpus builds into a consumer's directory, all six read back cleanly through the consumer's own reader, and `--check` still guards a shipped corpus. Importing has no side effects, which is why `main` sits behind an entry-point guard — see the symlink defect in *Corrections, second pass*. | **S6. Let the in-tree corpus be the rot detector.** Fixtures pin exact answers, so a toolchain change cannot silently break the parsers. A green `npm run test:all` from a clean clone is a complete rot check with no setup. |
| Zero dependencies; LGPL | **S3. LANDED.** "One file, no supply chain" is now a README subsection under the library docs, with the claim *verified rather than asserted*: `src/macho.mjs` was copied alone into an empty directory and used to parse `/usr/bin/ssh` and a fixture fat binary with no `node_modules` and no `package.json` present. `src/macho.mjs` + `src/api.mjs` is the entire importable surface, and that is stated rather than left to be discovered. | **S7. Keep the bug table and the comparison table as the credibility surface.** Seven documented failure modes and five named alternatives with honest `no` rows are a moat against "just use Ghidra". |
| `--json` everywhere; importable API | **S4. Make the JSON/API surface the front door for automated analysis.** Composable answers beat a terminal, and this is the differentiator no in-box tool has. | **S8. Freeze rather than rot.** The fixture suite means an archived repo can still demonstrate a working, verified state. |
| | | |
| **Weaknesses** | **WO — fix** | **WT — contain** |
| No CI, not in the existing gate — **both LANDED** | **W1. LANDED, both halves.** (a) `.githooks/pre-commit` runs `fixtures.mjs --check` then `smoke.mjs`, with the mutation check excluded at ~2m and CI named as its home; verified to *block* on a hand-edited fixture and on a failing suite. (b) The remote runner arrived first and went further than asked: `.github/workflows/test.yml`, three jobs, macOS + Linux + **Windows**. | **W5. Enforce the format-only boundary in the gate, not by intent — LANDED.** Now four `boundary:` checks in `smoke.mjs`, so it runs in `npm test` and on all three CI platforms rather than only on local commits. Scope is `src/`, `test/` and what `files` ships; `TOWS.md` is deliberately excluded, because the provenance assessment has to name what it assesses to be worth anything. Two ways it could have been a check that passes on nothing were found and closed while writing it — a denylist whose patterns go dead, and a walker that silently skipped top-level files because `readdirSync` throws `ENOTDIR` on them. Hence the positive control and the printed file count per group. |
| Overlapping tools; no man pages — **done** | **W2. LANDED.** `symgrep`/`symfind` merged into one `macho-sym` with `--regex` / `--all-imp` / `--no-dedupe`, on a single `searchSymbols` primitive; six man pages and shell completions for bash and zsh now ship in `files`. The old names were removed, not aliased. | **W6. Pin the mutation gate in CI — and treat an inconclusive mutation as a failure.** An inconclusive mutation used to exit 0, so a stale anchor silently reduced the mutation count while the run still printed "none surviving". That is the same confident-green failure the README records twice already, reached a third way. A surviving mutation is the single most informative signal this project can emit; so is a gate that stopped running. |
| Absent corpus member is silent | **W3. Name the absent system binaries.** Skipped *checks* are already reported honestly; an absent *target* is not. Printing which candidates were missing turns a machine-dependent count into a self-describing one. | **W7. Keep Limits above the fold.** The README already does this well; a reviewer reads the top of the file and nothing below it. |
| | | **W8. LANDED, as a decision rather than a gap.** `README.md` now carries **What this will not do**, between the comparison table and Use cases: disassembly, indirect/PLT resolution, dSYM/DWARF, ObjC/Swift metadata, ELF/PE, code signing and fixups — each with the reason, and a stated test for anything that would join the list. The test is not "is it hard"; indirect resolution is genuinely hard, which is why it stays out. The test is whether closing the gap would make the package *worse at the thing it is for*. DWARF is called out by name as a strategy change disguised as a feature. |

> **W-note — a deliberate reversal from the previous version.** That document
> named DWARF as the single highest-value next step. This one does not, because
> the project's own stated position contradicts it: `README.md` frames
> disassembly, DWARF/dSYM, Objective-C/Swift metadata and code signing as *four
> deliberate gaps* — "the ones where a general parser or a disassembler is
> strictly better, and closing them here would mean becoming one of those
> projects instead of this one". Adding DWARF is a strategy change disguised as
> a feature, and it should be argued for as one. The gaps that *are* worth
> closing — CI, tool consolidation, installation — are the ones that make this
> the thing it intends to be.

---

## Reading the matrix

The four SO/WO cells are the agenda, and most of it has now landed. What
remains is smaller than the matrix suggests.

**`W1` is closed, and closing it moved the agenda rather than ending it.** The
suite now runs in CI on three operating systems *and* in the local pre-commit
gate. Both halves were needed: CI covers what is pushed, the hook covers the
local loop, which is where a stale fixture actually gets committed from. The
verification claims in the README are now true in the sense that matters — they
are reproducible by someone who has never met the author.

**The most valuable outcomes were not in the matrix.** Shipping the fixture
corpus (S2) exposed a hardcoded shipped-file list that was scanning 16 files
where 31 ship, and making the generator importable introduced a symlink path
where `--check` passed on a drifted corpus without reading it. Neither was a
known weakness; both were found by *doing* the matrix items, and both are now
closed. That is the argument for working the list rather than re-reading it.

**`S5` remains the most important item, and it is not engineering.** The
project's only existential risk is how its origin is perceived, and the risk is
lower than it looks given how clean the tree is — and materially higher if the
disclosure stays implicit. The workspace solved this three times for its sibling
packages. `README.md` §Provenance is the right shape for this one; a standalone
`NOTICE.md` would be a shorter restatement of it.

**`S2` was an opportunity nobody had claimed, and it is now shipped.** The
fixture corpus is a better contribution than another CLI would have been. It is
what makes the seven defects reproducible, it is now importable by another
project, and it is the artefact a different project would want to borrow.