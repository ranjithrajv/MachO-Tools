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
| "62 checks" over five system binaries including Ollama | **182 checks.** The corpus is 6 generated fixtures plus 5 system-binary *candidates* (`/usr/bin/true`, `/usr/bin/ssh`, `/bin/ls`, a Go toolchain, ffmpeg), of which whichever exist are used. Ollama is still referenced, but as an optional **`.app` bundle** probe, not a binary. |
| "Not publishable as configured": `private: true`, no `repository`/`author` | Metadata is complete — repository, bugs, homepage, author, `exports`, `types`, `files`. No `private`. |
| "macOS only" | **Verified on macOS and Linux**; Windows exercises the fixtures half only. |
| "Publish provenance deliberately — every claim in `NOTICE.md`" | **macho-tools has no `NOTICE.md`.** Its three siblings all do. This is now a live gap, not a pending task. |

The old document also recommended DWARF as the single highest-value next step.
That contradicts this project's stated strategy — see `W-note` in the matrix.

---

## Inputs

### Strengths — internal, helpful

| | Evidence |
|---|---|
| **Zero dependencies, zero build step** | Node builtins only; `npm test` works on a clean clone with no install. `.gitignore` goes further and treats a `node_modules/` directory as a bug. |
| **No product knowledge** | No game, publisher, save file or proprietary format in `src/` or `test/`. Verified by scan. The only product-adjacent string is `LZ4`, used as an illustrative needle in the `findliteral` usage text and the same way in a test — a generic compression library, not a product fact. |
| **One reader, not seven** | `src/macho.mjs` owns fat headers, load commands, `LC_SYMTAB` and sections. Duplication was the root cause of a real defect: `mapliteral` hardcoded `cputype === 0x01000007` and threw on any Apple-silicon-native build. |
| **Two corpora with opposite assertion policies** | 6 generated fixtures (37,329 bytes, built by `test/fixtures.mjs`, asserted with *exact* counts and addresses) plus 4 system binaries (asserted against *invariants* only, pinning no counts because they move with a compiler release). This is the fix for "every verdict depended on what happened to be installed". |
| **Mutation testing, and it bites** | `test/mutation-check.mjs` reintroduces each historical defect into a copy of the tree. Latest run: **7 mutations, 7 caught.** Six of the seven are detected by the fixture generator's own self-check, independent of `smoke.mjs`. |
| **The suite verifies its own coverage** | It asserts that both architectures were exercised, that a symbol-less and a populated binary were both tested, and that every input shape a known defect needs was present. A test that silently skips half the input space and reports success is worse than no test. |
| **Both architectures decoded** | x86_64 `rel32` and arm64 `BL`, with an explicit `unsupported` list rather than a silent zero. |
| **Typed call scanning** | Code-sections-only by default, `--include-data` to widen, and `decoy.macho` plants a decoy call in data specifically so the filter is proven rather than asserted. |
| **A real public surface** | Every tool takes `--json`; `src/api.mjs` is importable; `api.d.ts` is hand-written and deliberately *narrower* than the implementation, because inferred types describe what the code happens to do rather than what it promises. Addresses are `bigint` end to end. |
| **Honest about itself** | A table of its own seven historical bugs, a comparison table against five named alternatives, and a Limits section that states the gaps rather than leaving them to be discovered. |
| **Publishable as configured** | Complete manifest metadata; nothing blocking an `npm publish`. |

### Weaknesses — internal, harmful

| | Evidence |
|---|---|
| **No CI, and not in the existing local gate** | 182 checks and a 7-mutation run exist and nothing runs them unattended. The workspace *already* has a versioned pre-commit gate (`.githooks/`) that runs two sibling suites plus a secret scan, and a pre-push hook running the full scan — macho-tools is simply absent from a gate that already exists. There is no remote runner at all. |
| **Indirect calls are invisible** | Register calls, jumps through a PLT stub, and any indirect call do not encode their target. Largest gap against Ghidra/IDA. |
| **No dSYM / DWARF** | 3 of 7 tools go blind on a stripped binary, and a shipped build whose symbols live in a sidecar is out of reach entirely. |
| **No disassembly, no load-command dump, no fixups/export trie/ObjC-Swift metadata** | Deliberate, and documented as deliberate — see `W-note`. |
| **arm64 scan steps 4 bytes at a time** | Sees aligned `BL`s only; an instruction at an unaligned address is missed. |
| **No `NOTICE.md`** | The three sibling packages each carry one; this is the only project in the workspace without one, and it is the one with the most to disclose. |
| **Two overlapping tools** | `symgrep` (regex) and `symfind` (substring) are near-duplicates with different ergonomics. 7 bins overstates the surface. |
| **Not installable as a CLI** | No man pages, no shell completions; `files` ships only `README.md`. Usable by vendoring, weak as a `brew`/`npm i -g` experience. |
| **An absent corpus member is silent** | `smoke.mjs` prints every skipped *check* loudly (`N skipped: ...` / "a skip means the input was unavailable"), and its coverage receipt asserts the generated corpus is complete. But `discover()` drops an absent *system binary* from the candidate list without a word, so "182 passed" and "150 passed, no ffmpeg on this box" differ only in the number. The check-level honesty is in place; the corpus-level half is not. |
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
| **Provenance and IP optics** | Extracted from reverse-engineering a commercial product. The code is clean of it; the lineage is knowable. **LGPL does not license Playrix IP.** This is the only threat that can end the project. |
| **The workspace's provenance apparatus does not cover this package** | The sibling projects exclude key material by four enforced boundaries — gitignored, `prepack`-excluded, `NEVER_VENDOR`, and untracked-stripped-from-history — with a secret-scan and a pre-push hook. macho-tools has none of that machinery and no NOTICE to state the position. |
| **Better-funded incumbents** | Ghidra is free with no licence server, which removes the usual objection to it. Hopper, Binary Ninja, LIEF, MachOKit. |
| **Abandonment** | One maintainer, no institutional home. The most likely way this ends is by not being continued. |
| **Silent rot against toolchain releases** | The invariant-only policy for system binaries is *correct* and also means nothing forces an update. With no CI, no signal ever arrives. |
| **No discoverability** | No CI badge, no docs site, seven flat binaries with thin help text. |
| **Conflation with the sibling `tools/` package** | The workspace-level "no product knowledge" guarantee is true of this package in isolation and easy to overstate. |

---

## The TOWS matrix

|  | **Opportunities** | **Threats** |
|---|---|---|
| **Strengths** | **SO — build** | **ST — defend** |
| Two corpora, 182 checks, 7/7 mutations | **S1. Publish the reader layer with a query interface, against `nm`/`otool`, referring to disassemblers rather than competing.** The launch asset is the comparison table plus a verification claim a reviewer can reproduce with `npm run test:all` — no key, no install, no game. | **S5. Write `NOTICE.md`, as the three siblings have.** State origin, state that no key material or product data ships, point at the repo's exclusion machinery. This is the highest-leverage defensive act available and it is currently missing. |
| One tested reader, no product knowledge | **S2. Ship the fixture generator as a first-class export.** A deterministic Mach-O corpus with known answers is what surfaced the slice-relative-offset bug, and other projects testing their own parsers need it more than this one does. | **S6. Let the in-tree corpus be the rot detector.** Fixtures pin exact answers, so a toolchain change cannot silently break the parsers. A green `npm run test:all` from a clean clone is a complete rot check with no setup. |
| Zero dependencies; LGPL | **S3. Lead with "vendor one file, no supply chain", and use LGPL deliberately.** It permits linking while keeping derived improvements open — the right posture for tooling that came from elsewhere, and a stronger claim than MIT would be here. | **S7. Keep the bug table and the comparison table as the credibility surface.** Seven documented failure modes and five named alternatives with honest `no` rows are a moat against "just use Ghidra". |
| `--json` everywhere; importable API | **S4. Make the JSON/API surface the front door for automated analysis.** Composable answers beat a terminal, and this is the differentiator no in-box tool has. | **S8. Freeze rather than rot.** The fixture suite means an archived repo can still demonstrate a working, verified state. |
| | | |
| **Weaknesses** | **WO — fix** | **WT — contain** |
| No CI, not in the existing gate | **W1. Two steps, in this order. (a) Add `macho-tools` to the existing `.githooks/pre-commit` suite loop — it already runs two sibling suites, so this is a two-line change with immediate value. (b) Then move that gate to a remote runner on macOS *and* Linux.** The suite needs no key, no install and no game, and its fixture half is deterministic, so it is already CI-ready. Everything else in this table is ergonomics. | **W5. Enforce the format-only boundary in the gate, not by intent.** One grep for product names across `src/` and `test/`. The property the project's entire reputation rests on is currently held by review discipline alone. |
| Overlapping tools; no man pages | **W2. Merge `symgrep`/`symfind` behind one binary with a mode, and add man pages and completions to `files`.** Six thin tools with thin help is a worse story than four good ones that install. | **W6. Pin the mutation gate in CI.** A surviving mutation is the single most informative signal this project can emit — it means a documented guarantee has quietly stopped being true. |
| Absent corpus member is silent | **W3. Name the absent system binaries.** Skipped *checks* are already reported honestly; an absent *target* is not. Printing which candidates were missing turns a machine-dependent count into a self-describing one. | **W7. Keep Limits above the fold.** The README already does this well; a reviewer reads the top of the file and nothing below it. |
| | | **W8. Do not chase ELF/PE or metadata breadth.** Incumbency is not answered by widening scope. |

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

The four SO/WO cells are the agenda. Three observations stand out.

**`W1` is the agenda.** Everything strategic is gated on the suite running
unattended. Right now 182 checks and a 7-mutation gate are a property of one
machine on one afternoon, which is not the same as a property of the project.

**`S5` is the most important item, and it is not engineering.** The project's
only existential risk remains how its origin is perceived, and the risk is
*lower* than it looks given how clean the tree is — and materially higher if the
disclosure stays implicit. The workspace already solved this problem three times
for its sibling packages. macho-tools is the one project that has not applied
the answer.

**`S2` is an opportunity nobody has claimed yet.** The fixture corpus is a
better contribution than another CLI would be. It is what makes the seven
defects reproducible, and it is the artefact a different project would want to
borrow.