# TOWS analysis — `macho-tools`

A strategic view of the project, derived from what the code and test suite
actually do today rather than from an aspirational description. Every claim
below is checkable against the repository, and the numbers were re-derived by
running the suites on 2026-10-03 against `a87991e` ("Surface sections, load
commands and UUID; reject unknown flags; extract strings").

TOWS is SWOT with the action step: the four factor lists are the inputs, and the
matrix is the output — pairing each internal factor with each external one to
generate a strategy, rather than leaving four disconnected lists that tell you
nothing about what to do on Monday.

## Corrections to the previous version

The previous version of this document was written on 2026-10-02 against an
older tree. It was wrong in eight places, and two of them inverted the agenda.
All are fixed below, and each is worth naming because the stale version was more
confident than it was correct.

| Stale claim | Reality on `a87991e` |
|---|---|
| **"Publishable as configured"** — "complete manifest metadata; nothing blocking an `npm publish`" | **Unpublishable under its current name.** npm's own validator returns `validForNewPackages: false` with the warning *"name can no longer contain capital letters"*, and the registry repeats it verbatim in the E404. The metadata is complete; the *name* is invalid. |
| **"Installable, not just vendorable"** — "`man macho-sym` works after `npm i -g`" | Never was, and cannot be. `README.md`:49 still instructs `npm install -g MachO-Tools`, which cannot succeed. `macho-tools` is also E404, so the name is unclaimed and free. |
| `W1` **"LANDED, both halves"** — `.githooks/pre-commit` "verified to *block* on a hand-edited fixture and on a failing suite" | **There was no `.githooks/` in this repository.** It lived at the workspace root; `core.hooksPath` was unset here and nothing was tracked. `CONTRIBUTING.md` was *correct* — it said "in the parent workspace" — so the code review caught what the strategic document did not. The local gate had not travelled with the package when it became its own repo. **Now closed:** both hooks are versioned here and blocking-verified. |
| "202 checks" | **310** in `smoke.mjs`, plus **183** in `mcp.mjs` and **36** in `skill.mjs` — **529 checks**, and 11 mutations. |
| "7 mutations, 7 caught" | **11 mutations, 11 caught** (9 by the generator's self-check, 2 by `smoke.mjs`). The latest commit message says *9*, so that claim is stale too, in the commit that introduced the two extra mutations. |
| "7 generated fixtures (39,568 bytes)" | **10 fixtures, 42,060 bytes** — `bits32.macho` and `strings.mjs`'s `strings.macho` joined, and an `LC_UUID` was added to `stripped.macho`. |
| "Six man pages", "six flat binaries" | **Nine man pages, nine `bin` entries** — eight CLI tools plus `macho-mcp`. |
| "CI is three jobs" | **Four** (`fixtures`, `test`, `protocol`, `mutation`), and only `test` is an OS matrix. `README.md` and `CONTRIBUTING.md` *both said three* until this pass corrected them. |

### Corrections, third pass

Two failures surfaced while writing the hooks, both in the guard rather than in
the code it guards — which is where the risk actually was:

1. *A flag-parsing regex in the first draft of the hook silently matched
   nothing.* It was meant to catch a `README.md` install line naming a different
   package than `package.json`, and it returned **no matches at all** on the very
   line it was written for, because `(?:-[^ ]+)*` sits after a mandatory space and
   so matches zero times against `npm install -g X`. A prose check that matches
   nothing is indistinguishable from a prose check that passes. It was rewritten
   as a check in `test/skill.mjs` — the suite that already holds prose to the
   tree — rather than kept as a regex inside a shell hook, which is the wrong
   place for a parser that has no positive control.
2. *The hooks resolved the git root before checking for `node`.* On a `PATH`
   without `node`, the hook died on `git` with exit 127 and no message. It still
   refused, so it was not a false green — but the likely cause went unnamed, and
   the fix is a two-line reorder found only by testing the failure rather than
   assuming it. The current hooks name the *actual* missing thing in both cases.

Both are the same shape as everything else in this document: **a verification
that cannot fail, or cannot explain itself, is worse than a missing one.** The
third and fourth are the first two in this project where the defect was in the
check's own text rather than in the reader it checked.

### Corrections, second pass

Recorded rather than quietly deleted, because a strategic document that is only
ever right about the present is indistinguishable from one that was never
checked.

**`api.d.ts` was no longer "deliberately narrower than the implementation". It
was stale.** That narrower-by-design stance was listed as a strength, and it was
right at the time: a hand-written `.d.ts` describes what the package *promises*,
not what the code happens to do. But the commit that added `segments`,
`sections`, `loadCommands`, `uuid` and the `findStrings` export **did not touch
`src/api.d.ts`**. Verified against the running code:

```
describe('test/fixtures/universal.macho').slices[0]
  → arch, offset, size, thin, readable, bits, nsyms, defined, note,
    textAddr, textSize, codeSections, segments, sections, loadCommands, uuid

api.mjs exports 19 symbols; api.d.ts did not declare findStrings.
```

A TypeScript consumer calling `slice.sections` got a compile error against a
field that demonstrably exists at runtime. That is not narrower-by-design, it is
a contract break — and commit `4115f08` was titled *"fix four contract
breaks"*, so the bar this project set for itself is the one being missed. Both
halves are now landed, and the gap is closed by a suite rather than by a review
(see *Corrections, third pass*).

**The provenance pointer now dead-ends at the existential risk.**
`README.md`:486 sends the reader to "the sibling project's `NOTICE.md` — reach it
from the repository root rather than by link here". The repository root *is*
this repository now. There is no `NOTICE.md` here. The one document whose entire
job is managing how the project's origin is perceived, points at a file that
does not exist, in the one direction a reviewer will actually follow. Everything
else in §Provenance is right — nothing proprietary ships, and that is enforced by
five `boundary:` checks over 44 shipped files — but the disclosure a sceptical
reader is asked to go read is unreachable.

**Two more confident greens, in the same shape as the four the project already
records in its README:**

1. **`npm publish --dry-run` succeeds.** It packs 54 files, prints
   `+ MachO-Tools@0.1.0`, and exits 0. It never asks the registry whether the
   name is acceptable, because a dry run is not a publish. The green is real and
   the conclusion it supports is false — the fifth instance of the exact failure
   this project has written four times about, reached by the shortest route.
2. **The mutation count in the commit message is stale.** `9 mutations, all
   caught; 8 by the generator's own self-check, 2 by smoke` — that is 10, not 9.
   The suite actually runs **11, all caught**. A commit message is the one piece
   of documentation nobody re-reads, which is presumably why it drifted while
   every checked-in claim stayed true.

The rule still holds, and this pass is the argument for it: **a verification that
cannot fail is worse than a missing one, because it reports success.** Three of
the four defects the README records were found by *doing* the matrix items. The
same is true of every finding above except the `.githooks` gap, which was found
by reading the tree against the previous version of this document.

---

## Inputs

### Strengths — internal, helpful

| | Evidence |
|---|---|
| **Zero dependencies, zero build step** | Node builtins only; `node_modules/` is absent and `.gitignore` treats its appearance as a bug. Re-verified today: five suites run on a clean clone with no install. |
| **No product knowledge, and it is a test rather than a review habit** | Five `boundary:` checks in `smoke.mjs`, all passing, scanning 16 files in the reader, 5 in the suite and **44 in what the package ships** — with a positive control (`the name check can actually fail — 3 patterns, all live`) and a derivation from `package.json`'s own `files` rather than a restated list. |
| **One reader, not nine** | `src/macho.mjs` owns fat headers, load commands, `LC_SYMTAB`, sections, `LC_UUID` and the 32/64-bit split. Duplication has shipped a real defect twice — the `mapliteral` cputype constant, and the section attribute predicate the latest commit deleted in favour of calling `isCodeSection`. |
| **Two corpora with opposite assertion policies** | 10 generated fixtures (42,060 bytes, exact counts and addresses) plus the system binaries present on the machine, asserted against *invariants* only. This is what makes a green run mean something on a bare CI runner. |
| **Mutation testing, and it bites** | Latest run: **11 mutations, 11 caught**, 9 of them by the fixture generator's own self-check. An inconclusive mutation fails the run. Every one of the eleven reintroduces a real historical bug. |
| **The suite verifies its own coverage** | It asserts both architectures were exercised, that a symbol-less and a populated binary were both tested, and that every input shape a known defect needs was present. |
| **The 32-bit path is no longer untested** | The previous version could not claim this: every fixture was 64-bit, so `if (wide)` meant the branch had never run. `bits32.macho` now pins it, and the nlist stride bug — which returned the right *number* of symbols one entry off, with names that looked like names — is mutation-locked. |
| **The loader surface is now visible** | `describe` carries `segments`, `sections`, `loadCommands` and `uuid`; unknown load commands are reported by number rather than dropped. Named, not interpreted — `LC_CODE_SIGNATURE` is a fact about a file. |
| **One dialect across every tool** | `rejectUnknownFlags()` gives all eight CLI tools the same usage-error behaviour, names a near miss, and a check asserts all sixteen documented flag combinations still parse. A typo'd `--regex` used to answer a different question and report a negative answer to it. |
| **`--json` everywhere; an importable API; a protocol and a skill** | 19 exports from `src/api.mjs`, `bigint` addresses end to end, a real MCP server driven over a real pipe by 183 checks that parse every stdout line, and an agent skill held to the tree by 36 checks. |
| **Honest about itself** | A table of its own historical bugs, a comparison table with honest `no` rows, a "What it will not do" section *with the test for joining it*, and a Limits section that states the gaps. |
| **CI on three operating systems** | Four jobs; the `test` job is a macOS/Linux/Windows matrix, and Windows is there for a stated reason — the reader claims platform-independence and only Windows has no `/usr/bin` to fall back on. |

### Weaknesses — internal, harmful

| | Evidence |
|---|---|
| ~~**The package cannot be published under its own name**~~ — **LANDED** | Now `macho-tools`. `validate-npm-package-name` reports `validForNewPackages: true` and npm's own character rules pass; `npm view macho-tools` is E404 because it is unpublished, not because it is unpublishable. `test/publish.mjs` asserts the name, the character rules, the `files` entries, every `bin` target, every `export` subpath and `types`, and that the docs name the same package — with a positive control on the specifier pattern, because a check that matched no install line would look exactly like one that passed. It runs in CI, so the dry run can no longer be the only witness. |
| ~~**`api.d.ts` has fallen behind the implementation**~~ — **LANDED** | The four `describe()` slice fields are declared, plus `findStrings`, `LoadCommand`, the iOS header facts (`filetype`, `platform`, `minos`, `sdk`, `cryptid`, `encrypted`), and the `Thin` fields `parseThin` actually returns. `test/types.mjs` holds the declared surface to the runtime one by reading real values off fixtures — and it earns its place: it caught nine more fields the concurrent work in `src/api.mjs` had added without touching the `.d.ts`. See *Corrections, third pass*. |
| ~~**No local gate in this repository**~~ — **LANDED** | `.githooks/pre-commit` (`fixtures.mjs --check` ~0.1s, then `smoke.mjs` ~4s) and `.githooks/pre-push` (adds `mcp.mjs`, `skill.mjs`), enabled with `git config core.hooksPath .githooks`. Verified to **block**, not merely run: a hand-edited fixture refuses a real `git commit`, with the corpus message and no commit created; a `uuid`-dropping mutation passes `fixtures --check` and is still caught by `smoke.mjs`, so the two checks were isolated from each other rather than one masking the other. Both hooks refuse with exit 1 rather than exit 0 when they cannot run — missing `node`, unresolvable root, or a tree with no `test/`. That last property was found *by* testing: the first version resolved the git root before checking for `node`, so a stripped `PATH` died on `git` with exit 127 and no explanation. Still a refusal, but an unreadable one. |
| ~~**The CI description is wrong in both documents that describe it**~~ — **LANDED** | Both corrected: `README.md` §Verify and `CONTRIBUTING.md` now say four jobs, name `test` and `protocol`, and state that only the reader suite is a three-OS matrix. The section telling you how to verify the README can now be trusted on that point. |
| **An absent corpus member is still silent** | `discover()` drops a missing system binary with a bare `continue` and no word. The suite prints every skipped *check* loudly and its coverage receipt is thorough; the corpus-level half of the same honesty is still missing. Unchanged from the previous version and still open. |
| **The provenance pointer is unreachable** | `README.md`:486 refers the reader to a `NOTICE.md` "from the repository root". There isn't one here. |
| **No tags, no releases, version `0.1.0`** | `git tag` is empty and `get_latest_release` 404s. The version has never been published or cut, so the artifact a badge vouches for has no version anyone can name. |
| **Indirect calls are invisible** | Register calls, jumps through a PLT stub, and any indirect call do not encode their target. Largest gap against Ghidra/IDA, and a permanent one by decision. |
| **The arm64 scan steps 4 bytes at a time** | Sees aligned `BL`s only; an instruction at an unaligned address is missed. |
| **No disassembly, no fixups, no export trie, no ObjC/Swift metadata, no DWARF** | Deliberate, and documented as deliberate with a stated test. Unchanged — see `W-note`. |
| **Bundle ergonomics are macOS-shaped** | `bundle.mjs` assumes `.app` / `Contents/MacOS`. Fine — that is the target — but the cross-platform story is thinner than a three-OS matrix suggests. |

### Opportunities — external, helpful

| | |
|---|---|
| **The obvious name is unclaimed** | `macho-tools` returns E404 and is free. So is the decision — nothing about the tooling changes, only the string in `package.json`. |
| **An agent-integration surface no Mach-O tool has** | The parity comparison puts `ipsw` at *skill only*. A tested MCP server plus a tested skill is a category of its own, and the fixture corpus means it can be exercised with no binary and no network. |
| **The fixture corpus is independently useful** | A deterministic Mach-O corpus with known answers — 32-bit, fat, symbol-less, populated, zero-fill, string-bearing — exported as `MachO-Tools/fixtures` and consumable by another project's parser tests. This is the artefact a different project borrows. |
| **Stable format, thin tooling** | Mach-O has barely changed in 30 years. `otool`/`nm` ship in the box but need `lipo` first, emit no JSON, and answer one question per invocation. |
| **Linux/Windows against Mac binaries** | `nm` and `otool` do not run off macOS at all. Server-side triage and CI are unserved by the in-box tools. |
| **Large universal binaries** | `nm` on a 476 MB universal binary takes minutes; this reads the symbol table directly. |
| **Security and malware triage** | Incident response wants byte-level facts, not a GUI. |
| **The defect history is publishable on its own** | Eleven mutation-locked bugs, including a 32-bit nlist stride that returned plausible names, is a write-up regardless of which toolkit reads them. |
| **A verifiable green is a marketing asset** | 529 checks and 11 mutations, reproducible offline in about five seconds by a stranger. That is rarer than it sounds and it is already built. |

### Threats — external, harmful

| | |
|---|---|
| **Provenance and IP optics** | Written while reversing a commercial product. The code is clean of it and that is now enforced; the lineage is knowable. **LGPL does not license the publisher's IP.** The only threat that can end the project — and the one document that manages it currently points readers at a file that is not there. |
| **Zero adoption from an unpublishable name** | The pitch is *"install it and read `man`"*. Until the name is valid, every reader who takes the README at its word gets a 404. `FEATURE-PARITY-IPSW.md` calls this "worth more than any row in this table and has not been addressed" — and it was written before the reason was known. |
| **Better-funded incumbents** | Ghidra is free with no licence server, which removes the usual objection to it. Hopper, Binary Ninja, LIEF, MachOKit. |
| **Abandonment** | One maintainer, no institutional home. The most likely way this ends is by not being continued. |
| **Silent rot against toolchain releases** | Largely retired: the `fixtures --check` job re-derives all 42,060 bytes, so a toolchain change that alters the readers fails the run rather than passing quietly. What is *not* pinned is the system-binary half, by design. |
| **No discoverability** | A CI badge, a public repo, no releases, no docs site, nine flat binaries. |
| **Conflation with the sibling `tools/` package** | The workspace-level "no product knowledge" guarantee is true of this package in isolation and easy to overstate from the outside. |

---

## The TOWS matrix

|  | **Opportunities** | **Threats** |
|---|---|---|
| **Strengths** | **SO — build** | **ST — defend** |
| 529 checks, 11 mutations, 4 CI jobs, 10 fixtures | **S1. Fix the name — LANDED.** `"name": "macho-tools"`. Every other asset in this project — nine man pages, ten completions, the fixture corpus, the MCP server, the agent skill — was already built and waiting for a channel that would accept it. `npm publish --dry-run` had been reporting `+ MachO-Tools@0.1.0` and exit 0 on the name npm refuses, so `test/publish.mjs` now asserts the property directly, in CI. | | **S5. Fix the provenance pointer before anything else ships.** §Provenance's job is to be followed by exactly the reader who is looking for a reason to stop trusting the project, and it currently dead-ends. The disclosure should live *in this repository*, not one level up in a workspace a standalone clone does not contain. Everything else in that section is right and is enforced; only the destination is broken. |
| One reader; both architectures; 32-bit now covered | **S2. Make the load-command surface a capability claim.** Sections, segments, named load commands and UUID were read but not surfaced, and are now surfaced. That is a real narrowing of the gap to `ipsw` on a format this project already owns — worth stating as a row won rather than as a bug fix. | **S6. Keep the five `boundary:` checks as the provenance proof.** A claim that nothing proprietary ships is worth nothing unverified; it is currently verified over 44 published files with a positive control. This is the single strongest answer to the existential threat and it must not be traded away for coverage. |
| Zero dependencies; one-file reader; LGPL | **S3. Publish the reader, not just the package.** `src/macho.mjs` alone parses real binaries with no `node_modules`, no lockfile and no install. That is the artefact that survives a hostile network, a supply-chain incident or a reader who will never run npm — and it needs no valid package name to be useful. | **S7. Freeze rather than rot.** With an exact-answer corpus, an archived repo can still demonstrate a verified working state to anyone who arrives later. |
| `--json`, MCP server, agent skill, importable API | **S4. Keep the agent surface first-class.** 183 protocol checks over a real pipe and 36 checks holding the skill to the tree is a stronger claim than the format coverage, and `ipsw` has no MCP server at all. | **S8. Publish the bug table.** Eleven mutation-locked defects with the reasoning attached is the credibility surface against "just use Ghidra". |
| | | |
| **Weaknesses** | **WO — fix** | **WT — contain** |
| Name invalid; `api.d.ts` stale; no local gate; CI mis-documented — **all LANDED** | **W1. Reopen the agent-consumability contract — LANDED, and then kept open by a suite.** The four `describe()` slice fields, `findStrings`, `LoadCommand`, the iOS header facts and the `Thin` fields are declared. What closes it permanently is `test/types.mjs`: it reads real values off fixtures and requires each declared, so the `.d.ts` cannot go stale again without CI going red. That mattered immediately — it caught nine further fields added to `src/api.mjs` without touching the `.d.ts`. The package is consumable by coding agents *by design*, and this is the one place a consumer would have found out it was lying. | **W7. Add a publish-readiness check, because the dry run cannot fail — LANDED.** `npm publish --dry-run` printed `+ MachO-Tools@0.1.0` and exited 0 on an unpublishable package. `test/publish.mjs` now asserts the name against npm's rule, the character rules, that every `files` entry exists, that every `bin` target and `export` subpath and `types` resolves, and that the docs name the same package the manifest does. Two positive controls, because a specifier regex that matched nothing would look exactly like one that passed. Runs in CI, so this is the sixth instance of the project's own failure mode with a detector attached rather than a paragraph. |
| No tags; `0.1.0` never cut; README/CONTRIBUTING CI drift — **drift LANDED** | **W2. Correct the CI description in both places. LANDED.** Four jobs, one matrix, both documents corrected. What remains is `W2b`: cut a tag, so `0.1.0` and the CI badge name an artefact a reader can fetch. | **W8. Ship the gate with the package, or drop the claim. LANDED — the first option.** `.githooks/` is now versioned here rather than living only in the parent workspace, `pre-commit` and `pre-push` are both blocking-verified, and both documents describe them. The failure mode this item was written to prevent — a strategic record claiming a local gate that does not exist in the repository a reader clones — is now closed. |
| Absent corpus member still silent; provenance pointer unreachable | **W3. Name the absent system binaries.** One `console.log` in `discover()`. Skipped *checks* are already reported honestly; a silently dropped *target* is not, and "310 passed" and "310 passed, no ffmpeg on this box" differ only in the number. | **W9. Keep the reversal.** Do not add DWARF, disassembly or ObjC/Swift metadata. The project's own stated scope makes each of them a strategy change disguised as a feature, and `W-note` below is the argument. |
| | **W4. Turn the version into a fact.** `0.1.0`, untagged, unreleased, with a badge vouching for it. Publishing under a valid name and cutting a tag makes the badge mean something and gives the fixture corpus a version to be pinned against by consumers. | |

> **W-note — the reversal stands.** The previous version of this document, and
> an earlier one before it, both named DWARF as the single highest-value next
> step. Neither does. `README.md` frames disassembly, DWARF/dSYM,
> Objective-C/Swift metadata and code signing as *deliberate gaps* — "the ones
> where a general parser or a disassembler is strictly better, and closing them
> here would mean becoming one of those projects instead of this one". Adding
> DWARF is a strategy change disguised as a feature, and it should be argued for
> as one. The gaps worth closing are the ones that make this the thing it
> intends to be — and as of `a87991e` that list is short, short enough to fit in
> a single commit.

---

## Reading the matrix

**The agenda inverted, and that is the headline.** The previous version's top
weakness was "no CI, not in the existing gate", and §Building was organised
around it. CI is now four jobs on three operating systems, the local hook
existed and was verified to block, and eleven mutations are locked. Every
`LANDED` marker in that document was checked before being carried forward, and
one of them — the local gate — turned out to be a workspace asset that did not
travel with the package. **This is what re-deriving instead of re-reading looks
like, and it is the argument for doing it every time the tree moves.**

**`S1` was the whole external quadrant, and it is now open.** Not one opportunity
on the right-hand side of this matrix could be reached by a reader who cannot
install the package, and the blocker was one word in `package.json` that
`npm publish --dry-run` reported as fine. What is left is `S2`: cut a tag and
publish, so the badge and the `0.1.0` in the manifest name an artefact a reader
can fetch. Everything else on the right-hand side is now reachable.

**`S5` and `W7` are the same item seen from two directions.** The provenance
disclosure is unreachable and the dry run cannot fail; both are the project's own
stated rule — *a verification that cannot fail is worse than a missing one,
because it reports success* — arriving through channels nobody re-reads. Six
instances now, across the flag parser, the shipped-file list, the symlinked
entry point, the mutation anchor, the CI description, and `npm publish
--dry-run`. The pattern is consistent enough to be worth a permanent detector
rather than a sixth paragraph about it.

**The most valuable outcomes were still not in the matrix.** Fixing the 32-bit
path surfaced three defects, none of which threw; adding an `LC_UUID` to a
fixture silently invalidated every encoded call displacement in the corpus and
forced the generator to lay code out for the header it actually builds. Both
were found by *doing* the work. That remains the strongest argument for working
the list rather than re-reading it — and it is why this document was re-derived
from a clean run rather than edited.
