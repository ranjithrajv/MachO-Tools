# Contributing

Mach-O binary introspection, in plain JavaScript, with no dependencies. This
file describes what a change has to survive, and why each rule exists — every
one of them is here because its absence produced a bug that reported success.

## Scope comes first

**This package is focused on Mach-O and nothing else.** Not a general
binary-format toolkit that happens to include one, not a disassembler, and not
a complete Mach-O parser. `README.md` § *What it will not do* is the list, and
it is a decision rather than a backlog: disassembly, indirect/PLT resolution,
dSYM/DWARF, Objective-C and Swift metadata, ELF and PE, code signing, fixups and
export tries.

The test for anything on that list is not "is it hard" — indirect call
resolution is genuinely hard, which is why it stays out. The test is whether
closing the gap would make this package **worse at the thing it is for**. A
package that answers 40% of a question is useful; one that answers all of a
question it was never built for is not.

So a pull request that adds any of those will not be merged, however good the
code is, and that is not a judgement about the contributor. It is what a
*decision* means in a repository: it survives contact with a well-meaning person
who has time. **Adding DWARF would be a strategy change disguised as a feature**
— that is not a review comment, it is an argument that belongs in an issue about
what this package becomes, where it can be argued on its own terms. Open the
issue before writing the code.

Adding depth *within* Mach-O is always welcome. A load command this reader does
not yet parse, a slice shape it gets wrong, a section flag it ignores, a symbol
table edge case — those are the changes that make the package better at its own
job, and they are the ones most likely to be missing.

## No application knowledge

The package's central claim is that every answer it gives is a fact about the
file format or about the bytes, and that it knows nothing about any
application — no publisher, no title, no container format. That claim is a test,
not a review habit: four `boundary:` checks in the suite scan `src/`, `test/` and
every file `package.json`'s `files` puts in the tarball, and fail if a product,
a title or its container format appears in any of them. The names are assembled
from fragments so that the check can include itself, and each group prints the
file count it scanned.

Concretely, when contributing:

- do not add a fixture, a magic number or a code comment that encodes knowledge
  of a specific product's layout, save format or version;
- do not vendor bytes, disassembly, asset data or key material into `src/`,
  `test/` or anywhere the tarball reaches;
- if a fix needs a real binary to be convincing, add it as a **generated
  fixture** instead. `test/fixtures.mjs` builds small Mach-O files whose answers
  are known by construction, which is both boundary-safe and better as a test,
  because it pins exact addresses instead of whatever the local machine has.

`TOWS.md` is deliberately outside that scan. It is the provenance assessment,
and naming what it assesses is the point of it.

## No dependencies, and no build step

Not a preference — it is what the README's install section promises.
`src/macho.mjs` imports exactly one thing, `node:fs`, and has no
internal imports, so it works as a single copied file; it stays small enough that
a reviewer can audit it by reading it, and a pipeline that must not reach the
network can run with no install at all.

A dependency would break both claims. So would a transpile step, a bundler, a
`tsconfig`, or anything else a reader has to install before they can check a
claim. Plain ESM JavaScript, Node ≥ 22.15, and `node:fs` plus friends.

If a change genuinely cannot be made without a dependency, that is an issue
first, on the same terms as a scope change.

## The gate

Three commands, three different kinds of evidence, and a change is not finished
until all three pass:

```sh
node test/fixtures.mjs --check    #  ~0.1s   the corpus matches its generator
node test/smoke.mjs               #  ~4s     the tools, on binaries they were not written for
node test/mcp.mjs                 #  ~15s    the protocol, driven over a real pipe
node test/skill.mjs               #  ~3s     the agent instructions match the tools
node test/mutation-check.mjs      #  ~2m     the historical bugs are still caught
```

Each suite prints its own counts. They are deliberately not written here: a
number in prose is a claim that some later commit has to remember, and the
failure mode is a document asserting a total the reader can disprove by running
one command. Read the number off the run.

`npm run test:all` runs all three in order. There is no `npm install` step
because there is nothing to install.

**`fixtures --check`** re-derives every byte of the generated corpus and
compares them to what is on disk. Never hand-edit a file under
`test/fixtures/`; run `node test/fixtures.mjs` to regenerate it. A hand-edited
or stale fixture is a test that has stopped testing while still reporting
success, and nothing else in the repository would notice.

**`smoke.mjs`** runs against two corpora. For the generated fixtures it asserts
**exact counts and exact addresses**, because the generator is versioned and its
answers are stable by construction. For system binaries (`/usr/bin/true`,
`/usr/bin/ssh`, a Go toolchain, ffmpeg) it asserts only invariants that hold for
*any* Mach-O — no counts, no addresses, because those move with a compiler
release and a test that pins them fails for the wrong reason. Whichever
candidates exist are used, and the suite prints every skipped check loudly.

**`mutation-check.mjs`** copies the tree, reintroduces one real historical bug at
a time, and requires the suite to fail. **An inconclusive mutation fails the
run**, because a mutation that could not be applied once reported green while
quietly reducing the count. If you change the reader and the mutation check
reports that one of its mutations no longer applies, that is a real finding:
either your change fixed the bug for good (remove the mutation and say so in the
PR) or it moved the code the anchor pointed at (fix the anchor in the same
commit).

CI runs four jobs — `fixtures` on ubuntu, `test` on a macOS/Linux/Windows
matrix, `protocol` (the MCP and skill suites) on ubuntu, and `mutation` on
ubuntu.

Locally there are two versioned hooks in `.githooks/`, enabled once per clone
with `git config core.hooksPath .githooks`. `pre-commit` runs `fixtures.mjs
--check` (~0.1s) then `smoke.mjs` (~4s); `pre-push` additionally runs `mcp.mjs`
and `skill.mjs`. The mutation check is in neither — it copies the tree and
re-runs the suite eleven times, so at ~2m it has its own CI job and is part of
`npm run test:all`. A gate nobody can afford to run is a gate nobody runs.

They are in `.githooks/` rather than `.git/hooks/` because that directory is
untracked, so a fresh clone would otherwise arrive with no guard at all. This
package had exactly that gap: the hooks lived only in the parent workspace, so a
standalone clone had neither a local gate nor a claim to one. Both hooks **refuse
rather than pass** when they cannot run — a missing `node`, an unresolvable repo
root, or a tree with no `test/` under it are all exits 1, because a hook that
exits 0 having checked nothing is worse than no hook.

Override with `--no-verify`. That is sometimes the right answer; the fix is to
re-run by hand before pushing, not to delete the hook.

## Writing a test

The failure mode this project has hit most is a check that cannot fail. It is
worse than a missing check, because it reports success. So:

- **give every check a positive control.** A check that only asserts an absence
  passes just as happily against a scanner that matches nothing. Prove the
  matcher works on an input where you know the answer first.
- **make skips loud.** A skip means the input was unavailable; it never means the
  check passed. Print it, and count it.
- **assert coverage, not just outcomes.** The suite asserts that a symbol-less
  binary and a populated one were both exercised, that both architectures were
  exercised, and that every input shape the known defects need was present. A
  test that quietly skips half the input space and reports success is worse than
  no test.
- **pin the exact thing that would catch the regression.** If the bug was a
  slice-relative offset, assert on a generated fat binary with slices at known
  offsets, not on whatever `/usr/bin` happens to contain.

## The defects the suite is built around

The tools were originally written alongside application-specific scripts, and the
boundary between them was invisible: a file that searched a binary for arbitrary
byte strings, sitting next to one that decoded a particular application's asset
formats. Separating them made the question sharper and found bugs that could not
have been found otherwise.

Every tool here had at some point been run against exactly one binary — the one
it was written for — and that is the worst possible way to test code that has to
work on any binary. Each of the following produced a clean exit code and a
plausible, wrong answer, and each is now a mutation the suite has to catch:

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
surface it — and it survived that long for a second reason worth copying: the
suite used to run **only** on system binaries, so on a bare CI runner it
discovered nothing, exited 2, and "checked nothing" was indistinguishable from
"failed to run".

## Four ways the suite reported green

A suite that has never been shown to fail is not evidence. This project has been
broken four distinct ways in its own verification, and every one of them printed
PASS. The general rule each time: **a verification that cannot fail is worse
than a missing one, because it reports success.**

- **A positive control that could not fail.** The smoke test only checked that
  the call finder *reported* an encoding, which it did even with its arm64
  comparison inverted — so a dead scanner passed. It now uses `findcall --list`
  to prove the matcher resolves real targets, then cross-checks the top one
  against the symbol reader, so two independent parsers have to agree. When the
  per-slice narration moved to stderr, `execFileSync` silently dropped it and
  the control reported `[undefined]` while asserting nothing; the suite now uses
  `spawnSync` and *asserts* the encoding it verified is a known one.
- **An expectation that matched the check *name***, which appears on PASS lines
  as well, so a wholly broken tool still "matched" and the run reported green. It
  now only accepts a `FAIL` line.
- **An incomplete mutation.** Removing only the `N_SECT` filter left the other
  guard (`value === 0n`) blocking the imported symbols, so the suite passed while
  establishing nothing. Each mutation now restores the actual original defect
  rather than approximating it.
- **A stale anchor, one level up.** One mutation was still written against the
  five-argument `tallySection` call, and `listCallTargets` has since grown a
  sixth argument — a `mapped` gate that keeps decoded destinations inside a
  mapped range. The mutation could no longer be applied, and the run printed
  `SKIP … anchor not found` and then **exited 0**, so `test:all` stayed green
  with seven mutations quietly reduced to six. An inconclusive mutation now
  fails the run like a survivor does, and the "none surviving" line only prints
  when every mutation really ran and was caught.

Write the mutation for the defect as it was, not for the shape of the defect as
you remember it.

## Why the call scan is section-typed

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

If a slice flags no section as instructions at all, the scan falls back to
untyped and says so in `untypedFallback` — reporting zero call sites there would
be the confident-wrong-answer failure this project keeps producing.

## Using the fixture corpus elsewhere

The generator is exported, because a project testing *its own* Mach-O reader
needs a known-answer corpus at least as much as this one does:

```js
import { buildFixtures } from 'macho-tools/fixtures';

const { files, manifest } = await buildFixtures({ out: '/tmp/corpus' });
// files.universal, files.arm64only, files.decoy, files.stripped, files.thin…
// manifest.callCounts, manifest.x86_64, manifest.arm64 — the exact addresses
//   and counts this project's own suite asserts, so both agree by construction
```

```sh
node node_modules/MachO-Tools/test/fixtures.mjs --out-dir /tmp/corpus
```

| Fixture | Shape it provides |
|---|---|
| `universal.macho` | Fat binary, both architectures, slices at known offsets |
| `arm64-only.macho` | No x86_64 slice to fall back to |
| `decoy.macho` | Code and data in one segment, with a planted decoy call in the data |
| `stripped.macho` | No symbol table at all |
| `thin-x86_64.macho`, `thin-arm64.macho` | Single-architecture, for the thin path |

Each fixture is minimal on purpose, so a failure points at one thing, and every
one is re-read with this project's reader and checked before it is written — a
fixture that does not hold up throws at build time rather than quietly weakening
your suite. `{ check: true }` verifies a corpus against the generator and writes
nothing. Nothing is written to disk on `import`; only calling `buildFixtures`
does.

The `decoy.macho` fixture is what makes the section-typing claim testable rather
than a matter of trust: it plants five bytes in a data section that decode as a
call to a function the code really does call, so the typed and untyped answers
differ by exactly one and the difference is attributable.

## Adding a tool

A new tool is small and the shape is fixed:

1. **One function in `src/api.mjs`.** The API is the supported interface and the
   package entry point. Every CLI is a thin wrapper over exactly one of its
   functions, so there is no behaviour behind the command line that an importer
   cannot reach, and no second copy of the reader free to answer differently.
2. **One CLI in `src/`.** Thin, and it delegates. Parsing goes in
   `src/macho.mjs`; `src/macho.mjs` does not grow a second reader.
3. **`--json`, the same envelope everywhere.** `{ tool, ok, binary, errors,
   messages?, notes?, data }`, `errors` holding machine-readable reason codes
   rather than prose, so a consumer can branch on `code` instead of
   pattern-matching an English sentence.
4. **stdout is JSON, diagnostics are stderr.** Progress lines, per-slice
   narration and "none found" prose all go to stderr, so `tool --json | jq`
   works.
5. **Exit codes are part of the contract.** `0` ran and found something, `1` ran
   and found nothing, `2` usage error, `3` could not do the job. A caller that
   cannot tell "found nothing" from "could not look" has the problem this
   project keeps fixing, so it is encoded in the exit status. Do not collapse
   `1` into `0`.
6. **Addresses are `bigint` in, `"0x…"` strings out.** A 64-bit vaddr does not
   survive a `Number`; anything above 2⁵³ loses its low bits, and a silent
   precision loss is indistinguishable from a correct answer.
7. **A negative answer is a value, not an exception.** No match is
   `{ matches: [] }` or `{ function: null }`. Genuine I/O failures still throw,
   so "no result" and "could not look" stay distinguishable.
8. **A man page and both completions.** `man/man1/macho-<name>.1`,
   `completions/macho.bash`, and `completions/_macho-<name>`; plus the `bin`,
   `man` and `files` entries in `package.json`.
9. **A README row.** The tools table, the flags table if you added a flag, and
   any claim about the new tool's accuracy.

## Documentation

Two documents, two audiences, and the split is deliberate:

- **`README.md` is for someone deciding whether to use this.** What it is, the
  tools, how to run them, how it compares, what it will not do, what it costs
  and what it cannot do. It is short on purpose — a reader who wants the
  reasoning behind a decision finds it here, in this file, not in a wall of
  prose before the first command runs.
- **`CONTRIBUTING.md` is this file: the reasoning, the history and the rules.**
  Defect tables, mutation mechanics, measurement data and the stories behind the
  rules belong here. If a contribution makes the README longer, ask whether the
  material is something a *user* needs in order to use the tool; if not, it goes
  here.

A document's numbers are a liability, not decoration. An earlier version of this
rule required the README to carry the suite's exact totals and to update them in
the same commit as any change that moved them — which is a rule about
remembering, and remembering is what the test suite is for. It was replaced
under the pressure of its own cost: a total in prose goes stale the moment
anyone adds an assertion, and the first time it does, it is wrong in a document
whose entire argument is that this project would rather say nothing than say
something confidently and incorrectly.

So neither file prints a count. What a document may do is state **what a check
establishes** — that `fixtures --check` proves the corpus was not hand-edited,
that `mutation-check` reintroduces one real historical defect at a time and
requires the suite to fail — and leave the totals to the run, where they are
printed by the thing that measured them. A claim that cannot go stale is worth
more than a number that can.

The exception is a number about something *outside* this repository, which no
commit here can change. Those carry the date they were checked: the `ipsw`
command counts in the README comparison are stated as of a specific `ipsw`
release, so a reader who finds them stale can tell whether the tool moved or the
document did.

If a change alters the plan rather than the code — a scope change, a new
boundary, a decision about what this is not — `TOWS.md` is where that is
recorded, and it is where the reasoning belongs. `README.md` § *What it will not do*
and § *Limits* should follow it, not lead it.

## Style

The surrounding code is the specification. Beyond that:

- **Comments explain why, not what.** The headers in `src/macho.mjs` and
  `src/findcall.mjs` are long on purpose: they record the bug a decision was
  made to prevent, which is the information a future reader cannot recover from
  the code. A comment restating the line below it is noise.
- Match the existing naming, spacing and comment density. Where the code has a
  house idiom — `bigint` literals with `n`, `0x` addresses, reason codes in
  kebab-case — follow it.
- Fail loudly and specifically. An error that says which slice, which offset and
  which architecture is worth ten that say "parse failed".
- Prefer a smaller change to a cleverer one. The readers here are short because
  they can be read end to end, and that is a feature the README advertises.

## Reporting a bug

An actionable report has: the exact command, the input (a path, or better a
minimal fixture), what you expected, and what you got — including the exit code
and the full stderr, which is where the per-slice narration lives. `--json` on
any tool makes the report easier to read.

If the bug is a *parse* bug — a wrong answer with a clean exit code rather than
an error — say so in the subject line. Those are the ones worth the most here,
and they are the ones that only a second, unrelated binary will ever surface.

## Licence

**LGPL-3.0-or-later.** Contributions are accepted under the same terms; there is
no CLA and none is needed.

Read `README.md` § *Provenance* before contributing: the code is clean of the
commercial product it was written while reversing, that cleanliness is enforced
by the boundary checks above, and LGPL covers this code without licensing anyone
else's intellectual property. Do not paste third-party code in; a fact about the
Mach-O format is not anyone's property, but an implementation of it can be.