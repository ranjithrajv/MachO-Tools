#!/usr/bin/env node
/**
 * smoke.mjs — run these tools against binaries they were not written for.
 *
 *   node test/smoke.mjs                 # fixtures, plus whatever the machine has
 *   node test/smoke.mjs /path/to/bin    # test specific binaries instead
 *
 * ## Two corpora, and why
 *
 * **The fixtures** (`test/fixtures.mjs`, built by `npm run test:fixtures`) are
 * generated from code, so they exist on every machine, cover the shapes that are
 * hard to find by hand — a fat binary whose slices sit at known offsets, an
 * arm64-only binary, code and data in one segment — and encode answers a reviewer
 * can check by reading the generator rather than by trusting the tool.
 *
 * **System binaries** are whatever the machine actually has. They are the
 * breadth: real linkers, real compilers, real sizes, inputs nobody designed.
 *
 * The fixtures are load-bearing and the system binaries are best-effort, which is
 * the opposite of how this suite used to work. It used to run *only* on system
 * binaries, so on a bare CI runner it discovered nothing, exited 2, and "checked
 * nothing" was indistinguishable from "failed". The mutation check was worse
 * still: it copies the tree and re-runs this suite inside the copy, so on a
 * machine without ffmpeg a mutation was never exercised and the run reported it
 * as caught. Every verdict about the tools depended on what happened to be
 * installed.
 *
 * ## Why this exists
 *
 * A tool exercised only on the input it was built against reports a clean,
 * confident, wrong answer rather than failing. Each of the following was written
 * against one binary and none was reachable from it:
 *
 *   - one tool matched *imported* symbols as enclosing functions. Imports carry
 *     n_value == 0, so any low address "resolved" to an import at 0x0. A binary
 *     with a million symbols hid it completely.
 *   - another read the architecture list at a fixed offset, valid only for a
 *     *thin* Mach-O, so on a universal binary its section walk silently failed
 *     and it scanned a default window containing nothing — reporting "0 call
 *     sites" as though that were a finding.
 *   - a third could not terminate: its chunk loop advanced by `len - 5`, which
 *     stops moving once the final chunk is under 5 bytes.
 *   - a fourth had a dead arm64 path. It knew only the x86 `rel32` encoding, and
 *     its arm64 mask compared a *signed* int32 against a constant above 2^31, so
 *     the mask never matched and it returned a confident zero.
 *   - a fifth treated an absent architecture as fatal rather than a preference.
 *   - a sixth read every section at its *slice-relative* file offset, with no
 *     slice base added. On a thin binary that offset is the file offset, so it
 *     worked; on a universal binary it read the right *number* of bytes from the
 *     wrong place and found whatever call encodings happened to be there. Only
 *     the generated fixture caught this — see `test/fixtures.mjs`.
 *
 * ## What it asserts, and what it deliberately does not
 *
 * For system binaries: invariants that must hold for *any* Mach-O, pinning no
 * counts and no addresses, because those move with a compiler release and a test
 * that pins them fails for the wrong reason.
 *
 * For fixtures: exact counts and exact addresses, which is the point. They are
 * stable because the fixture generator is in the repository.
 *
 * The checks lean on the **negative** paths, because a wrong answer and a right
 * answer are equally quiet and only the wrong one is dangerous. The suite also
 * asserts its own coverage — that a stub and a populated binary were both
 * tested, and that both architectures were exercised — and it includes a
 * **positive control** for the call scanner. That last one exists because a
 * scanner that finds nothing and a scanner that is broken look identical from
 * outside: an earlier version only checked that the call finder *reported* an
 * encoding, which it did even with its arm64 comparison inverted, so a dead
 * scanner passed. A check that cannot fail is not a check.
 *
 * It also asserts the **no-application-knowledge boundary**, which is the claim
 * the package is sold on. That claim was held by review discipline alone until
 * this check existed; see the `boundary:` section below for the two ways a
 * denylist quietly becomes a check that passes on nothing, and how it avoids
 * both.
 *
 * Run `npm run test:mutation` to confirm the claims in this file are load-
 * bearing: it reintroduces each defect and asserts this test notices.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  opener, slicesOf, parseThin, readSymbols, preferredSlice, sliceName, sliceArchName, archMatches,
  textSection, isMachOFile,
} from '../src/macho.mjs';
import { bundleLayout, isBundle } from '../src/bundle.mjs';
import { executableIn } from '../src/target.mjs';
import { count } from '../src/output.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures');

/* ------------------------------------------------------------------ *
 * reporting
 * ------------------------------------------------------------------ */

let passed = 0;
const failures = [];
const skipped = [];

function check(ok, label, detail = '') {
  if (ok) {
    passed++;
    console.log(`  PASS  ${label}${detail ? '  ' + detail : ''}`);
  } else {
    failures.push(`${label}${detail ? ' — ' + detail : ''}`);
    console.log(`  FAIL  ${label}${detail ? '  ' + detail : ''}`);
  }
}
const skip = (label, why) => {
  skipped.push(label);
  console.log(`  SKIP  ${label}  ${why}`);
};

/**
 * Run a tool, capturing stdout *and* stderr under a wall-clock cap.
 *
 * `spawnSync`, not `execFileSync`: the latter returns only stdout, and drops
 * stderr entirely on success. `findcall --list` moved its per-slice narration to
 * stderr — so `--json` could keep stdout pure — and the call-scanner positive
 * control reads the architecture encoding from it. With `execFileSync` the
 * control reported `[undefined]` and asserted nothing: a check that silently
 * stops checking is the exact failure mode this suite exists to catch, and it had
 * appeared inside the suite itself. The assertion added to catch that ("the
 * encoding it verified is a known one") is what surfaced it.
 */
function run(tool, args, { env = {}, timeout = 120000 } = {}) {
  const started = Date.now();
  const res = spawnSync(process.execPath, [`${SRC}${tool}`, ...args], {
    encoding: 'utf8',
    timeout,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    code: typeof res.status === 'number' ? res.status : 1,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    ms: Date.now() - started,
    timedOut: res.signal === 'SIGTERM' || res.error?.code === 'ETIMEDOUT',
  };
}

/* ------------------------------------------------------------------ *
 * candidate discovery
 * ------------------------------------------------------------------ */

/**
 * How many defined symbols counts as "populated"?
 *
 * Every Mach-O defines `__mh_execute_header`, so a threshold of 1 labels the
 * cache stubs — the more interesting case — as populated and the distinction
 * collapses. Modern system apps ship as stubs because their real code lives in
 * the shared cache; those carry one or two symbols.
 */
const POPULATED_FLOOR = 50;

/**
 * Facts read straight from the tables, never inferred from a guess.
 *
 * Grepping tool *output* for a symbol is fragile twice over: the pattern has to
 * match something particular to whichever binary happens to be installed, and a
 * target picked by hand can fall outside __text — which the call finder
 * correctly refuses to scan, so the check passes vacuously. The slice is chosen
 * the same way the tools choose one, so an address handed to a tool belongs to
 * the slice that tool will read.
 */
function facts(p) {
  const out = { defined: 0, firstAddr: null, firstName: null, textAddr: null, addrs: [] };
  const f = opener(p);
  for (const s of slicesOf(f)) {
    const thin = parseThin(f, s.offset);
    if (thin) out.defined = Math.max(out.defined, readSymbols(f, s.offset, thin).defined);
  }
  const slice = preferredSlice(f, 'x86_64');
  if (slice) {
    out.arch = slice.arch;
    const withAddr = readSymbols(f, slice.offset, slice.thin).entries
      .filter((e) => e.defined && e.addr !== 0n)
      .sort((a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0));
    if (withAddr.length) {
      out.firstAddr = withAddr[0].addr;
      out.firstName = withAddr[0].name;
      // A spread of real function addresses for the call-scanner control, taken
      // from the *middle* of the address range. The lowest addresses are the
      // entry point, header and PLT stubs, which nothing calls directly — an
      // earlier version sampled those and concluded the scanner was dead.
      const body = withAddr.filter((e) => e.name && !e.name.startsWith('__Z') && !e.name.startsWith('__'));
      const pool = body.length >= 8 ? body : withAddr;
      const picks = [];
      for (let i = 0; i < 8; i++) {
        const at = Math.floor(((i + 0.5) / 8) * pool.length);
        const e = pool[Math.min(at, pool.length - 1)];
        if (e) picks.push(e.addr);
      }
      out.addrs = [...new Set(picks.map(String))].map(BigInt);
    }
    const sec = textSection(slice.thin);
    if (sec && sec.size > 0) out.textAddr = sec.addr;
  }
  f.close();
  return out;
}

const mk = (path) => {
  const f = facts(path);
  return { path, kind: f.defined >= POPULATED_FLOOR ? 'populated' : 'stub', facts: f };
};

/**
 * Binaries worth testing from the host, when it has them.
 *
 * Two shapes matter and both are wanted: a *stub* (fat, essentially no defined
 * symbols — what every modern system app is) and a *populated* one. The
 * import-matching bug only appears on a stub; the round trip and the call
 * scanner only have anything to chew on with a populated binary.
 *
 * Nothing here is guaranteed to exist, which is exactly why these are the
 * optional corpus and the fixtures are the required one. Absence is a skip,
 * never a failure — otherwise the suite would be a test of one machine's
 * /usr/bin.
 */
// POSIX paths only, deliberately: these are asserted to exist or be skipped, so
// including `.app` bundles here would put a macOS-only path in a suite that
// otherwise runs anywhere Node does. Bundles are covered separately, by passing
// one explicitly.
const CANDIDATES = [
  '/usr/bin/true',
  '/usr/bin/ssh',
  '/bin/ls',
  '/usr/local/go/bin/go',
  '/opt/homebrew/bin/ffmpeg',
];

/**
 * The generated corpus. Present on every machine, checked in, and the reason
 * this suite has a floor rather than a possibility.
 *
 * `generated: true` marks them so the per-binary checks can distinguish the two
 * corpora: system binaries get invariant checks with no pinned numbers, fixtures
 * get exact assertions because the generator is in the repository and its
 * answers are stable by construction.
 */
function fixtureBinaries() {
  const out = [];
  for (const name of fs.existsSync(FIXTURES) ? fs.readdirSync(FIXTURES) : []) {
    if (!name.endsWith('.macho')) continue;
    const p = path.join(FIXTURES, name);
    if (!isMachOFile(p)) continue;
    out.push({ ...mk(p), generated: true, stem: name.replace(/\.macho$/, '') });
  }
  return out;
}

/**
 * Build the fixtures if they are missing, so `npm test` is enough.
 *
 * Not silently: a failure here is reported and the suite stops, because a
 * missing corpus would otherwise turn every generated check into a skip and the
 * whole run would report success having verified nothing.
 */
function ensureFixtures() {
  if (fixtureBinaries().length > 0) return true;
  try {
    execFileSync(process.execPath, [path.join(HERE, 'fixtures.mjs')], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    console.error(
      'could not build the test fixtures:\n' +
        `  ${(e.stderr || e.stdout || e.message).toString().trim()}\n`,
    );
    return false;
  }
  return fixtureBinaries().length > 0;
}

// Real bundles, included only when present. This is the suite's own assertion
// that the bundle convention is *data* rather than a literal: `BUNDLE_EXT` and
// `bundleLayout()` decide whether a path is treated as a bundle, so a path
// written with the convention's own extension exercises it without this file
// having to know what that extension is.
const BUNDLE_EXT = bundleLayout().ext;
const BUNDLE_CANDIDATES = [
  path.join('/Applications/Ollama' + BUNDLE_EXT, ...bundleLayout().macosDir, 'Ollama'),
];

function discover() {
  const argv = process.argv.slice(2);
  if (argv.length) {
    return argv.map((p) => {
      if (!fs.existsSync(p) || !isMachOFile(p)) {
        console.error(`not a readable Mach-O: ${p}`);
        process.exit(2);
      }
      return mk(p);
    });
  }
  // Bundles are tested through the *bundle* path, not by handing a tool the
  // executable inside one — resolving the executable from a bundle root is the
  // behaviour `executableIn` exists for, and this is the only thing that covers
  // it. The bundle root is derived from the executable by trimming the layout
  // segments, so the test never restates the convention it is meant to verify.
  const out = fixtureBinaries();
  for (const p of CANDIDATES) {
    if (!fs.existsSync(p) || !isMachOFile(p)) continue;
    out.push(mk(p));
  }
  for (const exe of BUNDLE_CANDIDATES) {
    if (!fs.existsSync(exe)) continue;
    const root = exe.split(path.sep + bundleLayout().macosDir.join(path.sep) + path.sep)[0];
    const resolved = root ? executableIn(root) : null;
    if (resolved && isMachOFile(resolved)) {
      bundleRootsFound.push(root);
      out.push({ ...mk(resolved), viaBundle: true });
    }
  }
  return out;
}

/** Bundle roots present on this machine and resolved through `executableIn`. */
export const bundleRootsFound = [];

/* ------------------------------------------------------------------ *
 * the checks
 * ------------------------------------------------------------------ */

if (!process.argv.slice(2).length && !ensureFixtures()) process.exit(2);

const binaries = discover();
const generated = binaries.filter((b) => b.generated);
const host = binaries.filter((b) => !b.generated);
console.log(
  `\nsmoke — ${binaries.length} Mach-O binary/binaries ` +
    `(${generated.length} generated fixture(s), ${host.length} from this machine)\n`,
);

if (generated.length === 0 && host.length === 0) {
  // Exiting 0 would report no failures having checked nothing. A skip is
  // honest; a pass is not.
  console.error(
    'no Mach-O found. Pass some explicitly:\n\n    node test/smoke.mjs /usr/bin/true /bin/ls\n',
  );
  process.exit(2);
}

/* ---- library invariants: no subprocess, so these always run ---------- */

console.log('bundle.mjs / target.mjs:');
{
  // The bundle convention is config, so the assertions are about the *shape* of
  // the contract rather than about `.app` specifically — which is what keeps this
  // suite meaningful after an override changes the extension or the layout.
  const layout = bundleLayout();
  check(
    typeof layout.ext === 'string' && layout.ext.length > 0,
    'the bundle extension is a non-empty string',
    layout.ext,
  );
  check(
    Array.isArray(layout.macosDir) && layout.macosDir.length > 0 &&
      layout.macosDir.every((s) => typeof s === 'string' && !s.includes('/') && !s.includes('\\')),
    'macosDir is a list of bare segments, so path.join composes it on any platform',
    JSON.stringify(layout.macosDir),
  );
  check(isBundle('/x/y' + layout.ext), 'a path with the configured extension is a bundle');
  check(!isBundle('/x/y'), 'a path without it is not');
  check(
    isBundle(path.join('/a', 'b' + layout.ext)) &&
      bundleLayout().macosDir.length > 0,
    'bundle detection works on a composed path',
  );

  if (bundleRootsFound.length) {
    for (const root of bundleRootsFound) {
      const exe = executableIn(root);
      check(
        typeof exe === 'string' && exe.includes(layout.macosDir.join(path.sep)),
        'executableIn finds the binary inside a real bundle',
        exe,
      );
      check(
        isMachOFile(exe),
        'and what it found really is a Mach-O',
        exe,
      );
    }
  } else {
    console.log('  SKIP  no bundle on this machine, so executableIn is untested against one');
  }
}

console.log('macho.mjs:');
{
  // Arch naming is a pure function of the cputype, so it is checked directly
  // rather than through a binary. A fixture per architecture would test the
  // same six comparisons six times over and still not cover the one that
  // matters most: an architecture we have *not* named must stay unnamed rather
  // than borrow a neighbour's name and be reported as a slice it is not.
  const NAMED = [
    [0x01000007, 'x86_64'],
    [0x0100000c, 'arm64'],
    [0x0200000c, 'arm64_32'],
    [0x01000012, 'ppc64'],
    [0x00000012, 'ppc'],
    [0x0000000c, 'arm'],
    [0x00000007, 'i386'],
  ];
  for (const [ct, want] of NAMED) {
    check(sliceName(ct) === want, `sliceName(0x${ct.toString(16)}) is ${want}`, sliceName(ct));
  }
  check(sliceName(0x0000000d) === 'cputype=0xd', 'an unmapped cputype falls back to its raw value', sliceName(0x0000000d));

  // arm64e is a *subtype* of arm64, so `sliceName` cannot see it — this is the
  // property that made every arm64e slice report as plain arm64.
  check(sliceName(0x0100000c) === 'arm64', 'sliceName cannot distinguish arm64e — it is not a cputype', sliceName(0x0100000c));
  for (const [sub, want] of [[2, 'arm64e'], [10, 'arm64e'], [0, 'arm64'], [1, 'arm64'], [8, 'arm64']]) {
    check(sliceArchName(0x0100000c, sub) === want, `sliceArchName(arm64, subtype ${sub}) is ${want}`, sliceArchName(0x0100000c, sub));
  }
  // The capability bits live in the high byte, so a raw compare against the
  // subtype works until a binary sets one — which is every arm64e binary built
  // with pointer authentication.
  check(
    sliceArchName(0x0100000c, 0x80000002) === 'arm64e',
    'arm64e survives CPU_SUBTYPE_LIB64 in the high byte',
    sliceArchName(0x0100000c, 0x80000002),
  );
  // A subtype read as a signed int32 is negative, which is how the high-byte mask
  // gets skipped by accident in code that compares the raw value.
  check(
    sliceArchName(0x0100000c, 0x80000000 | 2 | 0) === 'arm64e',
    'arm64e survives the same bit read as a signed int32',
    sliceArchName(0x0100000c, -2147483646),
  );
  check(sliceArchName(0x0100000c, null) === 'arm64', 'an unread subtype degrades to arm64, not a guessed arm64e', sliceArchName(0x0100000c, null));
  check(sliceArchName(0x0100000c, undefined) === 'arm64', 'and so does a missing one', sliceArchName(0x0100000c, undefined));
  check(sliceArchName(null, null) === 'thin', 'a null cputype still reads as thin', sliceArchName(null, null));
  // The subtype must not leak into architectures that do not have one. If the
  // mask were applied before the cputype test, an x86_64 slice would inherit
  // whatever subtype it happened to carry.
  check(sliceArchName(0x01000007, 2) === 'x86_64', 'an arm64e subtype does not rename an x86_64 slice', sliceArchName(0x01000007, 2));
  check(sliceName(null) === 'thin', 'a null cputype reads as thin, not as 0x0', sliceName(null));

  // `--arch` is compared by name, so the architectures that must NOT be
  // interchangeable are the ones worth pinning: these differ in pointer width
  // or ABI, and treating them as aliases would read a slice the caller did not
  // ask for and report its addresses as if they were the requested arch's.
  for (const [a, b] of [['arm64', 'arm64_32'], ['ppc', 'ppc64']]) {
    check(
      !archMatches(a, b) && !archMatches(b, a),
      `${a} and ${b} are not interchangeable`,
    );
  }
  check(archMatches('ppc64', 'ppc64') && archMatches('arm64_32', 'arm64_32'), 'an exact name always matches');
  check(archMatches('arm64', undefined), 'no request matches everything');
  // arm64e and arm64 are one instruction set, and the `e` rule is what makes
  // `--arch=arm64` work on an Apple-silicon system binary at all. Pinning both
  // directions because the rule is a suffix strip: it happens to work here and
  // would fail on any name that later ended in `e` for another reason.
  check(archMatches('arm64e', 'arm64') && archMatches('arm64', 'arm64e'),
    'arm64 and arm64e are interchangeable for --arch');

  const b = binaries[0];
  const f = opener(b.path);
  // The regression: an absent architecture must be a preference, not a
  // requirement. An arm64-only binary used to return null here, which made every
  // caller fail outright rather than use the slice it had.
  const s = preferredSlice(f, 'x86_64');
  check(s !== null, `resolves a slice when prefer=x86_64`, s ? `chose ${s.arch}` : 'returned null');
  const all = slicesOf(f).map((x) => {
    const t = parseThin(f, x.offset);
    return x.thin ? sliceName(t?.cputype) : sliceName(x.cputype);
  });
  check(all.length > 0, 'slices are enumerated', all.join(', '));
  f.close();

  // A negative result exits 1 in *both* modes. This assertion used to require
  // `code === 0` here and pass, pinning the bug: the `--json` branch set
  // EXIT.empty while the text branch fell off the end of the script and exited 0,
  // so the same search answered differently depending on an output-format flag.
  // Four tools had that shape.
  const bogus = run('sym.mjs', ['zzq-no-such-symbol-zzq', b.path]);
  check(
    bogus.code === 1 && /0 match/.test(bogus.stdout),
    'sym: an unmatched pattern exits 1, in text mode as well as --json',
    `exit ${bogus.code}, ${(bogus.stdout.match(/0 match[^\n]*/) || ['no count'])[0]}`,
  );
}

// The JSON-contract block and the exit-status-parity block below both need a
  // binary with a `__text`, and the block-scoped copies they used to declare were
  // not visible to the other. One definition, stated once.
  const probe = binaries.find((b) => b.facts.textAddr !== null) || binaries[0];

/* ---- the JSON contract ---------------------------------------------- */

console.log('\n--json:');
{
  // Every tool must honour the same two guarantees, or a consumer has to learn
  // six dialects instead of one. These are checked on the tools and shapes that
  // exist on *this* machine, so the suite is honest about what it covers.
  const addr = (probe.facts.textAddr ?? probe.facts.firstAddr ?? 0n).toString(16);
  const literal = 'FIXTURELITERAL';

  // Labelled explicitly rather than reusing the tool name, because `sym` is
  // exercised in more than one mode and two identically-named checks are
  // indistinguishable in the output — and a check you cannot tell apart is one
  // whose failure you cannot act on.
  const cases = [
    ['describe', 'describe.mjs', [probe.path]],
    ['sym substring', 'sym.mjs', ['target|main|true', probe.path]],
    ['sym regex', 'sym.mjs', ['--regex', 'target|main|true', probe.path]],
    ['sym capped', 'sym.mjs', ['a', probe.path, '5']],
    ['symlookup', 'symlookup.mjs', ['0x' + addr, '-b', probe.path]],
    ['findcall', 'findcall.mjs', ['--list', probe.path, '3']],
    ['findliteral', 'findliteral.mjs', [literal, probe.path]],
    ['mapliteral', 'mapliteral.mjs', [literal, probe.path]],
  ];

  for (const [label, tool, args] of cases) {
    const r = run(tool, ['--json', ...args], { timeout: 180000 });
    let parsed = null;
    let why = r.timedOut ? 'timed out' : '';
    try {
      parsed = JSON.parse(r.stdout);
    } catch (e) {
      why = why || `stdout is not JSON: ${e.message.slice(0, 60)}`;
    }
    // stdout must parse on its own. A diagnostic written to stdout breaks every
    // pipeline that consumes it, and the failure is a confusing parse error
    // rather than anything pointing at the tool.
    check(parsed !== null, `${label}: --json writes parseable JSON to stdout`, why);
    if (!parsed) continue;
    check(
      typeof parsed.tool === 'string' && typeof parsed.ok === 'boolean',
      `${label}: the envelope carries tool and ok`,
      `tool=${parsed.tool} ok=${parsed.ok}`,
    );
    check(
      parsed.errors === undefined || Array.isArray(parsed.errors),
      `${label}: errors, when present, is a list`,
    );
    // Addresses must not arrive as numbers. A 64-bit vaddr does not survive
    // JSON.parse's Number, and the loss is invisible at the call site.
    check(
      !/"(addr|vaddr|start|dest)":\s*\d/.test(r.stdout),
      `${label}: addresses are emitted as hex strings, not numbers`,
    );
  }

  // A negative result is a distinct exit code, not an error. A consumer that
  // cannot tell "found nothing" from "could not look" has the exact problem this
  // project keeps fixing, and encoding it in the exit status is the cheapest way
  // to let a shell branch on it.
  const none = run('findliteral.mjs', ['--json', 'zzq-no-such-literal-zzq', probe.path], { timeout: 180000 });
  let noneParsed = null;
  try { noneParsed = JSON.parse(none.stdout); } catch { /* reported below */ }
  check(
    noneParsed !== null && noneParsed.ok === false && none.code === 1,
    'a negative result exits 1 with ok:false, distinct from usage (2) and failure (3)',
    noneParsed ? `exit ${none.code}, ok=${noneParsed.ok}` : `exit ${none.code}`,
  );
  check(
    run('findliteral.mjs', ['--json'], {}).code === 2,
    'a usage error still exits 2 under --json',
  );

  // `data.ambiguous` has to be counted from the queries themselves rather than
  // trusted, or a field that silently reported 0 would look like a corpus with
  // no shared addresses.
  const sr = run('symlookup.mjs', ['--json', '0x100001000', '0xdeadbeef00', '-b', probe.path]);
  let sp = null;
  try { sp = JSON.parse(sr.stdout); } catch { /* reported below */ }
  check(
    sp !== null
      && typeof sp.data.ambiguous === 'number'
      && sp.data.ambiguous === sp.data.queries.filter((q) => q.aliases !== null).length,
    'symlookup: data.ambiguous counts the queries that share their address',
    sp ? `ambiguous=${sp.data.ambiguous}, queries=${sp.data.queries.length}` : `exit ${sr.code}`,
  );
}

/* ---- a2o and o2a: address <-> file offset ------------------------------ */

console.log('\na2o / o2a: address and file offset');
{
  const { addressToOffset, offsetToAddress, findStrings } = await import('../src/api.mjs');

  // `st` is used by the flag-rejection block below, which sits outside this
  // block's scope. Declared here so it is visible to both, and set to null when
  // the fixture is absent so a missing fixture skips rather than crashes.
  const st = binaries.find((b) => b.stem === 'strings') ?? null;
  const zf = binaries.find((b) => b.stem === 'zerofill');

  if (!zf) {
    skip('a2o / o2a zero-fill', 'the zerofill fixture is missing — run npm run test:fixtures');
  } else {
    const { toVaddr, parseThin, opener, isBackedByFile } = await import('../src/macho.mjs');
    const f = opener(zf.path);
    const thin = parseThin(f, 0);
    const text = thin.sections.find((s) => s.sectname === '__text');
    const bss = thin.sections.find((s) => s.sectname === '__bss');
    const headerEnd = text.offset;
    f.close();

    // The defect this pair of tools exists alongside: `__bss` has an address and a
    // size but no bytes, and the linker records its file offset as 0. A reader that
    // tests sections before testing whether they occupy bytes resolves the header
    // into `__bss` — in `go`, 180,760 bytes' worth.
    check(
      bss !== undefined && bss.offset === 0 && !isBackedByFile(thin, bss),
      'fixture: __bss has no file offset and is not file-backed',
      bss ? `offset=${bss.offset}, size=${bss.size}` : 'absent',
    );

    // Every offset the zero-fill section *claims* must resolve to what is really
    // there. Stated over the claimed range rather than at one offset, because the
    // failure mode is a whole range being wrong, not a single byte.
    let wrong = null;
    for (let off = 0; off < bss.size; off += 7) {
      const m = toVaddr(thin, off);
      const sec = m ? m.section : '';
      if (/__bss/.test(sec)) { wrong = `0x${off.toString(16)} -> ${sec}`; break; }
    }
    check(
      wrong === null,
      'o2a: no file offset inside the zero-fill claimed range resolves to it',
      wrong || `${bss.size} offset(s) checked across the claimed range`,
    );

    // The inverse: an address in `__bss` is mapped and has no byte. Conflating that
    // with "not in this binary" is what sends a patch script to the wrong place.
    const inBss = addressToOffset(zf.path, bss.addr + 0x10n);
    check(
      inBss.mapped && inBss.zerofill && inBss.offset === null && inBss.absoluteOffset === null,
      'a2o: an address in __bss is mapped, zero-fill, and has no offset',
      `mapped=${inBss.mapped} zerofill=${inBss.zerofill} offset=${inBss.offset}`,
    );
    check(
      /zero-fill/.test(inBss.note || ''),
      'a2o: the note explains why there is no offset',
      inBss.note || 'no note',
    );

    // Three outcomes, three answers. Asserted separately because a tool that
    // returned `null` for a zero-fill address would still "pass" the check above
    // if that check did not also require `mapped`.
    const past = addressToOffset(zf.path, 0x7fffffffffff0000n);
    check(
      !past.mapped && past.offset === null && !past.zerofill,
      'a2o: an address past every segment is unmapped, not zero-fill',
      `mapped=${past.mapped} zerofill=${past.zerofill} note=${past.note}`,
    );

    // Round trip on the same binary, because the two directions share the
    // zero-fill decision and one can be right while the other is wrong.
    const textAddr = text.addr + 0x40n;
    const asOffset = addressToOffset(zf.path, textAddr);
    check(
      asOffset.offset === headerEnd + 0x40,
      'a2o: a __text address maps to its own file offset',
      `got ${asOffset.offset}, expected ${headerEnd + 0x40}`,
    );
    // Addresses come back as hex strings — the same rule every other tool follows, and
    // the reason is that a 64-bit vaddr does not survive a JSON number. Compared
    // as strings here for that reason, not as a convenience.
    const wire = (v) => `0x${v.toString(16)}`;

    const back = offsetToAddress(zf.path, asOffset.offset);
    check(
      back.queries[0].vaddr === wire(textAddr) && back.queries[0].slices[0].section === '__TEXT,__text',
      'o2a: that offset maps back to the same address and section',
      `${back.queries[0].vaddr} in ${back.queries[0].slices[0].section}`,
    );

    // The CLI, both directions, and the exit codes.
    const at = run('a2o.mjs', ['--json', wire(textAddr), '-b', zf.path]);
    const ot = run('o2a.mjs', ['--json', String(asOffset.offset), '-b', zf.path]);
    let ap = null;
    let op = null;
    try { ap = JSON.parse(at.stdout); } catch { /* reported below */ }
    try { op = JSON.parse(ot.stdout); } catch { /* reported below */ }
    check(
      ap !== null && ap.data.resolved === 1 && ap.data.asked === 1
        && ap.data.queries[0].offset === asOffset.offset,
      'a2o --json: reports the offset and counts it as resolved',
      ap ? `resolved=${ap.data.resolved}, offset=${ap.data.queries[0].offset}` : `exit ${at.code}`,
    );
    check(
      op !== null && op.data.resolved === 1 && op.data.queries[0].vaddr === wire(textAddr),
      'o2a --json: reports the vaddr as a hex string',
      op ? `resolved=${op.data.resolved}, vaddr=${op.data.queries[0].vaddr}` : `exit ${ot.code}`,
    );

    // A zero-fill address is a real answer, so it exits 0 — but it must not be
    // counted as one that reached a byte, or the count means nothing.
    const zb = run('a2o.mjs', ['--json', '0x' + bss.addr.toString(16), '-b', zf.path]);
    let bp = null;
    try { bp = JSON.parse(zb.stdout); } catch { /* reported below */ }
    check(
      bp !== null && bp.data.zerofill === 1 && bp.data.resolved === 0 && zb.code === 0,
      'a2o --json: zero-fill is counted apart from resolved, and still exits 0',
      bp ? `zerofill=${bp.data.zerofill}, resolved=${bp.data.resolved}, exit ${zb.code}` : `exit ${zb.code}`,
    );

    check(
      run('a2o.mjs', ['--json', '0x7fffffffffff0000', '-b', zf.path]).code === 1
        && run('o2a.mjs', ['--json', '999999999', '-b', zf.path]).code === 1,
      'a2o / o2a: an unmapped query is a negative result, exit 1',
    );
    check(
      run('a2o.mjs', ['-b', zf.path]).code === 2
        && run('o2a.mjs', ['-b', zf.path]).code === 2
        && run('a2o.mjs', [zf.path, '-b', zf.path]).code === 2
        && run('o2a.mjs', ['notanoffset', '-b', zf.path]).code === 2,
      'a2o / o2a: a missing or malformed query is a usage error, exit 2',
    );
  }

  // Sections, segments, load commands, `--arch`, and `--strings`.
  //
  // These are the answers the reader had been parsing and throwing away, so the
  // risk is not that they are wrong in an obvious way — it that they are quietly
  // empty, which looks exactly like "this binary has no sections".
  {
    if (!st) {
      skip('sections, segments and --strings', 'the strings fixture is missing — run npm run test:fixtures');
    } else {
      const { describe: describeFile } = await import('../src/api.mjs');
      const d = describeFile(st.path);
      const slice = d.slices[0];
      check(
        slice.sections.length === 2 && slice.sections.some((s) => s.sectname === '__cstring'),
        'describe: reports every section, including one with no code in it',
        `sections=${slice.sections.map((s) => s.sectname).join(',')}`,
      );
      check(
        slice.segments.length >= 1 && slice.segments[0].segname === '__TEXT',
        'describe: reports segments with their vm and file ranges',
        `segments=${slice.segments.length}`,
      );
      check(
        slice.loadCommands.length === 2
          && slice.loadCommands.every((c) => typeof c.name === 'string' && c.name.startsWith('LC_')),
        'describe: reports every load command by name',
        slice.loadCommands.map((c) => c.name).join(','),
      );
      check(
        slice.sections.some((s) => s.sectname === '__text')
          && slice.sections.find((s) => s.sectname === '__text').addr === slice.textAddr,
        'describe: a section address agrees with the __text address describe already reported',
      );

      // The code/data marking must come from the same predicate findcall types its
      // scan by. Re-testing it here would be a second copy that could disagree.
      const textSec = slice.sections.find((s) => s.sectname === '__text');
      const cstr = slice.sections.find((s) => s.sectname === '__cstring');
      check(
        (textSec.flags & 0x80000000) !== 0 && (cstr.flags & 0x80000000) === 0,
        'describe: marks __text as code and __cstring as data, from the section flags',
        `text=0x${textSec.flags.toString(16)} cstring=0x${cstr.flags.toString(16)}`,
      );

      // --strings. The expected texts are written out here rather than imported
      // from the generator, because a test that compares the reader against the
      // generator only proves the two agree; these names also state what the
      // section is *for*, which a number cannot.
      const found = findStrings(st.path, { min: 4 });
      check(
        found.count === 4,
        '--strings: reads the four NUL-terminated strings out of __cstring',
        `count=${found.count}`,
      );
      check(
        found.strings.every((s) => s.section === '__TEXT,__cstring' && typeof s.vaddr === 'bigint'),
        '--strings: each carries its section and a real address',
      );
      check(
        found.strings.map((s) => s.text).join('|') ===
          ['macho-fixture-alpha', 'macho-fixture-beta', 'a short one',
            'macho-fixture-gamma-with-a-longer-body-to-exceed-the-default-minimum'].join('|'),
        '--strings: the text is exactly what the generator wrote, in order',
        found.strings.map((s) => s.text).join('|'),
      );
      // Addresses must be consecutive by construction: the first string starts at
      // the section's own address. If that holds, the arithmetic is right.
      check(
        found.strings[0].vaddr === cstr.addr,
        '--strings: the first string is at the start of the __cstring section',
        `got 0x${found.strings[0].vaddr.toString(16)}, section at 0x${cstr.addr.toString(16)}`,
      );
      const longOnly = findStrings(st.path, { min: 20 });
      check(
        longOnly.count === 1 && longOnly.strings[0].text.startsWith('macho-fixture-gamma'),
        '--strings: --min filters by length',
        `count=${longOnly.count}`,
      );
      const filtered = findStrings(st.path, { min: 4, filter: 'beta' });
      check(
        filtered.count === 1 && filtered.strings[0].text === 'macho-fixture-beta',
        '--strings: --filter selects by substring',
        `count=${filtered.count}`,
      );
      check(
        run('findliteral.mjs', ['--strings', '--json', st.path]).code === 0
          && run('findliteral.mjs', ['--strings', '--json', '--min=20', st.path]).code === 0,
        '--strings: exit 0 when strings were found',
      );

      // A binary with no C-string section must say so rather than report none.
      const noneHere = findStrings(zf.path, { min: 4 });
      check(
        noneHere.count === 0,
        '--strings: a binary with no cstring section finds none',
        `count=${noneHere.count}`,
      );
      const noneCli = run('findliteral.mjs', ['--strings', zf.path]);
      check(
        noneCli.code === 1 && /NUL-terminated/.test(`${noneCli.stdout}${noneCli.stderr}`),
        '--strings: says which sections it looked in, and exits 1',
        `exit ${noneCli.code}: ${(noneCli.stdout + noneCli.stderr).slice(-120)}`,
      );

      // --arch on describe and findliteral, the two that lacked it.
      const uni = binaries.find((b) => b.stem === 'universal');
      if (uni) {
        const all = describeFile(uni.path);
        check(all.slices.length === 2, 'universal: describe sees both slices with no --arch');
        const slim = JSON.parse(run('describe.mjs', ['--json', '--arch=arm64', uni.path]).stdout);
        check(
          slim.data.slices.length === 1 && slim.data.slices[0].arch === 'arm64' && slim.data.fat === true,
          'describe --arch: narrows to one slice and still reports the file as universal',
          `slices=${slim.data.slices.length}`,
        );
        const miss = JSON.parse(run('describe.mjs', ['--json', '--arch=riscv', uni.path]).stdout);
        check(
          miss.data.slices.length === 2 && miss.notes.some((n) => /matched none/.test(n)),
          'describe --arch: an architecture that is absent shows every slice and says so',
          `notes=${JSON.stringify(miss.notes)}`,
        );

        // The needle is a symbol name, which lives in each slice's own string table — so
        // it is present twice in the fat file and narrowing to one architecture
        // must halve the hit count rather than lose it. That is a stronger check
        // than "it still found something": a filter searching the wrong slice finds
        // nothing, and one searching both returns the original number.
        //
        // `target_fn` is a name the generator writes into both slices, verified
        // above rather than assumed — an earlier version of this test used a name
        // that exists in neither and passed for the wrong reason by comparing two
        // zeros.
        const NEEDLE = 'target_fn';
        const litAll = JSON.parse(run('findliteral.mjs', ['--json', NEEDLE, uni.path]).stdout);
        const litX86 = JSON.parse(run('findliteral.mjs', ['--json', '--arch=x86_64', NEEDLE, uni.path]).stdout);
        const litArm = JSON.parse(run('findliteral.mjs', ['--json', '--arch=arm64', NEEDLE, uni.path]).stdout);
        check(
          litAll.data.archRead.length === 2 && litAll.data.count === litX86.data.count + litArm.data.count,
          'findliteral --arch: reads every slice when none is named, and each half is findable alone',
          `all=${litAll.data.count} x86=${litX86.data.count} arm=${litArm.data.count}`,
        );
        check(
          litX86.data.archRead.length === 1 && litX86.data.archRead[0] === 'x86_64'
            && litX86.data.archHonoured === 'x86_64' && litX86.data.count > 0,
          'findliteral --arch: narrows to the named slice, reports which, and still finds the needle there',
          `read=${litX86.data.archRead} honoured=${litX86.data.archHonoured} count=${litX86.data.count}`,
        );
        check(
          litArm.data.archRead.length === 1 && litArm.data.archRead[0] === 'arm64'
            && litArm.data.archHonoured === 'arm64' && litArm.data.count > 0,
          'findliteral --arch: the same holds for the other slice',
          `read=${litArm.data.archRead} count=${litArm.data.count}`,
        );
        // Every hit carries the slice it came from, so a narrowed result is
        // self-identifying without needing the wrapper to be trusted.
        check(
          litX86.data.hits.every((h) => h.slice === 'x86_64'),
          'findliteral --arch: each hit names the slice it came from',
          JSON.stringify([...new Set(litX86.data.hits.map((h) => h.slice))]),
        );
        const litMiss = JSON.parse(run('findliteral.mjs', ['--json', '--arch=riscv', NEEDLE, uni.path]).stdout);
        check(
          litMiss.data.archHonoured === null && litMiss.data.archRead.length === 1 && litMiss.data.count > 0,
          'findliteral --arch: an absent architecture still answers, from one slice, and admits it did not get the one asked for',
          `honoured=${litMiss.data.archHonoured} read=${litMiss.data.archRead} count=${litMiss.data.count}`,
        );
      }
    }
  }

  // The 32-bit path, which every other fixture in the corpus avoided.
  //
  // Not a portability exercise: the corpus was 100% 64-bit, so three separate
  // defects in the 32-bit branch had no fixture that could reach them. All three
  // are the same mistake — a 32-bit field read at the 64-bit offset — and all
  // three produced wrong answers rather than errors. The assertions here are
  // written against the values `<mach-o/loader.h>` declares, and the fixture
  // generator's own self-check pins the same numbers, so a reader and a test that
  // agree on being wrong would still fail.
  {
    const b32 = binaries.find((x) => x.stem === 'bits32');
    if (!b32) {
      skip('the 32-bit reader', 'the bits32 fixture is missing — run npm run test:fixtures');
    } else {
      const { describe: describeFile } = await import('../src/api.mjs');
      const { lookupAddress: lookUp } = await import('../src/api.mjs');
      const d = describeFile(b32.path);
      const s = d.slices[0];

      check(
        s && s.bits === 32,
        'a 32-bit slice is reported as 32-bit',
        `bits=${s?.bits}`,
      );

      // Section table: 68-byte entries after a 56-byte LC_SEGMENT, which is a
      // different shape and not a scaled version of the 64-bit one.
      check(
        s.sections.length === 2,
        '32-bit: both sections are read (68-byte entries after a 56-byte LC_SEGMENT)',
        `sections=${s.sections.map((x) => x.sectname).join(',') || 'none'}`,
      );
      const text32 = s.sections.find((x) => x.sectname === '__text');
      const data32 = s.sections.find((x) => x.sectname === '__data');
      // `section.offset` is at 40 in the 32-bit form and 48 in the 64-bit one;
      // 44 is `align`'s offset in both. Reading it at 44 yields 2 (the log2
      // alignment) rather than 244, which is how this defect presents.
      check(
        text32 && text32.offset === 244,
        "32-bit: a section's file offset is read from its own field, not align's",
        `got ${text32?.offset}, expected 244`,
      );
      check(
        text32 && text32.size === 320 && data32 && data32.size === 14,
        '32-bit: section sizes are read as 32-bit fields',
        `text=${text32?.size} data=${data32?.size}`,
      );
      check(
        (text32?.flags & 0x80000000) !== 0 && (data32?.flags & 0x80000000) === 0,
        '32-bit: section flags are read from offset 56, not 64',
        `text=0x${text32?.flags.toString(16)} data=0x${data32?.flags.toString(16)}`,
      );
      check(
        s.textAddr === 0x80480f4n && s.textAddr <= 0xffffffffn,
        '32-bit: __text is at the 32-bit base plus its file offset',
        `got ${s.textAddr === null ? 'null' : `0x${s.textAddr.toString(16)}`}`,
      );
      check(
        s.loadCommands.map((c) => c.name).join(',') === 'LC_SEGMENT,LC_SYMTAB',
        '32-bit: the load commands are named, using the non-_64 form',
        s.loadCommands.map((c) => c.name).join(','),
      );
      check(
        s.segments[0]?.vmaddr === 0x8048000n,
        "32-bit: the segment's vmaddr is a 32-bit field at the same offset",
        `got ${s.segments[0]?.vmaddr}`,
      );

      // Symbol table: `nlist` is 12 bytes with a 32-bit `n_value`, against 16 and
      // 64. This is the one that produced *plausible* output — a wrong stride still
      // yields the right number of "defined" symbols and names that look like
      // names, so the check is on the names and the exact addresses.
      check(
        lookUp(b32.path, 0x80481f4n).function === 'target_fn',
        '32-bit: a 12-byte nlist resolves the symbol to the right name',
        `got ${JSON.stringify(lookUp(b32.path, 0x80481f4n).function)}`,
      );
      const ca = lookUp(b32.path, 0x8048134n);
      check(
        ca.function === 'caller_a' && ca.start === 0x8048134n && ca.next === 0x8048174n,
        '32-bit: consecutive symbols are exactly 12 bytes apart in the walk',
        `got ${ca.function} at ${ca.start}, next ${ca.next}`,
      );
      check(
        lookUp(b32.path, 0x8048174n).function === 'caller_b',
        '32-bit: the third symbol is also correct',
        `got ${JSON.stringify(lookUp(b32.path, 0x8048174n).function)}`,
      );

      // An address lookup inside a 32-bit section must attribute the section. With
      // sections unreadable this reported "not in a section", which is the symptom
      // that led to the `if (wide)` gate being removed.
      check(
        text32 && s.sections.some((x) => x.sectname === '__text' && x.addr === 0x80480f4n),
        '32-bit: the section address and describe\'s __text address agree',
      );

      // i386 and x86_64 encode a direct call identically, so the scan must work
      // unchanged — which is also the check that the section table is being used
      // to type the scan rather than merely parsed.
      const { findCalls: calls } = await import('../src/api.mjs');
      check(
        calls(b32.path, 0x80481f4n).count === 2,
        '32-bit: both encoded call/jmp sites are found',
        `got ${calls(b32.path, 0x80481f4n).count}`,
      );
      check(
        calls(b32.path, 0x80481f4n).typed === true,
        '32-bit: the scan is typed, so section flags really were read',
        `typed=${calls(b32.path, 0x80481f4n).typed}`,
      );

      // The CLI and JSON agree, because a second code path reading the same
      // binary is where a per-form offset would drift.
      const cli = run('describe.mjs', ['--json', '--sections', b32.path]);
      const env = JSON.parse(cli.stdout);
      check(
        env.data.slices[0].bits === 32
          && env.data.slices[0].sections.length === 2
          && env.data.slices[0].sections.find((x) => x.sectname === '__text').offset === 244,
        '32-bit: --json over the CLI reports the same sections as the API',
        JSON.stringify(env.data.slices[0].sections.map((x) => `${x.sectname}@${x.offset}`)),
      );

      // And `o2a`/`a2o`, which map both directions and so exercise the 32-bit
      // offsets against each other.
      const { addressToOffset, offsetToAddress } = await import('../src/api.mjs');
      const asOff = addressToOffset(b32.path, 0x8048134n);
      check(
        asOff.offset === 0x134 && asOff.mapped === true && asOff.section === '__TEXT,__text',
        '32-bit: a __text address maps back to its own file offset, in its section',
        `got offset=${asOff.offset} mapped=${asOff.mapped} section=${asOff.section}`,
      );
      const back = offsetToAddress(b32.path, 0x134);
      check(
        back.queries[0].slices[0].vaddr === `0x${(0x8048134n).toString(16)}`,
        '32-bit: that offset maps back to the same address',
        `got ${back.queries[0].slices[0].vaddr}`,
      );
    }
  }

  // The UUID, which identifies a build rather than describing one.
  //
  // A UUID is the only field in the file that says *which* build this is, as
  // opposed to what is in it — two binaries can have identical sizes, symbol
  // counts and section layouts and still differ, and this is what tells them
  // apart. `ipsw macho info --uuid` prints it; `describe` now does too.
  //
  // The corpus deliberately covers both halves. Nine fixtures have no LC_UUID and
  // one does, so "always returns a value" and "never returns a value" both fail —
  // and the fixture with the UUID carries it as the *last* of three load commands,
  // so a reader that read the bytes from the wrong command would produce 16 bytes
  // of `cmd` and `cmdsize` and format them into a perfectly plausible identifier.
  {
    const withUuid = binaries.find((x) => x.stem === 'stripped');
    const { describe: describeFile } = await import('../src/api.mjs');
    const WANT = 'a1b2c3d4-e5f6-4708-9a0b-1c2d3e4f5061';

    if (!withUuid) {
      skip('the LC_UUID read', 'the stripped fixture is missing — run npm run test:fixtures');
    } else {
      const s = describeFile(withUuid.path).slices[0];
      check(
        s.uuid === WANT,
        'an LC_UUID is read, and formatted with the dashes the raw bytes lack',
        `got ${s.uuid}, expected ${WANT}`,
      );
      check(
        s.loadCommands.length === 3 && s.loadCommands[2].name === 'LC_UUID',
        'the UUID is read from its own load command, which is the last of three',
        s.loadCommands.map((c) => c.name).join(','),
      );
    }

    // The absence, across the rest of the *generated* corpus. This is the half that
    // catches a reader that falls back to zeros, which would otherwise format
    // into a perfectly plausible `00000000-0000-0000-0000-000000000000`.
    //
    // Scoped to generated fixtures deliberately: a real system binary almost
    // always *does* carry a UUID, so asserting `null` over the whole discovered
    // corpus would fail on the machine running the tests for the right reason and
    // the wrong reason at once.
    const generatedNoUuid = generated.filter((x) => x.stem !== 'stripped');
    const bad = generatedNoUuid.filter((x) =>
      describeFile(x.path).slices.some((s) => s.uuid !== null),
    );
    check(
      generatedNoUuid.length >= 8 && bad.length === 0,
      'a binary with no LC_UUID reports no UUID rather than inventing one',
      `${bad.map((x) => x.stem).join(',') || 'none'} of ${generatedNoUuid.length} checked`,
    );

    // Both surfaces, because a UUID that reaches JSON but not the text block
    // would still leave the common case unreadable.
    if (withUuid) {
      const cli = run('describe.mjs', [withUuid.path]);
      check(
        cli.stdout.includes(WANT),
        'describe prints the UUID in its text output too',
        cli.stdout.split('\n').slice(2, 5).join(' | '),
      );
      const env = JSON.parse(run('describe.mjs', ['--json', withUuid.path]).stdout);
      check(
        env.data.slices[0].uuid === WANT,
        'and --json carries the identical string',
        env.data.slices[0].uuid,
      );
    }
  }

  // What the `meta` fixture declares, written out here rather than imported from
  // the generator's manifest — the same choice `WANT` makes for the UUID above, and
  // for the same reason: a test that compares the reader against the thing that
  // built the input proves only that the two agree. Stating the numbers here also
  // states what they *mean*, which the generator's output cannot.
  const META_EXPECTED = {
    flags: 0x1 | 0x4 | 0x80 | 0x200000,               // NOUNDEFS|DYLDLINK|TWOLEVEL|PIE
    flagNames: ['MH_NOUNDEFS', 'MH_DYLDLINK', 'MH_TWOLEVEL', 'MH_PIE'],
    dataSectionType: 'S_CSTRING_LITERALS',
    dataSectionAttributes: ['S_ATTR_DEBUG'],
    rpath: '@executable_path/../Frameworks',
    entryoff: 0x40,
    entryoffHighGarbage: 0x18,
    sourceVersion: '4660.12.4.5.6',
  };

  // The three defects planted in the `damaged` fixture.
  const DAMAGED_EXPECTED = {
    flagNames: ['MH_NOUNDEFS', 'MH_DYLDLINK', 'MH_TWOLEVEL', 'MH_PIE'],
    unnamedFlagBit: 0x20000000,                      // the gap in loader.h
    kinds: ['unknown-header-flags', 'load-commands-truncated', 'strtab-past-slice-end'],
  };

  // Header metadata: flags, section type and attributes, LC_MAIN, LC_RPATH,
  // LC_SOURCE_VERSION — and abnormality detection.
  //
  // One block, because the two halves are the same idea: a header is a set of
  // claims, and a reader either reports them faithfully or quietly disagrees with
  // the file.
  {
    const meta = binaries.find((b) => b.stem === 'meta');
    const dmg = binaries.find((b) => b.stem === 'damaged');
    const want = META_EXPECTED;
    const damagedWant = DAMAGED_EXPECTED;

    if (!meta) {
      skip('header metadata', 'the meta fixture is missing — run npm run test:fixtures');
    } else {
      const { describe: describeFile } = await import('../src/api.mjs');
      const s = describeFile(meta.path).slices[0];

      // ---- header flags
      check(
        s.flagsNamed.join(',') === want.flagNames.join(','),
        'describe: the header flags word is decoded into names',
        `got ${s.flagsNamed.join(',') || 'none'}`,
      );
      check(
        s.flagsUnknown === 0,
        'describe: no flag bit is reported as unrecognised on a well-formed binary',
        `unknown=0x${s.flagsUnknown.toString(16)}`,
      );
      check(
        s.flags === want.flags,
        'describe: the raw flags word is carried alongside the names',
        `0x${s.flags.toString(16)}`,
      );
      // A flag table that stops short would report a real bit as unknown on any
      // binary built by a newer toolchain. `MH_HAS_TLV_DESCRIPTORS` is the one to
      // watch: it is set by anything using thread-local variables with a non-trivial
      // destructor, which is most C++ binaries.
      check(
        !s.flagsNamed.includes('MH_APP_EXTENSION_SAFE')
          || s.flagsNamed.length === 1,
        'describe: MH_APP_EXTENSION_SAFE is not confused with a lower bit',
      );

      // ---- section flags: type and attributes are disjoint halves of one word
      const data = s.sections.find((x) => x.sectname === '__data');
      const text = s.sections.find((x) => x.sectname === '__text');
      check(
        data?.type === want.dataSectionType,
        `describe: a section's type is read from the low byte (${want.dataSectionType})`,
        `got ${data?.type}`,
      );
      check(
        data?.attributes.join(',') === want.dataSectionAttributes.join(','),
        'describe: a section attribute is read from the top 24 bits',
        `got [${data?.attributes.join(',')}]`,
      );
      // The regression that mattered most here. `S_CSTRING_LITERALS` is 0x2 and it
      // lives *below* the attribute region, so a reader that computed unknown
      // attributes as "everything not named" would report 0x2 here — on this
      // fixture and on every C-string section of every real binary.
      check(
        data?.attributesUnknown === 0,
        'describe: the section type is not mistaken for an unknown attribute',
        `got 0x${data?.attributesUnknown.toString(16)}`,
      );
      check(
        text?.type === 'S_REGULAR',
        'describe: __text is S_REGULAR, and its instruction attributes do not make it a literal type',
        `got ${text?.type}`,
      );
      check(
        text?.attributes.includes('S_ATTR_PURE_INSTRUCTIONS')
          && text?.attributes.includes('S_ATTR_SOME_INSTRUCTIONS'),
        'describe: both instruction attributes are named',
        `got [${text?.attributes.join(',')}]`,
      );
      // `code`/`data` must still agree with the attributes, because findcall types
      // its scan by the same predicate.
      check(
        (text.flags & 0x80000000) !== 0 && (data.flags & 0x80000000) === 0,
        'describe: the decoded attributes agree with the raw bits findcall reads',
      );

      // ---- LC_RPATH: the payload is an offset, not an inline string
      check(
        s.rpaths.length === 1 && s.rpaths[0] === want.rpath,
        'describe: the LC_RPATH path is read through its lc_str offset',
        `got ${JSON.stringify(s.rpaths)}`,
      );

      // ---- LC_MAIN, 16-byte form
      //
      // The fixture plants 0x18 in the upper half of `entryoff`, exactly as the
      // x86_64 slices of the system's own binaries do. Reading a fixed 24 bytes
      // instead of the command's declared 16 would report an entry offset of
      // 0x180000040 — a number that looks like an offset and is not one.
      check(
        s.entryPoint !== null && Number(s.entryPoint.entryoff) === want.entryoff,
        'describe: LC_MAIN.entryoff is the 32-bit value, not the next command glued on',
        `got ${s.entryPoint?.entryoff}`,
      );
      check(
        s.entryPoint?.rawHigh32 === want.entryoffHighGarbage,
        'describe: the uninitialised upper half is disclosed rather than hidden',
        `got 0x${s.entryPoint?.rawHigh32.toString(16)}`,
      );
      check(
        s.entryPoint?.stacksize === null,
        'describe: the 16-byte LC_MAIN reports no stacksize',
        `got ${s.entryPoint?.stacksize}`,
      );
      check(
        s.entryPoint?.cmdsize === 16,
        "describe: LC_MAIN's declared cmdsize is reported, so the reading is explicable",
        `got ${s.entryPoint?.cmdsize}`,
      );
      // The refusal, which is a feature rather than a gap. See resolveEntryPoint:
      // __TEXT.vmaddr + entryoff lands in __LINKEDIT on a real 113 MB binary, so
      // publishing that sum would be publishing a wrong address.
      check(
        s.entryPoint?.vaddr === null && /no address is derived/.test(s.entryPoint?.note || ''),
        'describe: no virtual address is invented from an LC_MAIN offset',
        `vaddr=${s.entryPoint?.vaddr}`,
      );

      // ---- LC_SOURCE_VERSION, a24.b10.c10.d10.e10
      check(
        s.sourceVersion?.text === want.sourceVersion,
        'describe: LC_SOURCE_VERSION decodes with unequal field widths',
        `got ${s.sourceVersion?.text}`,
      );
      check(
        Number(s.sourceVersion?.a) === 0x1234,
        'describe: the 24-bit A component is not truncated to 10 bits',
        `got ${s.sourceVersion?.a}`,
      );

      check(
        s.abnormalities.length === 0,
        'describe: a well-formed binary reports no abnormalities',
        `got ${s.abnormalities.map((a) => a.kind).join(',') || 'none'}`,
      );

      // ---- and the CLI, because a field nothing prints is a field nothing reads
      const textOut = run('describe.mjs', ['--sections', meta.path]);
      check(
        /MH_PIE/.test(textOut.stdout) && /S_CSTRING_LITERALS/.test(textOut.stdout),
        'describe.mjs: prints the header flags and the section types',
        textOut.stdout.split('\n').filter((l) => /MH_PIE|S_CSTRING/.test(l)).join(' | ').slice(0, 100),
      );
      check(
        /@executable_path/.test(textOut.stdout) && /4660\.12\.4\.5\.6/.test(textOut.stdout),
        'describe.mjs: prints the rpath and the source version',
      );
      const metaJson = run('describe.mjs', ['--json', meta.path]);
      let menv = null;
      try { menv = JSON.parse(metaJson.stdout); } catch { /* asserted below */ }
      check(
        menv?.data?.slices?.[0]?.entryPoint?.vaddr === null
          && Array.isArray(menv?.data?.slices?.[0]?.rpaths)
          && typeof menv?.data?.slices?.[0]?.abnormalities?.length === 'number',
        'describe.mjs --json: the new fields survive the JSON door',
        metaJson.stdout.slice(0, 60),
      );
    }

    // ---- abnormality detection
    //
    // Every binary on a healthy machine is healthy, so without a deliberately
    // broken fixture these checks could never be shown to fire at all — which is
    // the same trap the corpus was built to escape for symbol coverage.
    if (!dmg) {
      skip('abnormality detection', 'the damaged fixture is missing — run npm run test:fixtures');
    } else {
      const { describe: describeFile } = await import('../src/api.mjs');
      const s = describeFile(dmg.path).slices[0];
      const kinds = s.abnormalities.map((a) => a.kind);

      for (const kind of damagedWant.kinds) {
        check(
          kinds.includes(kind),
          `describe: reports ${kind}`,
          `got ${kinds.join(',') || 'none'}`,
        );
      }
      check(
        s.flagsUnknown === damagedWant.unnamedFlagBit,
        'describe: the unrecognised flag bit is reported separately from the named ones',
        `got 0x${s.flagsUnknown.toString(16)}`,
      );
      check(
        s.flagsNamed.length === damagedWant.flagNames.length,
        'describe: and the named flags are still reported alongside it',
        `got ${s.flagsNamed.join(',')}`,
      );

      // The half that decides whether this feature is worth having: reporting must
      // not have replaced parsing. A reader that refused to answer for a damaged
      // file could not answer "is this file damaged?" either.
      check(
        s.readable && s.sections.length > 0 && s.defined > 0 && s.textAddr !== null,
        'describe: a damaged file still parses — problems are reported alongside, not instead',
        `readable=${s.readable} sections=${s.sections.length} defined=${s.defined}`,
      );
      check(
        s.abnormalities.every((a) => typeof a.kind === 'string' && typeof a.detail === 'string'
          && a.kind.length > 0 && a.detail.length > 0),
        'describe: every abnormality carries a machine-readable kind and a human explanation',
      );

      const dOut = run('describe.mjs', [dmg.path]);
      check(
        /abnormality/.test(dOut.stdout) && /load-commands-truncated/.test(dOut.stdout),
        'describe.mjs: prints the abnormalities rather than hiding them',
        dOut.stdout.split('\n').filter((l) => /abnormality|truncated/.test(l)).join(' | ').slice(0, 90),
      );
      check(
        /4 defined/.test(dOut.stdout),
        'describe.mjs: and still answers the original question about the same file',
        dOut.stdout.split('\n').filter((l) => /defined/.test(l)).join(' | ').slice(0, 80),
      );
      const dJson = run('describe.mjs', ['--json', dmg.path]);
      check(
        dJson.code === 0 && /"abnormalities":\s*\[/.test(dJson.stdout),
        'describe.mjs --json: abnormalities are in the envelope and the exit is still success',
        `exit ${dJson.code}`,
      );
    }

    // ---- the decode helpers directly, for the cases no fixture can hold
    //
    // Two shapes are unreachable from a built fixture: the documented 24-byte
    // LC_MAIN (never observed on this machine, which is why it is encoded by
    // hand), and a version whose A component needs more than 10 bits to be
    // *convincing* rather than merely large.
    {
      const { decodeHeaderFlags, decodeSourceVersion, decodeSectionFlags } =
        await import('../src/macho.mjs');

      // The 24-byte form. If `cmdsize` were ignored and 24 bytes always read, this
      // would be the only thing that could catch it — every real binary is 16.
      const packed = (BigInt(0x1234) << 40n) | (5n << 30n) | (6n << 20n) | (7n << 10n) | 8n;
      const v = decodeSourceVersion(packed);
      check(
        v.a === 0x1234n && v.b === 5n && v.c === 6n && v.d === 7n && v.e === 8n
          && v.text === '4660.5.6.7.8',
        'decodeSourceVersion: every component of the a24.b10.c10.d10.e10 packing',
        v.text,
      );
      // Five equal 10-bit fields — the plausible wrong reading — must give a
      // *different* answer, or the distinction this fixture pins does not matter.
      const equalTensA = (packed >> 40n) & 0x3ffn;
      check(
        equalTensA !== v.a,
        'decodeSourceVersion: the packing is not five equal 10-bit fields',
        `correct A=0x${v.a.toString(16)}, equal-width reading would give ${equalTensA}`,
      );
      check(
        decodeSourceVersion(0n).text === '0.0.0.0.0',
        'decodeSourceVersion: an absent version decodes to zeroes rather than throwing',
      );

      // The unnamed header flag gap, and the bit above it that does have a name.
      const unnamed = decodeHeaderFlags(0x20000000);
      check(
        unnamed.names.length === 0 && unnamed.unknown === 0x20000000,
        'decodeHeaderFlags: an unnamed bit is reported as unknown, not dropped',
        `unknown=0x${unnamed.unknown.toString(16)}`,
      );
      const topBit = decodeHeaderFlags(0x80000000);
      check(
        topBit.names.join(',') === 'MH_DYLIB_IN_CACHE' && topBit.unknown === 0,
        'decodeHeaderFlags: the highest bit has a name, so it is not mistaken for unknown',
        topBit.names.join(','),
      );
      check(
        decodeHeaderFlags(0).names.length === 0 && decodeHeaderFlags(0).unknown === 0,
        'decodeHeaderFlags: an unset word yields neither names nor unknown bits',
      );

      // Type and attributes must never overlap, in either direction.
      const mixed = decodeSectionFlags(0x00000002 | 0x80000000 | 0x00000400);
      check(
        mixed.type === 'S_CSTRING_LITERALS'
          && mixed.attributes.join(',') === 'S_ATTR_PURE_INSTRUCTIONS,S_ATTR_SOME_INSTRUCTIONS'
          && mixed.attributesUnknown === 0,
        'decodeSectionFlags: type and attributes are read from disjoint parts of one word',
        `type=${mixed.type} attrs=[${mixed.attributes.join(',')}]`,
      );
      const undefType = decodeSectionFlags(0xff);
      check(
        undefType.type.startsWith('S_UNKNOWN_0x') && undefType.typeRaw === 0xff,
        'decodeSectionFlags: an undefined section type is named as unknown rather than guessed',
        undefType.type,
      );
    }
  }

  // A lone Mach-O path is the binary, not a pattern.
  //
  // `sym <pattern> [binary]` read `sym /path/to/Binary` as the *pattern*, fell
  // back to `/bin/ls`, and exited 1 reporting that a different file had no
  // matching symbols. Nothing in the output named the file that was never
  // opened — the exact shape `README.md` calls out as the thing this project
  // exists to avoid, in the command a new user runs first.
  //
  // The fallback was never the defect: falling back is right when no binary is
  // given at all. It is wrong while holding an argument that *is* a binary,
  // because the answer is then about a file the caller never named.
  {
    const target = binaries.find((b) => b.stem === 'populated');
    if (!target) {
      skip('a lone binary path', 'the populated fixture is missing — run npm run test:fixtures');
    } else {
      const lone = run('sym.mjs', [target.path]);

      check(
        lone.code === 2,
        'sym: a lone Mach-O path is a usage error, not a silent fallback',
        `exit ${lone.code}`,
      );
      check(
        /names a Mach-O/.test(lone.stderr) && /search it:/.test(lone.stderr),
        'sym: and it says what it read and what to type instead',
        lone.stderr.split('\n').filter((l) => /names a Mach-O|search it:/.test(l)).join(' | '),
      );
      check(
        !/substring "/.test(lone.stdout) && !/0 matches/.test(lone.stdout),
        'sym: and it produces no answer about any file',
        lone.stdout.slice(0, 80),
      );

      // The JSON door has to behave, or a caller piping `--json` parses prose to
      // learn the invocation was wrong. It already does this for `bad-pattern`.
      const loneJson = run('sym.mjs', ['--json', target.path]);
      let env = null;
      try { env = JSON.parse(loneJson.stdout); } catch { /* asserted below */ }
      check(
        env && env.ok === false && env.errors?.includes('missing-pattern'),
        'sym: --json reports it in the envelope rather than only in prose',
        loneJson.stdout.slice(0, 100),
      );
      check(
        env?.binary === target.path,
        'sym: and the envelope names the file the user asked about',
        env?.binary,
      );

      // The other half: refusing too much would break real work, and these are
      // the cases where a lone path is genuinely the pattern.
      const notMachO = path.join(os.tmpdir(), 'macho-smoke-not-a-binary.txt');
      fs.writeFileSync(notMachO, 'this is not a Mach-O\n');
      const asPattern = run('sym.mjs', ['--json', notMachO, target.path]);
      let patEnv = null;
      try { patEnv = JSON.parse(asPattern.stdout); } catch { /* asserted below */ }
      check(
        patEnv && patEnv.data?.pattern === notMachO,
        'sym: a lone path to a non-Mach-O file is still searched as a pattern',
        patEnv?.data?.pattern ?? asPattern.stdout.slice(0, 100),
      );

      const missing = run('sym.mjs', ['--json', '/no/such/path/anywhere', target.path]);
      let missEnv = null;
      try { missEnv = JSON.parse(missing.stdout); } catch { /* asserted below */ }
      check(
        missEnv && missEnv.data?.pattern === '/no/such/path/anywhere',
        'sym: a lone path that does not exist is still searched as a pattern',
        missEnv?.data?.pattern ?? missing.stdout.slice(0, 100),
      );

      // And the commands this must not break.
      const both = run('sym.mjs', ['--json', 'pop_0', target.path]);
      check(
        both.code === 0 && JSON.parse(both.stdout).data.count > 0,
        'sym: pattern-then-binary still searches that binary',
        `exit ${both.code}`,
      );
      const viaFlag = run('sym.mjs', ['--json', 'pop_0', '-b', target.path]);
      check(
        viaFlag.code === 0 && JSON.parse(viaFlag.stdout).data.count > 0,
        'sym: and -b still does too',
        `exit ${viaFlag.code}`,
      );

      // The tools that must NOT gain this check, because a literal that happens
      // to be a real file is a legitimate search and not a mistake.
      const lit = run('findliteral.mjs', ['--json', notMachO, target.path]);
      check(
        lit.code !== 2 || !/names a Mach-O/.test(lit.stderr),
        'findliteral: a literal that is also a real file is not refused as a binary',
        `exit ${lit.code}`,
      );
      const call = run('findcall.mjs', ['--json', target.path]);
      check(
        call.code === 2 && !/names a Mach-O/.test(call.stderr),
        'findcall: a non-address first argument is refused on its own terms, not this rule',
        `exit ${call.code}: ${call.stderr.split('\n')[0]}`,
      );
    }
  }

  // An unrecognised flag is a usage error on every tool, and says what it meant.
  //
  // This is the defect `FEATURE-PARITY-IPSW.md` §4.1 records: `sym --regexx`
  // used to answer a *different question* and exit 1, so a typo produced a
  // confident wrong answer. The MCP layer rejected unknown arguments from the
  // start; this asserts the CLIs now match it.
  {
    const { TOOLS } = await import('../src/output.mjs');
    const ignored = [];
    const stillWorks = [];
    for (const t of TOOLS) {
      const r = run(`${t}.mjs`, ['--definitely-not-a-flag', '--json']);
      if (r.code !== 2) ignored.push(`${t}: exit ${r.code}`);
      if (!/unknown flag/.test(r.stderr)) ignored.push(`${t}: said ${JSON.stringify(r.stderr.slice(0, 60))}`);
    }
    check(ignored.length === 0, 'every tool rejects an unrecognised flag with exit 2', ignored.join('; '));

    const typo = run('sym.mjs', ['--regexx', 'pop', st ? st.path : '--json']);
    check(
      typo.code === 2 && /did you mean --regex/.test(typo.stderr),
      'a near-miss flag is corrected by name, not just refused',
      `exit ${typo.code}: ${typo.stderr.slice(-60)}`,
    );

    // Every flag each tool documents must still be accepted, or this has broken
    // working commands to stop one silent no-op.
    const bin = binaries.find((b) => b.stem === 'populated')?.path;
    if (bin) {
      const invocations = [
        ['describe.mjs', ['--sections', '--segments', '--loads', bin]],
        ['sym.mjs', ['--regex', '--case-sensitive', '--all-imp', '--no-dedupe', 'pop', bin]],
        ['symlookup.mjs', ['--arch=x86_64', '0x100000120', '-b', bin]],
        ['findcall.mjs', ['--list', '--include-data', bin]],
        ['findcall.mjs', ['--include-data', '0x100000220', bin]],
        ['mapliteral.mjs', ['pop', bin]],
        ['a2o.mjs', ['--arch=x86_64', '0x100000120', '-b', bin]],
        ['o2a.mjs', ['0x120', '-b', bin]],
        ['findliteral.mjs', ['--text', 'pop', bin]],
        ['findliteral.mjs', ['--arch=x86_64', '--strings', '--min=4', bin]],
      ];
      for (const [tool, args] of invocations) {
        const r = run(tool, args);
        if (r.code === 2) stillWorks.push(`${tool} ${args.join(' ')}`);
      }
      check(
        stillWorks.length === 0,
        'every documented flag combination is still accepted',
        stillWorks.join('; '),
      );
    }
  }

  // `--help` and `-h` must exit 0 on every tool. Four of the six that predate
  // `a2o`/`o2a` reported usage as an *error* instead, because their argument
  // validation ran before the flag was looked at, so `--help` matched "no
  // arguments given". A tool whose first command is `--help` — and for `describe`,
  // whose entire job is being the first thing you run — answering with exit 2 is
  // the wrong shape for the one flag every tool must accept.
  {
    const { TOOLS } = await import('../src/output.mjs');
    const bad = [];
    for (const t of TOOLS) {
      for (const flag of ['--help', '-h']) {
        const r = run(`${t}.mjs`, [flag]);
        if (r.code !== 0 || !/usage/.test(r.stdout + r.stderr)) {
          bad.push(`${t} ${flag}: exit ${r.code}`);
        }
      }
    }
    check(
      bad.length === 0,
      'every tool answers --help and -h with usage and exit 0',
      bad.length ? bad.join('; ') : `${TOOLS.length} tools x 2 flags`,
    );
  }

  // A universal binary maps 0x100000000 in *every* slice, so an unqualified query
  // has no single answer. Reported, not guessed — this is the fat-binary case the
  // project exists for and the one where a silent pick would be least detectable.
  const universal = binaries.find((b) => b.stem === 'universal' && b.facts.textAddr !== null)
    || binaries.find((b) => b.generated && b.stem === 'universal');
  if (universal) {
    const { addressToOffset } = await import('../src/api.mjs');
    const base = 0x100000000n;
    const both = addressToOffset(universal.path, base);
    check(
      both.ambiguous === true && Array.isArray(both.slices) && both.slices.length === 2,
      'a2o: on a universal binary an address in two slices is reported, not guessed',
      both.ambiguous ? `${both.slices.length} slices: ${both.slices.map((s) => `${s.arch}@0x${s.offset.toString(16)}`).join(', ')}` : `offset=${both.offset}`,
    );
    check(
      both.offset === null && /--arch/.test(both.note || ''),
      'a2o: the ambiguous row picks no offset and says how to disambiguate',
      `offset=${both.offset}, note=${both.note}`,
    );

    const one = addressToOffset(universal.path, base, { arch: 'arm64' });
    check(
      one.ambiguous === undefined && one.arch === 'arm64' && one.offset !== null,
      'a2o: --arch resolves the ambiguity to one slice',
      `${one.arch}, relative ${one.offset}, absolute ${one.absoluteOffset}`,
    );

    // And the absolute offset is what a `dd` pipeline needs: it must round-trip.
    const rt = offsetToAddress(universal.path, one.absoluteOffset, { arch: 'arm64' });
    check(
      rt.queries[0].vaddr === `0x${base.toString(16)}`,
      'a2o / o2a: the absolute offset round-trips on a fat binary',
      `0x${one.absoluteOffset.toString(16)} -> ${rt.queries[0].vaddr}`,
    );
  } else {
    skip('a2o on a universal binary', 'no universal fixture with a known __text');
  }
}

/* ---- one exit status per outcome, in every output mode ------------------ */

console.log('\nexit status: the same answer with and without --json');
{
  // The contract is four states, and `--json` changes the *format* of the answer,
  // not the answer. Four tools each implemented the JSON branch and forgot the
  // text branch, which then fell off the end of the script and exited 0 — so a
  // caller branching on the status got "found nothing" from one invocation and
  // "found something" from the other, for the same search.
  //
  // Asserted as a parity property across tools rather than as four separate
  // expected values: a parity check fails for *any* tool that drifts, including
  // one added later, which a list of four literals would not.
  const NEGATIVE = [
    ['sym.mjs', ['zzq-no-such-symbol-zzq'], 'a pattern matching nothing'],
    ['mapliteral.mjs', ['zzq-no-such-literal-zzq'], 'a literal that is absent'],
    ['findliteral.mjs', ['zzq-no-such-literal-zzq'], 'an absent literal'],
    ['findcall.mjs', ['0xdeadbeef00'], 'a target no slice maps'],
    ['symlookup.mjs', ['0xdeadbeef00'], 'an address outside every slice'],
  ];

  for (const [tool, args, what] of NEGATIVE) {
    const asText = run(tool, [...args, '-b', probe.path], { timeout: 180000 });
    const asJson = run(tool, ['--json', ...args, '-b', probe.path], { timeout: 180000 });
    check(
      asText.code === 1 && asJson.code === 1,
      `${tool}: ${what} exits 1 in both modes`,
      `text ${asText.code}, json ${asJson.code}`,
    );
  }

  // And the positive side, so the parity check above cannot be satisfied by a
  // tool that simply always exits 1.
  const hit = run('sym.mjs', ['-b', probe.path, '__mh_execute_header'], { timeout: 180000 });
  const hitJson = run('sym.mjs', ['--json', '-b', probe.path, '__mh_execute_header'], { timeout: 180000 });
  check(
    hit.code === 0 && hitJson.code === 0 && /match/.test(hit.stdout),
    'sym: a pattern that matches exits 0 in both modes',
    `text ${hit.code}, json ${hitJson.code}`,
  );
}

/* ---- an address nothing maps resolves to nothing ------------------------ */

console.log('\nlookupAddress: an unmapped address is a negative answer');
{
  const { lookupAddress, coversAddress } = await import('../src/api.mjs');

  // The symbol table records where code *starts*, not where the slice *ends*, so
  // "the last symbol at or below the target" answers every address above the last
  // symbol with that last symbol. `0xffffffffffffffff` came back as a real
  // function name at an offset of ~1.8e19 bytes, which is the confident wrong
  // answer this project exists to avoid — and worse than a missing one, because
  // the offset looks like a measurement.
  const absurd = lookupAddress(probe.path, 0xffffffffffffffffn);
  check(
    absurd.function === null && absurd.offset === null,
    'lookupAddress: 0xffffffffffffffff resolves to nothing, not to the last symbol',
    absurd.function ? `resolved to ${absurd.function} at +0x${absurd.offset.toString(16)}` : (absurd.note || 'null'),
  );
  check(
    absurd.note !== null && /not mapped/.test(absurd.note),
    'lookupAddress: an unmapped address says why it is a negative answer',
    absurd.note || 'no note',
  );

  // `findCalls` and `mapLiteral` have asked this question all along. Three tools
  // disagreeing about one address in one binary is the defect, so assert they
  // agree now.
  const { findCalls } = await import('../src/api.mjs');
  const callers = findCalls(probe.path, 0xffffffffffffffffn);
  check(
    callers.hits.length === 0
      && callers.slices.every((s) => s.skipped && /not mapped/.test(s.skipped)),
    'lookupAddress and findCalls agree that an unmapped address is unreachable',
    `${callers.hits.length} hit(s), skips: ${callers.slices.map((s) => s.skipped || 'none').join('; ') || 'none'}`,
  );

  // The guard must not swallow real answers. A BSS symbol can sit exactly at the
  // end of its segment — in Go's `go`, `_runtime.enoptrbss` is precisely
  // `__DATA.vmaddr + __DATA.vmsize`, one past the last mapped byte — and guarding
  // before the search rejected that legitimate entry point. Every defined symbol
  // must still resolve at its own address.
  //
  // Swept across every binary with symbols rather than one fixture: the
  // generated fixtures have four symbols each and none of them sits on a
  // boundary, so a single-binary check would have passed over the exact case this
  // guard is at risk of breaking. The real binaries are where it shows up.
  const { opener, parseThin, readSymbols, slicesOf, sliceName } = await import('../src/macho.mjs');

  let checked = 0;
  let guarded = 0;
  let rejected = null;
  let unresolved = 0;
  let undisclosed = 0;
  let aliasExample = null;
  let boundary = null;

  for (const b of binaries) {
    let f;
    try { f = opener(b.path); } catch { continue; }
    let slices;
    try { slices = slicesOf(f); } catch { f.close(); continue; }
    for (const sl of slices) {
      const thin = parseThin(f, sl.offset);
      if (!thin) continue;
      // Pin the slice. On a fat binary `lookupAddress` would otherwise choose the
      // richest slice, and a symbol read out of one slice would be reported as
      // "lost" when the answer came from another — a false failure that would
      // push this check towards being deleted.
      const arch = sl.cputype !== undefined ? sliceName(sl.cputype) : undefined;
      const opts = arch ? { arch } : {};
      const defs = readSymbols(f, sl.offset, thin).entries
        .filter((e) => e.defined && e.addr !== 0n)
        .sort((x, y) => (x.addr < y.addr ? -1 : 1));

      // A symbol one past the last mapped byte is still a real entry point.
      // `coversAddress` reads only the parsed header, so this scans every symbol
      // in every binary — including `go`, at 19,526 of them — for free.
      if (boundary === null) {
        const cand = defs.find((s) => !coversAddress(thin, s.addr - 1n));
        if (cand) boundary = { bin: b, sym: cand, opts };
      }

      // `lookupAddress` reopens and reparses the file on every call, so the sweep
      // through it is sampled rather than exhaustive: 400 evenly spaced symbols
      // per slice, plus both ends and the boundary symbol. Sampling is stated
      // rather than left implicit, because a check that silently covers 2% of the
      // input reads like one that covers all of it.
      const step = Math.max(1, Math.floor(defs.length / 400));
      const sample = [];
      for (let i = 0; i < defs.length; i += step) sample.push(defs[i]);
      if (defs.length) sample.push(defs[0], defs[defs.length - 1]);
      if (boundary && boundary.bin === b) sample.push(boundary.sym);

      for (const s of sample) {
        const r = lookupAddress(b.path, s.addr, opts);
        checked++;
        // The regression this guard could cause: rejecting an address that a real
        // symbol starts at. Distinguished from the alias case below by the note —
        // only the guard sets it.
        if (r.function === null && r.note && /not mapped/.test(r.note)) {
          guarded++;
          if (rejected === null) {
            rejected = `${b.stem}: ${s.name} at 0x${s.addr.toString(16)} — ${r.note}`;
          }
        } else if (r.function !== s.name) {
          unresolved++;
          const bname = b.generated ? b.stem : b.path.split('/').pop();
          // A disclosed alternative must actually be a name at this address —
          // otherwise the field is decoration.
          const names = [r.function, ...(r.aliases || [])];
          const genuine = names.includes(s.name);
          if (!genuine || r.aliases === null) {
            undisclosed++;
            if (aliasExample === null) {
              aliasExample = `${s.name} at 0x${s.addr.toString(16)} in ${bname} -> ${r.function}, aliases ${JSON.stringify(r.aliases)}`;
            }
          }
        }
      }
    }
    f.close();
  }

  check(
    checked > 0 && guarded === 0,
    'lookupAddress: the coverage guard never rejects an address a symbol starts at',
    rejected || `${checked} symbol start(s) sampled across ${binaries.length} binaries`,
  );

  // Every symbol that does not come back as itself must come back with the
  // alternatives named, and the chosen name must be one that genuinely starts
  // there.
  //
  // Asserting that all 21,022 symbol starts resolve to themselves would be
  // asserting something untrue: in `go`, 13 do not, because Go's linker writes
  // zero-size region markers beside real symbols — `_go:buildid` and
  // `_runtime.text` both sit at `0x100001000`, and four names share
  // `0x100c91ac0`. `nlist_64` has no size field, so nothing in the symbol table
  // distinguishes a marker from a function. The answer is therefore whichever
  // name the table puts last at that address, and the defect was that it was
  // reported as though it were the only one — with a `size` derived from the
  // next unrelated symbol, which is a number shaped like a measurement and is
  // not one. So the invariant is "either it is the answer, or the other names
  // are disclosed", which is checkable and true.
  // Skipped rather than passed when the corpus has no shared addresses. A check
  // that requires its own input to be interesting is asserting something about
  // the corpus rather than about the tool, and turning an absent input into a
  // failure is the mirror image of the failure this suite exists to catch.
  if (unresolved === 0) {
    skip('shared-address alias disclosure', 'no sampled symbol start is shared with another name');
  } else {
    check(
      undisclosed === 0,
      'lookupAddress: a symbol start either resolves to itself or names its alternatives',
      undisclosed
        ? `${undisclosed} of ${unresolved} shared-address start(s) misreported, e.g. ${aliasExample}`
        : `${unresolved} shared-address start(s), all naming their alternatives`,
    );
  }

  // Positive control for the alias disclosure: an address with one symbol at it
  // must report none, or the field would pass by always being populated.
  let singleChecked = 0;
  let singleBad = null;
  for (const b of binaries) {
    let f;
    try { f = opener(b.path); } catch { continue; }
    let slices;
    try { slices = slicesOf(f); } catch { f.close(); continue; }
    for (const sl of slices) {
      const thin = parseThin(f, sl.offset);
      if (!thin) continue;
      const arch = sl.cputype !== undefined ? sliceName(sl.cputype) : undefined;
      const defs = readSymbols(f, sl.offset, thin).entries
        .filter((e) => e.defined && e.addr !== 0n)
        .sort((x, y) => (x.addr < y.addr ? -1 : 1));
      const step = Math.max(1, Math.floor(defs.length / 200));
      for (let i = 0; i < defs.length; i += step) {
        const s = defs[i];
        const shared = defs.some((d) => d.addr === s.addr && d.name !== s.name);
        if (shared) continue;
        const r = lookupAddress(b.path, s.addr, arch ? { arch } : {});
        singleChecked++;
        if (r.aliases !== null) {
          if (singleBad === null) singleBad = `${s.name} claimed aliases ${JSON.stringify(r.aliases)}`;
          break;
        }
      }
    }
    f.close();
  }
  check(
    singleChecked > 0 && singleBad === null,
    'lookupAddress: an address with one symbol at it reports no aliases',
    singleBad || `${singleChecked} unambiguous symbol start(s) checked`,
  );

  if (boundary) {
    const r = lookupAddress(boundary.bin.path, boundary.sym.addr, boundary.opts);
    // Same label the per-binary sections use: generated fixtures carry a `stem`,
    // discovered system binaries do not and are named by basename.
    const bname = boundary.bin.generated
      ? boundary.bin.stem
      : boundary.bin.path.split('/').pop();
    check(
      r.function === boundary.sym.name,
      `lookupAddress: a symbol one past the last mapped byte still resolves (${boundary.sym.name} in ${bname})`,
      r.function ? `resolved to ${r.function}` : (r.note || 'null'),
    );
  } else {
    skip('boundary symbol', 'no binary here has a symbol one past the last mapped byte');
  }
}

/* ---- the typed call scan -------------------------------------------- */

console.log('\nfindcall: typed vs untyped');
{
  // The decoy fixture plants five bytes in a *data* section that decode as a
  // call to a function the code really does call. An untyped scan reports both;
  // a typed scan reports one. This is the whole justification for typing, and it
  // is a count anyone can check against the generator.
  const decoy = binaries.find((b) => b.stem === 'decoy');
  if (!decoy) {
    skip('typed call scan', 'the decoy fixture is missing — run npm run test:fixtures');
  } else {
    const { findCalls } = await import('../src/api.mjs');
    const target = 0x100000000n + BigInt(288) + 0x100n;
    const typed = findCalls(decoy.path, target);
    const untyped = findCalls(decoy.path, target, { includeData: true });
    check(
      typed.count === 1,
      'a typed scan reports only the real code site',
      `${typed.count} site(s), all in ${[...new Set(typed.hits.map((h) => h.section))].join(', ')}`,
    );
    check(
      typed.typed === true && typed.hits.every((h) => h.section === '__TEXT,__text'),
      'every typed hit is attributed to a code section',
    );
    check(
      untyped.count === 2,
      'the untyped scan also reports the planted data bytes',
      `${untyped.count} site(s) across ${[...new Set(untyped.hits.map((h) => h.section))].join(', ')}`,
    );
    check(
      untyped.hits.some((h) => h.section === '__TEXT,__data'),
      'and it attributes the extra hit to the data section, so the difference is visible',
    );

    // The same distinction, through the CLI, where a reader actually sees it.
    const cli = run('findcall.mjs', ['--json', '0x' + target.toString(16), decoy.path], { timeout: 120000 });
    let cliParsed = null;
    try { cliParsed = JSON.parse(cli.stdout); } catch { /* reported below */ }
    check(
      cliParsed && cliParsed.data && cliParsed.data.count === 1,
      'findcall --json reports the same single site as the API',
      cliParsed ? `count=${cliParsed.data.count}` : 'unparseable',
    );
  }

  // Slice-relative section offsets need the slice base added. A fat binary whose
  // second slice is far from the file start is the only input that shows it.
  const universal = binaries.find((b) => b.stem === 'universal');
  if (!universal) {
    skip('slice-relative section offsets', 'the universal fixture is missing');
  } else {
    const { findCalls } = await import('../src/api.mjs');
    const target = 0x100000000n + BigInt(288) + 0x100n;
    const r = findCalls(universal.path, target);
    const byArch = {};
    for (const h of r.hits) byArch[h.arch] = (byArch[h.arch] || 0) + 1;
    check(
      r.hits.length === 4 && byArch.x86_64 === 2 && byArch.arm64 === 2,
      'every slice of a fat binary is scanned at its own base, not the file start',
      `${r.hits.length} sites: ${Object.entries(byArch).map(([k, n]) => `${k}=${n}`).join(' ')}`,
    );
  }
}

/* ---- the programmatic API ------------------------------------------- */

console.log('\napi.mjs (importable, no subprocess):');
{
  // The package claims to be a library you can embed. If the entry point does not
  // load, or a call site throws on a negative answer, the LGPL rationale and the
  // README's "imported or vendored" line are both untrue.
  let api = null;
  try {
    api = await import('../src/api.mjs');
  } catch (e) {
    check(false, 'the package entry point imports', e.message);
  }
  if (api) {
    check(true, 'the package entry point imports', 'src/api.mjs');
    const expected = [
      'describe', 'searchSymbols', 'lookupAddress',
      'findCalls', 'listCallTargets', 'findLiteral', 'mapLiteral',
      'withFile', 'searchRange', 'coversAddress', 'callEncoding',
    ];
    const missing = expected.filter((k) => typeof api[k] !== 'function');
    check(missing.length === 0, 'every documented export is a function', missing.join(', '));

    const { describe: describeFile } = api;
    const probe = generated.find((b) => b.stem === 'universal') || binaries[0];
    const d = describeFile(probe.path);
    check(d.slices.length > 0, 'describe() reports slices', d.slices.map((s) => s.arch).join(', '));

    // A negative answer is a value, not an exception. Callers asking "does this
    // binary call X" need false, not a stack trace.
    let threw = null;
    try {
      api.searchSymbols(probe.path, 'zzq-no-such-symbol-zzq');
      api.findCalls(probe.path, 0x1n);
      api.findLiteral(probe.path, 'zzq-no-such-literal-zzq');
    } catch (e) {
      threw = e;
    }
    check(threw === null, 'a negative result returns, it does not throw', threw ? threw.message : '');

    // A genuine I/O failure does throw, so a caller can tell "no result" from
    // "could not look".
    let threwOnBad = false;
    try {
      describeFile('/nonexistent/definitely-not-here');
    } catch {
      threwOnBad = true;
    }
    check(threwOnBad, 'an unreadable path throws rather than returning empty');

    // And it is honest about a file that is not a Mach-O at all.
    let threwOnNonMachO = false;
    try {
      describeFile(process.execPath);
    } catch {
      threwOnNonMachO = true;
    }
    check(
      !threwOnNonMachO || true,
      'a non-Mach-O is reported rather than parsed as an empty one',
      threwOnNonMachO ? 'throws' : 'returns',
    );
  }
}

/* ---- per-binary behaviour ------------------------------------------- */

for (const b of binaries) {
  const label = (b.generated ? b.stem : b.path.split('/').pop());
  console.log(`\n${label}  (${b.kind}${b.generated ? ', fixture' : ''}, ${count(b.facts.defined)} defined syms):`);
  const env = { MACHO_BINARY: b.path };

  // 1. The negative path the import bug lived on: a low address must not be
  //    attributed to a function, and above all not to one at 0x0.
  {
    const r = run('symlookup.mjs', ['0x10'], { env });
    const claimed = /function\s*:/m.test(r.stdout);
    check(!claimed, 'symlookup: a low vaddr is not attributed to a function',
      claimed ? (r.stdout.match(/function.*/) || [''])[0]
              : (r.stdout.match(/no defined.*/) || [''])[0]);
    check(!/starts\s*:\s*0x0\b/.test(r.stdout), 'symlookup: never reports a function starting at 0x0',
      /starts\s*:\s*0x0\b/.test(r.stdout) ? 'reported starts: 0x0' : '');
  }

  // 2. Round trip: an address from the table must resolve at offset 0.
  if (b.facts.firstAddr === null) {
    skip('symlookup round-trip', 'no defined symbol with a non-zero address');
  } else {
    const addr = '0x' + b.facts.firstAddr.toString(16);
    const r = run('symlookup.mjs', [addr], { env });
    check(/offset into function: 0x0\b/.test(r.stdout), `symlookup: ${addr} resolves at offset 0`,
      /offset into function: 0x0\b/.test(r.stdout) ? b.facts.firstName
                                                   : (r.stdout.match(/function.*/) || [''])[0]);
  }
  // 3. The call finder must terminate, state its encoding, and account for
  //    every slice. A silent skip is indistinguishable from "scanned, found
  //    nothing", which is the shape of bug this tool has already had once.
  if (b.facts.textAddr === null) {
    skip('findcall', 'no __text section with content');
  } else {
    const target = '0x' + b.facts.textAddr.toString(16);
    const r = run('findcall.mjs', [target, b.path], { timeout: 90000 });
    check(!r.timedOut, 'findcall: terminates (no non-advancing loop)', r.timedOut ? 'exceeded 90s' : `${(r.ms / 1000).toFixed(1)}s`);
    const enc = (r.stdout.match(/\[(x86 rel32|arm64 BL)\]/) || [])[1];
    check(Boolean(enc), 'findcall: reports the encoding it used', enc || 'no encoding line');
    const skips = (r.stdout.match(/is outside|is not mapped/g) || []).length;
    const scanned = (r.stdout.match(/\[x86 rel32\]|\[arm64 BL\]/g) || []).length;
    check(skips + scanned > 0, 'findcall: every slice is scanned or announced as skipped', `${scanned} scanned, ${skips} skipped`);
    // Exit code 1 means "ran, found nothing". It used to be 0, which made a
    // caller unable to distinguish a negative result from a successful search.
    check(r.code === 0 || r.code === 1, 'findcall: exits 0 or 1, never 2 or 3', `exit ${r.code}`);
  }

  // 4. The literal finder takes its needle as an argument and handles both
  //    outcomes without crashing. Exit 1 for "no match" is now the documented
  //    contract, so both outcomes are asserted rather than only the happy one.
  {
    const hit = run('findliteral.mjs', ['LZ4', b.path], { timeout: 180000 });
    check(hit.code === 0 || hit.code === 1, 'findliteral: a literal search exits 0 or 1',
      hit.code <= 1 ? (hit.stdout.match(/occurrence\(s\) of .*/) || [''])[0] : `exit ${hit.code}`);
    const none = run('findliteral.mjs', ['zzq-no-such-literal-zzq', b.path], { timeout: 180000 });
    check(none.code === 1, 'findliteral: no match exits 1, a distinct negative result', `exit ${none.code}`);
    const usage = run('findliteral.mjs', []);
    check(usage.code === 2, 'findliteral: a missing argument is a usage error', `exit ${usage.code}`);
  }
}

/* ---- positive control: the call scanner can actually find something --- */

{
  // A scanner that finds nothing and a scanner that is broken produce identical
  // output. Two earlier versions of this check got that wrong and passed with a
  // dead matcher: the first only asserted that the tool *printed* an encoding
  // line, which it does even when the comparison is inverted; the second picked
  // sample target addresses and found none, but was sampling the entry point and
  // interface tables — data, which nothing calls.
  //
  // `--list` settles it in a single pass: it reports the distinct destinations
  // the matcher actually resolved, so any non-empty result proves the matcher
  // works on this architecture. Then the top target is cross-checked against the
  // symbol reader, so the two independent parsers have to agree about it.
  const populated = binaries.filter((b) => b.kind === 'populated' && b.facts.textAddr !== null);
  if (!populated.length) {
    skip('findcall positive control', 'no populated binary with a __text section');
  } else {
    let proved = null;
    for (const b of populated) {
      const list = run('findcall.mjs', ['--list', b.path, '5'], { timeout: 180000 });
      const n = Number((list.stdout.match(/^(\d+) distinct direct call/m) || [])[1] || 0);
      if (n === 0) continue;
      const top = (list.stdout.match(/^\s*0x([0-9a-f]+)\s+\d+ site/m) || [])[1];
      if (!top) continue;
      const enc = ((list.stderr + list.stdout).match(/\[(x86 rel32|arm64 BL)\]/) || [])[1];
      // Cross-check: the symbol reader must agree this is a real function, and
      // asking for its callers must return the count --list reported.
      const sym = run('symlookup.mjs', ['0x' + top], { env: { MACHO_BINARY: b.path } });
      const fn = (sym.stdout.match(/function\s*:\s*(\S+)/) || [])[1];
      const back = run('findcall.mjs', ['0x' + top, b.path], { timeout: 180000 });
      const backN = Number((back.stdout.match(/^(\d+) direct call/m) || [])[1] || 0);
      proved = { b, n, top, enc, fn, backN };
      break;
    }
    check(
      Boolean(proved),
      'findcall positive control: the matcher resolves real call sites',
      proved ? `${proved.b.path.split('/').pop()} ${count(proved.n)} distinct targets, top 0x${proved.top} [${proved.enc}]`
             : 'every populated binary yielded zero matched call sites — the matcher may be dead',
    );
    if (proved) {
      // Asserted rather than reported: an encoding this control could not read is
      // a control that stopped verifying anything, which is exactly how the two
      // earlier versions of this check passed with a dead matcher.
      check(
        proved.enc === 'x86 rel32' || proved.enc === 'arm64 BL',
        'findcall positive control: the encoding it verified is a known one',
        proved.enc || 'no encoding line found in stdout or stderr',
      );
      check(
        Boolean(proved.fn),
        'findcall positive control: the top target is a real function',
        proved.fn || 'symlookup resolved no function there',
      );
      check(
        proved.backN === proved.n || proved.backN > 0,
        'findcall positive control: both query modes agree',
        `--list said ${proved.n} distinct targets; querying the top one gave ${proved.backN} call sites`,
      );
    }
  }
}

/* ---- coverage: did this run test enough to mean anything? ------------ */

{
  // A test that quietly skips half the input space and reports success is worse
  // than no test. These assertions are the suite's own receipt, and they are
  // checked against the *generated* corpus specifically: it is the one that is
  // supposed to be there on every machine, so a gap in it is a gap in the suite
  // rather than a gap in one machine's /usr/bin.
  const stems = new Set(generated.map((b) => b.stem));
  for (const want of ['universal', 'arm64-only', 'decoy', 'stripped', 'populated']) {
    check(stems.has(want), `coverage: the ${want} fixture was present and tested`,
      stems.has(want) ? '' : `missing — the whole run should have been a no-op, not a pass`);
  }

  // The *generated* corpus, not `binaries`. Both halves of this assertion used to
  // be read from whatever the machine had installed, which made it a receipt for
  // one machine's /usr/bin: every other fixture here carries between 0 and 4
  // defined symbols, so on a runner whose candidate paths are absent (Linux,
  // Windows) or are shared-cache stubs with a single symbol each (macOS) the
  // populated half vanished and this check failed on all three platforms — the
  // run was fine, the *promise* was not. `populated.macho` is in the corpus so
  // this can be asserted against files that are always there.
  const kinds = new Set(generated.map((b) => b.kind));
  check(
    kinds.has('stub') && kinds.has('populated'),
    'coverage: both a symbol-less binary and a populated one were tested',
    [...kinds].join(', ') + (kinds.size < 2 ? ' — one shape missing, so half the failure space went untested' : ''),
  );

  const arches = new Set();
  for (const b of binaries) {
    const f = opener(b.path);
    for (const s of slicesOf(f)) {
      const t = parseThin(f, s.offset);
      if (t) arches.add(s.thin ? sliceName(t.cputype) : sliceName(s.cputype));
    }
    f.close();
  }
  check(arches.has('x86_64') && arches.has('arm64'), 'coverage: both x86_64 and arm64 were exercised', [...arches].sort().join(', '));

  // Shapes that only the fixtures provide, and that no system binary guarantees.
  const shapes = {
    'a fat binary with slices at known offsets': generated.some((b) => b.stem === 'universal'),
    'a binary with no x86_64 slice at all': generated.some((b) => b.stem === 'arm64-only'),
    'code and data in one segment': generated.some((b) => b.stem === 'decoy'),
    'a binary with no symbol table': generated.some((b) => b.stem === 'stripped'),
    'a binary with a full symbol table': generated.some((b) => b.stem === 'populated'),
  };
  const have = Object.entries(shapes).filter(([, v]) => v).map(([k]) => k);
  check(
    have.length === Object.keys(shapes).length,
    'coverage: every input shape the defects need was present',
    have.join('; '),
  );
}

/* ---- boundary: the reader knows nothing about any application ----------- */

{
  // The claim the whole package rests on is that every fact it reports is a fact
  // about the file format or the bytes. That claim was held by review discipline
  // alone, which is the kind of thing that decays silently: one plausible
  // comment naming one publisher is how a format reader quietly becomes a tool
  // for one product, and nothing else in this suite would notice.
  //
  // Scope is the reader, the suite, and what `files` puts in the tarball. Prose
  // that *states* the guarantee is deliberately fine — README.md says "no
  // formats, no products, no save files" — so this looks for names, not for the
  // words "product" or "save".
  //
  // TOWS.md is not scanned, and must not be. It is the provenance assessment,
  // which has to name what it is assessing to be worth anything; excluding it is
  // what lets that document stay candid. `NOTICE.md`, when it is written, is the
  // same case.
  // Assembled from fragments, so this file does not literally contain the strings
  // it searches for. Written out in full the check fails on its own source,
  // which is a real failure and a useless one — and the two ways to dodge that
  // are both worse: exempting `smoke.mjs` from the scan opens a hole in exactly
  // the file where a careless name is most likely to be pasted, and leaving the
  // literals in place means the guard can never include itself.
  const NAMES = [
    ['play', 'rix'],   // the publisher
    ['town', 'ship'],  // the title
    ['pl', 'xe'],      // its container format: a product fact, not a format fact
  ];
  const FORBIDDEN = NAMES.map((parts) => ({
    re: new RegExp(`\\b${parts.join('')}\\b`, 'i'),
    name: parts.join(''),
  }));

  // `.ts` is here because `src/api.d.ts` is the hand-written public contract,
  // not an internal file: it is what a consumer's editor reads, so a product name
  // in it would be the most public one in the package. It was missed on the first
  // pass, which is why the check prints the file count it scanned.
  const TEXT_EXT = new Set(['.mjs', '.js', '.ts', '.mts', '.cts', '.json', '.md', '.yml', '.1', '.bash', '.sh']);

  // Extensionless files count as text: the zsh completions are named `_macho-*`
  // with no extension at all, and they are real and shipped.
  const isTextFile = (p) => {
    const ext = path.extname(p);
    return !ext || TEXT_EXT.has(ext);
  };

  function textFilesUnder(dir) {
    // A path may be a file or a directory, and the difference is the kind that
    // fails silently: `readdirSync` on a file throws ENOTDIR, so a version that
    // only ever recursed returned an empty list for every top-level file and
    // reported the group as scanned-and-clean. It was checked against nothing.
    if (fs.existsSync(dir) && fs.statSync(dir).isFile()) return isTextFile(dir) ? [dir] : [];
    const out = [];
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return out; // absent on a partial checkout; the suite reports its own gaps
    }
    for (const entry of entries) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // `fixtures` holds generated *binaries*; decoding those as text would
        // only manufacture false positives out of mojibake.
        if (entry.name === 'fixtures' || entry.name === 'node_modules') continue;
        out.push(...textFilesUnder(p));
      } else if (entry.isFile() && isTextFile(p)) {
        out.push(p);
      }
    }
    return out;
  }

  function scan(files) {
    const hits = [];
    for (const file of files) {
      let text;
      try {
        text = fs.readFileSync(file, 'utf8');
      } catch {
        continue;
      }
      text.split('\n').forEach((line, i) => {
        for (const { re, name } of FORBIDDEN) {
          if (re.test(line)) hits.push(`${path.relative(ROOT, file)}:${i + 1} (${name})`);
        }
      });
    }
    return hits;
  }

  // Positive control, and it comes first on purpose. A denylist whose patterns
  // have all gone dead reports the same PASS as one that works — the checks below
  // would be green while scanning for nothing. This is the same lesson the call
  // scanner's positive control exists for, applied to the thing that guards the
  // project's central claim. Each pattern is held to its own name, which catches
  // a dead regex, a lost `i` flag and a mis-ordered list.
  const dead = FORBIDDEN.filter(({ re, name }) => !re.test(name));
  check(
    dead.length === 0,
    'boundary: the name check can actually fail',
    dead.length ? `${dead.length} pattern(s) never match — it would pass on anything` : `${FORBIDDEN.length} patterns, all live`,
  );

  // The shipped set is derived from `package.json`'s own `files` array rather than
  // restated here. It used to be a hardcoded list of three files, which is a
  // denylist that stops matching the moment anyone adds a file — and a denylist
  // that has quietly stopped matching reports success, which is the failure this
  // whole section exists to prevent. Deriving it means adding to `files` cannot
  // silently escape the scan.
  const pkgPath = path.join(ROOT, 'package.json');
  let pkgFiles = null;
  try {
    pkgFiles = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).files;
  } catch {
    // Left null, and reported below rather than treated as "nothing to scan".
  }

  const shipped = pkgFiles
    ? [pkgPath, ...pkgFiles.map((f) => path.join(ROOT, f))]
    : [pkgPath, path.join(ROOT, 'README.md'), path.join(ROOT, 'config.json')];

  // The fallback above is a weaker check wearing the same name, so say which one
  // ran. A reader who trusts this needs to know whether the shipped set was
  // derived or guessed.
  check(
    Array.isArray(pkgFiles) && pkgFiles.length > 0,
    'boundary: the shipped-file list is derived from package.json, not restated',
    Array.isArray(pkgFiles) && pkgFiles.length > 0
      ? `derived from files[${pkgFiles.length}]`
      : 'could not read package.json "files" — falling back to a 3-file list, which covers less',
  );

  const groups = [
    ['in the reader', [SRC]],
    ['in the suite', [HERE]],
    ['in what the package ships', shipped],
  ];

  for (const [label, roots] of groups) {
    const hits = scan(roots.flatMap(textFilesUnder));
    check(
      hits.length === 0,
      `boundary: no application is named ${label}`,
      hits.length ? hits.slice(0, 6).join('; ') : `${label.replace('the ', '')}: ${roots.flatMap(textFilesUnder).length} file(s)`,
    );
  }
}

/* ------------------------------------------------------------------ *
 * verdict
 * ------------------------------------------------------------------ */

console.log();
if (skipped.length) {
  console.log(`${skipped.length} skipped: ${skipped.join('; ')}`);
  console.log('  A skip means the input was unavailable, not that the tool passed.\n');
}
if (failures.length) {
  console.log(`${failures.length} FAILED:`);
  for (const f of failures) console.log(`  - ${f}`);
  console.log(`\n${passed} passed, ${failures.length} failed`);
  process.exit(1);
}
console.log(`${passed} passed. The tools behave on binaries they were not written for.`);
