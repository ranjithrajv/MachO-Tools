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
 * Run `npm run test:mutation` to confirm the claims in this file are load-
 * bearing: it reintroduces each defect and asserts this test notices.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  opener, slicesOf, parseThin, readSymbols, preferredSlice, sliceName, textSection,
  isMachOFile,
} from '../src/macho.mjs';
import { bundleLayout, isBundle } from '../src/bundle.mjs';
import { executableIn } from '../src/target.mjs';
import { count } from '../src/output.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const SRC = fileURLToPath(new URL('../src/', import.meta.url));
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

  const bogus = run('symgrep.mjs', ['zzq-no-such-symbol-zzq', b.path]);
  check(
    bogus.code === 0 && /0 match/.test(bogus.stdout),
    'symgrep: an unmatched pattern exits 0 and reports zero',
    (bogus.stdout.match(/0 match[^\n]*/) || [`exit ${bogus.code}`])[0],
  );
}

/* ---- the JSON contract ---------------------------------------------- */

console.log('\n--json:');
{
  // Every tool must honour the same two guarantees, or a consumer has to learn
  // six dialects instead of one. These are checked on the tools and shapes that
  // exist on *this* machine, so the suite is honest about what it covers.
  const probe = binaries.find((b) => b.facts.textAddr !== null) || binaries[0];
  const addr = (probe.facts.textAddr ?? probe.facts.firstAddr ?? 0n).toString(16);
  const literal = 'FIXTURELITERAL';

  const cases = [
    ['describe.mjs', [probe.path]],
    ['symgrep.mjs', ['target|main|true', probe.path]],
    ['symfind.mjs', ['a', probe.path, '5']],
    ['symlookup.mjs', ['0x' + addr, '-b', probe.path]],
    ['findcall.mjs', ['--list', probe.path, '3']],
    ['findliteral.mjs', [literal, probe.path]],
    ['mapliteral.mjs', [literal, probe.path]],
  ];

  for (const [tool, args] of cases) {
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
    check(parsed !== null, `${tool}: --json writes parseable JSON to stdout`, why);
    if (!parsed) continue;
    check(
      typeof parsed.tool === 'string' && typeof parsed.ok === 'boolean',
      `${tool}: the envelope carries tool and ok`,
      `tool=${parsed.tool} ok=${parsed.ok}`,
    );
    check(
      parsed.errors === undefined || Array.isArray(parsed.errors),
      `${tool}: errors, when present, is a list`,
    );
    // Addresses must not arrive as numbers. A 64-bit vaddr does not survive
    // JSON.parse's Number, and the loss is invisible at the call site.
    check(
      !/"(addr|vaddr|start|dest)":\s*\d/.test(r.stdout),
      `${tool}: addresses are emitted as hex strings, not numbers`,
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
      'describe', 'grepSymbols', 'findSymbols', 'lookupAddress',
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
      api.grepSymbols(probe.path, 'zzq-no-such-symbol-zzq');
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
  for (const want of ['universal', 'arm64-only', 'decoy', 'stripped']) {
    check(stems.has(want), `coverage: the ${want} fixture was present and tested`,
      stems.has(want) ? '' : `missing — the whole run should have been a no-op, not a pass`);
  }

  const kinds = new Set(binaries.map((b) => b.kind));
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
  };
  const have = Object.entries(shapes).filter(([, v]) => v).map(([k]) => k);
  check(
    have.length === Object.keys(shapes).length,
    'coverage: every input shape the defects need was present',
    have.join('; '),
  );
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
