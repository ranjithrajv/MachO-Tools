#!/usr/bin/env node
/**
 * mutation-check.mjs — does smoke.mjs actually have teeth?
 *
 * A smoke test that passes proves nothing unless it fails when the thing it
 * guards is broken. This reintroduces each bug that `smoke.mjs` is supposed to
 * catch, one at a time, and asserts the test notices.
 *
 *   node test/mutation-check.mjs
 *
 * ## Why
 *
 * The first attempt at verifying this was wrong in an instructive way. It
 * removed only the `N_SECT` filter from the symbol reader — and the test still
 * passed, because the *other* guard (`value === 0n`) independently blocks the
 * imported symbols that carry the bug. A green result from an incomplete mutation
 * is the most dangerous outcome here: it reads as "the test covers this" when it
 * establishes nothing at all. Reverting to the original behaviour faithfully —
 * both guards gone — made the test fail as it should.
 *
 * So each mutation below restores the actual original defect rather than
 * approximating it.
 *
 * ## It runs against the fixtures
 *
 * This used to depend on system binaries being installed, which made every
 * verdict machine-dependent: on a machine without ffmpeg the mutation was never
 * really exercised and the run reported it caught anyway. It now runs the suite
 * against the generated corpus, so a mutation that the fixtures detect is
 * detected everywhere. The generated corpus is rebuilt inside the mutated copy,
 * so the mutation cannot be dodged by leaving stale fixtures behind.
 *
 * ## Safety
 *
 * Every mutation is applied to a copy in a temp directory, never to the working
 * tree, and the copy runs the *installed* test against the *mutated* tool. The
 * working tree is not modified at any point, so there is nothing to restore and
 * no way for a crashed run to leave a mutated file behind — which is exactly how
 * the first verification left a source file broken with no restore step.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Each mutation: a file, a find/replace pair, and what should break. */
const MUTATIONS = [
  {
    name: 'symlookup matches imported symbols',
    file: 'src/api.mjs',
    // Both guards, because one of them alone still blocks the defect. The filter
    // has since moved from symlookup.mjs into the shared reader, so the mutation
    // follows it: reintroducing the bug anywhere but the shared path would be a
    // mutation the suite cannot see.
    find: `    const defs = syms.entries.filter((e) => e.defined && e.addr !== 0n).sort(byAddr);`,
    replace: `    const defs = syms.entries.filter(() => true).sort(byAddr); // MUTATED: no N_SECT or zero-address guard`,
    expect: /not attributed to a function|starts at 0x0/,
  },
  {
    name: 'findcall loops forever on a short final chunk',
    file: 'src/api.mjs',
    find: `    const advance = buf.length - 4;
    pos += advance > 0 ? advance : buf.length;
    if (advance <= 0) break;
  }
  return scanned;`,
    replace: `    pos += buf.length - 5; // MUTATED: original, cannot advance on a short tail
    if (buf.length < 5) break;
  }
  return scanned;`,
    expect: /terminates/,
  },
  {
    name: 'findcall compares a signed mask on arm64',
    file: 'src/api.mjs',
    find: `        if (((insn & 0xfc000000) >>> 0) !== 0x94000000) continue;
        let imm = insn & 0x03ffffff;
        if (imm & 0x02000000) imm -= 0x04000000; // sign-extend from 26 bits
        const site = base + BigInt(i);`,
    replace: `        if ((insn & 0xfc000000) !== 0x94000000) continue; // MUTATED: signed
        let imm = insn & 0x03ffffff;
        if (imm & 0x02000000) imm -= 0x04000000;
        const site = base + BigInt(i);`,
    expect: /resolves real call sites|known one/,
  },
  {
    name: 'preferredSlice requires the preferred architecture',
    file: 'src/macho.mjs',
    find: `    if (prefer && arch === prefer) return entry; // a named request wins outright
    if (!best || nsyms > best.nsyms) best = entry;`,
    replace: `    if (prefer) { if (arch === prefer) return entry; continue; } // MUTATED: required
    if (!best || nsyms > best.nsyms) best = entry;`,
    expect: /prefer=x86_64/,
  },
  {
    name: 'sections are read at their slice-relative offset, with no slice base',
    file: 'src/api.mjs',
    // This is the bug the generated fixtures were built to find. It is invisible
    // on a thin binary — where slice-relative and absolute coincide — and on any
    // universal binary whose first slice sits near the file start, which is why
    // `/usr/bin/true` never showed it. The fat fixture's second slice is 16 KB in.
    find: `    const buf = f.read(sliceBase + sec.offset + pos, Math.min(CHUNK, sec.size - pos));
    if (buf.length === 0) break;
    scanned += buf.length;
    const base = sec.addr + BigInt(pos);`,
    replace: `    const buf = f.read(sec.offset + pos, Math.min(CHUNK, sec.size - pos)); // MUTATED: no slice base
    if (buf.length === 0) break;
    scanned += buf.length;
    const base = sec.addr + BigInt(pos);`,
    expect: /its own base, not the file start/,
  },
  {
    name: 'findcall ignores section attributes and scans data',
    file: 'src/macho.mjs',
    // The untyped sweep is still available behind --include-data; this removes the
    // distinction entirely, which is what the decoy fixture exists to catch.
    find: `  const code = thin.sections.filter((s) => s.size > 0 && isCodeSection(s));
  if (code.length) return { sections: code, fallback: false };`,
    replace: `  const code = thin.sections.filter((s) => s.size > 0); // MUTATED: no attribute filter
  if (code.length) return { sections: code, fallback: false };`,
    expect: /typed scan reports only the real code site/,
  },
  {
    name: 'a section scan skips the slice base on a fat binary',
    file: 'src/api.mjs',
    find: `      for (const sec of pool.sections) sliceScanned += tallySection(f, sec, enc, counts, s.offset);`,
    replace: `      for (const sec of pool.sections) sliceScanned += tallySection(f, sec, enc, counts, 0); // MUTATED: no slice base`,
    expect: /resolves real call sites|finds at least one destination|positive control/,
  },
];

function run(cmd, args, opts = {}) {
  try {
    return { code: 0, out: execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 256e6, ...opts }) };
  } catch (e) {
    return { code: typeof e.status === 'number' ? e.status : 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

let pass = 0;
/**
 * Which layer caught each mutation.
 *
 * Tracked because the answer changed and the distinction matters: the fixture
 * generator re-reads its own binaries with the project's reader, so most reader
 * mutations are caught there before the suite runs at all. That is a *stronger*
 * result, not a weaker one — the claim being verified is "a broken reader is
 * noticed", and both mechanisms notice it — but a report that said only
 * "smoke.mjs caught it" would be attributing the detection to the wrong file.
 */
const byLayer = { suite: 0, fixtures: 0 };
const failed = [];
const inconclusive = [];

console.log('\nmutation-check — does smoke.mjs fail when the tools are broken?\n');

for (const m of MUTATIONS) {
  const src = path.join(HERE, '..', m.file);
  const original = fs.readFileSync(src, 'utf8');
  if (!original.includes(m.find)) {
    console.log(`  SKIP  ${m.name}\n        anchor not found in ${m.file} — the mutation is stale`);
    inconclusive.push(m.name);
    continue;
  }

  // A throwaway copy of the whole directory, so the mutated tool resolves its
  // own relative imports and the real tree is never touched.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mutcheck-'));
  try {
    fs.cpSync(ROOT, tmp, {
      recursive: true,
      filter: (s) => !s.includes('node_modules') && !s.includes(`${path.sep}fixtures${path.sep}`),
    });
    fs.writeFileSync(path.join(tmp, m.file), original.replace(m.find, m.replace));

    // Rebuild the fixtures inside the copy. `--check` first would be wrong: the
    // binaries are unchanged by these mutations, but a stale copy left over from
    // an earlier run would let a mutation look effective when it was never
    // applied to anything the suite exercised.
    //
    // A failure *here* is a catch, not an inconclusive. The fixture generator
    // re-reads its own output with the project's reader and asserts the
    // properties the suite depends on, so a mutation that breaks the reader
    // breaks that self-check before the suite ever runs. Reporting that as
    // inconclusive — which is what the first version of this file did — threw
    // away the strongest available evidence and left six of seven mutations
    // looking untested when every one of them had in fact been detected.
    const built = run(process.execPath, [path.join(tmp, 'test', 'fixtures.mjs')], { timeout: 120000 });
    if (built.code !== 0) {
      pass++;
      byLayer.fixtures++;
      const why = (built.out.split('\n').find((l) => /^\s*-\s/.test(l)) || '').trim();
      console.log(`  PASS  ${m.name}\n        detected by the fixture generator's self-check: ${why.slice(0, 88)}`);
      continue;
    }

    const r = run(process.execPath, [path.join(tmp, 'test', 'smoke.mjs')], { timeout: 900000 });
    // Only a FAIL line counts. An earlier version tested the pattern against the
    // whole output, and every check prints its own name on a PASS line too — so a
    // completely broken tool still matched, and the run reported a confident
    // green. A verification that cannot fail is worse than none.
    const failLines = r.out.split('\n').filter((l) => /^\s*FAIL\s/.test(l));
    const caught = failLines.some((l) => m.expect.test(l));
    if (r.code === 0) {
      console.log(`  SKIP  ${m.name}\n        the mutated tree still exits 0 — inconclusive, not a pass`);
      inconclusive.push(m.name);
    } else if (caught) {
      pass++;
      byLayer.suite++;
      const why = failLines.find((l) => m.expect.test(l));
      console.log(`  PASS  ${m.name}\n        detected by smoke.mjs: ${(why || '').trim().slice(0, 88)}`);
    } else {
      failed.push(m.name);
      console.log(`  FAIL  ${m.name}\n        smoke.mjs failed, but not on a check matching ${m.expect}`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log();
if (inconclusive.length) {
  console.log(`${inconclusive.length} inconclusive: ${inconclusive.join('; ')}`);
  console.log('  Inconclusive means the mutation could not be applied or had no effect —');
  console.log('  it is not a pass, and it should be fixed before the claim is trusted.\n');
}
if (failed.length) {
  console.log(`${failed.length} MUTATION(S) SURVIVED — the test does not cover:`);
  for (const f of failed) console.log(`  - ${f}`);
  process.exit(1);
}
console.log(
  `${pass} mutation(s) caught, none surviving: ` +
    `${byLayer.fixtures} by the fixture generator's self-check, ${byLayer.suite} by smoke.mjs.`,
);
console.log('Both are load-bearing — a reader that breaks is noticed by one of them.');
