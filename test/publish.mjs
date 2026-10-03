#!/usr/bin/env node
/**
 * Can this package actually be published, and does it say what it publishes?
 *
 * `npm publish --dry-run` is the command that looks like this check and is not
 * one. It packs the tarball, prints `+ MachO-Tools@0.1.0` and exits 0 — on a name
 * npm refuses outright:
 *
 *     npm error 404 'MachO-Tools@*' is not in this registry.
 *     npm error 404 This package name is not valid, because
 *     npm error 404 1. name can no longer contain capital letters
 *
 * A dry run never asks the registry whether a name is acceptable, because a dry
 * run is not a publish. So the one command a maintainer reaches for reports
 * success on the one thing that was broken. This asserts the properties
 * directly instead.
 *
 * Run by `npm test` and by `.githooks/pre-push`, so it is checked on every
 * platform in CI rather than only on a maintainer's machine.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
let passed = 0;
const ok = (m) => { passed++; console.log(`  PASS  ${m}`); };
const bad = (m) => { failures++; console.log(`  FAIL  ${m}`); };
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

console.log('\npublish — can this package ship, and do the docs agree?\n');

const pkg = JSON.parse(read('package.json'));
const name = pkg.name ?? '';

/* ------------------------------------------------------------------ *
 * 1. The name is one npm will accept.
 * ------------------------------------------------------------------ */

console.log('name');

// npm's own rule for a name published for the first time: no capital letters.
// Hand-rolled rather than imported, because `validate-npm-package-name` is a
// dependency and this package has none — so it carries a positive control, since
// a hand-rolled check that quietly stops matching is the failure this file
// exists to catch.
const rejectsCapitals = (n) => n !== n.toLowerCase();

// `macho_tools` is deliberately absent from this list: `_` is already illegal in
// an npm name, so a predicate that rejected it would be testing a second rule
// and could fail while the rule it exists for still works.
const control = rejectsCapitals('MachO-Tools') && !rejectsCapitals('macho-tools') && rejectsCapitals('MachOTools');
if (!control) {
  bad('the capital-letter predicate no longer discriminates, so it cannot be trusted');
} else {
  ok('the capital-letter predicate discriminates, so it can be trusted');
}

if (rejectsCapitals(name)) {
  bad(`"${name}" cannot be published — a new package name must be lowercase`);
  console.log('        npm reports: validForNewPackages: false — "name can no longer contain capital letters"');
  console.log('        `npm publish --dry-run` will still print success. It does not validate the name.');
} else {
  ok(`"${name}" is a valid name for a new package`);
}

if (!name) {
  bad('"name" is empty');
} else if (name !== name.toLowerCase()) {
  // Already reported above; do not double-count.
} else if (!/^[a-z0-9][a-z0-9._-]*$/.test(name)) {
  bad(`"${name}" contains characters npm does not allow`);
} else {
  ok(`"${name}" satisfies npm's character rules`);
}

/* ------------------------------------------------------------------ *
 * 2. The docs name the same package the manifest does.
 * ------------------------------------------------------------------ */

// A README install line pointing at a different name is the same class of
// defect as a typo'd flag: the command looks right and installs something else.
// The pattern is anchored on `npm install`/`npm i` followed by flags, then a
// package specifier — and every alternative tried during this work either missed
// the line or matched nothing at all, which is why the control below exists.
const SPECIFIER = /npm (?:i|install)(?:[ \t]+-{1,2}[\w-]+)*[ \t]+(['"]?)([@a-z0-9][\w./-]*)\1/g;

const docs = ['README.md', 'CONTRIBUTING.md', 'skill/README.md', 'skill/macho-tools/SKILL.md']
  .filter((f) => fs.existsSync(path.join(root, f)));

let seen = 0;
for (const doc of docs) {
  const text = read(doc);
  for (const m of text.matchAll(SPECIFIER)) {
    seen++;
    // Skip versioned specifiers (`macho-tools@1.2.3`) and anything scoped.
    const named = m[2].replace(/@[^@/]*$/, '');
    if (named === name) {
      ok(`${doc} installs "${named}", matching package.json`);
    } else {
      bad(`${doc} says \`npm install ${m[2]}\` but package.json says "${name}"`);
    }
  }
}

// A check that finds nothing has not verified anything — it looks exactly like a
// check that passed. Require at least the README's own install line to be found,
// and prove the pattern can still see it.
const readmeHasInstall = /npm (?:i|install)/.test(read('README.md'));
if (!readmeHasInstall) {
  bad('README.md has no npm install line for the pattern to check');
} else if (seen === 0) {
  bad('the specifier pattern matched no install line at all, so it verified nothing');
} else {
  ok(`the specifier pattern found ${seen} install line(s), so it is looking at something`);
}

/* ------------------------------------------------------------------ *
 * 3. The tarball the manifest describes contains what it should.
 * ------------------------------------------------------------------ */

console.log('\nmanifest');

// `files` is what ships. Deriving the published set from it rather than
// restating a literal list is deliberate: a restated list drifts, and the
// `boundary:` checks in smoke.mjs scan exactly this set.
const declared = pkg.files ?? [];
if (!declared.length) {
  bad('package.json has no "files", so the published set is undefined');
} else {
  ok(`"files" names ${declared.length} entries, and smoke.mjs derives the published set from it`);

  // Every entry must exist, or npm silently ships less than the manifest claims.
  let missing = [];
  for (const entry of declared) {
    if (!fs.existsSync(path.join(root, entry))) missing.push(entry);
  }
  if (missing.length) {
    bad(`"files" names entries that do not exist: ${missing.join(', ')}`);
    console.log('        npm skips these silently, so the package ships less than it claims');
  } else {
    ok('every entry in "files" exists on disk');
  }
}

// The install line is only true if the binaries it installs are declared.
const bins = Object.keys(pkg.bin ?? {});
if (!bins.length) {
  bad('package.json declares no "bin", so `npm install -g` installs no commands');
} else {
  ok(`"bin" declares ${bins.length} command(s): ${bins.join(', ')}`);
  const absentBins = bins.filter((b) => !fs.existsSync(path.join(root, pkg.bin[b])));
  if (absentBins.length) {
    bad(`"bin" points at files that do not exist: ${absentBins.join(', ')}`);
  } else {
    ok('every declared command has a file behind it');
  }
}

// The MCP server is the integration claim, and it only works if it is published
// as a binary rather than left as a source file.
if (bins.includes('macho-mcp') && !(pkg.exports ?? {})['./macho']) {
  console.log('  note  macho-mcp ships as a binary but ./macho is not an export subpath');
} else if (bins.includes('macho-mcp')) {
  ok('the MCP server is both a published binary and a reachable export');
}

for (const [subpath, target] of Object.entries(pkg.exports ?? {})) {
  if (typeof target !== 'string' || target.includes('*')) continue;
  fs.existsSync(path.join(root, target))
    ? ok(`export "${subpath}" resolves to ${target}, which exists`)
    : bad(`export "${subpath}" points at ${target}, which does not exist`);
}

if (pkg.types) {
  fs.existsSync(path.join(root, pkg.types))
    ? ok(`"types" resolves to ${pkg.types}, which exists`)
    : bad(`"types" points at ${pkg.types}, which does not exist`);
}

console.log(
  failures === 0
    ? `\n${passed} passed. The package can be published, and the docs name it.\n`
    : `\n${passed} passed, ${failures} FAILED. Nothing here is fixable by a green suite.\n`,
);
process.exit(failures === 0 ? 0 : 1);