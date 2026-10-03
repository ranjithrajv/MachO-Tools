import fs from "node:fs";
import path from "node:path";

const dts = fs.readFileSync("src/api.d.ts", "utf8");
const api = await import(path.resolve("src/api.mjs"));

let fail = 0;
const ok = (m) => console.log("  PASS  " + m);
const bad = (m) => { fail++; console.log("  FAIL  " + m); };

console.log("\n=== every runtime export is declared ===");
for (const k of Object.keys(api).sort()) {
  const re = new RegExp(`\\b${k}\\b`);
  re.test(dts) ? ok(`${k} declared`) : bad(`${k} MISSING from api.d.ts`);
}

console.log("\n=== the new describe() slice fields are declared ===");
// Read the real shape off a fixture, then require each field to appear in the
// describe() return type specifically — not merely somewhere in the file.
//
// The substring ends at the *first* `\n};` after the signature. That is the
// return type's own closing brace, and it matters: searching the rest of the
// file for a field name would find it in some unrelated declaration and pass,
// which is the failure this file exists to catch. Scoping the search to the
// block is what makes the check able to fail.
const slice = api.describe("test/fixtures/universal.macho").slices[0];
const start = dts.indexOf("export declare function describe(");
const block = dts.slice(start, dts.indexOf("\n};", start));
for (const k of Object.keys(slice)) {
  new RegExp(`\\b${k}\\??:`).test(block)
    ? ok(`describe().slices[].${k} declared`)
    : bad(`describe().slices[].${k} MISSING`);
}

// Positive control: the scoping above must be able to fail. A field name that
// genuinely exists elsewhere in the file, and nowhere in describe()'s block,
// has to be reported missing. `Symtab` is one: it is a real interface here, and
// describe() does not return it.
new RegExp("\\bSymtab\\b").test(dts) && !/\bSymtab\b/.test(block)
  ? ok("positive control: a field present elsewhere is still reported missing here")
  : bad("positive control: the describe() block is not scoped, so a missing field could pass");

console.log("\n=== declared types match what the reader returns ===");
const isBig = (v) => typeof v === "bigint";
const checks = [
  ["sections[].addr is bigint at runtime", isBig(slice.sections[0].addr),
    /addr: bigint/.test(dts)],
  ["segments[].vmaddr is bigint at runtime", isBig(slice.segments[0].vmaddr),
    /vmaddr: bigint/.test(dts)],
  ["loadCommands[] is non-empty", slice.loadCommands.length > 0,
    /loadCommands: LoadCommand\[\]/.test(block)],
];
for (const [name, runtime, declared] of checks) {
  runtime && declared ? ok(name) : bad(`${name} (runtime=${runtime} declared=${declared})`);
}

// `Thin` is the shape `parseThin` hands every other function, so it drifts the
// same way `describe` does. Asserted against a real parsed header rather than a
// fixture, because the fields below are header facts that no fixture pins.
const { parseThin } = await import(path.resolve("src/macho.mjs"));
const opener = api.withFile("test/fixtures/populated.macho", (f) => parseThin(f, 0));
let thinBlock = dts.slice(dts.indexOf("export interface Thin {"));
thinBlock = thinBlock.slice(0, thinBlock.indexOf("\n}"));
for (const k of Object.keys(opener)) {
  new RegExp(`\\b${k}[?]?:`).test(thinBlock)
    ? ok(`Thin.${k} declared`)
    : bad(`Thin.${k} MISSING — parseThin returns it`);
}

console.log("\n=== findStrings round-trips through its declared shape ===");
const r = api.findStrings("test/fixtures/strings.macho");
let fb = dts.slice(dts.indexOf("export declare function findStrings("));
fb = fb.slice(0, fb.indexOf("\n>;"));
for (const k of Object.keys(r)) {
  new RegExp(`\\b${k}[?]?:`).test(fb)
    ? ok(`findStrings().${k} declared`)
    : bad(`findStrings().${k} MISSING`);
}

// `--arch` is a preference, not a filter: an absent architecture reads anyway
// rather than returning nothing. Three things must therefore hold at once, and
// asserting only the first is how `arch` came to echo a request that had been
// silently ignored — the function reported `arch: 'arm64'` after reading every
// slice in the file.
const uni = "test/fixtures/universal.macho";
const honoured = api.findStrings(uni, { arch: "arm64" });
const ignored = api.findStrings(uni, { arch: "sparc" });
const all = api.findStrings(uni);

honoured.archRead.length === 1 && honoured.archRead[0] === "arm64" && honoured.archHonoured === "arm64"
  ? ok("findStrings --arch narrows to that slice and says so")
  : bad(`findStrings --arch did not narrow: read=[${honoured.archRead}] honoured=${honoured.archHonoured}`);

all.archRead.length > 1
  ? ok("findStrings without --arch reads every slice")
  : bad("findStrings without --arch should read every slice");

ignored.archHonoured === null && ignored.archRead.length >= 1
  ? ok("an absent architecture falls through to a real read, honoured stays null")
  : bad(`absent arch: expected honoured=null with a real read, got honoured=${ignored.archHonoured} read=[${ignored.archRead}]`);
const s = api.describe("test/fixtures/stripped.macho").slices[0];
console.log(`  (stripped.macho uuid at runtime: ${JSON.stringify(s.uuid)})`);
/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s.uuid ?? "")
  ? ok("uuid is a lowercase RFC-4122 shape, as declared")
  : bad("uuid does not match its declared shape");

console.log(fail === 0 ? "\nall declared-shape checks passed" : `\n${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);