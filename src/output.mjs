/**
 * output.mjs — argument parsing and JSON emission, shared by every tool.
 *
 * ## Why `--json` lives here rather than in each tool
 *
 * Each tool already had its own argument handling, and each did it slightly
 * differently: some read positionals by index, some filtered out anything
 * starting with `--`, and none of them could produce machine-readable output.
 * That is the state these tools were in for their entire life, and it is why
 * they were only usable by a person at a terminal.
 *
 * `--json` changes what the tools are *for*. The text output is a report; a
 * report is something a person reads. Structured output is something a script,
 * a pipeline or an agent consumes, and it is what makes these tools composable
 * with anything else rather than terminal-only. It is also the cheapest
 * possible path to "ask a question of a 476 MB binary in a shell pipeline":
 *
 *     node src/findcall.mjs --json 0x100085c30 /usr/local/go/bin/go | jq '.hits | length'
 *
 * ## The contract
 *
 * Two guarantees, because a consumer that has to work around them will not
 *   1. **stdout is JSON only.** Progress lines, the per-slice narration and the
 *      "none found" prose all go to stderr under `--json`. This matters more
 *      than it looks: it is the difference between `tool --json | jq` working
 *      and it silently reading its own diagnostics as data.
 *   2. **It is one object, always.** Envelope shape, not a bare array, so a
 *      consumer can read `.tool`, `.ok` and `.warnings` on a failure without
 *      first guessing what a success looks like.
 *
 * Addresses are emitted as `"0x..."` strings rather than JSON numbers. A 64-bit
 * vaddr does not survive `Number` — anything above 2^53 loses its low bits —
 * and a silent precision loss in the tool's output would be indistinguishable
 * from a correct answer. This is exactly the class of bug the rest of this
 * project exists to avoid, so it is fixed at the boundary rather than left to
 * whoever writes the consumer.
 */

/**
 * Envelope keys every tool emits, so consumers can rely on the shape.
 *
 * Six tools, and `sym` is one of them rather than the two it replaced: the
 * `symgrep`/`symfind` pair went away with the merge rather than being kept as
 * aliases, so neither name can appear here any more.
 */
export const TOOLS = ['describe', 'sym', 'symlookup', 'findcall', 'findliteral', 'mapliteral'];

/**
 * Split argv into flags and positionals.
 *
 * A bare `--` is honoured, because a Mach-O path may legitimately begin with a
 * dash and there is no other way to say so. `--flag=value` is accepted for the
 * same reason `getopt` accepts it.
 */
/**
 * Flags that take a separate value, so `-b /bin/ls` consumes `/bin/ls`.
 *
 * Without this list the value falls through as a positional, and in
 * `symlookup` — where every positional is an address — that produced
 * "addresses must be hex: got /bin/ls". A usage error naming the wrong problem
 * is worse than no usage error, because it sends the reader looking in the
 * wrong place.
 */
export const VALUE_FLAGS = new Set(['b', 'binary', 'arch', 'max', 'include']);

export function parseArgs(argv) {
  const flags = new Set();
  const opts = {};
  const positional = [];
  let literal = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (literal) { positional.push(a); continue; }
    if (a === '--') { literal = true; continue; }

    // Single-dash flags count as flags. They used to be treated as positionals,
    // so `symlookup -b /bin/ls` parsed `-b` as a vaddr. A bare `-` (stdin, by
    // convention) stays positional rather than becoming a flag.
    if (a.length > 1 && a.startsWith('-') && a !== '-') {
      const body = a.replace(/^--?/, '');
      const eq = body.indexOf('=');
      if (eq > 0) {
        const name = body.slice(0, eq);
        flags.add(name);
        opts[name] = body.slice(eq + 1);
      } else {
        flags.add(body);
        if (VALUE_FLAGS.has(body) && i + 1 < argv.length) opts[body] = argv[++i];
      }
      continue;
    }
    positional.push(a);
  }
  return { flags, opts, positional };
}

/**
 * Serialise a value as JSON, with BigInt rendered as a hex string.
 *
 * `JSON.stringify` throws on a BigInt, which every address in this codebase
 * is, so the naive `JSON.stringify(result)` fails on every tool. Converting in
 * a replacer — rather than by hand at each call site — means a BigInt cannot be
 * forgotten: the first address anyone adds to a new tool is handled here, not
 * by whoever notices the crash.
 */
export function toJSON(value) {
  return JSON.stringify(value, (_key, v) => {
    if (typeof v === 'bigint') return `0x${v.toString(16)}`;
    return v;
  }, 2);
}

/**
 * Emit one JSON envelope and exit with `code`.
 *
 * `errors` is a list of machine-readable reason codes, not prose, so a consumer
 * can branch on `code === "no-symbols"` without pattern-matching an English
 * sentence. The prose lives in `messages` for the human reading stderr.
 */
export function emitJSON({ tool, binary, ok = true, data = null, errors = [], messages = [], notes = [] }, code = 0) {
  // Normalised rather than trusted: `notes: null` is a natural thing to write
  // when a tool has nothing to say, and it crashed the emitter rather than
  // emitting nothing. A helper that throws on `null` is a helper every caller
  // has to remember to guard, and one caller will not.
  const msgs = Array.isArray(messages) ? messages : [];
  const nts = Array.isArray(notes) ? notes : [];
  for (const m of [...msgs, ...nts]) process.stderr.write(m + '\n');
  process.stdout.write(
    toJSON({
      tool,
      ok,
      binary: binary ?? null,
      errors,
      // Omitted rather than emitted as null or []: an absent key is
      // distinguishable from an empty list, which is the distinction between
      // "nothing to report" and "there is nothing there" that this project
      // keeps having to be careful about.
      ...(msgs.length ? { messages: msgs } : {}),
      ...(nts.length ? { notes: nts } : {}),
      data,
    }) + '\n',
  );
  process.exit(code);
}

/**
 * Thousands-separated integer, locale-independently.
 *
 * `toLocaleString()` groups according to the machine's locale, so the same
 * count prints as `5,880,564` in one locale and `58,80,564` in another — where
 * it reads as fifty-eight million and is off by a factor of ten. A number a
 * reader has to re-parse by eye is a number that will be misread, so the
 * separator is fixed here rather than inherited.
 */
export function count(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return String(n);
  return String(Math.trunc(Math.abs(n))).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** Standard exit codes. Documented because callers branch on them. */
export const EXIT = {
  ok: 0,
  /** The tool ran but found nothing. Distinct from `fail` on purpose: a caller
   *  that treats "no matches" as an error will treat a working tool as broken. */
  empty: 1,
  /** Usage error — bad or missing arguments. */
  usage: 2,
  /** The tool could not do its job: unreadable file, unknown architecture. */
  fail: 3,
};

/** Print usage and exit 2. Every tool routes through this. */
export function usage(lines) {
  process.stderr.write(lines.join('\n') + '\n');
  process.exit(EXIT.usage);
}
