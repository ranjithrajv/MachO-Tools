#!/usr/bin/env node
/**
 * symlookup.mjs — which function contains this virtual address?
 *
 *   node src/symlookup.mjs <hex-vaddr> [<hex-vaddr> ...] [--json] [--arch=<name>]
 *   node src/symlookup.mjs 0x100085c30 -b /path/to/binary
 *
 * `nm` on a large universal binary takes minutes, so this reads `LC_SYMTAB`
 * directly and binary-searches the nlist_64 array. That is the whole reason this
 * tool exists, and it is why the symbol filtering below is not an optimisation.
 *
 * ## Why there is no positional binary argument
 *
 * Every positional argument here is an address to resolve, so a path cannot be
 * told apart from a vaddr by position — it would have to be guessed from whether
 * it starts with `0x`, which is exactly the kind of inference that turns a typo
 * into a wrong answer. The binary comes from `-b`/`--binary`, `$MACHO_BINARY` or
 * `$MACHO_APP` instead, and the tool says which it used.
 *
 * ## The bug this no longer has
 *
 * This tool parsed `LC_SYMTAB` itself and then filtered candidates with
 * `(type & N_TYPE) !== N_SECT` *and* `value === 0n`. Both guards matter: only
 * removing one leaves the other blocking the imported symbols that carry the
 * defect, which is what made the first mutation check inconclusive.
 *
 * Imported symbols carry `n_value == 0`, so including them makes any low address
 * resolve to an import sitting at zero. That went unnoticed while this was only
 * pointed at one binary, whose million dense symbols meant the search always
 * landed on real code. Pointed at a dyld-cache stub — `/usr/bin/ssh` has 449
 * symbols of which exactly 1 is defined — the old code answered
 * `function: _write, starts: 0x0` for 0x1000, which is both wrong and
 * plausible-looking.
 */
import { requireBinary } from './target.mjs';
import { lookupAddress } from './api.mjs';
import { parseArgs, emitJSON, usage, EXIT } from './output.mjs';

const { flags, positional, opts } = parseArgs(process.argv.slice(2));

const HELP = [
  'usage: node src/symlookup.mjs <hex-vaddr> [<hex-vaddr> ...] [--json] [--arch=<name>] [-b <binary>]',
  '',
  '  every positional argument is an address, so the binary comes from',
  '  -b/--binary, $MACHO_BINARY or $MACHO_APP.',
  '',
  'options:',
  '  --arch=<name>      read one architecture (x86_64, arm64)',
  '  -b, --binary <p>   the binary to read',
  '  --json             one JSON object on stdout; prose to stderr',
  '  -h, --help         this message',
];

if (flags.has('help') || flags.has('h')) {
  process.stdout.write(HELP.join('\n') + '\n');
  process.exit(EXIT.ok);
}

if (positional.length === 0) usage(HELP);

const binary = requireBinary({ argv: opts.binary || opts.b });
const arch = opts.arch;
const wantHex = positional.every((a) => /^0x[0-9a-fA-F]+$/.test(a));
if (!wantHex) {
  usage(['addresses must be hex with an 0x prefix, e.g. 0x100085c30', `  got: ${positional.find((a) => !/^0x[0-9a-fA-F]+$/.test(a))}`]);
}

const results = [];
for (const arg of positional) {
  try {
    results.push(lookupAddress(binary, BigInt(arg), { arch }));
  } catch (e) {
    // Two different problems arrive here and they need different codes: a
    // reader failure (`io`/`unknown-encoding`, exit 3) means the file is the
    // problem, while anything else means this particular address was. Calling
    // both `bad-address` sent a caller to fix its query when the binary was
    // simply not there.
    const reader = typeof e.code === 'string' && e.code !== 'bad-address';
    const code = reader ? e.code : 'bad-address';
    const exit = reader ? EXIT.fail : EXIT.usage;
    if (flags.has('json')) {
      emitJSON({ tool: 'symlookup', binary, ok: false, errors: [code],
        messages: [`${arg}: ${e.message}`] }, exit);
    }
    console.error(`${arg}: ${e.message}`);
    process.exit(exit);
  }
}

// Computed once and used by both output modes, so the exit status cannot depend
// on whether `--json` was passed.
const resolved = results.filter((r) => r.function).length;

if (flags.has('json')) {
  const found = resolved;
  emitJSON({
    tool: 'symlookup',
    binary,
    ok: true,
    notes: found === 0
      ? ['no address resolved — the slice is stripped, or the addresses are outside it']
      : null,
    data: {
      queries: results,
      resolved: found,
      asked: results.length,
      // Counted separately from `resolved`, because an address that resolved to
      // a name shared with others is a weaker answer than one that resolved alone
      // and a caller summing `resolved` should be able to tell the difference.
      ambiguous: results.filter((r) => r.aliases).length,
    },
  }, found ? EXIT.ok : EXIT.empty);
}

for (const r of results) {
  console.log(`vaddr 0x${r.vaddr.toString(16)}:`);
  if (!r.function) {
    // Distinguish "nothing is defined here" from "no symbol covers this
    // address" — on a stub binary the honest answer is the first, and saying
    // only the second invites the reader to trust the other case.
    console.log(`  (${r.note})`);
    continue;
  }
  console.log(`  function : ${r.function}`);
  console.log(`  starts   : 0x${r.start.toString(16)}  (offset into function: 0x${r.offset.toString(16)})`);
  if (r.next !== null) console.log(`  ends     : 0x${r.next.toString(16)}  (size ~${r.size} bytes)`);
  // Several symbols can start at one address — Go's linker writes zero-size
  // region markers beside real symbols, and a C library aliases one name under
  // several. Nothing in the symbol table says which is a function, so the size
  // above may be an artefact of the next unrelated symbol. Saying so beats
  // printing a byte count that looks measured and is not.
  if (r.aliases) console.log(`  also at  : ${r.aliases.join(', ')} — this address is not one symbol's alone`);
  console.log();
}

// An address that resolves to nothing is a negative result, not a failure — and
// this was the fourth text path that fell off the end and exited 0 while its
// `--json` twin exited 1.
process.exit(resolved ? EXIT.ok : EXIT.empty);
