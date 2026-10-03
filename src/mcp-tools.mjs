/**
 * mcp-tools.mjs — the tool surface, as data plus handlers.
 *
 * ## Why this file exists separately from the protocol
 *
 * `mcp.mjs` is JSON-RPC and era negotiation, and it should stay that way. What a
 * tool *is* — its name, what it is for, what it refuses to do, what shape its
 * arguments take — is a different concern with a different rate of change, and
 * putting the two together is how a protocol file grows a 300-line tool table
 * nobody can review.
 *
 * ## One tool per question
 *
 * Eight tools, matching the eight CLIs, because a model picks a tool by reading a
 * description and a tool that answers two questions answers neither one well.
 * There is deliberately no combined "inspect this binary" tool: an agent that
 * wants the slice list, an address lookup and its callers is three calls, and
 * each of those is cheap enough that bundling them saves a round trip at the
 * cost of a schema that says "and also".
 *
 * ## What an agent cannot be trusted to know
 *
 * Three things, and every tool description says them, because a model that does
 * not know them will confidently do the wrong thing:
 *
 *   1. **Addresses are hex strings.** `"0x100085c30"`, never a JSON number. A
 *      64-bit vaddr does not survive a double, and an agent that sends
 *      `1091523120` has silently lost the low bits before the file is opened.
 *      The schema enforces the `0x` form with a pattern, which is stronger than
 *      anything the CLI can do — see the note on silent flags in `CONTRIBUTING`.
 *   2. **A negative answer is not an error.** No matches returns a result with
 *      an empty list and `ok: true`. An agent that treats it as a failure will
 *      retry variations forever, so it is reported as a value.
 *   3. **Direct calls only.** Indirect and PLT calls do not encode their target
 *      in the instruction and are invisible here. `findcall` output is a
 *      shortlist of sites *worth* disassembling, not a call graph.
 *
 * ## Naming
 *
 * Prefixed with `macho-` even though the server already scopes them, because
 * tool names are only unique within a server and every real client aggregates
 * several. `describe` and `search` are the two most collision-prone words in
 * this space; the spec's own guidance is to prefix.
 */

/**
 * Reason codes a handler may report. Shared with the CLIs, which emit the same
 * set, so `errors` means one thing across a shell pipeline and an agent session.
 *
 * The `no-*` codes are the CLIs' way of saying "ran fine, found nothing" — a
 * value, not a failure — and they stay listed because the CLIs emit them and the
 * output schema must permit them. **This layer does not put them in `errors`**,
 * because what a client branches on here is `isError`, and a model told a
 * literal is absent with `isError: true` goes looking for a different binary
 * instead of accepting the answer. Nothing-found arrives as a note, with
 * `data.count === 0` as the precise signal; `errors` is for failing to do the
 * job at all.
 */
export const REASON_CODES = [
  'bad-arguments',   // the caller's fault and fixable — an agent should retry differently
  'bad-address',     // an address was not hex, or not in any slice
  'bad-pattern',     // not a valid regular expression
  'no-match',        // ran fine, the literal was not there
  'no-call-sites',   // ran fine, nothing calls the target: a value, not a failure
  'no-symbols',      // ran fine, nothing matched
  'unknown-encoding', // readable, but not a Mach-O
  'io',              // the path could not be read
];

/* ------------------------------------------------------------------ *
 * schemas
 * ------------------------------------------------------------------ */

/**
 * The envelope, once.
 *
 * This is the same shape the CLIs emit under `--json`, deliberately: a consumer
 * should not have to learn a second dialect depending on whether it arrived by
 * pipe or by agent. It is also why `outputSchema` can promise `errors` and
 * `data` — the reason codes are what let a caller self-correct.
 */
const ENVELOPE = {
  type: 'object',
  required: ['tool', 'ok', 'binary', 'errors', 'data'],
  properties: {
    tool: { type: 'string', description: 'Which tool produced this.' },
    ok: { type: 'boolean', description: 'True when the tool ran, whether or not it found anything.' },
    binary: { type: ['string', 'null'], description: 'The file that was read.' },
    errors: {
      type: 'array',
      items: { type: 'string', enum: REASON_CODES },
      description: 'Machine-readable reason codes. Empty when ok is true.',
    },
    messages: { type: 'array', items: { type: 'string' }, description: 'Prose for a human, for each code above.' },
    notes: { type: 'array', items: { type: 'string' }, description: 'Caveats that do not make the answer wrong.' },
    data: { type: ['object', 'null'], description: 'The answer. null when ok is false.' },
  },
};

/** A 64-bit virtual address. A pattern, deliberately — see the header note. */
const ADDRESS = {
  type: 'string',
  pattern: '^0x[0-9a-fA-F]+$',
  description: 'A virtual address as a hex string with an 0x prefix, e.g. "0x100085c30". Never a JSON number: a 64-bit address does not survive one.',
};

/** File offset, decimal string or number. Kept separate from ADDRESS on purpose. */
const OFFSET = {
  type: 'integer',
  minimum: 0,
  description: 'An absolute file offset, exactly as reported by macho-findliteral.',
};

const BINARY = {
  type: 'string',
  minLength: 1,
  description:
    'Absolute path to a Mach-O file, or to an application bundle (the executable inside is found automatically). ' +
    'Required: unlike the CLI, there is no fallback binary, because an agent asking to describe "nothing" should be told to pass a path.',
};

const ARCH = {
  type: 'string',
  enum: ['x86_64', 'arm64'],
  description:
    'Restrict to one slice of a universal binary. A preference, not a requirement: if the named slice is absent the richest one is read instead.',
};

const obj = (properties, required = []) => ({
  type: 'object',
  properties,
  ...(required.length ? { required } : {}),
});

/* ------------------------------------------------------------------ *
 * validation
 * ------------------------------------------------------------------ */

/**
 * Check arguments against the parts of JSON Schema this file uses.
 *
 * A real validator is ~1,000 lines and a dependency, and this package has
 * neither. What it has instead is the property that matters for an agent: every
 * message names the offending key, what was expected, and what arrived, because
 * a validation error the model cannot act on is a retry loop. Which is also why
 * an unknown key is an error rather than being ignored — silently dropping
 * `includeData` and running the narrower query anyway is exactly the
 * confident-wrong-answer failure this project exists to avoid, and the CLI's
 * flag parser is currently guilty of it.
 *
 * Returns `{ args }` or `{ error }`. Never throws.
 */
export function validate(schema, args, path = '') {
  if (schema.type === 'object') {
    if (args === null || typeof args !== 'object' || Array.isArray(args)) {
      return { error: `${path || 'arguments'}: expected an object, got ${describe(args)}` };
    }
    for (const key of Object.keys(args)) {
      if (!Object.hasOwn(schema.properties, key)) {
        const known = Object.keys(schema.properties);
        return {
          error:
            `${path ? path + '.' : ''}${key}: unknown argument. ` +
            (known.length ? `This tool accepts: ${known.join(', ')}.` : 'This tool takes no arguments.'),
        };
      }
    }
    for (const key of schema.required || []) {
      if (args[key] === undefined) return { error: `${key}: required, but not given` };
    }
    for (const [key, sub] of Object.entries(schema.properties)) {
      if (args[key] === undefined) continue;
      const r = validate(sub, args[key], `${path ? path + '.' : ''}${key}`);
      if (r.error) return r;
    }
    return { args };
  }

  if (schema.type === 'string') {
    if (typeof args !== 'string') {
      // The description is appended on a type mismatch, not only on a pattern
      // mismatch, and that is the whole point. "expected a string, got the
      // number 1091523120" tells a model it did something wrong but not what to
      // send instead, so it tries another wrong thing. For an address the thing
      // to send instead is a hex string; saying so is the difference between one
      // retry and a loop.
      return {
        error:
          `${path}: expected a string, got ${describe(args)}.` +
          (schema.description ? ` ${schema.description}` : ''),
      };
    }
    if (schema.enum && !schema.enum.includes(args)) {
      return { error: `${path}: ${JSON.stringify(args)} is not one of: ${schema.enum.join(', ')}` };
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(args)) {
      return {
        error:
          `${path}: ${JSON.stringify(args)} is not valid here. ` +
          `It must match ${schema.pattern}` +
          (schema.description ? ` — ${schema.description}` : ''),
      };
    }
    if (schema.minLength !== undefined && args.length < schema.minLength) {
      return { error: `${path}: must not be empty` };
    }
    return { args };
  }

  if (schema.type === 'integer') {
    if (!Number.isInteger(args)) return { error: `${path}: expected a whole number, got ${describe(args)}` };
    if (schema.minimum !== undefined && args < schema.minimum) {
      return { error: `${path}: must be >= ${schema.minimum}, got ${args}` };
    }
    return { args };
  }

  if (schema.type === 'boolean') {
    if (typeof args !== 'boolean') return { error: `${path}: expected true or false, got ${describe(args)}` };
    return { args };
  }

  if (schema.type === 'array') {
    if (!Array.isArray(args)) return { error: `${path}: expected a list, got ${describe(args)}` };
    if (schema.items) {
      for (let i = 0; i < args.length; i++) {
        const r = validate(schema.items, args[i], `${path}[${i}]`);
        if (r.error) return r;
      }
    }
    return { args };
  }

  return { args };
}

function describe(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'a list';
  if (typeof v === 'number') return `the number ${v}`;
  return `a ${typeof v} (${JSON.stringify(v)?.slice(0, 40)})`;
}

/** `"0x1000"` → `0x1000n`. Throws a message an agent can use, not a BigInt trace. */
export function parseAddress(v, key = 'address') {
  if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v);
  throw Object.assign(new Error(`${key}: ${JSON.stringify(v)} is not a hex address. Pass a string like "0x100085c30" — a JSON number would lose the low bits of a 64-bit address.`), {
    code: 'bad-address',
  });
}

/* ------------------------------------------------------------------ *
 * helpers shared by handlers
 * ------------------------------------------------------------------ */

/**
 * The binary a call refers to, or a reason code saying why there isn't one.
 *
 * `$MACHO_BINARY` is honoured so an MCP client can be configured once rather
 * than every call repeating the path. The CLI's documented fallback binary is
 * deliberately *not* used: a person running `macho-describe` with no argument
 * getting `/bin/ls` is a convenience, and an agent being handed `/bin/ls`
 * because it forgot the argument is a wrong answer with a real-looking shape.
 */
function binaryOf(args) {
  const b = args.binary || process.env.MACHO_BINARY || process.env.MACHO_APP;
  if (!b) {
    return {
      error: {
        errors: ['bad-arguments'],
        messages: ['no binary given. Pass `binary`: an absolute path to a Mach-O file or an application bundle. Set $MACHO_BINARY or $MACHO_APP to avoid repeating it.'],
      },
    };
  }
  return { binary: b };
}

/** Wrap a handler so it always yields an envelope, never an exception. */
async function guard(tool, binary, fn) {
  try {
    const { data, notes = [], errors = [] } = await fn();
    return { tool, ok: errors.length === 0, binary, errors, notes, data };
  } catch (e) {
    return {
      tool,
      ok: false,
      binary,
      errors: [typeof e.code === 'string' && REASON_CODES.includes(e.code) ? e.code : 'io'],
      messages: [e.message],
      data: null,
    };
  }
}

/** The best few lines to hand back as the text block. */
const hex = (v) => (v === null || v === undefined ? null : typeof v === 'string' ? v : `0x${BigInt(v).toString(16)}`);
const n = (v) => Number(v).toLocaleString('en-US');

/**
 * One short, human-shaped rendering per tool.
 *
 * This exists because `structuredContent` is for a program and the text block is
 * for the model, and a model given 20,000 lines of JSON has to spend its
 * context re-deriving what matters. Twenty lines that say what was found, in
 * what architecture, and what to do about a short list is worth more than the
 * whole structure — which is still there, complete, in `structuredContent`.
 *
 * Every branch names the caveat that most often turns a correct answer into a
 * wrong conclusion. That is the part worth the lines.
 */
function lines(tool, env) {
  const d = env.data;
  const L = [];

  // No data means the tool did not answer, so there is nothing to summarise.
  // This must be checked first: every failure path sets `data: null`, so
  // reading `d.size` unguarded turns a clean `io` or `unknown-encoding` result
  // into a TypeError — which reaches the client as an unexplained internal error
  // instead of the reason code that would have told it what to do. An error path
  // that cannot be reported is the one failure this whole layer exists to remove.
  if (d === null || d === undefined) {
    for (const m of env.messages || []) L.push(m);
    for (const note of env.notes || []) L.push(`note: ${note}`);
    if (env.errors?.length) L.push(`failed with: ${env.errors.join(', ')}`);
    return L.join('\n');
  }

  switch (tool) {
    case 'macho-describe':
      L.push(`${env.binary} — ${(d.size / 1048576).toFixed(1)} MB, ${d.fat ? 'universal' : 'thin'}, ${d.slices.length} slice(s)`);
      for (const s of d.slices) {
        L.push(
          `  ${s.arch.padEnd(7)} ${s.readable ? `${n(s.defined)} defined / ${n(s.nsyms)} symbols` : `unreadable — ${s.note}`}` +
            `  ${s.codeSections} code section(s)  __text ${hex(s.textAddr)}+${n(s.textSize)}`,
        );
      }
      if (d.slices.every((s) => s.readable && s.defined === 0)) {
        L.push('No symbols in any slice (stripped, or a dyld-cache stub). macho-findcall and macho-findliteral still work — they read bytes, not names.');
      }
      break;

    case 'macho-sym':
      L.push(
        `${d.mode === 'regex' ? `regex /${d.pattern}/${d.flags || ''}` : `substring "${d.pattern}"`}: ` +
          `${n(d.count)} match(es), ${n(d.uniqueCount)} unique, in ${d.arch}`,
      );
      for (const m of d.matches.slice(0, 20)) L.push(`  ${hex(m.addr)}  ${m.name}${m.defined ? '' : '  (import)'}`);
      if (d.matches.length > 20) L.push(`  ...and ${n(d.matches.length - 20)} more, all in structuredContent`);
      if (d.truncated) L.push(`  truncated: more matched than the ${n(d.matches.length)} returned — raise max to see the rest`);
      if (d.count === 0) L.push('  no match. A stripped binary has no names to match; findcall and findliteral read bytes instead and are unaffected.');
      break;

    case 'macho-symlookup':
      for (const q of d.queries) {
        L.push(
          q.function
            ? `${hex(q.vaddr)} → ${q.function}  [${hex(q.start)} .. ${hex(q.next)})  +${hex(q.offset)} into the function`
            : `${hex(q.vaddr)} → no symbol covers this address in ${q.arch}`,
        );
      }
      if (d.queries.some((q) => !q.function)) {
        L.push('An address with no symbol is not necessarily unmapped — this reads the symbol table only, with no dSYM or DWARF.');
      }
      break;

    case 'macho-findcall':
      if (d.listing) {
        L.push(`${n(d.total)} distinct direct call target(s) from ${n(d.scanned)} bytes of code in ${d.slices.map((s) => s.arch).join(', ')} (${d.slices[0]?.encoding || 'unknown encoding'})`);
        for (const t of d.targets.slice(0, 20)) L.push(`  ${hex(t.dest)}  ${n(t.sites)} site(s)`);
        if (d.targets.length > 20) L.push(`  ...and ${n(d.targets.length - 20)} more, all in structuredContent`);
      } else {
        L.push(`${n(d.count)} direct call site(s) target ${hex(d.target)}  [${d.slices.map((s) => `${s.arch}: ${s.encoding}`).join(', ')}]`);
        for (const h of d.hits.slice(0, 25)) L.push(`  ${hex(h.addr)}  ${h.kind}  ${h.section}`);
        if (d.hits.length > 25) L.push(`  ...and ${n(d.hits.length - 25)} more, all in structuredContent`);
        if (d.unsupported.length) L.push(`  not scanned: ${d.unsupported.join(', ')} — no decoder for that architecture`);
        if (d.count === 0) L.push('  none found. This finds only calls whose target is encoded in the instruction: indirect, register and PLT calls are invisible, so an empty result does NOT mean nothing calls it.');
      }
      break;

    case 'macho-findliteral':
      L.push(`${n(d.count)} occurrence(s) of ${JSON.stringify(d.literal)} (hex ${d.hex}) in ${n(d.scanned)} bytes across ${d.slices.length} slice(s)`);
      for (const h of d.hits.slice(0, 20)) {
        L.push(`  file ${h.off}  ${hex(h.vaddr)}  ${h.section}${h.inText ? '' : '  (outside __TEXT)'}`);
        L.push(`    …${JSON.stringify(h.context.pre)}|${JSON.stringify(h.context.hit)}…`);
      }
      if (d.hits.length > 20) L.push(`  ...and ${n(d.hits.length - 20)} more, all in structuredContent`);
      if (d.count === 0) L.push('  no contiguous match. A value assembled at runtime from parts never appears as one literal — try macho-mapliteral with explicit offsets, or macho-findcall on the handler.');
      break;

    case 'macho-mapliteral':
      L.push(`slice ${d.arch} at file offset ${hex(d.sliceOffset)}${d.explicit ? ' (offsets given explicitly)' : `, ${d.locations.length} literal location(s) in __TEXT`}`);
      for (const m of d.locations) {
        L.push(`  file ${m.off} → ${hex(m.vaddr)}  ${m.section}`);
        L.push(`    …${JSON.stringify(m.context.pre)}|${JSON.stringify(m.context.hit)}…`);
        L.push(`    ${n(m.pointerCount)} pointer(s) to it — these are the sites worth disassembling:`);
        for (const p of m.pointers.slice(0, 10)) L.push(`      file ${p.off} → ${hex(p.vaddr)}  ${p.section || '-'}`);
        if (m.pointers.length > 10) L.push(`      ...and ${n(m.pointers.length - 10)} more`);
        if (m.pointersTruncated) L.push('      (capped by max_pointers)');
      }
      for (const u of d.unmapped) L.push(`  file ${u.off} → UNMAPPED: at a file offset no slice maps, so it has no vaddr`);
      if (d.locations.length === 0) L.push('  no literal found in __TEXT. If the magic is assembled at runtime rather than stored, pass the file offsets explicitly.');
      else if (d.locations.every((m) => m.pointerCount === 0)) L.push('  no pointers to any of these addresses: nothing dispatches on this magic by reference, so it is matched inline.');
      break;

    case 'macho-a2o':
      L.push(`${d.resolved} of ${d.asked} address(es) reached a byte  (${d.zerofill} zero-fill, ${d.unmapped} unmapped)`);
      for (const q of d.queries) {
        if (q.ambiguous) {
          // "pass arch", not "pass --arch": the flag spelling is the CLI's, and this
          // layer's argument is `arch`.
          L.push(`  ${q.query} → ${(q.note || '').replace('--arch', 'arch')}`);
          for (const s of q.slices) L.push(`      ${(s.arch || '-').padEnd(8)} file offset ${s.offset}  ${s.section || '-'}`);
          continue;
        }
        if (!q.mapped) {
          L.push(`  ${q.query} → not mapped by any slice — it is in none of them, so there is nothing to read`);
        } else if (q.zerofill) {
          L.push(`  ${q.query} → ${q.section} is zero-fill: mapped in memory, but no byte of it exists in the file`);
        } else {
          L.push(`  ${q.query} → file offset ${q.offset} (absolute ${q.absoluteOffset})  ${q.section || '-'}`);
        }
      }
      L.push('  offset is slice-relative; absoluteOffset is the position in the file');
      break;

    case 'macho-o2a':
      L.push(`${d.resolved} of ${d.asked} offset(s) resolved to an address`);
      for (const q of d.queries) {
        if (q.ambiguous) {
          L.push(`  file ${q.query} → inside ${q.slices.length} slices (${q.slices.map((s) => s.arch).join(', ')}) — pass arch to choose one`);
        } else if (q.vaddr) {
          const s = q.slices.find((x) => x.vaddr === q.vaddr) || q.slices[0];
          // Every mapped slice is listed, not just the winner: on a fat binary the
          // slices that do not reach this offset are as much a part of the answer
          // as the one that does.
          L.push(`  file ${q.query} → ${q.vaddr}  ${s.arch}  ${s.section || 'no section — the header and load commands sit in __TEXT but in none'}`);
        } else if (q.slices.some((s) => !s.mapped)) {
          L.push(`  file ${q.query} → not inside any slice that maps it`);
        } else {
          L.push(`  file ${q.query} → no section or segment maps this offset`);
        }
      }
      L.push('  offsets are absolute positions in the file; each slice reports its own relative offset too');
      break;

    default:
      L.push(JSON.stringify(d, null, 2));
  }
  for (const note of env.notes || []) L.push(`note: ${note}`);
  for (const m of env.messages || []) L.push(m);
  return L.join('\n');
}

/* ------------------------------------------------------------------ *
 * the table
 * ------------------------------------------------------------------ */

/**
 * The tools, in a fixed order.
 *
 * Order is not cosmetic: the spec asks for deterministic ordering so clients can
 * cache the list, and an agent reads the list top to bottom on a cold start. It
 * runs from "what is this file" to "what calls this address", which is the order
 * the questions get asked.
 */
export const TOOLS = [
  {
    name: 'macho-describe',
    title: 'Describe a Mach-O binary',
    description:
      'Every slice: architecture, file extent, whether it is thin or universal, symbol counts, where __TEXT starts, ' +
      'and how many sections are flagged as instructions. Call this FIRST on any binary — it tells you which slices the ' +
      'other tools will read and whether there are any symbol names to search at all.\n\n' +
      'Does not parse load commands, code signature, Objective-C or Swift metadata.',
    inputSchema: obj({ binary: BINARY }, ['binary']),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-describe', b.binary, async () => {
        const { describe } = await import('./api.mjs');
        return { data: describe(b.binary) };
      });
    },
  },

  {
    name: 'macho-sym',
    title: 'Search a Mach-O symbol table',
    description:
      'Search defined symbols by substring, or by regular expression with regex:true. Returns names with their addresses.\n\n' +
      'Returns an empty list — ok:true — when nothing matches; that is an answer, not a failure. ' +
      'A stripped binary has no symbol table at all and will return nothing for any pattern.\n\n' +
      'Does not demangle Swift or C++ names, and does not read Objective-C metadata.',
    inputSchema: obj(
      {
        binary: BINARY,
        pattern: { type: 'string', minLength: 1, description: 'Substring to match, or a regular expression when regex is true.' },
        regex: { type: 'boolean', description: 'Treat pattern as a regular expression rather than a literal substring.' },
        case_sensitive: { type: 'boolean', description: 'Match case exactly. Default is case-insensitive.' },
        include_imports: { type: 'boolean', description: 'Include imported symbols. Default is defined symbols only.' },
        dedupe: { type: 'boolean', description: 'One row per distinct name. Default true.' },
        max: { type: 'integer', minimum: 1, description: 'Cap on returned rows. Default 4000.' },
        arch: ARCH,
      },
      ['binary', 'pattern'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-sym', b.binary, async () => {
        const { searchSymbols } = await import('./api.mjs');
        const r = searchSymbols(b.binary, args.pattern, {
          mode: args.regex ? 'regex' : 'substring',
          flags: args.case_sensitive ? '' : 'i',
          definedOnly: !args.include_imports,
          dedupe: args.dedupe !== false,
          max: args.max || 4000,
          arch: args.arch,
        });
        const notes = [
          r.note ? `${r.note} — nothing to search` : null,
          r.truncated ? `truncated to ${r.matches.length} of ${r.count} matching entries` : null,
          r.count === 0 ? 'no symbol matched; a stripped binary has no names to match against' : null,
        ].filter(Boolean);
        return { data: r, notes, errors: r.note ? ['no-symbols'] : [] };
      });
    },
  },

  {
    name: 'macho-symlookup',
    title: 'Which function contains this address?',
    description:
      'Resolve one or more virtual addresses to the function that contains them, with that function\'s bounds and its ' +
      'offset from the entry point. The way to turn an address from a crash log, a disassembly or another tool into a name.\n\n' +
      'Returns function:null — ok:true — for an address no symbol covers. Only defined, address-bearing symbols are ' +
      'considered: an imported symbol sits at zero, so including it would make every low address resolve to an import, ' +
      'which is a confident wrong answer.\n\n' +
      'No dSYM or DWARF, so a build whose symbols live in a sidecar cannot be resolved here.',
    inputSchema: obj(
      { binary: BINARY, addresses: { type: 'array', items: ADDRESS, minItems: 1, description: 'One or more hex address strings.' }, arch: ARCH },
      ['binary', 'addresses'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-symlookup', b.binary, async () => {
        const { lookupAddress } = await import('./api.mjs');
        const queries = args.addresses.map((a) => lookupAddress(b.binary, parseAddress(a), { arch: args.arch }));
        return { data: { queries } };
      });
    },
  },

  {
    name: 'macho-findcall',
    title: 'Find direct calls to an address, or list what a binary calls',
    description:
      'Two modes. With `target`: the direct call/jmp sites that target one address — the callers, with their addresses. ' +
      'With `list_targets:true`: the distinct addresses the binary calls at all.\n\n' +
      'IMPORTANT: direct calls only. An indirect call, a register call or a jump through a PLT stub does not encode its ' +
      'target in the instruction and is invisible here. Every hit is a site worth opening in a disassembler, not a proven ' +
      'call-graph edge. On x86_64 the scan is typed by section rather than by instruction, so it can also match a byte ' +
      'inside a multi-byte instruction; on arm64 it steps 4 bytes and sees only aligned BLs.\n\n' +
      'Unaffected by stripped binaries — it reads bytes, not names.',
    inputSchema: obj(
      {
        binary: BINARY,
        target: { ...ADDRESS, description: 'The address being called. Omit when using list_targets.' },
        list_targets: { type: 'boolean', description: 'Instead of finding callers, list the distinct addresses this binary calls.' },
        min_sites: { type: 'integer', minimum: 0, description: 'With list_targets: drop addresses called fewer than this many times.' },
        max: { type: 'integer', minimum: 1, description: 'Cap on returned sites or targets. Default unlimited for callers.' },
        include_data: { type: 'boolean', description: 'Widen the scan from code sections to every section. Off by default because it is what produces data false positives.' },
        arch: ARCH,
      },
      ['binary'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      if (args.list_targets === undefined && args.target === undefined) {
        throw Object.assign(
          new Error('give either `target` (to find its callers) or `list_targets: true` (to list what the binary calls). Both omitted means neither question was asked.'),
          { code: 'bad-arguments' },
        );
      }
      return guard('macho-findcall', b.binary, async () => {
        const { findCalls, listCallTargets } = await import('./api.mjs');
        const opts = { arch: args.arch, includeData: args.include_data === true, max: args.max || 0 };
        if (args.list_targets) {
          const r = listCallTargets(b.binary, { ...opts, minSites: args.min_sites || 0 });
          // `listing: true` is ours, not the reader's. The CLI distinguishes the
          // two modes by which flag was given; a model needs the same thing as a
          // field, because both modes otherwise share a shape closely enough to
          // be read as the wrong one.
          return {
            data: { ...r, listing: true },
            errors: [],
            notes: [
              r.total ? null : 'no direct call target found — this binary may be entirely indirect, or the scan was empty',
              'direct calls only — indirect, register and PLT calls do not appear',
              'scanned code sections only; pass include_data to widen, accepting data false positives',
            ].filter(Boolean),
          };
        }
        const r = findCalls(b.binary, parseAddress(args.target, 'target'), opts);
        return {
          data: r,
          // Empty is not a failure, and `isError` is what a model reads — see the
          // note on REASON_CODES. The CLI distinguishes this case with exit 1;
          // this layer does it with `ok: true` and `data.count: 0`.
          errors: [],
          notes: [
            r.count
              ? null
              : 'no direct call site found. This finds only calls whose target is encoded in the instruction, so indirect, register and PLT calls are invisible here — an empty result does NOT mean nothing calls this.',
            'scanned code sections only; pass include_data to widen',
          ].filter(Boolean),
        };
      });
    },
  },

  {
    name: 'macho-findliteral',
    title: 'Find a byte literal anywhere in a file',
    description:
      'Search for a literal byte sequence anywhere in the binary — inside code, inside data, in any slice — and report ' +
      'each occurrence with its file offset, its virtual address, and surrounding bytes for context.\n\n' +
      'Matched as raw latin1 bytes, so escapes work: "\\x1f\\x8b" for a gzip header. This is a byte search, not a strings ' +
      'dump: it finds a magic inside code as readily as one in __DATA, and it does not stop at NUL.\n\n' +
      'A value assembled at runtime from parts never appears as a contiguous literal, so an empty result is common and ' +
      'means only that.',
    inputSchema: obj(
      {
        binary: BINARY,
        literal: { type: 'string', minLength: 1, description: 'The bytes to find. Latin1 escapes such as \\x1f\\x8b are interpreted.' },
        text_only: { type: 'boolean', description: 'Restrict to the slice named in $MACHO_TEXT_SLICE, for a single architecture.' },
        max: { type: 'integer', minimum: 1, description: 'Cap on occurrences returned. Default unlimited.' },
      },
      ['binary', 'literal'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-findliteral', b.binary, async () => {
        const { findLiteral } = await import('./api.mjs');
        const r = findLiteral(b.binary, args.literal, { textOnly: args.text_only === true, max: args.max || 0 });
        return {
          data: r,
          // Empty is an answer. See the note on REASON_CODES: `isError` is what
          // the model reads, and "this literal is not in the file" is the answer
          // to the question, not a failure to answer it.
          errors: [],
          notes: [
            r.count ? null : 'no contiguous match — a value assembled at runtime from parts never appears as one literal',
            r.truncated ? `truncated to ${r.hits.length} of the occurrences found` : null,
          ].filter(Boolean),
        };
      });
    },
  },

  {
    name: 'macho-mapliteral',
    title: 'Map a literal to addresses, then find what points at it',
    description:
      'The tool that answers "where is this format magic, which addresses does it map to, and what code handles it". ' +
      'Finds each occurrence of the literal, maps it to the virtual address it loads at, then finds the pointers in the ' +
      'binary that reference those addresses — which is the set of sites worth disassembling.\n\n' +
      'Pass `offsets` to skip the first pass and map specific file offsets, as reported by macho-findliteral.\n\n' +
      'An empty pointer list means nothing references that literal by address, which usually means it is matched inline ' +
      'or built at runtime rather than through a table.',
    inputSchema: obj(
      {
        binary: BINARY,
        literal: { type: 'string', minLength: 1, description: 'The bytes to map. Latin1 escapes are interpreted.' },
        offsets: { type: 'array', items: OFFSET, description: 'Specific file offsets to map, instead of searching for the literal.' },
        max_pointers: { type: 'integer', minimum: 1, description: 'Cap on pointers reported per occurrence. Default 40.' },
        arch: ARCH,
      },
      ['binary', 'literal'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-mapliteral', b.binary, async () => {
        const { mapLiteral } = await import('./api.mjs');
        const r = mapLiteral(b.binary, args.literal, {
          arch: args.arch,
          offsets: args.offsets || null,
          maxPointers: args.max_pointers || 40,
        });
        const pointed = r.locations.reduce((t, x) => t + x.pointerCount, 0);
        return {
          data: r,
          errors: [],
          notes: [
            r.locations.length === 0
              ? 'no literal in __TEXT — this is an answer, not a failure. If the magic is assembled at runtime rather than stored, pass the file offsets explicitly.'
              : null,
            r.locations.length && pointed === 0
              ? 'no pointers to any of these addresses — nothing dispatches on this magic by reference, so it is matched inline'
              : null,
          ].filter(Boolean),
        };
      });
    },
  },

  {
    name: 'macho-a2o',
    title: 'Map a virtual address to a file offset',
    description:
      'Which byte of the file does this virtual address correspond to. Reports both the slice-relative offset ' +
      '(matching the section table) and the absolute offset (a position in the file, for dd or a patch script) — they ' +
      'differ on every slice but the first of a universal binary.\n\n' +
      'Three outcomes, kept distinct: an offset (mapped, and there is a byte), zerofill:true (mapped, but no byte — ' +
      '__bss, __noptrbss, __PAGEZERO have addresses and no bytes in the file), and mapped:false (not in this binary). ' +
      'Conflating the last two is what sends a patch script to the wrong place.\n\n' +
      'Pass `arch` on a universal binary. Without it an address is reported as ambiguous rather than guessed, because ' +
      'every slice maps __TEXT at 0x100000000.',
    inputSchema: obj(
      {
        binary: BINARY,
        addresses: {
          type: 'array',
          items: ADDRESS,
          minItems: 1,
          description: 'Virtual addresses, as "0x…" strings. A 64-bit address does not survive a JSON number.',
        },
        arch: ARCH,
      },
      ['binary', 'addresses'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-a2o', b.binary, async () => {
        const { addressToOffset } = await import('./api.mjs');
        const queries = args.addresses.map((a) => addressToOffset(b.binary, parseAddress(a), { arch: args.arch }));
        return {
          data: {
            queries,
            asked: queries.length,
            // Counted apart rather than folded into one number: a caller deciding
            // whether it can read a byte needs to know which of these it got.
            resolved: queries.filter((q) => q.offset !== null).length,
            zerofill: queries.filter((q) => q.zerofill).length,
            unmapped: queries.filter((q) => !q.mapped).length,
          },
          errors: [],
          notes: [
            'offset is slice-relative; absoluteOffset is the position in the file',
            'zerofill means mapped in memory but absent from the file — there is no byte to read',
            queries.some((q) => q.ambiguous) ? 'a universal binary maps one address in every slice; pass arch to choose one' : null,
          ].filter(Boolean),
        };
      });
    },
  },

  {
    name: 'macho-o2a',
    title: 'Map a file offset to a virtual address',
    description:
      'Which virtual address does this byte of the file have. The inverse of macho-a2o.\n\n' +
      'Offsets are absolute positions in the file. Every slice is examined, because the same offset is a different ' +
      'address in each — the section table records offsets relative to the slice, so in /bin/ls the x86_64 slice at ' +
      '0x4000 and the arm64 slice at 0x10000 give different answers for the same relative offset.\n\n' +
      'The Mach-O header and load commands lie inside __TEXT\'s segment range but in no section, so they resolve to a ' +
      'real address with no section name. That is an answer, not a gap.',
    inputSchema: obj(
      {
        binary: BINARY,
        offsets: {
          type: 'array',
          items: OFFSET,
          minItems: 1,
          description: 'Absolute file offsets, as reported by macho-findliteral or macho-a2o.',
        },
        arch: ARCH,
      },
      ['binary', 'offsets'],
    ),
    outputSchema: ENVELOPE,
    async run(args) {
      const b = binaryOf(args);
      if (b.error) throw Object.assign(new Error(b.error.messages[0]), { code: 'bad-arguments' });
      return guard('macho-o2a', b.binary, async () => {
        const { offsetToAddress } = await import('./api.mjs');
        const r = offsetToAddress(b.binary, args.offsets.map((o) => BigInt(o)), { arch: args.arch });
        return {
          data: {
            ...r,
            asked: r.queries.length,
            resolved: r.queries.filter((q) => q.vaddr !== null).length,
          },
          errors: [],
          notes: [
            'offsets are absolute positions in the file; each slice also reports its own slice-relative offset',
            'a section-less answer is still a real address — the header and load commands sit in __TEXT but in no section',
          ],
        };
      });
    },
  },
];

/** Look a tool up by name, for `tools/call`. */
export function findTool(name) {
  return TOOLS.find((t) => t.name === name) || null;
}

/**
 * The list, as the protocol wants it.
 *
 * A fresh array each call rather than a shared constant: the spec requires that
 * the set not vary per connection, and handing out the same array a client could
 * mutate would make that true by accident rather than by construction.
 */
export function toolDefinitions() {
  return TOOLS.map((t) => ({
    name: t.name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    outputSchema: t.outputSchema,
    annotations: {
      readOnlyHint: true,
      openWorldHint: false,
    },
  }));
}

/** Run a tool and produce the pair a tool result needs: text plus structure. */
export async function callTool(name, args) {
  const tool = findTool(name);
  if (!tool) return null;

  const v = validate(tool.inputSchema, args ?? {});
  if (v.error) return failed(name, args, v.error, 'bad-arguments');

  let env;
  try {
    env = await tool.run(v.args);
  } catch (e) {
    // A tool's own preconditions — no binary given, neither `target` nor
    // `list_targets` — are thrown before `guard()` is reached, so without this
    // they reach the client as an internal error. That is the wrong layer: a
    // model can fix a bad argument by reading the message, which is precisely
    // what a tool execution error is for and a protocol error is not.
    env = failed(name, args, e.message,
      typeof e.code === 'string' && REASON_CODES.includes(e.code) ? e.code : 'io').envelope;
  }
  return { envelope: env, isError: !env.ok, text: lines(name, env) };
}

function failed(name, args, message, code) {
  const env = {
    tool: name,
    ok: false,
    binary: (args && args.binary) || process.env.MACHO_BINARY || process.env.MACHO_APP || null,
    errors: [code],
    messages: [message],
    data: null,
  };
  return { envelope: env, isError: true, text: message };
}

/**
 * Server-level guidance, sent once at discovery.
 *
 * This is the highest-leverage text in the whole integration: it is the only
 * place an agent is told what the server is *bad* at, and a model that reads
 * "no disassembly, hand the addresses to Ghidra" will hand them over, whereas
 * one told only what it can do will keep trying to make it disassemble.
 */
export const INSTRUCTIONS = [
  'Mach-O introspection: fat headers, symbol tables, sections, and __TEXT. Facts about the file format and the bytes only — this server knows nothing about any application.',
  '',
  'The usual loop: macho-describe to see the slices and whether symbols exist, macho-sym to find a name, macho-symlookup to turn an address into a function, macho-findcall for its callers, and macho-findliteral / macho-mapliteral to work out which code handles a file format.',
  '',
  'Three things that will otherwise waste your time:',
  '• Addresses are hex STRINGS ("0x100085c30"), never JSON numbers — a 64-bit address does not survive a number.',
  '• An empty result is an answer, not a failure. ok:true with an empty list means the question was answered. Do not retry it.',
  '• macho-findcall sees DIRECT calls only. Indirect, register and PLT calls do not encode their target and will not appear, so an empty result does not mean nothing calls the target.',
  '',
  'No disassembly, no load-command dump, no code signature, no Objective-C or Swift metadata, no dSYM/DWARF, and not ELF or PE. When you need to know what the code DOES rather than where it is, hand the addresses to a disassembler — the output here is a shortlist of sites worth opening, not a decoded answer.',
].join('\n');

export { hex };
