#!/usr/bin/env node
/**
 * mcp.mjs (test) — the protocol, exercised over a real pipe.
 *
 * ## Why this spawns a subprocess
 *
 * Everything interesting about an MCP server happens on a stream, not in a
 * return value: whether stdout stays valid JSON-RPC, whether the process exits
 * on EOF, whether a stray `console.log` corrupts the framing. Testing `handle()`
 * directly answers none of those — it is the one part of this file that is
 * simple, and the parts that can fail silently are the transport and the
 * lifecycle. So the tests drive a real process over a real pipe and assert on
 * every byte it writes.
 *
 * ## What "stdout is the protocol" is worth proving
 *
 * A polluted stdout does not fail here. It fails in the *client*, which reports
 * a parse error against a message the client never sent, and the natural place
 * to look is the client. So every test that runs the server parses every line
 * of stdout and asserts it is a well-formed JSON-RPC message. Any stray write on
 * any code path — including the ones a test does not think to reach — turns a
 * test red rather than a user's session green.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'src', 'mcp.mjs');
const FIXTURES = path.join(HERE, 'fixtures');

// Imported at the top so the tool count can be asserted against the real list
// rather than a literal, in every place that needs it.
const { TOOLS } = await import('../src/mcp-tools.mjs');
const MODERN = '2026-07-28';

let pass = 0;
let fail = 0;
const skipped = [];

function check(ok, name, detail = '') {
  if (ok) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}${detail ? `\n          ${detail}` : ''}`);
  }
}

function skip(name, why) {
  skipped.push({ name, why });
  console.log(`  SKIP  ${name}\n          ${why}`);
}

/* ------------------------------------------------------------------ *
 * driving the server
 * ------------------------------------------------------------------ */

const meta = (version = MODERN, extra = {}) => ({
  'io.modelcontextprotocol/protocolVersion': version,
  'io.modelcontextprotocol/clientCapabilities': {},
  ...extra,
});

/**
 * Run a scripted session and return what came back.
 *
 * `expectLines` is how many stdout lines to wait for before finishing, so a
 * notification (which correctly produces no reply) does not stall the test.
 * When it is given, a kill timer backs it up: a server that stops answering
 * should fail the test that was waiting on it, not hang the run until something
 * upstream notices. A test that can hang is a test that gets skipped quietly.
 *
 * `raw: true` sends each line verbatim instead of JSON-encoding it, which is
 * what the malformed-input test needs — `JSON.stringify('{ broken')` is itself a
 * valid JSON string, so the default path would have tested the wrong thing.
 */
function session(lines, { env = {}, expectLines = null, timeoutMs = 30000, raw = false } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVER], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    let killed = false;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ out, err, code: child.exitCode ?? child.signalCode, timedOut: killed });
    };
    const timer = setTimeout(() => {
      killed = true;
      process.stderr.write(`[test] no answer within ${timeoutMs}ms; killing the server\n`);
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (d) => {
      out += d;
      if (expectLines !== null && out.split('\n').filter(Boolean).length >= expectLines) child.stdin.end();
    });
    child.stderr.on('data', (d) => (err += d));
    child.on('close', finish);
    const body = raw ? lines.join('\n') : lines.map((l) => JSON.stringify(l)).join('\n');
    child.stdin.write(body + '\n');
    if (expectLines === null) child.stdin.end();
  });
}

/** Parse stdout, refusing anything that is not a JSON-RPC message. */
function parseStream(out) {
  const lines = out.split('\n').filter((l) => l.length);
  const msgs = [];
  const bad = [];
  for (const l of lines) {
    try {
      const m = JSON.parse(l);
      if (m && m.jsonrpc === '2.0' && (m.result !== undefined || m.error !== undefined)) msgs.push(m);
      else bad.push(l);
    } catch {
      bad.push(l);
    }
  }
  return { msgs, bad, count: lines.length };
}

const byId = (msgs, id) => msgs.find((m) => m.id === id);

/**
 * Serialise with BigInt rendered as a hex string.
 *
 * The envelope holds real BigInts — only the wire form converts them — so a plain
 * `JSON.stringify` throws on the first address. That this test has to do the
 * conversion itself is the point: it is the same conversion `mcp.mjs` performs
 * before sending, and doing it twice with the same rule is what lets the
 * assertions below check the *serialised* form rather than trusting the
 * conversion happened.
 */
const json = (v) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `0x${x.toString(16)}` : x));

/* ------------------------------------------------------------------ *
 * tests
 * ------------------------------------------------------------------ */

console.log('\nmcp: the protocol\n');

/* ---- 1. the modern era ------------------------------------------------ */

{
  const { out, err, code } = await session([
    { jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: meta() } },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: meta() } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: path.join(FIXTURES, 'universal.macho') }, _meta: meta() } },
  ], { expectLines: 3 });

  const { msgs, bad } = parseStream(out);
  check(bad.length === 0, 'every stdout line is a JSON-RPC message', bad[0] && `not a message: ${bad[0].slice(0, 120)}`);
  check(code === 0, 'exits 0 when stdin closes', `exit=${code}`);

  const d = byId(msgs, 1)?.result;
  check(!!d, 'server/discover answers');
  check(d?.resultType === 'complete', 'a modern result carries resultType', `got ${d?.resultType}`);
  check(
    Array.isArray(d?.supportedVersions) && d.supportedVersions.includes(MODERN),
    'discover advertises the modern revision',
    JSON.stringify(d?.supportedVersions),
  );
  check(!!d?.capabilities?.tools, 'discover declares the tools capability');
  check(
    d?._meta?.['io.modelcontextprotocol/serverInfo']?.name === 'MachO-Tools',
    'discover identifies the server in _meta',
  );
  check(
    typeof d?.instructions === 'string' && /disassembl/i.test(d.instructions),
    'discover carries instructions that state what the server will not do',
  );

  const l = byId(msgs, 2)?.result;
  // Derived from `TOOLS` rather than written as a literal, so adding a tool does
  // not leave a count assertion quietly reporting the wrong number — the failure
  // mode being "a check that stops checking".
  check(
    Array.isArray(l?.tools) && l.tools.length === TOOLS.length,
    `tools/list returns all ${TOOLS.length} tools`,
    `got ${l?.tools?.length}`,
  );
  check(l?.resultType === 'complete', 'tools/list carries resultType in the modern era');

  const c = byId(msgs, 3)?.result;
  check(c?.isError === false, 'a good call is not an error');
  check(!!c?.structuredContent, 'a call returns structuredContent');
  check(c?.structuredContent?.ok === true, 'structuredContent is the same envelope the CLIs emit');
  check(c?.structuredContent?.tool === 'macho-describe', 'the envelope names its tool');
  check(
    Array.isArray(c?.content) && c.content[0]?.type === 'text' && typeof c.content[0].text === 'string',
    'a call also returns a text block, as the spec asks for alongside structured content',
  );
  check(
    Array.isArray(c?.structuredContent?.errors) && c.structuredContent.errors.length === 0,
    'a successful call carries no reason codes',
  );
}

/* ---- 2. the legacy era ------------------------------------------------ */

{
  const { out } = await session([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-sym', arguments: { binary: path.join(FIXTURES, 'populated.macho'), pattern: 'main' } } },
  ], { expectLines: 4 });

  const { msgs, bad } = parseStream(out);
  check(bad.length === 0, 'legacy session: every stdout line is a JSON-RPC message');
  const init = byId(msgs, 1)?.result;
  check(init?.protocolVersion === '2025-06-18', 'initialize echoes a legacy version it supports', init?.protocolVersion);
  check(!!init?.capabilities?.tools, 'initialize declares the tools capability');
  check(!('resultType' in (init || {})), 'a legacy result omits resultType, which legacy schemas predate');
  check(byId(msgs, 2)?.result?.tools?.length === TOOLS.length, 'tools/list works after the legacy handshake');
  const call = byId(msgs, 3)?.result;
  check(!('resultType' in (call || {})), 'a legacy tools/call omits resultType too');
  check(call?.structuredContent?.ok === true, 'legacy tools/call returns the same envelope');
  check(
    !msgs.some((m) => m.id === undefined),
    'a notification produces no reply',
  );
}

/* ---- 3. version negotiation ------------------------------------------- */

{
  const { out } = await session([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2020-01-01', capabilities: {} } },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: meta('1999-01-01') } },
    { jsonrpc: '2.0', id: 3, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN } } },
    { jsonrpc: '2.0', id: 4, method: 'ping', params: { _meta: meta() } },
  ], { expectLines: 4 });

  const { msgs } = parseStream(out);
  const legacy = byId(msgs, 1)?.result;
  check(
    legacy && legacy.protocolVersion !== '2020-01-01',
    'initialize does not claim a version it does not speak',
    legacy?.protocolVersion,
  );
  const bad = byId(msgs, 2)?.error;
  check(bad?.code === -32022, 'an unsupported version is -32022 UnsupportedProtocolVersion', `got ${bad?.code}`);
  check(
    Array.isArray(bad?.data?.supported) && bad.data.supported.includes(MODERN),
    'the error lists the versions it does support, so the client can retry',
  );
  const missing = byId(msgs, 3)?.error;
  check(missing?.code === -32602, 'a modern request missing a required _meta key is -32602', `got ${missing?.code}`);
  check(
    /clientCapabilities/.test(missing?.message || ''),
    'that error names the field that was missing, rather than just refusing',
    missing?.message,
  );
  check(byId(msgs, 4)?.result !== undefined, 'ping answers');
}

/* ---- 4. the exit-code contract, over the wire ------------------------- */

{
  const fixture = path.join(FIXTURES, 'populated.macho');
  const { out } = await session([
    // exit 3, io: no such file
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: '/nonexistent/nope' }, _meta: meta() } },
    // exit 3, unknown-encoding: readable, not a Mach-O
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: path.join(HERE, 'mcp.mjs') }, _meta: meta() } },
    // exit 2, bad-arguments: neither target nor list_targets
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-findcall', arguments: { binary: fixture }, _meta: meta() } },
    // exit 2, bad-arguments: a mistyped key, which must NOT be ignored
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'macho-describe', arguments: { binry: fixture }, _meta: meta() } },
    // exit 1: ran, found nothing — and this is NOT an error
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'macho-sym', arguments: { binary: fixture, pattern: 'zzz-no-such-symbol-zzz' }, _meta: meta() } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: fixture, literal: 'zzz-no-such-literal-zzz' }, _meta: meta() } },
  ], { expectLines: 6 });

  const { msgs, bad } = parseStream(out);
  check(bad.length === 0, 'every error path still writes only JSON-RPC');

  const codes = (id) => byId(msgs, id)?.result?.structuredContent?.errors;
  check(codes(1)?.[0] === 'io', 'a missing path reports io', JSON.stringify(codes(1)));
  check(
    codes(2)?.[0] === 'unknown-encoding',
    'a readable non-Mach-O reports unknown-encoding, not io',
    JSON.stringify(codes(2)),
  );
  check(
    codes(1)?.[0] !== codes(2)?.[0],
    'those two are distinguishable — the CLI reported both as io, which made them one problem',
  );
  check(codes(3)?.[0] === 'bad-arguments', 'a missing required mode reports bad-arguments');
  check(codes(4)?.[0] === 'bad-arguments', 'an unknown argument key is rejected rather than ignored');

  const typo = byId(msgs, 4)?.result;
  check(typo?.isError === true, 'an unknown argument key is an error the model can act on');
  check(
    /binary/.test(typo?.structuredContent?.messages?.[0] || ''),
    'and the message names the key it wanted',
    typo?.structuredContent?.messages?.[0],
  );

  // The one that matters most for an agent.
  for (const [id, tool] of [[5, 'macho-sym'], [6, 'macho-findliteral']]) {
    const r = byId(msgs, id)?.result;
    check(
      r?.isError === false && r?.structuredContent?.ok === true,
      `${tool}: finding nothing is ok:true, not a failure — a model must not retry it`,
      `isError=${r?.isError} ok=${r?.structuredContent?.ok}`,
    );
  }
  check(
    codes(6)?.length === 0,
    'a literal that is not there carries no reason code: `errors` is for failing, not for answering "none"',
    JSON.stringify(codes(6)),
  );
  check(
    /no contiguous match/.test(byId(msgs, 6)?.result?.structuredContent?.notes?.join(' ') || ''),
    'and the note says why, so a model can tell an absent literal from a broken scan',
    JSON.stringify(byId(msgs, 6)?.result?.structuredContent?.notes),
  );
}

/* ---- 5. addresses cannot silently lose precision --------------------- */

{
  const fixture = path.join(FIXTURES, 'populated.macho');
  const { out } = await session([
    // A JSON number, which is exactly how a 64-bit address dies silently.
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: fixture, addresses: [1091523120] }, _meta: meta() } },
    // Not hex at all.
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: fixture, addresses: ['100085c30'] }, _meta: meta() } },
    // A real one, and past 2^53 so any Number conversion would be visible.
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: fixture, addresses: ['0x100085c30'] }, _meta: meta() } },
    // Past 2^53, to prove nothing is clamped or truncated on the way through.
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: fixture, addresses: ['0xfffffffffffffff0'] }, _meta: meta() } },
    // And a batch, which is the reason `addresses` is a list.
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: fixture, addresses: ['0x100000000', '0x100000120', '0x100000300'] }, _meta: meta() } },
  ], { expectLines: 5 });

  const { msgs } = parseStream(out);
  for (const [id, what] of [[1, 'a JSON number'], [2, 'an address without 0x']]) {
    const r = byId(msgs, id)?.result;
    check(r?.isError === true, `${what} is rejected`, `isError=${r?.isError}`);
    check(
      /hex string|0x1000|"0x/.test(r?.structuredContent?.messages?.[0] || ''),
      `and ${what} gets told to send a hex string instead, so it can self-correct`,
      r?.structuredContent?.messages?.[0],
    );
  }

  const ok = byId(msgs, 3)?.result;
  check(ok?.isError === false, 'a hex address string is accepted');

  // The 64-bit claim, actually tested rather than asserted in a comment.
  // The 64-bit claim, actually tested rather than asserted in a comment.
  // Note the `.data` hop: the wire payload is the same envelope the CLIs emit,
  // so the answer sits under `data` rather than at the top level.
  const far = byId(msgs, 4)?.result?.structuredContent;
  check(
    far?.data?.queries?.[0]?.vaddr === '0xfffffffffffffff0',
    'an address beyond 2^53 survives the round trip exactly, with no low bits lost',
    json(far?.data?.queries?.[0]),
  );
  check(
    far?.data?.queries?.[0]?.function === null && far?.data?.queries?.[0]?.note,
    'and an address no slice maps is reported as such, not guessed at',
    json(far?.data?.queries?.[0]),
  );
  check(
    !/"vaddr":\s*\d/.test(json(far)),
    'and it is serialised as a string, never a JSON number',
  );

  const batch = byId(msgs, 5)?.result?.structuredContent;
  check(batch?.data?.queries?.length === 3, 'several addresses are answered in one call', `${batch?.data?.queries?.length}`);
  check(
    batch?.data?.queries?.every((q) => typeof q.vaddr === 'string'),
    'each answer carries its address as a string',
  );
  check(
    batch?.data?.queries?.[2]?.function === 'target_fn',
    'and the third address resolves to the function that actually contains it',
    json(batch?.data?.queries?.[2]),
  );
}

/* ---- 6. protocol errors vs tool errors ------------------------------- */

{
  const { out } = await session([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-nope', arguments: {}, _meta: meta() } },
    { jsonrpc: '2.0', id: 2, method: 'no/such/method', params: { _meta: meta() } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { _meta: meta() } },
    { jsonrpc: '2.0', id: 4, method: 'resources/list', params: { _meta: meta() } },
  ], { expectLines: 4 });

  const { msgs } = parseStream(out);
  check(byId(msgs, 1)?.error?.code === -32602, 'an unknown tool is a protocol error');
  check(
    Array.isArray(byId(msgs, 1)?.error?.data?.available),
    'and it lists the tools that do exist, so the model can pick one',
  );
  check(byId(msgs, 2)?.error?.code === -32601, 'an unknown method is -32601');
  check(byId(msgs, 3)?.error?.code === -32602, 'tools/call with no name is -32602');
  // Only `tools` was advertised, so `resources` genuinely is not available.
  check(byId(msgs, 4)?.error?.code === -32601, 'an unadvertised capability is -32601, not an empty list');
}

/* ---- 7. malformed input ---------------------------------------------- */

{
  // Sent verbatim: `JSON.stringify` would turn each of these into a valid JSON
  // *string*, which is a different input entirely.
  const { out } = await session(
    [
      '{ this is not json',
      '',
      '"a bare json string, which is not a request"',
      '[1,2,3]',
      '{"jsonrpc":"1.0","id":1,"method":"ping"}',
      '{"jsonrpc":"2.0","id":2}',
      '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"_meta":' + meta() + '}}',
    ],
    { expectLines: 6, raw: true },
  );
  const { msgs, bad } = parseStream(out);
  check(bad.length === 0, 'garbage on stdin does not corrupt stdout', bad[0]?.slice(0, 120));
  // Seven lines in, one of them blank and legitimately unanswered, so six replies.
  check(msgs.length === 6, 'every malformed line is answered; none is dropped in silence', `${msgs.length} replies for 6 bad lines`);
  const code = (i) => msgs[i]?.error?.code;
  check(
    code(0) === -32700,
    'text that is not JSON at all is -32700 ParseError',
    JSON.stringify(msgs.map((m) => m.error?.code)),
  );
  check(
    code(1) === -32600 && code(2) === -32600,
    'valid JSON that is not a request object (a string, an array) is -32600, not silently ignored',
    JSON.stringify(msgs.map((m) => m.error?.code)),
  );
  check(
    code(3) === -32600,
    'a wrong jsonrpc version is -32600',
    JSON.stringify(msgs.map((m) => m.error?.code)),
  );
  check(
    code(4) === -32600,
    'a request with no method is -32600, rather than treated as a notification and silently dropped',
    JSON.stringify(msgs.map((m) => m.error?.code)),
  );
  check(
    code(5) === -32700,
    'a truncated message is -32700',
    JSON.stringify(msgs.map((m) => m.error?.code)),
  );
  check(
    msgs.filter((m) => m.id === null).length === 4,
    'a message whose id could not be read is answered with no id',
    JSON.stringify(msgs.map((m) => m.id)),
  );
  check(
    msgs.filter((m) => m.id !== null).every((m) => m.error && 'code' in m.error),
    'and every reply that does have an id is correlated with it',
  );
}

/* ---- 8. --help stays out of the protocol ----------------------------- */

{
  const { out, err, code } = await session([]);
  check(code === 0, 'an empty session exits cleanly', `exit=${code}`);

  const help = await new Promise((resolve) => {
    const c = spawn(process.execPath, [SERVER, '--help'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let o = '';
    let e = '';
    c.stdout.on('data', (d) => (o += d));
    c.stderr.on('data', (d) => (e += d));
    c.on('close', () => resolve({ o, e }));
  });
  check(help.o === '', '--help writes nothing to stdout', help.o.slice(0, 80));
  check(/mcpServers|claude mcp add/.test(help.e), '--help explains how to register the server, on stderr');
}

/* ---- 9. the tool table is well-formed -------------------------------- */

{
  const { toolDefinitions, TOOLS, REASON_CODES, callTool, validate } = await import('../src/mcp-tools.mjs');

  const defs = toolDefinitions();
  check(defs.length === TOOLS.length, 'every tool is described', `${defs.length} of ${TOOLS.length}`);
  check(
    new Set(defs.map((d) => d.name)).size === defs.length,
    'tool names are unique',
  );
  check(
    defs.every((d) => /^[A-Za-z0-9_.-]{1,128}$/.test(d.name)),
    'tool names use only the characters the spec allows',
    defs.map((d) => d.name).find((n) => !/^[A-Za-z0-9_.-]{1,128}$/.test(n)),
  );
  check(
    defs.every((d) => d.description && d.description.length > 80),
    'every tool has a description worth routing on',
  );
  check(
    defs.every((d) => d.inputSchema?.type === 'object' && d.inputSchema && !('required' in {})),
    'every tool has an object inputSchema',
  );
  check(
    defs.every((d) => d.outputSchema?.type === 'object'),
    'every tool declares an outputSchema, so a client can validate the result',
  );
  check(
    defs.every((d) => JSON.stringify(toolDefinitions().map((x) => x.name)) === JSON.stringify(defs.map((x) => x.name))),
    'tool order is deterministic, so a client can cache the list',
  );
  check(
    defs.every((d) => d.annotations?.readOnlyHint === true),
    'every tool is marked read-only, which is true: this package only reads',
  );

  // Prefixed names: the spec warns that `describe` and `search` collide when a
  // client aggregates servers.
  check(
    defs.every((d) => d.name.startsWith('macho-')),
    'tool names are prefixed, so they do not collide in a client aggregating servers',
  );

  // The validator must actually reject things, or it is decoration.
  const schema = TOOLS[2].inputSchema;
  check(validate(schema, { binary: '/x', addresses: ['0x10'] }).error === undefined, 'the validator accepts good input');
  check(
    /pattern/.test(validate(schema, { binary: '/x', addresses: ['nope'] }).error || '') ||
    /\^0x/.test(validate(schema, { binary: '/x', addresses: ['nope'] }).error || ''),
    'and rejects a bad address with a message that states the rule',
    validate(schema, { binary: '/x', addresses: ['nope'] }).error,
  );
  check(
    /unknown argument/.test(validate(schema, { binary: '/x', addresses: ['0x10'], nope: 1 }).error || ''),
    'and rejects an unknown key rather than ignoring it',
  );
  check(
    REASON_CODES.includes('io') && REASON_CODES.includes('unknown-encoding'),
    'the two failure kinds have distinct codes',
  );

  // No tool may be shipped untested: run each against a fixture with known
  // answers, so a renamed field or a broken handler cannot pass unnoticed.
  //
  // The probe values are real, read out of the corpus rather than guessed —
  // `populated.macho` has symbols named `_pop_NN` and a call to 0x100000220, and
  // it contains no printable string literals at all, so a literal probe against
  // it would prove nothing except that the tool returns an empty list.
  const populated = path.join(FIXTURES, 'populated.macho');
  const universal = path.join(FIXTURES, 'universal.macho');

  // Literal probes need a binary that has literal bytes in it. The generated
  // corpus is deliberately code-and-symbols only, so this falls back to a
  // system binary and skips rather than asserting something hollow when there
  // is none — the same rule the rest of the suite follows.
  const REAL = ['/usr/local/go/bin/go', '/bin/ls', '/usr/bin/ls'].find((p) => {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  });
  let realLiteral = null;
  let realMapLiteral = null;
  if (REAL) {
    const { callTool: probe } = await import('../src/mcp-tools.mjs');
    // Each tool needs a literal that satisfies *its own* success condition, and
    // they are different conditions: `findliteral` is satisfied by any byte
    // sequence, while `mapliteral` also needs a hit inside __TEXT. Stopping at
    // the first literal that merely satisfies the weaker one left the stronger
    // tool permanently skipped, which is a check that never ran and looked like
    // one that had.
    for (const lit of ['runtime.main', 'Go build ID', 'go:buildid', 'main', 'GCC', 'darwin']) {
      const a = await probe('macho-findliteral', { binary: REAL, literal: lit });
      if (a?.envelope?.data?.count > 0 && !realLiteral) realLiteral = lit;
      const b = await probe('macho-mapliteral', { binary: REAL, literal: lit });
      if (b?.envelope?.data?.locations?.length > 0 && !realMapLiteral) realMapLiteral = lit;
      if (realLiteral && realMapLiteral) break;
    }
  }

  // Probes for a2o/o2a are derived rather than hardcoded. The address is read from
  // the fixture's own `__text`, so the tool is handed something that is genuinely
  // there rather than a constant that happens to work; a stale hardcoded address
  // would make this check pass or fail for a reason unrelated to the tools.
  let realAddr = null;
  if (REAL) {
    try {
      const { describe } = await import('../src/api.mjs');
      const slice = describe(REAL).slices.find((s) => s.textAddr);
      if (slice) realAddr = `0x${(slice.textAddr + 0x40n).toString(16)}`;
    } catch {
      /* reported as a skip below */
    }
  }

  // The offset comes from `a2o` rather than being written down, so the two halves
  // are checked against each other and neither can drift from the reader.
  let realOffset = null;
  if (realAddr) {
    try {
      const { addressToOffset } = await import('../src/api.mjs');
      const row = addressToOffset(REAL, BigInt(realAddr));
      if (row.absoluteOffset !== null) realOffset = row.absoluteOffset;
    } catch {
      /* reported as a skip below */
    }
  }

  // The fixture carrying NUL-terminated strings, for the `--strings` mode. Taken
  // from the corpus rather than a system binary so the assertion is exact and
  // reproducible; the generated fixtures are otherwise code-and-symbols only,
  // which is why this one exists.
  const stringsBin = fs.existsSync(path.join(FIXTURES, 'strings.macho'))
    ? path.join(FIXTURES, 'strings.macho')
    : null;

  // One entry per *mode*, not per tool. A second mode that nothing exercises is a
  // mode that exists only until someone calls it, and `--strings` and
  // `list_targets` both arrived without one.
  const probes = {
    'macho-describe': [
      { binary: universal },
      { binary: universal, arch: 'arm64' },
    ],
    'macho-sym': [{ binary: populated, pattern: 'pop' }],
    'macho-symlookup': [{ binary: populated, addresses: ['0x100000120'] }],
    'macho-findcall': [
      { binary: populated, target: '0x100000220' },
      { binary: populated, list_targets: true },
    ],
    'macho-findliteral': [
      ...(realLiteral ? [{ binary: REAL, literal: realLiteral }] : []),
      ...(stringsBin ? [{ binary: stringsBin, strings: true }] : []),
    ],
    'macho-mapliteral': realMapLiteral ? [{ binary: REAL, literal: realMapLiteral }] : [],
    'macho-a2o': realAddr ? [{ binary: REAL, addresses: [realAddr] }] : [],
    'macho-o2a': realOffset !== null ? [{ binary: REAL, offsets: [realOffset] }] : [],
  };

  const SKIP_WHY = {
    'macho-o2a': 'no Mach-O with a mappable address was available',
    'macho-a2o': 'no Mach-O with a mappable address was available',
    'macho-mapliteral': 'no Mach-O with a known literal was available (looked at /usr/local/go/bin/go, /bin/ls, /usr/bin/ls)',
    'macho-findliteral': 'no Mach-O with a known literal, and no strings fixture (looked at /usr/local/go/bin/go, /bin/ls, /usr/bin/ls)',
  };

  for (const d of defs) {
    const modes = probes[d.name] ?? [];
    if (!modes.length) {
      // The reason differs per tool — a missing literal, a missing __text — so it is
      // stated rather than left as one generic sentence that would be wrong for
      // whichever tool happened to skip.
      skip(`${d.name}: runs against a real binary`, SKIP_WHY[d.name] || 'no suitable input was available');
      continue;
    }
    for (const [i, probeArgs] of modes.entries()) {
      const label = modes.length > 1 ? `${d.name} [mode ${i + 1}]` : d.name;
      const out = await callTool(d.name, probeArgs);
      check(
        out && out.envelope && out.envelope.tool === d.name && typeof out.text === 'string' && out.text.length > 0,
        `${label}: runs against a real binary and produces a result`,
        JSON.stringify(out?.envelope?.errors),
      );
      check(
        out?.envelope?.ok === true,
        `${label}: finds what is actually there (errors=${JSON.stringify(out?.envelope?.errors)})`,
      );
      check(
        out?.envelope?.data !== null && out?.envelope?.data !== undefined,
        `${label}: returns data`,
      );
      check(
        !/\bundefined\b|\[object Object\]|NaN/.test(out?.text || ''),
        `${label}: its text block reads as prose, with no undefined leaking through`,
        (out?.text || '').split('\n').find((l) => /undefined|\[object Object\]|NaN/.test(l)),
      );
      check(
        (out?.envelope?.errors || []).every((c) => REASON_CODES.includes(c)),
        `${label}: emits only documented reason codes`,
        JSON.stringify(out?.envelope?.errors),
      );
      // Only the *address* fields. `off`, `offset` and `absoluteOffset` are file
      // positions, which are small integers by nature and are correctly JSON
      // numbers — and a check that flagged them would have pushed someone to
      // hex-string a byte count, which is not what this rule is for.
      check(
        !/"(?:vaddr|addr|dest|target|start|next|textAddr)":\s*\d/.test(json(out?.envelope?.data)),
        `${label}: no address is serialised as a JSON number`,
        json(out?.envelope?.data)?.slice(0, 200),
      );
    }
    void 0;
  }

  // The `--strings` mode specifically: an empty result is an answer, so the
  // interesting checks are that it found the fixture's four strings and that its
  // addresses are real, not merely that it did not crash.
  if (stringsBin) {
    const out = await callTool('macho-findliteral', { binary: stringsBin, strings: true });
    check(
      out?.envelope?.data?.count === 4,
      'macho-findliteral --strings: reads the four fixture strings',
      JSON.stringify(out?.envelope?.data?.count),
    );
    check(
      out?.envelope?.data?.strings?.every((s) => s.section === '__TEXT,__cstring'),
      'macho-findliteral --strings: names the section each string came from',
    );
    check(
      out?.text?.includes('__cstring'),
      'macho-findliteral --strings: says which sections it searched, in the text block',
    );
  }

  // The 32-bit fixture, over the wire.
  //
  // The point is not that the protocol works on a 32-bit binary — it is that the
  // 32-bit sections reach a client at all. Before the reader was fixed, `describe`
  // reported zero sections for this binary, so a model asking "what sections does
  // this have" over MCP got an empty list with `ok: true`, which is the hardest
  // kind of wrong answer to notice.
  const bits32 = fs.existsSync(path.join(FIXTURES, 'bits32.macho'))
    ? path.join(FIXTURES, 'bits32.macho')
    : null;
  if (!bits32) {
    skip('the 32-bit binary over MCP', 'the bits32 fixture is missing — run npm run test:fixtures');
  } else {
    const { out } = await session([
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: bits32 }, _meta: meta() } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-symlookup', arguments: { binary: bits32, addresses: ['0x80481f4'] }, _meta: meta() } },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-findcall', arguments: { binary: bits32, target: '0x80481f4' }, _meta: meta() } },
    ], { expectLines: 3 });
    const { msgs } = parseStream(out);
    const d32 = byId(msgs, 1)?.result?.structuredContent?.data;
    const s32 = d32?.slices?.[0];

    check(
      s32?.bits === 32,
      'over MCP: a 32-bit slice is reported as 32-bit',
      `bits=${s32?.bits}`,
    );
    check(
      s32?.sections?.length === 2
        && s32.sections.find((x) => x.sectname === '__text')?.offset === 244,
      'over MCP: its sections reach the client with the right file offsets',
      JSON.stringify(s32?.sections?.map((x) => `${x.sectname}@${x.offset}`)),
    );
    check(
      s32?.sections?.every((x) => typeof x.addr === 'string' && x.addr.startsWith('0x')),
      'over MCP: 32-bit addresses are strings, as everywhere else',
    );
    check(
      /LC_SEGMENT\b/.test(byId(msgs, 1)?.result?.content?.[0]?.text || ''),
      'over MCP: the text block names the non-_64 load command, so it is legible without parsing JSON',
      (byId(msgs, 1)?.result?.content?.[0]?.text || '').split('\n').slice(0, 6).join(' | '),
    );
    const q32 = byId(msgs, 2)?.result?.structuredContent?.data?.queries?.[0];
    check(
      q32?.function === 'target_fn' && q32?.start === '0x80481f4',
      'over MCP: symlookup resolves a symbol through a 12-byte nlist',
      `function=${q32?.function} start=${q32?.start}`,
    );
    check(
      byId(msgs, 3)?.result?.structuredContent?.data?.count === 2,
      'over MCP: findcall finds both 32-bit call/jmp sites',
      JSON.stringify(byId(msgs, 3)?.result?.structuredContent?.data?.count),
    );
  }
}

// The UUID, over the wire.
//
// Same reason as the 32-bit block above: the protocol is not what is under test,
// the *field reaching the client* is. A `describe` that listed LC_UUID by name
// while reporting no UUID would let a model conclude the binary is unsigned or
// un-identifiered, which is a claim about the build and not about the file.
{
  const stripped = fs.existsSync(path.join(FIXTURES, 'stripped.macho'))
    ? path.join(FIXTURES, 'stripped.macho')
    : null;
  if (!stripped) {
    skip('the UUID over MCP', 'the stripped fixture is missing — run npm run test:fixtures');
  } else {
    const WANT = 'a1b2c3d4-e5f6-4708-9a0b-1c2d3e4f5061';
    const { out } = await session([
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: stripped }, _meta: meta() } },
    ], { expectLines: 1 });
    const { msgs } = parseStream(out);
    const r1 = byId(msgs, 1)?.result;

    check(
      r1?.structuredContent?.data?.slices?.[0]?.uuid === WANT,
      'over MCP: the UUID reaches the client in structuredContent',
      JSON.stringify(r1?.structuredContent?.data?.slices?.[0]?.uuid),
    );
    check(
      (r1?.content?.[0]?.text || '').includes(WANT),
      'over MCP: and in the text block, so it is legible without parsing JSON',
      (r1?.content?.[0]?.text || '').split('\n').slice(1, 4).join(' | '),
    );
    check(
      r1?.structuredContent?.ok === true,
      'over MCP: and it does not turn the envelope into an error',
    );
  }
}

/* ---- 10. an empty result is an answer, not an error ----------------- */

{
  // The generated corpus carries no printable literals, so these are the only
  // correct answer there — and it is the case where a tool that reported "not
  // found" as a failure would send a model looking for a different binary.
  const { callTool } = await import('../src/mcp-tools.mjs');
  const corpus = path.join(FIXTURES, 'populated.macho');
  for (const [tool, args] of [
    ['macho-findliteral', { binary: corpus, literal: 'no-such-literal-anywhere' }],
    ['macho-mapliteral', { binary: corpus, literal: 'no-such-literal-anywhere' }],
    ['macho-sym', { binary: corpus, pattern: 'no-such-symbol-anywhere' }],
    ['macho-findcall', { binary: corpus, target: '0x7fffffff0000' }],
  ]) {
    const out = await callTool(tool, args);
    check(
      out?.envelope?.ok === true && out?.envelope?.errors?.length === 0,
      `${tool}: finding nothing is ok:true with no reason codes`,
      JSON.stringify(out?.envelope?.errors),
    );
    check(out?.isError === false, `${tool}: is not flagged as an error to the client`);
    check(
      out?.envelope?.notes?.length > 0,
      `${tool}: does say in a note that nothing was found, so the model can tell "ran and found none" from "did not run"`,
      JSON.stringify(out?.envelope?.notes),
    );
  }

  // And the same over the wire, where `isError` is what a client actually reads.
  const { out } = await session([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: corpus, literal: 'no-such-literal-anywhere' }, _meta: meta() } },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: corpus, strings: true }, _meta: meta() } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: '/nonexistent/nope', literal: 'x' }, _meta: meta() } },
  ], { expectLines: 3 });
  const { msgs } = parseStream(out);

  const empty = byId(msgs, 1)?.result;
  check(
    empty?.isError === false && empty?.structuredContent?.ok === true,
    'over MCP: a literal that is absent is not an error',
    `isError=${empty?.isError}`,
  );
  const noStrings = byId(msgs, 2)?.result;
  check(
    noStrings?.isError === false && noStrings?.structuredContent?.data?.count === 0,
    'over MCP: --strings on a binary with no cstring section answers empty, not error',
    `isError=${noStrings?.isError} count=${noStrings?.structuredContent?.data?.count}`,
  );
  check(
    /gopclntab/.test((noStrings?.structuredContent?.notes || []).join(' ')),
    'and explains that a Go-style binary keeps its strings elsewhere, so zero is informative',
    JSON.stringify(noStrings?.structuredContent?.notes),
  );
  const missing = byId(msgs, 3)?.result;
  check(
    missing?.isError === true && missing?.structuredContent?.errors?.[0] === 'io',
    'over MCP: a missing binary IS an error, so the two are distinguishable',
    `isError=${missing?.isError} errors=${JSON.stringify(missing?.structuredContent?.errors)}`,
  );

  // The new modes, over the wire, with real answers rather than just no-crash.
  const stringsBin = fs.existsSync(path.join(FIXTURES, 'strings.macho')) ? path.join(FIXTURES, 'strings.macho') : null;
  if (stringsBin) {
    const r = await session([
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: stringsBin, strings: true }, _meta: meta() } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: stringsBin }, _meta: meta() } },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macho-findliteral', arguments: { binary: stringsBin }, _meta: meta() } },
    ], { expectLines: 3 });
    const s = parseStream(r.out);
    const stringsOut = byId(s.msgs, 1)?.result;
    check(
      stringsOut?.structuredContent?.data?.count === 4,
      'over MCP: --strings returns the fixture strings',
      JSON.stringify(stringsOut?.structuredContent?.data?.count),
    );
    check(
      /__cstring/.test(stringsOut?.content?.[0]?.text || ''),
      'and names the section in the text block, so the answer is legible without parsing JSON',
    );
    const descOut = byId(s.msgs, 2)?.result;
    const sec0 = descOut?.structuredContent?.data?.slices?.[0];
    check(
      Array.isArray(sec0?.sections) && sec0.sections.length === 2 && Array.isArray(sec0?.loadCommands),
      'over MCP: describe carries segments, sections and load commands',
      `sections=${sec0?.sections?.length} loads=${sec0?.loadCommands?.length}`,
    );
    check(
      /__cstring/.test(descOut?.content?.[0]?.text || ''),
      'and the text block lists them, which is the whole point of a summary',
    );
    // Neither mode given is a usage error the model can fix, so it must be an
    // actionable message rather than a silent empty result.
    const neither = byId(s.msgs, 3)?.result;
    check(
      neither?.isError === true && /strings/.test(neither?.structuredContent?.messages?.[0] || ''),
      'over MCP: findliteral with neither literal nor strings says which one to give',
      JSON.stringify(neither?.structuredContent?.messages),
    );
  }
}

/* ---- 11. the header fields reach a client, on the same contract -------- */

{
  // A field the CLI prints but MCP drops is a contract held by one door and not
  // the other, which is the project's own word for not a contract. The header
  // facts and the abnormality report are exactly where that would show up: both
  // are per-slice additions to `describe`, and an agent has no other way to see
  // them than this payload.
  const metaBin = path.join(FIXTURES, 'meta.macho');
  const dmgBin = path.join(FIXTURES, 'damaged.macho');
  if (!fs.existsSync(metaBin) || !fs.existsSync(dmgBin)) {
    skip({ name: 'header fields over MCP', why: 'the meta/damaged fixtures are missing — run npm run test:fixtures' });
  } else {
    const r = await session([
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: metaBin }, _meta: meta() } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'macho-describe', arguments: { binary: dmgBin }, _meta: meta() } },
    ], { expectLines: 2 });
    const s = parseStream(r.out);
    const good = byId(s.msgs, 1)?.result;
    const bad = byId(s.msgs, 2)?.result;
    const g = good?.structuredContent?.data?.slices?.[0];
    const b = bad?.structuredContent?.data?.slices?.[0];

    check(
      Array.isArray(g?.flagsNamed) && g.flagsNamed.includes('MH_PIE') && g.flagsUnknown === 0,
      'over MCP: the decoded header flags reach the client',
      JSON.stringify(g?.flagsNamed),
    );
    check(
      g?.sections?.some((x) => x.sectname === '__data' && x.type === 'S_CSTRING_LITERALS'),
      'over MCP: a section type reaches the client',
      g?.sections?.map((x) => `${x.sectname}=${x.type}`).join(' '),
    );
    check(
      Array.isArray(g?.rpaths) && g.rpaths[0] === '@executable_path/../Frameworks'
        && g?.sourceVersion?.text === '4660.12.4.5.6',
      'over MCP: LC_RPATH and LC_SOURCE_VERSION reach the client',
      `rpaths=${JSON.stringify(g?.rpaths)} version=${g?.sourceVersion?.text}`,
    );
    // The refusal must survive serialisation, or an agent will read a null and
    // compute `__TEXT.vmaddr + entryoff` itself — the one thing the reader declines
    // to do because the sum is wrong.
    check(
      g?.entryPoint && g.entryPoint.vaddr === null && /no address is derived/.test(g.entryPoint.note || ''),
      'over MCP: the entry point arrives with no invented address',
      `vaddr=${JSON.stringify(g?.entryPoint?.vaddr)}`,
    );
    check(
      Array.isArray(g?.abnormalities) && g.abnormalities.length === 0,
      'over MCP: a healthy binary reports an empty abnormality list, not a missing field',
      JSON.stringify(g?.abnormalities),
    );

    // And the damaged half. It has to arrive as data on a *successful* call:
    // a client that cannot see the report cannot warn the user.
    check(
      bad?.isError === false && Array.isArray(b?.abnormalities) && b.abnormalities.length === 3,
      'over MCP: abnormalities arrive on a successful call, not as an error',
      `isError=${bad?.isError} kinds=${b?.abnormalities?.map((a) => a.kind).join(',')}`,
    );
    check(
      b?.flagsUnknown === 0x20000000 && b?.flagsNamed?.length === 4,
      'over MCP: an unnamed flag bit is reported beside the named ones',
      `unknown=0x${b?.flagsUnknown?.toString(16)}`,
    );
    check(
      b?.sections?.length > 0 && b?.defined > 0,
      'over MCP: a damaged file still reports what could be read',
      `sections=${b?.sections?.length} defined=${b?.defined}`,
    );
    check(
      /abnormalit/i.test(bad?.content?.[0]?.text || ''),
      'and the text block mentions them, so a model reading prose sees them too',
    );
  }
}

/* ---- 12. the stdout guard is real ----------------------------------- */

{
  const { guardStdout, stdoutStrayWrites } = await import('../src/mcp.mjs');
  const before = stdoutStrayWrites();
  guardStdout();
  process.stdout.write('a stray debug line\n');
  check(stdoutStrayWrites() === before + 1, 'a non-protocol write to stdout is counted', `${stdoutStrayWrites()} vs ${before}`);
  process.stderr.write('[test] the guard diverted the line above to stderr; restoring stdout\n');
  process.stdout.write = process.stdout.constructor.prototype.write.bind(process.stdout);
}

/* ------------------------------------------------------------------ *
 * summary
 * ------------------------------------------------------------------ */

console.log(`\n${pass} passed. The protocol holds over a real pipe.`);
if (skipped.length) {
  console.log(`${skipped.length} skipped:`);
  for (const s of skipped) console.log(`  ${s.name}\n    ${s.why}`);
  console.log('  A skip means the input was unavailable, not that the check passed.');
}
console.log(fail ? `\n${fail} FAILED.` : '');
process.exit(fail ? 1 : 0);
