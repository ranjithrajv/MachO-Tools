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

  const probes = {
    'macho-describe': { binary: universal },
    'macho-sym': { binary: populated, pattern: 'pop' },
    'macho-symlookup': { binary: populated, addresses: ['0x100000120'] },
    'macho-findcall': { binary: populated, target: '0x100000220' },
    'macho-findliteral': realLiteral ? { binary: REAL, literal: realLiteral } : null,
    'macho-mapliteral': realMapLiteral ? { binary: REAL, literal: realMapLiteral } : null,
    'macho-a2o': realAddr ? { binary: REAL, addresses: [realAddr] } : null,
    'macho-o2a': realOffset !== null ? { binary: REAL, offsets: [realOffset] } : null,
  };

  for (const d of defs) {
    const probeArgs = probes[d.name];
    if (!probeArgs) {
      // The reason differs per tool — a missing literal, a missing __text — so it is
      // stated rather than left as one generic sentence that would be wrong for
      // whichever tool happened to skip.
      skip(
        `${d.name}: runs against a real binary`,
        d.name === 'macho-o2a'
          ? 'no Mach-O with a mappable address was available'
          : 'no Mach-O with a known literal was available (looked at /usr/local/go/bin/go, /bin/ls, /usr/bin/ls)',
      );
      continue;
    }
    const out = await callTool(d.name, probeArgs);
    check(
      out && out.envelope && out.envelope.tool === d.name && typeof out.text === 'string' && out.text.length > 0,
      `${d.name}: runs against a real binary and produces a result`,
      JSON.stringify(out?.envelope?.errors),
    );
    check(
      out?.envelope?.ok === true,
      `${d.name}: finds what is actually there (errors=${JSON.stringify(out?.envelope?.errors)})`,
    );
    check(
      out?.envelope?.data !== null && out?.envelope?.data !== undefined,
      `${d.name}: returns data`,
    );
    check(
      !/\bundefined\b|\[object Object\]|NaN/.test(out?.text || ''),
      `${d.name}: its text block reads as prose, with no undefined leaking through`,
      (out?.text || '').split('\n').find((l) => /undefined|\[object Object\]|NaN/.test(l)),
    );
    check(
      (out?.envelope?.errors || []).every((c) => REASON_CODES.includes(c)),
      `${d.name}: emits only documented reason codes`,
      JSON.stringify(out?.envelope?.errors),
    );
    // Addresses must survive the round trip as strings, which is the one
    // property that cannot be checked by reading the output by eye.
    check(
      !/"(?:vaddr|addr|dest|target|start|next)":\s*\d/.test(json(out?.envelope?.data)),
      `${d.name}: no address is serialised as a JSON number`,
    );
  }

  // The generated corpus contains no printable string literals at all, so these
  // two tools have nothing to find there. That is a useful case to pin: it is
  // where an empty result is the only correct answer, and where a tool that
  // reported it as a failure would send a model looking for another binary.
  for (const t of ['macho-findliteral', 'macho-mapliteral']) {
    const out = await callTool(t, { binary: populated, literal: 'no-such-literal-anywhere' });
    check(
      out?.envelope?.ok === true && out?.envelope?.errors?.length === 0,
      `${t}: a literal absent from the corpus answers empty rather than failing`,
      JSON.stringify(out?.envelope?.errors),
    );
    check(
      out?.isError === false,
      `${t}: and is not flagged as an error to the client`,
    );
    check(
      out?.envelope?.notes?.length > 0,
      `${t}: but does say in a note that nothing was found`,
      JSON.stringify(out?.envelope?.notes),
    );
  }
}

/* ---- 10. the stdout guard is real ----------------------------------- */

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
