#!/usr/bin/env node
/**
 * mcp.mjs — this package as a Model Context Protocol server.
 *
 *   node src/mcp.mjs            # speak MCP on stdin/stdout
 *   node src/mcp.mjs --help     # usage, on stderr
 *
 * ## Why an MCP server and not another CLI
 *
 * Not differentiation — Hopper, Binary Ninja 6.0 and `ipsw` all ship one, and by
 * the time this was written that made it table stakes. It is *distribution*: an
 * MCP server is how an agent discovers that a capability exists at all, and
 * without one this package is invisible to every agent-driven workflow while
 * being excellent at the thing those workflows want. The comparison in
 * `COMPETITIVE-LANDSCAPE.md` puts the honest version: this is a doorway, not an
 * advantage.
 *
 * It is also nearly free here, and that is the real reason it landed. The tools
 * already emitted `--json` on a single envelope with four exit codes and
 * `bigint` addresses rendered as strings — which is what MCP's `structuredContent`
 * and `isError` want. There was no new dialect to invent, only a transport to
 * put around the existing one.
 *
 * ## Dual-era, because the protocol changed underneath this
 *
 * MCP is mid-migration. Revisions up to `2025-11-25` open a session with an
 * `initialize` handshake. Revision `2026-07-28` removed the handshake entirely:
 * every request carries its own version in `_meta`, and there is no session to
 * remember. A server written for only one era fails against half the clients in
 * the wild, and which era a given client speaks is not something this process
 * gets to choose — the client's *first message* decides.
 *
 * So both are served:
 *
 *   • a request carrying `_meta["io.modelcontextprotocol/protocolVersion"]` is
 *     modern, and is served statelessly from that message alone;
 *   • an `initialize` request selects legacy semantics for this process, which
 *     is the scoping the spec allows;
 *   • `server/discover` (mandatory in the modern revision) answers for both, so
 *     a dual-era client can probe and settle the question immediately.
 *
 * `resultType` is written on modern results and omitted on legacy ones. Modern
 * requires it; legacy schemas predate it, and an unknown key is the kind of
 * thing that gets a strict validator to reject the whole response.
 *
 * ## One rule broken on purpose
 *
 * A modern request missing a required `_meta` key must be rejected with
 * `-32602`, and the era is undefined when `_meta` is absent entirely. This
 * server serves such a request as **legacy** rather than rejecting it, because
 * legacy needs no per-request metadata — so the permissive reading cannot
 * misjudge any client that follows the spec, and it rescues every one that
 * doesn't. `protocolVersion` and `clientCapabilities` *are* enforced when `_meta`
 * is present, because by then the client has told us which era it is in and
 * there is nothing left to be lenient about.
 *
 * ## stdout is the protocol
 *
 * A single stray `console.log` in any code path corrupts the framing, and the
 * symptom is a client that reports a parse error somewhere else entirely — a
 * failure that points at the wrong file. So stdout is guarded: every write goes
 * through one function, and anything else is diverted to stderr and counted.
 * `test/mcp.mjs` asserts the count is zero, which is the only way to know the
 * guard is not itself the thing that is broken.
 */
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';
import process from 'node:process';
import { toolDefinitions, callTool, INSTRUCTIONS, findTool } from './mcp-tools.mjs';

/* ------------------------------------------------------------------ *
 * versions
 * ------------------------------------------------------------------ */

/** The modern revision: no handshake, per-request `_meta`. */
const MODERN = '2026-07-28';

/**
 * Revisions that open with `initialize`, newest first.
 *
 * The order is the preference order for the case a client asks for something we
 * do not have: answer with the newest of these rather than the oldest, since a
 * client that can speak 2025-11-25 can usually speak more than one.
 */
const LEGACY = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const SUPPORTED = [MODERN, ...LEGACY];

const SERVER_NAME = 'MachO-explorer';
const { version: SERVER_VERSION } = createRequire(import.meta.url)('../package.json');

/* ------------------------------------------------------------------ *
 * JSON-RPC
 * ------------------------------------------------------------------ */

const ERR = {
  parse: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internal: -32603,
  // The one code in the reserved MCP range this server is allowed to emit.
  unsupportedVersion: -32022,
};

/* ------------------------------------------------------------------ *
 * stdout guard
 * ------------------------------------------------------------------ */

/**
 * Reserve stdout for the protocol, and make a violation visible.
 *
 * Diverted rather than thrown: the alternative is to abort mid-session, which
 * turns a stray debug line into an outage. Diverting keeps the stream valid and
 * leaves evidence in two places — the stderr line and `strayWrites`, which the
 * test suite asserts on. A guard that could only fail loudly would be a guard
 * that gets commented out the first time it is inconvenient.
 */
let strayWrites = 0;
const realWrite = process.stdout.write.bind(process.stdout);

/** How many non-protocol writes have been diverted. Asserted on by the tests. */
export const stdoutStrayWrites = () => strayWrites;

export function guardStdout() {
  process.stdout.write = (chunk, ...rest) => {
    const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null;
    const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    // The one legitimate writer: our own framed message.
    if (text.startsWith('{"jsonrpc"')) {
      const ok = realWrite(chunk, ...(cb ? [cb] : []));
      return ok;
    }
    strayWrites++;
    process.stderr.write(`[macho-mcp] diverted a non-protocol write to stdout: ${text.slice(0, 200)}\n`);
    if (cb) cb(false);
    return false;
  };
}

/** One message, one line, no embedded newlines. `JSON.stringify` guarantees both. */
function send(msg) {
  realWrite(JSON.stringify(msg) + '\n');
}

const respond = (id, result) => send({ jsonrpc: '2.0', id, result });
const fail = (id, code, message, data) =>
  send({ jsonrpc: '2.0', id, error: data === undefined ? { code, message } : { code, message, data } });

/* ------------------------------------------------------------------ *
 * era
 * ------------------------------------------------------------------ */

/** Which era a request speaks, or `'unsupported'` if it says a version we lack. */
function eraOf(msg) {
  const meta = msg?.params?._meta;
  if (!meta || typeof meta !== 'object') return 'legacy'; // see the header note
  const v = meta['io.modelcontextprotocol/protocolVersion'];
  if (typeof v !== 'string') return 'legacy';
  return SUPPORTED.includes(v) ? (v === MODERN ? 'modern' : 'legacy') : 'unsupported';
}

/** Everything after the era is known, so results can be shaped correctly. */
function shape(era, body) {
  if (era !== 'modern') return body;
  return {
    resultType: 'complete',
    _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
    ...body,
  };
}

const CAPABILITIES = { tools: { listChanged: false } };

/* ------------------------------------------------------------------ *
 * methods
 * ------------------------------------------------------------------ */

async function handle(msg, state) {
  const { id, method, params } = msg;
  const isRequest = id !== undefined && id !== null;

  // `notifications/*` never get a reply, and must not be answered even on error.
  if (!isRequest) {
    if (method === 'notifications/initialized') state.era = 'legacy';
    return;
  }

  // --- the modern probe, and the one method that must work before anything else
  if (method === 'server/discover') {
    const era = eraOf(msg);
    if (era === 'unsupported') return unsupported(id, params);
    // Answered in the modern shape whatever era asked: it is the discovery
    // mechanism, so answering it in a dialect the caller cannot read would make
    // it useless for the only job it has.
    return respond(id, {
      resultType: 'complete',
      supportedVersions: SUPPORTED,
      capabilities: CAPABILITIES,
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
      instructions: INSTRUCTIONS,
      ttlMs: 3600000,
      cacheScope: 'public',
    });
  }

  // --- the legacy handshake
  if (method === 'initialize') {
    state.era = 'legacy';
    const asked = params?.protocolVersion;
    const chosen = LEGACY.includes(asked) ? asked : LEGACY[0];
    return respond(id, {
      protocolVersion: chosen,
      capabilities: CAPABILITIES,
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION, title: 'MachO-explorer' },
      instructions: INSTRUCTIONS,
    });
  }

  const era = eraOf(msg);
  if (era === 'unsupported') return unsupported(id, params);

  // Required `_meta` keys, enforced once the client has identified its era.
  if (params?._meta && typeof params._meta === 'object') {
    const missing = ['io.modelcontextprotocol/protocolVersion', 'io.modelcontextprotocol/clientCapabilities']
      .filter((k) => params._meta[k] === undefined);
    if (missing.length) {
      return fail(id, ERR.invalidParams,
        `params._meta is missing required field(s): ${missing.join(', ')}. ` +
        `This server speaks ${SUPPORTED.join(', ')}.`);
    }
  }

  switch (method) {
    case 'ping':
      return respond(id, shape(era, {}));

    case 'tools/list':
      return respond(id, shape(era, { tools: toolDefinitions() }));

    case 'tools/call':
      return callTools(id, era, params);

    default:
      return fail(id, ERR.methodNotFound, `Unknown method: ${method}`,
        state.era === null
          ? {
              note:
                'No initialize handshake was seen and the request carried no modern _meta, so it was served as ' +
                `protocol ${LEGACY[0]}. Send initialize, or set _meta["io.modelcontextprotocol/protocolVersion"] to one of: ` +
                SUPPORTED.join(', '),
              supported: SUPPORTED,
            }
          : { supported: SUPPORTED });
  }
}

function unsupported(id, params) {
  const requested = params?._meta?.['io.modelcontextprotocol/protocolVersion'] ?? null;
  return fail(id, ERR.unsupportedVersion, 'Unsupported protocol version', { supported: SUPPORTED, requested });
}

/**
 * Run a tool and turn the outcome into a tool result.
 *
 * The distinction that matters: a *validation* failure is a tool execution error
 * (`isError: true`), not a protocol error, because a model can fix a bad
 * argument by reading the message and retrying. Only a request that does not
 * parse as a `tools/call` is a protocol error. The spec asks for exactly this
 * split, and it is also the behaviour this package already had — an empty
 * result is `ok: true`, and a wrong path is `ok: false` with a reason code.
 */
async function callTools(id, era, params) {
  const name = params?.name;
  if (typeof name !== 'string') return fail(id, ERR.invalidParams, 'tools/call requires a string `name`');
  if (!findTool(name)) {
    const known = toolDefinitions().map((t) => t.name);
    return fail(id, ERR.invalidParams, `Unknown tool: ${name}`, { available: known });
  }
  if (params.arguments !== undefined && (params.arguments === null || typeof params.arguments !== 'object' || Array.isArray(params.arguments))) {
    return fail(id, ERR.invalidParams, 'tools/call `arguments` must be an object when present');
  }

  const out = await callTool(name, params.arguments ?? {});
  const body = {
    content: [{ type: 'text', text: out.text }],
    structuredContent: bigintSafe(out.envelope),
    isError: out.isError,
  };
  return respond(id, shape(era, body));
}

/**
 * BigInt → `"0x…"`, because `JSON.stringify` throws on one.
 *
 * Every address in this package is a BigInt, so without this the first tool call
 * that returns an address fails at serialisation — inside the server, where the
 * client sees an unexplained internal error rather than an answer. Same reason
 * `output.mjs` does it for the CLIs.
 */
function bigintSafe(value) {
  return JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? `0x${v.toString(16)}` : v)));
}

/* ------------------------------------------------------------------ *
 * loop
 * ------------------------------------------------------------------ */

export function serve({ input = process.stdin, output = process.stdout } = {}) {
  const state = { era: null };
  let buffer = '';
  let open = true;

  const onLine = (line) => {
    const text = line.trim();
    if (!text) return; // keepalive newlines are legal and carry nothing

    let msg;
    try {
      msg = JSON.parse(text);
    } catch (e) {
      // No id could be read, so there is nothing to correlate — the one case
      // where an error response without an id is correct.
      return fail(null, ERR.parse, `Parse error: ${e.message}`);
    }

    // Valid JSON is not the same as a valid request. A bare string, number or
    // array parses and then has no `method`, so treating it as a notification
    // drops it in silence: the client waits for a reply that was never coming
    // and eventually reports a timeout with nothing to act on. Naming it
    // Invalid Request is the difference between a diagnosable failure and a hang.
    if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
      const got = msg === null ? 'null' : Array.isArray(msg) ? 'an array' : typeof msg;
      return fail(null, ERR.invalidRequest, `Invalid Request: expected a JSON-RPC object, got ${got}`);
    }
    if (msg.jsonrpc !== '2.0') {
      return fail(msg.id ?? null, ERR.invalidRequest,
        `Invalid Request: jsonrpc must be "2.0", got ${JSON.stringify(msg.jsonrpc)}`);
    }
    if (typeof msg.method !== 'string' || !msg.method) {
      return fail(msg.id ?? null, ERR.invalidRequest, 'Invalid Request: `method` must be a non-empty string');
    }

    const reply = handle(msg, state);
    Promise.resolve(reply).catch((e) => {
      if (msg.id !== undefined && msg.id !== null) fail(msg.id, ERR.internal, `Internal error: ${e.message}`);
      else process.stderr.write(`[macho-mcp] ${e.stack || e.message}\n`);
    });
  };

  input.setEncoding('utf8');
  input.on('data', (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      onLine(line);
    }
    // A single line longer than this is not a JSON-RPC message. Without a cap a
    // client that writes a huge blob with no newline grows the buffer without
    // bound; with one, the process says so instead of dying quietly.
    if (buffer.length > 64 * 1024 * 1024) {
      process.stderr.write('[macho-mcp] a single line exceeded 64 MiB without a newline; dropping the buffer\n');
      buffer = '';
    }
  });

  // EOF is the portable shutdown signal. Exiting here rather than lingering is
  // what stops a client from having to escalate to SIGTERM and then SIGKILL.
  const done = () => {
    if (!open) return;
    open = false;
    process.exit(0);
  };
  input.on('end', done);
  input.on('close', done);
  input.on('error', done);
  if (input.resume) input.resume();

  return { state, strayWrites: () => strayWrites };
}

/* ------------------------------------------------------------------ *
 * entry point
 * ------------------------------------------------------------------ */

function usage() {
  return [
    'usage: node src/mcp.mjs',
    '',
    'Speaks the Model Context Protocol on stdin/stdout, for one JSON-RPC message per line.',
    'Meant to be launched by an MCP client, not run by hand.',
    '',
    'Register it with a client:',
    '',
    '  claude mcp add macho -- node /absolute/path/to/src/mcp.mjs',
    '',
    'or in .mcp.json:',
    '',
    '  { "mcpServers": { "macho": { "command": "node",',
    '      "args": ["/absolute/path/to/src/mcp.mjs"],',
    '      "env": { "MACHO_BINARY": "/path/to/a/binary" } } } }',
    '',
    'This help goes to stderr on purpose: stdout carries the protocol and nothing else.',
  ].join('\n');
}

const invokedDirectly =
  process.argv[1] &&
  // realpath on both sides, because Node resolves import.meta.url through a
  // symlink while argv[1] still holds the linked path. Comparing the raw values
  // makes an npm-linked install conclude it was imported rather than run, do
  // nothing, and exit 0 — which is the same silent-pass shape as a verification
  // check that stops reading.
  (() => {
    try {
      return realpathSync(process.argv[1]) === realpathSync(new URL(import.meta.url).pathname);
    } catch {
      return false;
    }
  })();

if (invokedDirectly) {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stderr.write(usage() + '\n');
    process.exit(0);
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stderr.write(`${SERVER_NAME} ${SERVER_VERSION}\n`);
    process.exit(0);
  }
  // A server with no client attached is a mistake worth naming, rather than a
  // process that sits there appearing to work.
  if (process.stdin.isTTY) {
    process.stderr.write(usage() + '\n\nno MCP client on stdin: this process speaks JSON-RPC and waits for one.\n');
    process.exit(2);
  }
  guardStdout();
  serve();
}
