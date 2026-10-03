# Agent Skills

This directory holds [Agent Skills](https://agentskills.io) for `MachO-Tools` —
portable instruction sets that teach a coding agent how to use this package.

| Skill | For |
|---|---|
| [`macho-tools/SKILL.md`](macho-tools/SKILL.md) | Reading Mach-O binaries: slices, symbols, addresses, call sites, literal triage |

The format is an open standard, so the same directory works with Claude Code,
Codex, Cursor, VS Code, Copilot, Gemini CLI, Goose, OpenCode and the rest —
see the [client list](https://agentskills.io/clients). Copy the skill directory
into wherever your agent looks for skills:

```sh
# Claude Code, per project
mkdir -p .claude/skills && cp -r skill/macho-tools .claude/skills/

# or for every project
mkdir -p ~/.claude/skills && cp -r skill/macho-tools ~/.claude/skills/
```

## Why a skill and not only the MCP server

The MCP server makes the tools *callable*; it does not make an agent *use them
well*. The two failure modes worth preventing are both about knowledge rather
than access:

- **A wrong address type.** A model that sends `1091523120` instead of
  `"0x100085c30"` gets a plausible address pointing at real, wrong code. The
  skill says so up front, in the place a model reads before its first call.
- **Retrying a negative answer.** An agent that treats "no matches" as a failure
  will try variations indefinitely. The skill states that an empty result is an
  answer, and that exit status 1 is not an error.

The server's `instructions` field carries a short version of the same warnings,
for clients that surface it. The skill carries the long version, plus the
workflow and the fallbacks, for clients that do not.

## Both, not either

The skill works with no MCP server configured — it documents the CLI, which
needs nothing installed but Node. An agent that has only the CLI still gets the
address-type rule, the exit-code table and the direct-calls-only caveat, which
are the three things that produce confidently wrong answers.
