# The stdio MCP proxy

`revoco.mcp.proxy` puts revoco in front of an existing MCP server, so an agent
host — Claude Code, Cursor, anything speaking the stdio transport — is gated on
recoverability without the server or the host knowing.

It was ported from `mcp-gate`, whose decision layer duplicated `revoco.gate`;
the transport was the part that did not exist here. It is 291 lines with 13
tests. **It shipped without an entry point or a mention in any document**, which
is why this file exists — see finding 13 in [ADAPTERS.md](ADAPTERS.md).

## Shape

The MCP spec makes this easy: stdio servers are launched as a subprocess by the
client, so a proxy slots in by *becoming* the subprocess the client launches and
launching the real server itself.

```
MCP client (agent host)
    | stdin/stdout — talks to the proxy as if it were the server
    v
revoco stdio proxy
    | stdin/stdout — spawns the real server as a subprocess
    v
upstream MCP server
```

## Why it is not just an allow/deny filter

revoco splits authorization from execution deliberately. `authorize` plans the
undo and journals it against prior state; `confirm` records that the action
actually happened. A proxy that only forwarded would throw the second half away,
and the undo plan would never bind the arguments you can only learn from the
*response* — the payment id, the created resource's identifier.

So the proxy correlates JSON-RPC ids. A gated `tools/call` holds its verdict
until upstream answers, then confirms on a result or abandons on an error. An
action that failed upstream must not leave a live undo plan behind claiming it
can reverse something that never happened.

Only `tools/call` is gated. The handshake, `initialize` and discovery are not
actions, and gating them would break the session for no benefit.

## Limits, stated rather than discovered

- A `tools/call` without an `id` cannot be correlated to a response, so it
  cannot be confirmed. It is **refused** rather than forwarded unconfirmable.
- Line-delimited JSON only, one message per line, which is what the stdio
  transport specifies. No batching.
- Upstream stderr is passed through to the operator untouched.
- Tools whose calls were never answered are readable as `proxy.stranded` at
  shutdown, so a supervisor can act on it rather than scrape the log.

## Running it

There is deliberately **no `revoco mcp` subcommand**. The proxy needs an actor
private key, and where that key comes from is a deployment decision this project
should not make silently on an operator's behalf. `Caller`'s own docstring is
the reason:

> stdio has no client-to-server authentication, so identity cannot be derived
> from the transport. [...] a token read from the environment proves only that
> whoever launched the process could read the environment.

So [`scripts/mcp_stdio_proxy.py`](../scripts/mcp_stdio_proxy.py) is a **reference
launcher**, not a supported entry point. It reads the key from a file path given
explicitly on the command line — not from an environment variable — and it is
meant to be copied and adapted, with the identity wiring replaced by whatever
your deployment actually uses.

```bash
python scripts/mcp_stdio_proxy.py \
    --key /run/secrets/agent.key \
    --actor agent-7 \
    --delegation "$DELEGATION_ID" \
    -- npx -y @modelcontextprotocol/server-filesystem /srv/data
```

In an MCP client config, that whole command is what you register in place of the
server you are wrapping.

## Two things the caller must supply

`action_of` and `risk_of` both default to the safe answer, and both are worth
overriding:

- **`action_of`** — MCP does not say whether a tool reads or writes, and
  guessing from the name is how `invoices.approve` gets treated as a read. The
  default is `"write"` for everything: safe, and noisy enough that you will want
  to narrow it.
- **`risk_of`** — defaults to `0`. Policy rules keyed on risk cannot fire until
  something supplies a real number.

Neither can be inferred correctly from the protocol, which is why they are
parameters rather than heuristics.
