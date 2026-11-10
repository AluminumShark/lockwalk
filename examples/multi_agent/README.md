# Multi-agent demo

A small, fake trading desk built from real OpenAI Agents SDK and Pydantic AI objects. It
shows what lockwalk adds for systems where agents call other agents: the agent call graph,
`never_reaches` rules with the path that breaks them, and the role x tool table.

Agents and tools run only in the Cedar example's door tests (agents with fake models, tools
after their side effects are replaced). [Ask the IAM](#ask-the-iam) asks an IAM questions.
Importing `app.py` only constructs the agents: no model is called, no network
connection is opened, and no API key is needed. `discover`, `coverage`, and `lockwalk test`
without `[harness]` never call a tool. With `[harness]`, `lockwalk test` may call these tools
in a worker subprocess, but only after it has replaced their side effects (`demo_trading.py`)
with counters; the side effects raise if they ever really run. The remote agent exists only
in the registry.

| File | What it is |
|---|---|
| `app.py` | The agents, built with the real frameworks. Its tools ask a small demo door before they act |
| `demo_door.py` | The demo door (example code, not part of lockwalk): asks the IAM, raises `PermissionError` on deny |
| `demo_trading.py` | The side effects (they raise if they really run) and the small tables the door reads |
| `registry.yaml` | What discovery cannot tell lockwalk: roles, entry agents, identities, tool risks, and the calls made inside tool code |
| `security-spec.yaml` | Hand-written expected answers: five `path:` cases and three `never_reaches` rules |
| `fixtures.yaml` | Test identities and resources, for `lockwalk test` only (see [Ask the IAM](#ask-the-iam)) |
| `deny-only-spec.yaml` | The spec reduced to its deny cases, to show the positive-control check (see [Ask the IAM](#ask-the-iam)) |
| `waivers.yaml`, `waivers-expired.yaml` | Two waivers for RULE-001 and RULE-002, one valid and one expired (see [Waivers](#waivers)) |
| `.lockwalk.toml` | Points lockwalk at the registry, the spec, the fixtures, and the two framework entry points in `app.py` |

## The system

| Agent | Built with | What lockwalk knows about its calls |
|---|---|---|
| `supervisor` | OpenAI Agents SDK | Entry agent for analysts and traders. Discovered: hands off to `finance-agent` |
| `trade-desk` | OpenAI Agents SDK | Entry agent for traders only. Discovered: hands off to `trade-agent` |
| `finance-agent` | OpenAI Agents SDK | Discovered: uses `trade-agent` through `as_tool()`. Declared: calls `pricing-agent` inside its `get_quote` tool |
| `trade-agent` | OpenAI Agents SDK | Uses its own identity (`delegation_mode: agent`). Discovered: hands back to `finance-agent`, which makes a cycle. Declared: calls `market-oracle` inside its `confirm_price` tool |
| `pricing-agent` | Pydantic AI | Discovered: its own `get_stock_price` tool |
| `market-oracle` | Remote agent run by the exchange (`remote:` in the registry) | Nothing: it is opaque |

lockwalk discovers handoffs and `as_tool()` from the objects. It cannot see a call that a
tool function makes to another agent, so `registry.yaml` declares those two routes with
`calls`. Once an agent declares `calls`, the list must be complete: lockwalk warns about any
discovered edge that `calls` does not list.

## Run it

From the repository root:

```bash
uv sync
cd examples/multi_agent
uv run lockwalk discover
uv run lockwalk coverage    # exits 1 (expected)
```

`uv sync` installs the development environment, which includes both frameworks
(`openai-agents` and `pydantic-ai-slim`). If you use pip instead, install those two packages
into the environment that runs lockwalk: the discovery worker imports `app.py` with the
same Python interpreter as lockwalk.

You can also stay in the repository root and add
`--config examples/multi_agent/.lockwalk.toml` to both commands.

`.lockwalk.toml` points at both OpenAI entry agents with one list,
`app:OPENAI_ENTRY_AGENTS`. One target per entry agent works too (from `examples/multi_agent`;
targets on the command line replace the ones in `.lockwalk.toml`):

```bash
uv run lockwalk discover --python app:supervisor --python app:trade_desk --python app:pricing_agent
```

Both OpenAI walks then reach the agents that the two entry agents share, so they report the
same tools. lockwalk merges a tool that several Python sources describe identically, and the
tool lists every one of them as a source. A tool that an MCP server or a JSON export also
reports is still an error, because two servers can describe two different tools the same
way.

### The agent graph

`discover` (and `coverage`) draw one tree per entry agent. Each edge shows its kind and
where lockwalk learned it: `discovered` from the objects, `declared` in the registry. An
agent is expanded once; later it is marked `(see above)`, a loop back is `(cycle)`, and a
node whose calls are unknown is `(opaque)`.

```text
Agent graph (entry agents: supervisor, trade-desk):
  supervisor  [delegation_mode=user]
    -[handoff, discovered]-> finance-agent  [delegation_mode=user]
      -[calls, declared]-> pricing-agent  [delegation_mode=on_behalf_of]
        -[uses_tool, discovered]-> get_stock_price  (risk=low)
      -[agent_as_tool, discovered]-> trade-agent  [delegation_mode=agent]
        -[calls, declared]-> finance-agent  [delegation_mode=user]  (cycle)
        -[handoff, discovered]-> finance-agent  [delegation_mode=user]  (cycle)
        -[calls, declared]-> market-oracle  (opaque)
        -[uses_tool, discovered]-> confirm_price  (risk=medium)
        -[uses_tool, discovered]-> execute_trade  (risk=critical)
      -[calls, declared]-> trade-agent  [delegation_mode=agent]  (see above)
      -[uses_tool, discovered]-> get_quote  (risk=low)
      -[uses_tool, discovered]-> read_portfolio  (risk=high)
  trade-desk  [delegation_mode=user]
    -[handoff, discovered]-> trade-agent  [delegation_mode=agent]  (see above)
```

Two routes appear twice, once `discovered` and once `declared`: `finance-agent` to
`trade-agent`, and `trade-agent` to `finance-agent`. That is expected. The code has these
routes, and both agents declare `calls` for the routes discovery cannot see, so their
`calls` lists must name these agents too.

Below the tree come the role reachability table (every tool each role can reach, with the
`delegation_mode` of the last agent, which says whose identity it uses, and the cases or
rules that cover it), the rule results, and these notes:

```text
Graph notes:
  Cycles: finance-agent -> trade-agent -> finance-agent
  Opaque: market-oracle
```

### What coverage finds

Only the end of the `coverage` output is shown here, without the graph notes and the last
line (the report path):

```text
Never-reaches rules:
  RULE-001  FAIL          role:analyst -> tool:execute_trade
    supervisor -[handoff, discovered]-> finance-agent -[agent_as_tool, discovered]-> trade-agent -[uses_tool, discovered]-> execute_trade
  RULE-002  INCONCLUSIVE  agent:market-oracle -> tool:execute_trade (passes through opaque: market-oracle)
  RULE-003  PASS          agent:pricing-agent -> tool:execute_trade

Warnings:
  - agent 'trade-agent' calls tools with its own identity; the IAM will not see the user. Through it, roles analyst, trader can reach 1 high-risk tool: execute_trade
  - role 'trader' can reach 1 high-risk tool that no case or rule covers: read_portfolio (risk=high)

Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
```

- **RULE-001 fails.** Analysts may use `supervisor`, and the line under the rule is the
  path that proves an analyst can reach `execute_trade`. Worse, `trade-agent` calls the
  tool with its own identity, so your IAM sees `trade-agent`, not the analyst, and cannot
  tell them apart. That is the first warning.
- **RULE-002 is inconclusive.** `market-oracle` is remote, so lockwalk cannot see whether
  it calls back into your agents. An INCONCLUSIVE rule fails the gate by default
  (`fail_on_never_reaches_inconclusive = true`).
- **RULE-003 passes.** lockwalk walked `pricing-agent` and found no route to
  `execute_trade`. Like every PASS, this covers only the calls lockwalk can see: a call
  made inside `get_stock_price` would need a `calls` declaration.
- The second warning is a role x tool gap: traders can reach `read_portfolio` (high risk)
  and no case or rule covers that. It is only a warning, because the default
  `fail_on_unspecified_role_risk` is `["critical", "unknown"]`. Add a trader case for
  `read_portfolio` to cover it.

The full results, including every edge, cycle, rule witness, and reachability row, are in
`examples/multi_agent/.lockwalk/coverage.json`, next to `.lockwalk.toml`. That is also where
the report goes when you run with `--config` from the repository root. It is report
`schema_version` "3": see `agent_graph`, `reachability`, and `rules`.

## Fix 1: remove the route

Analysts should not be able to trade at all; traders trade through `trade-desk`. So
`finance-agent` should not use `trade-agent`. Make two edits:

1. In `app.py`, delete the `trade_agent.as_tool(...)` entry from `finance-agent`'s tools.
2. In `registry.yaml`, change `finance-agent`'s calls to `calls: [pricing-agent]`.

Both are needed because lockwalk trusts your declarations. If you only make the first
edit, `calls` still says that `finance-agent` calls `trade-agent`, and RULE-001 still
fails, now with this path:

```text
    supervisor -[handoff, discovered]-> finance-agent -[calls, declared]-> trade-agent -[uses_tool, discovered]-> execute_trade
```

After both edits, `coverage` shows:

```text
  RULE-001  PASS          role:analyst -> tool:execute_trade
```

## Fix 2: declare what market-oracle calls

If you know that `market-oracle` never calls any of your agents (for example from the
exchange's API contract), say so in `registry.yaml`:

```yaml
  - id: market-oracle
    description: The exchange's remote price oracle. lockwalk cannot see what it calls.
    remote: https://oracle.example/a2a
    calls: []
```

`calls: []` means "calls no other agent". lockwalk cannot check this declaration; it only
uses it. Now `coverage` shows:

```text
  RULE-002  PASS          agent:market-oracle -> tool:execute_trade
```

With both fixes, the gate passes:

```text
Gate: PASS (exit 0)
```

The identity warning stays (traders still reach `execute_trade` through `trade-agent`),
and so does the `read_portfolio` gap until you add a case for it. To undo the edits, run
`git checkout -- examples/multi_agent` from the repository root.

## Waivers

Say you accept both findings for now: RULE-002 because `market-oracle` is a third party, and
RULE-001 until the handoff is removed. A waiver records that, with an owner and an expiry
date. Two files are shipped, and they are used with `--waivers` only (they are not in
`.lockwalk.toml`). Run these from this folder.

```bash
uv run lockwalk coverage                                   # exit 1: RULE-001, RULE-002
uv run lockwalk coverage --waivers waivers.yaml            # exit 0: both are waived
uv run lockwalk coverage --waivers waivers-expired.yaml    # exit 1: the waivers expired
```

With `waivers.yaml`, the findings stay in the report with a mark, and the gate passes:

```text
  RULE-001  FAIL          role:analyst -> tool:execute_trade [waived: WAIVE-002]
  RULE-002  INCONCLUSIVE  agent:market-oracle -> tool:execute_trade (passes through opaque: market-oracle) [waived: WAIVE-001]
```

```text
Gate: PASS (exit 0)
Waived:
  - never_reaches: RULE-002 (INCONCLUSIVE) (WAIVE-001, owner alice@example.com, until 2027-01-31)
  - never_reaches: RULE-001 (FAIL) (WAIVE-002, owner alice@example.com, until 2027-01-31)
```

With `waivers-expired.yaml` (same waivers, dated 2026-06-30), both findings block again and
each waiver is listed under "Waivers needing attention":

```text
Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
Waivers needing attention:
  expired      WAIVE-001: waiver WAIVE-001 expired on 2026-06-30 (owner alice@example.com); RULE-002 blocks the gate again
  expired      WAIVE-002: waiver WAIVE-002 expired on 2026-06-30 (owner alice@example.com); RULE-001 blocks the gate again
```

`waivers.yaml` expires on 2027-01-31 on purpose. After that date it shows the expired
behavior too. To keep the demo passing, edit the dates, but not further ahead than
`[gate] max_waiver_days` (90 days) from today. `lockwalk coverage --summary` prints the short
form of any of these runs. See [Waivers](../../docs/lockwalk-coverage.md#waivers) for the rules.

## Ask the IAM

Everything above is static. `lockwalk test` also asks a real IAM whether these routes are
authorized. Two examples do that with the same agents, spec, and fixtures:

- [`examples/iam_cedar`](../iam_cedar/README.md): a local Cedar engine, asked through
  `decide()`. No Docker needed.
- [`examples/iam_cerbos`](../iam_cerbos/README.md): a Cerbos PDP in Docker, asked through
  AuthZEN.

`fixtures.yaml` describes the test identities and resources: `alice` (analyst) and `bob`
(trader), the service identity of `trade-agent`, the portfolios, orders, and stock symbol that
the cases use, and the `probes`. `probes` name one stand-in user per role and one stand-in
resource per type; the escalation check (does the identity the route uses get an allow that
the user alone would not?) uses them as the stand-in user and resource for the role x tool
rows.
`.lockwalk.toml` points at the file, and `coverage` does not read it. Every resource also
has `tool_args`, the arguments lockwalk passes when it calls a tool for the door tests.

The app also has a small demo door: each tool asks the IAM before it acts
(`demo_door.py`, with the side effects in `demo_trading.py`; both are example code, not part
of lockwalk). The Cedar example uses it for the door tests: it adds `[harness]`, replaces
the side effects with counters, and calls the tools. Two environment switches break the door
on purpose: `LOCKWALK_DEMO_BYPASS=<tool>` (that tool skips the door) and
`LOCKWALK_DEMO_OWN_IDENTITY=finance-agent` (the handoff to `finance-agent` drops the user).
See [The door demo](../iam_cedar/README.md#the-door-demo). The Cerbos example has no
`[harness]`.

Both IAM examples have the same deliberate hole: `trade-agent` calls with its own service
identity, and its policy lets that identity trade on any account. `test` reports it as a
FAIL_POLICY for CASE-005 and as an ESCALATION.

`deny-only-spec.yaml` is a spec with only the deny cases (CASE-002 and CASE-005).
With it, nothing shows that the IAM understood the questions, so CASE-002 becomes
INCONCLUSIVE. Run it from either example directory:

```bash
uv run lockwalk test --spec ../multi_agent/deny-only-spec.yaml
```

The [guide](../../docs/lockwalk-test.md#what-lockwalk-test-does) explains what the output means,
and has the details.

## Watch real traffic

`traces/` has seven small hand-written OTLP files (OTel GenAI attributes, the agent and tool
names of this app, and door records and effect markers), as an OpenTelemetry Collector would
write them. `lockwalk observe` compares them with the map above and with the spec. Run from
this folder:

```bash
uv run lockwalk observe --traces traces/ok.jsonl         # exit 0
uv run lockwalk observe --traces traces/off_map.jsonl    # exit 1
uv run lockwalk observe --traces traces/unknown.jsonl    # exit 1
uv run lockwalk observe --traces traces/mismatch.jsonl   # exit 1
uv run lockwalk observe --traces traces/unguarded.jsonl  # exit 1
uv run lockwalk observe --traces traces/bypass.jsonl     # exit 1
uv run lockwalk observe --traces traces/untested.jsonl   # exit 1
```

| File | What it shows |
|---|---|
| `ok.jsonl` | Two traces and every route on the map: `supervisor` -> `finance-agent` (tools, and `pricing-agent` inside `get_quote`), and `trade-desk` -> `trade-agent` (tools). 9 routes ON_MAP, gate PASS. `get_quote` has no door record and no case; it is low risk, so UNGUARDED and UNTESTED are shown but do not block |
| `off_map.jsonl` | `supervisor` calls `trade-agent` directly. The map only has `supervisor` -> `finance-agent`, so this route is OFF_MAP, with the line to add to `registry.yaml` |
| `unknown.jsonl` | `supervisor` calls `refund-agent`, which is not in the app. It is an UNKNOWN agent |
| `mismatch.jsonl` | `trade-agent` uses its own identity (`delegation_mode: agent`), but the door asked the IAM about the user: identity MISMATCH |
| `unguarded.jsonl` | `finance-agent` runs `read_portfolio` (high risk) with no door record, and an effect marker says the work ran: UNGUARDED |
| `bypass.jsonl` | The door denied `execute_trade`, and an effect marker says it ran anyway: BYPASS |
| `untested.jsonl` | `trade-agent` runs `confirm_price` on a path no case tests (`trade-desk` -> `trade-agent`): UNTESTED. `confirm_price` has medium risk, so it blocks only because this folder's `.lockwalk.toml` widens `fail_on_untested_path` to medium and above (the default is critical and unknown) |
| `waivers-observe.yaml` | Waivers for the findings of `untested.jsonl`, `unguarded.jsonl` and `mismatch.jsonl`. It does not cover `bypass.jsonl` |

Waive one finding and the gate passes:

```bash
uv run lockwalk observe --traces traces/untested.jsonl --waivers waivers-observe.yaml   # exit 0
uv run lockwalk observe --traces traces/bypass.jsonl --waivers waivers-observe.yaml     # exit 1
```

The waivers that match nothing in a run are listed under "Waivers needing attention". The
file expires on 2027-01-31, like `waivers.yaml`. `lockwalk coverage --waivers
waivers-observe.yaml` accepts the same file and prints only `3 waiver(s) are checked only by
lockwalk observe`.

If you ran `lockwalk coverage` in this folder, every `observe` run adds the warning `the test
report comes from lockwalk coverage; run lockwalk test for the side-by-side`. That is expected
and harmless.

`lockwalk inspect --trace c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3 --traces traces/off_map.jsonl`
shows how the trace was read (with the door records and effect markers under their tool
calls, and `user: present` or `user: missing` on the first line). The [guide](../../docs/lockwalk-observe.md) explains the rest, including how to leave
door records in your own traces.
The files in `.lockwalk/` are written next to `.lockwalk.toml` (`observe.json`); they are not
committed.

## What lockwalk cannot see here

- Calls made inside tool code, such as `get_quote` and `confirm_price`. They are declared
  with `calls`.
- What the remote `market-oracle` does inside. It stays opaque until you declare its
  `calls`.
- Whether the identities in the registry are true. `roles` and `delegation_mode` are
  hand-written; lockwalk only uses them for these static checks.
- `as_tool()` is recognized through private attributes of the OpenAI Agents SDK, so a new
  version of the framework could break it.
