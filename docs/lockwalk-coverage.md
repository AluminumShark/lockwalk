# lockwalk coverage: the full guide

`lockwalk discover` and `lockwalk coverage` read your registry, your spec and your tool sources,
draw the map of which agents and roles can reach which tools, and apply a gate. They never run
an agent or a tool, but they do import your Python modules and read their properties, which
runs your code (see [Where the tool list comes from](#where-the-tool-list-comes-from)). This guide has the details: where the tool list comes from, how the map is
built, every field of the two files, the gate, waivers, the summary output, MCP sources, and the
report format.

Contents:

1. [Where the tool list comes from](#where-the-tool-list-comes-from)
2. [The agent graph](#the-agent-graph)
3. [Registry and spec fields](#registry-and-spec-fields)
4. [Gate and exit codes](#gate-and-exit-codes)
5. [Waivers](#waivers)
6. [Summary output](#summary-output)
7. [MCP sources: secrets, optional servers, and snapshots](#mcp-sources-secrets-optional-servers-and-snapshots)
8. [coverage.json](#coveragejson)

## Where the tool list comes from

lockwalk merges every source into one inventory. Every agent framework has to describe its
tools to the model as a name, a description, and a JSON Schema, so lockwalk reads that shape
instead of needing one adapter per framework. It also opens tool containers, so `--python`
can point at a plain tool list or straight at a framework object:

| Framework | Point `--python` at |
|---|---|
| LangChain / LangGraph | the tool list, a `ToolNode`, a toolkit, or a compiled graph |
| Agno | the tool list, a `Toolkit`, an `Agent`, or a `Team` |
| OpenAI Agents SDK | the tool list or an `Agent` |
| Pydantic AI | the tool list, a `FunctionToolset`, or an `Agent` |
| CrewAI | the tool list, an `Agent`, or a `Crew` |
| Hermes Agent | `'model_tools:get_tool_definitions()'` inside the Hermes venv, or a JSON export |

A target can also be a list of these, for example several entry agents. When it holds
agents, teams, crews, or graphs, lockwalk also walks them to find the agents they reach and
the edges between them (see [The agent graph](#the-agent-graph)).

The five frameworks above Hermes are tested with their real objects (CrewAI in its own
environment, because its dependencies conflict with the others; see
[CONTRIBUTING.md](../CONTRIBUTING.md)). Hermes Agent
was run for real, with a fake model, and its traces were read by `lockwalk observe`; see
[Hermes Agent](lockwalk-observe.md#hermes-agent). Other frameworks work when their tools
have a `.name` or are plain functions, and the JSON export works for anything.

| Source | Flag | Config table |
|---|---|---|
| Hand-written registry (the only source of `risk`) | `--registry registry.yaml` | `[lockwalk] registry` |
| MCP server `tools/list` (needs `lockwalk[mcp]`) | `--mcp stdio://server.py` or `--mcp http://host/mcp` | `[[inventory.mcp]]` |
| Python objects (LangChain, other frameworks, plain functions) | `--python myapp.tools:TOOLS` or `--python path/to/tools.py:TOOLS` | `[[inventory.python]]` |
| JSON export (any language): an array of tool descriptions, or `{"tools": [...]}` | `--tools-json tools.json` | `[[inventory.json]]` |

lockwalk never calls MCP `tools/call`. `coverage` never invokes a tool; only the door tests of
`lockwalk test` do (see [Door tests](lockwalk-test.md#door-tests)). It does run your code to find the tools:

- The Python source imports your module in a subprocess (no stdin, stdout discarded, a
  timeout, and the whole process tree killed on timeout). It reads the attributes of the
  objects it finds, which runs their property code, but it never runs an agent and never
  calls a tools factory (`tools=<function>`). It calls a toolkit's `get_tools()` when that
  takes no arguments, and it calls the target itself if you write `module:attr()`. It never
  calls an async `get_tools()`, such as that of a Pydantic AI toolset resolved at run time:
  on an agent, such a toolset makes the agent opaque (see
  [What discovery can see](#what-discovery-can-see)); as the target itself, or in a tool
  list that no agent holds, it fails the source, so point at the tool list instead.
- The MCP source starts your server (for `stdio://` targets) and sends only `tools/list`.
  The server's stderr goes to a temporary file and is never shown or stored in reports.

Point lockwalk only at modules and servers that are safe to import and start. A tool that no
registry entry declares gets `risk=unknown`. Terminal output is plain ASCII: non-ASCII and
control characters are escaped, so tool data cannot steer your terminal.

Several `--python` targets of one app often reach the same sub-agents, so they report the
same tools. lockwalk merges a tool that several Python sources describe identically. Two
sources that describe one tool name differently are still an error, and so is any duplicate
that involves an MCP or JSON source, because two servers can describe two different tools
the same way.

## The agent graph

In a multi-agent system, an agent can reach a tool it does not hold: it hands off to another
agent, calls an agent wrapped as a tool, or leads a team. A spec can cover every tool and
still miss that an analyst reaches `execute_trade` through three agents. lockwalk builds a
static map of who can call whom, from your framework objects and your registry, and walks
it. Nothing runs.

In the [multi-agent demo](../examples/multi_agent/README.md), analysts may only use
`supervisor`, yet they can reach the critical `execute_trade` through two more agents:

```text
Never-reaches rules:
  RULE-001  FAIL          role:analyst -> tool:execute_trade
    supervisor -[handoff, discovered]-> finance-agent -[agent_as_tool, discovered]-> trade-agent -[uses_tool, discovered]-> execute_trade
  RULE-002  INCONCLUSIVE  agent:market-oracle -> tool:execute_trade (passes through opaque: market-oracle)
  RULE-003  PASS          agent:pricing-agent -> tool:execute_trade
```

The line under RULE-001 is the witness: the route that breaks the rule. RULE-002 is
INCONCLUSIVE because `market-oracle` is a remote agent, and lockwalk does not know what it
calls (see [Opaque agents and INCONCLUSIVE](#opaque-agents-and-inconclusive)). The demo's
README walks through the full tree, the role x tool table, and two fixes.

`discover` and `coverage` both show the graph: one tree per entry agent, then the role x
tool table, the rule results, and notes on cycles and opaque nodes. Cycles are fine: lockwalk
lists them and expands each agent once.

The graph's nodes are agents, remote agents (declared with `remote:`, or found as an Agno or
LangGraph remote object), and MCP servers attached to agents. Tools are not nodes. Every edge
has a kind and a provenance:

| Edge kind | Meaning |
|---|---|
| `uses_tool` | can call this tool |
| `agent_as_tool` | calls another agent that is wrapped as a tool |
| `handoff` | hands the conversation to another agent; LangGraph routes are handoffs too |
| `team` | a team, crew, or graph that includes this member |
| `remote` | uses an MCP server |
| `calls` | any other call between agents |

| Provenance | Where lockwalk learned it |
|---|---|
| `discovered` | read from your objects |
| `inferred` | guessed: the route may exist, for example from a LangGraph router with no declared destinations |
| `declared` | written by you: `calls`, `supported_agents`, delegation tools, or a source's `agents` |

Entry agents are the agents users talk to. lockwalk uses the agents marked `entry: true` in
the registry. If none is marked, it uses the objects your `--python` targets point at, and
if there are none of those either, every agent, with a warning.

Roles start only at entry agents, so whatever no entry agent reaches is never checked by a
rule or the role x tool table. Two things point at that:

- When the registry marks entry agents, a `--python` target object that it does not mark,
  and that no entry agent reaches, gets a warning, for example `agent 'trade-desk' is a
  top-level discovery target but is not marked entry: true; no role starts there`. Check
  whether users talk to it. A target that an entry agent reaches is an ordinary sub-agent
  (pointing a target at one is how discovery learns about it), so it gets no warning.
- The graph notes list the agents that no entry agent reaches, as
  `Not reachable from entry agents: ...` (at most five; `agent_graph.unreachable` in
  `coverage.json` lists them all).

### What discovery can see

Verified with real objects on openai-agents 0.24.0, agno 3.1.12, langgraph 1.2.20,
pydantic-ai-slim 2.66.0, and crewai 1.15.36. No model is called and no agent runs.

| Framework feature | What lockwalk sees |
|---|---|
| OpenAI Agents SDK `handoffs=[agent]` | `handoff`, discovered |
| OpenAI Agents SDK `handoffs=[handoff(agent)]` | `handoff`, discovered. **Private API**: reads `_agent_ref` |
| OpenAI Agents SDK `agent.as_tool()` | `agent_as_tool`, discovered, and the wrapped agent is walked too. **Private API**: reads `_is_agent_tool`, `_tool_origin`, and `_agent_instance` |
| OpenAI Agents SDK `mcp_servers` | `remote` to an MCP server node; lockwalk does not connect |
| OpenAI Agents SDK `HostedMCPTool` | a plain tool, not an MCP server node |
| Agno `Team(members=...)` | `team` from the leader to each member, and no edges between members |
| Agno `MCPTools` | `remote` to an MCP server node; lockwalk does not connect |
| Agno `RemoteAgent`, `RemoteTeam` | an opaque remote node; its attributes are never read (see [Security notes](lockwalk-security.md#security-notes)) |
| CrewAI `Crew(agents=...)` | `team` from the crew to each agent. CrewAI agents are named by their `role` |
| CrewAI `manager_agent=` | `team` from the manager to every agent |
| CrewAI `manager_llm=` | not seen: CrewAI creates that manager only at kickoff |
| CrewAI `allow_delegation=True` | `calls`, inferred, to every coworker |
| CrewAI `Task(tools=...)` | `uses_tool` from the task's agent. For a task with no agent, inferred edges from every agent, and the crew is opaque |
| CrewAI `Agent(mcps=[...])` | `remote` to an MCP server node |
| LangGraph compiled graph | the graph and each of its nodes are agents, with ids `<graph>:<node>`; a subgraph node is expanded the same way. **Internal API**: reads `graph.builder` |
| LangGraph edges, and conditional edges with known destinations (a path map or a `Literal` return type) | `handoff`, discovered. **Internal API** |
| LangGraph conditional edges with no known destinations | `handoff`, inferred, to every node of the graph |
| LangGraph `Command[Literal[...]]` return type, or `destinations=` | `handoff`, discovered. **Internal API** |
| LangGraph `Command(goto=...)` with no declared destination | not seen |
| LangGraph `ToolNode` | not a node: a route into it is `uses_tool` to each of its tools |
| LangGraph `RemoteGraph` node | an opaque remote node; never read |
| Pydantic AI `Agent(name=..., tools=...)` | `uses_tool`, discovered. An agent without `name=` is not a node; its tools are still collected, with a warning |
| Pydantic AI `FunctionToolset`, and a `CombinedToolset` of toolsets, in `toolsets=` | read like a tool list: `uses_tool`, discovered |
| Pydantic AI toolsets resolved at run time in `toolsets=`: `PrefixedToolset`, `FilteredToolset`, `RenamedToolset`, other wrapper toolsets, and a function decorated with `@agent.toolset` | not seen: they list their tools only inside a run. The agent is opaque, with hidden tools, and lockwalk warns `agent 'X' uses a toolset that is resolved at run time (PrefixedToolset); lockwalk cannot list its tools`. This applies to any toolset whose `get_tools()` is async and that lockwalk cannot open |
| Pydantic AI MCP toolsets in `toolsets=` | `remote` to an MCP server node; lockwalk does not connect |
| Pydantic AI agent run inside a tool function | not seen: declare `calls` |
| Your own routing code | not seen: declare `calls` |

Not verified yet: LangChain v1 `create_agent`, and Pydantic AI MCP toolsets with the real
classes (they need `fastmcp`; the tests use a stand-in with the same shape).

Rows marked **Private API** or **Internal API** read framework attributes that are not part of
the public API, so a framework upgrade can break them. lockwalk's tests pin them for the
versions above. If the `handoff()` or LangGraph attributes change, lockwalk marks the agent or
graph opaque and warns.

For `as_tool()`, lockwalk reads two signals and checks that they still work. The wrapper
sets `_is_agent_tool = True`, and it records its origin: `_tool_origin.type` is
`ToolOriginType.AGENT_AS_TOOL` (a plain function tool has no origin). Either signal marks a
wrapper, and then `_agent_instance` must hold the agent. lockwalk cannot tell which
function tools wrap agents when:

- a tool is a wrapper by either signal, but no agent is found (for example a release that
  keeps the `_is_agent_tool` field but no longer sets it, while the origin still says
  `AGENT_AS_TOOL`), or
- the SDK's `FunctionTool` no longer has `_is_agent_tool` at all, for a tool whose origin
  does not say it is a wrapper.

Then lockwalk still collects those tools as plain tools, marks every agent that holds one
opaque (its tools are hidden, so `calls` does not help), and warns once: `openai-agents
<version> changed how as_tool() is stored; lockwalk cannot tell which tools wrap agents, so
agents with function tools are treated as opaque`. Rules through those agents are then
INCONCLUSIVE, even when discovery finds another agent that holds the wrapped agent's tools.

What lockwalk cannot notice is narrower: a release in which `FunctionTool` still has the
`_is_agent_tool` field, but `as_tool()` no longer sets it, and the wrapper's `_tool_origin`
no longer says `AGENT_AS_TOOL` (or is gone). If the field itself disappears from the class,
lockwalk does notice, as above. In that one case a wrapper is read as a plain tool, without
a warning. It shows up as an undeclared tool with `risk=unknown`,
which the default gate fails, but the route through it is gone. If nothing else is known to
hold the wrapped agent's tools, rules to them are INCONCLUSIVE; if discovery or the
registry knows another holder, a rule can PASS without seeing that route. Pin the framework
versions you have checked.

### What lockwalk cannot see, and how to fill the gap

| lockwalk cannot see | Fill the gap with |
|---|---|
| A call made inside tool code (such as a Pydantic AI agent run inside a tool), or your own router | `calls` on the calling agent |
| A LangGraph `Command(goto=...)` with no declared destination | a `Command[Literal[...]]` return type or `destinations=`, which lockwalk reads |
| What a remote agent calls | `remote:` and `calls` in the registry; add the agent to the `supported_agents` of the tools it uses |
| A "tool" that is really another agent, for example an agent exposed over MCP | `delegation_tools` in the registry |
| The tools of an MCP server attached to an agent | an `[[inventory.mcp]]` source whose `name` is the server's name. lockwalk matches them by label (`mcp:<name>`) only, never by URL |
| An MCP server that lockwalk cannot reach | `optional = true` on its source, with `agents` |
| An agent known only by its name, or more than 32 agents deep | `calls` (and `supported_agents` for its tools) in the registry, or a `--python` target that points at it |
| An agent without a name, such as a Pydantic AI `Agent` without `name=` | give it a name |
| The tools of an Agno tools factory (`tools=<function>`), which lockwalk never calls, or any other tool list it cannot read | nothing in the registry: the agent stays opaque even with `calls`. Give the agent a tool list instead. Adding it to the `supported_agents` of the factory's tools lets a rule FAIL, but never PASS |
| An inferred edge that does not exist (a CrewAI coworker, an open LangGraph router) | `calls` on that agent, which drops its inferred edges to other agents. Its inferred `uses_tool` edges stay, because `calls` names agents, not tools. To drop those, let the code say where the route goes: a path map or a `Literal` return type on the LangGraph router, or an agent on the CrewAI task |

### Opaque agents and INCONCLUSIVE

An agent or remote agent is known, not opaque, only when lockwalk knows what it calls and
could read all of its tools. lockwalk knows what it calls when either:

1. discovery walked inside it and could read everything it links to, or
2. the registry declares its `calls`. `calls: []` means "calls no other agent", and counts.

Every other agent is opaque, for example one known only by its name, one past the depth
limit, one behind a delegation tool, a remote agent without `calls`, and, in a run without
discovery, every agent without `calls`.

An agent also stays opaque when discovery could not read all of its tools: a tools factory,
a tool that raised or that lockwalk cannot recognize, a `tools` attribute that is not a
list, an MCP server without a usable name or with a name that another server already has,
tool containers nested more than 5 levels deep, a CrewAI task that has tools but no agent,
a LangGraph `ToolNode` tool that cannot be read, or a LangGraph route that cannot be read
in a graph that has a `ToolNode` (a route into a `ToolNode` is how a node reaches its
tools; the graph and the nodes whose routes may be lost stay opaque). Declaring `calls`
does not help here, because `calls` lists agents, not tools. lockwalk then warns, for
example `agent 'desk' declares 'calls', but lockwalk could not read all of its tools, so it
stays opaque`, and the node has `tools_hidden: true` in `coverage.json`.

An MCP server node is opaque unless it matches a configured source that was read; an
optional source that could not be read is always opaque. The tree marks these nodes
`(opaque)`.

A `never_reaches` rule has one of four results:

| Result | Meaning |
|---|---|
| FAIL | a route reaches the target; the witness shows it |
| INCONCLUSIVE | no route is visible, but a hidden route may exist: the start reaches an opaque node, no agent is known to use the target tool, or no entry agent lists the starting role |
| PASS | no route, nothing opaque on the way, the rule has somewhere to start, and some agent is known to use the target tool |
| ERROR | the rule names an unknown agent, tool, or role (exit 2) |

An INCONCLUSIVE rule fails the gate by default. To settle it, let discovery see the opaque
agent, or declare its `calls` (unless its tools are hidden: then only the first works).

A tool that no agent is known to use is in no route at all, yet some agent can still call
it. So a rule to that tool is INCONCLUSIVE, with the reason in the rule's line and in its
`problems`, for example `no agent is known to use tool 'execute_trade'; set 'agents' on its
source or 'supported_agents' in the registry`. When there are rules or registry `roles`,
one warning lists the first five of these tools. An agent is known to use a tool when
discovery found it holding the tool, when the tool's `supported_agents` names it, or when
the `agents` of a source that reports the tool name it.

In the same way, a rule that starts at a role that no entry agent lists starts nowhere and
checks nothing, so it is INCONCLUSIVE, with the reason `no entry agent lists role 'ops', so
lockwalk cannot tell where it starts; mark its entry agent with entry: true and add the role
to its roles`. The role x tool table has no rows for such a role either, so whenever the
registry has `roles`, one warning lists the first five roles that no entry agent lists. A
role that does start somewhere, but reaches nothing that matters, still gives PASS. A role
that is not in the `roles` list is still an ERROR.

This matters for registry-only runs. Without discovery, lockwalk has looked inside no agent,
so a rule that starts at an agent without `calls` can FAIL but never PASS. That is why the
finance demo declares `calls: []` on both of its agents.

### Declarations

lockwalk trusts what you declare; it cannot check it.

- A stale `calls` entry keeps a removed route in the graph, with no warning. Remove a declared
  call when the code no longer makes it.
- Once an agent declares `calls`, the list must also name the agents that discovery finds it
  calling. Otherwise lockwalk warns, for example
  `agent 'A' reaches 'B' (handoff, discovered) but its registry 'calls' does not list 'B'`.
  A delegation tool counts as a declared call, so `calls` does not need to repeat it.
- The tree can then show the same pair twice: once `declared`, once `discovered`.

## Registry and spec fields

`schema_version` is `'1'`. Every field in the table below is optional. A registry that marks no
agent `entry: true` gets the warning `no agent is marked entry: true; every agent is treated as
an entry point`.

### registry.yaml

```yaml
schema_version: '1'
roles: [analyst, trader]
agents:
  - id: supervisor
    entry: true
    roles: [analyst, trader]
    delegation_mode: user
    calls: [finance-agent]
  - id: finance-agent
    delegation_mode: user
    calls: [market-oracle]
  - id: research-agent
    delegation_mode: on_behalf_of
    calls: []
  - id: market-oracle
    remote: https://oracle.example/a2a
delegation_tools:
  - id: ask_research_agent
    agent: research-agent
    supported_agents: [finance-agent]
tools:
  - id: get_stock_price
    action: market:read
    risk: low
    supported_agents: [research-agent]
  - id: execute_trade
    action: trade:execute
    risk: critical
    supported_agents: [finance-agent]
```

| Field | Meaning |
|---|---|
| `roles` (top level) | The role names your IAM uses. This list turns on every role feature: agent `roles`, roles in cases and rules, and the role x tool table |
| `entry` | Users talk to this agent directly. Default `false` |
| `roles` (on an agent) | Entry agents only: the roles that may use it. Each must be in the top-level list. An entry agent without `roles` is open to every role, with a warning |
| `calls` | The agents it calls. Left out means unknown; `[]` means none. Each must be declared under `agents`, so a typo is an error |
| `remote` | The http(s) URL of a remote agent (see [URLs](lockwalk-security.md#urls)). It stays opaque until you declare its `calls` |
| `delegation_mode` | Whose identity it sends with its tool calls: `user`, `agent` (its own), or `on_behalf_of` (the agent acting for the user). Left out means unknown |
| `delegation_tools` | Tools that are really agents. Each has an `id` (not a tool id), an `agent` (required), and optional `supported_agents` and `description` |

A delegation tool is left out of tool coverage: write the spec for the tools behind its agent
instead. Every agent that can use it (its `supported_agents`, the `agents` of a source that
reports it, or an agent that discovery finds holding it) gets an `agent_as_tool` edge to its
`agent`. A case or rule that targets it is an ERROR.

A source other than Python that reports a name declared under `delegation_tools` gets a warning
on every run, even when that is what you meant (an agent exposed over MCP, for example), and the
warning cannot be turned off. It is there because a real tool with that name would otherwise
vanish from the report. A Python walk reports its own agent-as-tool wrappers that way, so it does
not warn, which also means a real Python tool with the name of a delegation tool is skipped
without a warning.

Without the top-level `roles` list, `reachability` is null in the report, entry agents cannot
list roles, and a rule that starts at a `role` is an ERROR. With the list, every role in
cases and rules must be in it.

### security-spec.yaml

`never_reaches` rules say that a tool or agent must never be reachable, by any route:

```yaml
never_reaches:
  - id: RULE-001
    role: analyst
    tool: execute_trade
    reason: Analysts must never trade, through any route
  - id: RULE-002
    agent: research-agent
    target_agent: finance-agent
```

- Start at exactly one of `agent` or `role`. A role starts at every entry agent it may use.
- Target exactly one of `tool` or `target_agent`.
- Rule ids must be unique, and different from every case id.
- A rule that names an unknown agent, tool, or role, or that uses `role` while the registry
  has no `roles` list, is ERROR (exit 2).

A case can give the route it takes with `path:` instead of `agent:`:

```yaml
cases:
  - id: CASE-011
    actor: alice
    role: analyst
    path: [supervisor, finance-agent, research-agent]
    tool: get_stock_price
    action: market:read
    resource_fixture: TSMC
    expect: allow
```

- Set exactly one of `agent` or `path`. `agent: X` is the same as `path: [X]`.
- A name in `path` that the registry does not declare and no source discovered makes the
  case ERROR.
- For an `expect: allow` path case, lockwalk warns (and never marks the case ERROR) when a
  step is not an edge in the graph, when the last agent has no known way to use the tool, or,
  with roles on, when the role cannot start at the first agent. Deny cases are not checked: a
  route that does not exist is the expected defense.

## Gate and exit codes

```toml
[gate]
fail_on_unspecified_risk           = ["critical", "unknown"]          # default
require_deny_case_for_risk         = ["high", "critical", "unknown"]  # default
fail_on_never_reaches_inconclusive = true                             # default
fail_on_unspecified_role_risk      = ["critical", "unknown"]          # default
```

- `never_reaches`: a FAIL rule is always a violation. An INCONCLUSIVE rule is one too, unless
  you set `fail_on_never_reaches_inconclusive = false`.
- `fail_on_unspecified_role_risk`: a role can reach a tool (REACHABLE, not INCONCLUSIVE), and
  no valid case with that role and tool, and no rule from that role to that tool, covers it.
  If the tool's risk is in the list, that is a violation. If it is not, but the risk is high,
  critical, or unknown, lockwalk only warns.

| Exit code | Meaning |
|---|---|
| 0 | No errors and no gate violations |
| 1 | Gate violated |
| 2 | Configuration or environment error, a failed source, an invalid case or rule, an agent graph error, any ERROR (a case, rule, or escalation check that could not be answered), or an unexpected crash: the result cannot be trusted |

A violation that an active waiver covers does not count (see [Waivers](#waivers)). ERROR wins
over FAIL: when a run has both, the exit code is 2, and the FAILs are still in the
report. `lockwalk test` has gate keys of its own (see the
[guide](lockwalk-test.md#gate-keys-and-exit-codes)). `discover` only reports and exits
0, or 2 when an inventory source or the agent graph has a problem. A tool is `SPECIFIED` only when at
least one of its cases is valid. Every other tool is `UNSPECIFIED`: no valid case targets it.
Text output calls these "tools without spec", and `inventory.tools[*].coverage` in
`coverage.json` holds the word.

When stdout cannot take the output, the exit code still tells the truth:

| Command | Reader closed the pipe (`\| head`) | Other failure, such as a full disk |
|---|---|---|
| `coverage`, `test`, `observe` | the gate's code | the gate's code, with a note on stderr, because the report file is written |
| `discover --save-snapshot` | 0 | 0, with a note on stderr, because the snapshot file is written |
| `discover`, `inspect`, `diff`, `--version` | 0 | 2, because stdout was the only output |

## Waivers

A waiver is an accepted risk with an owner and an expiry date. A waived finding stays in the
report, marked `[waived: ID]`, but it no longer blocks the gate. When the waiver expires, the
finding blocks again. Waivers live in their own file, apart from the spec: the spec says what
should be true, a waiver says what you accept for now.

```yaml
# waivers.yaml
schema_version: '1'
waivers:
  - id: WAIVE-001
    match: {rule: RULE-002}
    reason: market-oracle is a third party; its contract was reviewed by security
    owner: alice@example.com
    expires: 2027-01-31
```

Use it with `--waivers waivers.yaml`, or set `waivers = "waivers.yaml"` under `[lockwalk]` in
`.lockwalk.toml` (a flag path is relative to where you run lockwalk, a config path to the config
file). The flag wins. `coverage`, `test` and `observe` all apply it. Every key is required, ids
must be unique, and an unknown key is an error.

`match` takes exactly one of these. Names are plain strings: no wildcards, so one waiver covers
one finding.

| `match` | Covers | Gate keys |
|---|---|---|
| `{case: CASE-006}` | A case | `case`, `fail_on_inconclusive_case` |
| `{rule: RULE-002}` | A `never_reaches` rule | `never_reaches` |
| `{escalation: {case: CASE-006}}` | An escalation row that comes from a case | `fail_on_escalation`, `fail_on_inconclusive_escalation`, `fail_on_unchecked_escalation` |
| `{escalation: {role: analyst, tool: execute_trade, via: trade-agent}}` | An escalation row from the role x tool table | the same three |
| `{identity: CASE-006}` | An identity MISMATCH | `fail_on_identity_mismatch` |
| `{role_gap: {role: trader, tool: read_portfolio}}` | A role that reaches a tool no case or rule covers | `fail_on_unspecified_role_risk` |
| `{tool_gap: execute_trade}` | A tool with no case, or no deny case | `fail_on_unspecified_risk`, `require_deny_case_for_risk` |

Five more kinds, `route`, `unknown`, `unguarded`, `observed_identity` and `untested_path`, are
checked only by `lockwalk observe`; see the
[observe guide](lockwalk-observe.md#waivers-and---summary).

The rules:

- **A waiver acts on gate violations.** The violations move from `gate.violations` to
  `gate.waived`, and the report rows get `waived_by`. The finding's own status (FAIL_POLICY, for
  example) does not change.
- **An ERROR cannot be waived.** An ERROR means the test itself is broken. The waiver is
  reported as `not_allowed`, with a warning, and the exit code stays 2.
- **Expiry.** `expires` is a date (`YYYY-MM-DD`, UTC), and the whole day counts. After it, the
  waiver does nothing, the finding blocks again, and a warning names the waiver, the date and
  the owner.
- **No long waivers.** `expires` may not be more than `[gate] max_waiver_days` days after today
  (default 90, range 1 to 3650). A later date is a configuration error (exit 2). A date in the
  past is allowed: it is just expired.
- **A waiver that matches nothing** gets a warning that it may be stale. So does a waiver whose
  finding an earlier waiver already covers.
- **Test-only kinds.** `case`, `escalation` and `identity` can only be checked by
  `lockwalk test`. In `coverage` an unexpired waiver of these kinds gets no warning: the report counts it as
  "checked only by lockwalk test". An expired one still warns. The observe kinds are quiet in
  `coverage` and `test` in the same way ("checked only by lockwalk observe"). One waivers file can serve all three commands.
- A waivers file that cannot be read or is invalid is a configuration error (exit 2).

The demo in [`examples/multi_agent`](../examples/multi_agent/README.md#waivers) ships two files.
Without a waiver, `coverage` fails on RULE-001 and RULE-002. With `waivers.yaml`:

```bash
cd examples/multi_agent
uv run lockwalk coverage --waivers waivers.yaml    # exit 0
```

```text
Never-reaches rules:
  RULE-001  FAIL          role:analyst -> tool:execute_trade [waived: WAIVE-002]
    supervisor -[handoff, discovered]-> finance-agent -[agent_as_tool, discovered]-> trade-agent -[uses_tool, discovered]-> execute_trade
  RULE-002  INCONCLUSIVE  agent:market-oracle -> tool:execute_trade (passes through opaque: market-oracle) [waived: WAIVE-001]
  RULE-003  PASS          agent:pricing-agent -> tool:execute_trade
```

```text
Gate: PASS (exit 0)
Waived:
  - never_reaches: RULE-002 (INCONCLUSIVE) (WAIVE-001, owner alice@example.com, until 2027-01-31)
  - never_reaches: RULE-001 (FAIL) (WAIVE-002, owner alice@example.com, until 2027-01-31)
```

With `waivers-expired.yaml` (the same waivers, dated 2026-06-30) the findings block again:

```bash
uv run lockwalk coverage --waivers waivers-expired.yaml    # exit 1
```

```text
Warnings:
  - agent 'trade-agent' calls tools with its own identity; the IAM will not see the user. Through it, roles analyst, trader can reach 1 high-risk tool: execute_trade
  - role 'trader' can reach 1 high-risk tool that no case or rule covers: read_portfolio (risk=high)

Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
Waivers needing attention:
  expired      WAIVE-001: waiver WAIVE-001 expired on 2026-06-30 (owner alice@example.com); RULE-002 blocks the gate again
  expired      WAIVE-002: waiver WAIVE-002 expired on 2026-06-30 (owner alice@example.com); RULE-001 blocks the gate again
```

The shipped `waivers.yaml` expires on 2027-01-31 on purpose. After that date it behaves like
`waivers-expired.yaml`. This is the rule working, not a bug. The report lists every waiver
under `waivers` in `coverage.json`, with its status: `applied`, `expired`, `unmatched` or
`not_allowed`. The full rules and warning texts are in the
[guide](lockwalk-test.md#waivers).

## Summary output

A large system prints a lot. `--summary` (for `coverage` and `test`) prints only the counts
and what needs action. It leaves out the agent tree and the role x tool table.
`coverage.json` is complete either way.

```bash
cd examples/multi_agent
uv run lockwalk coverage --summary    # exit 1
```

```text
lockwalk coverage - multi-agent-demo-v1
Cases: 5 (UNTESTED 5)
Tools: 5 registered, 2 without a case, 0 high-risk without a deny case
Gate: FAIL (exit 1)

Blocking (2):
  never_reaches: RULE-001 (FAIL)
  never_reaches: RULE-002 (INCONCLUSIVE)

Warnings (2):
  - agent 'trade-agent' calls tools with its own identity; the IAM will not see the user. Through it, roles analyst, trader can reach 1 high-risk tool: execute_trade
  - role 'trader' can reach 1 high-risk tool that no case or rule covers: read_portfolio (risk=high)
```

Categories appear only when they have items, in this order: Errors, Blocking, Waived, Waivers
needing attention, Warnings. Each shows at most 20 lines, then `... and N more; see
coverage.json`. Errors that differ only in their leading id are grouped into one line, so an
unreachable IAM gives one line, not one per case. The [guide](lockwalk-test.md#summary-output)
has the details.

## MCP sources: secrets, optional servers, and snapshots

### `env` and `headers`

```toml
[[inventory.mcp]]
name = "finance-tools"
target = "stdio://examples/finance_agent/mcp_server.py"
env = { FINANCE_API_KEY = "${FINANCE_API_KEY}" }

[[inventory.mcp]]
name = "pricing"
target = "https://mcp.example.com/mcp"
headers = { Authorization = "Bearer ${PRICING_TOKEN}" }
```

- `${NAME}` is read from the environment when lockwalk connects. `$$` is a literal `$`; any
  other `$` is a configuration error.
- `env` is for stdio servers (a `stdio://` target, or `command`), and `headers` is for
  http(s) targets.
- An unset variable fails the source: `environment variable 'FINANCE_API_KEY' is not set`.
- Header values must be printable ASCII, with no whitespace at either end.
- The values never reach reports, snapshots, or the terminal. See
  [Secrets in MCP configuration](lockwalk-security.md#secrets-in-mcp-configuration).

### Optional sources

```toml
[[inventory.mcp]]
name = "pricing"
target = "https://mcp.example.com/mcp"
optional = true
agents = ["finance-agent"]
```

`optional = true` needs a `name`, and `agents`: the agents that use this server. When
lockwalk cannot read the source at all (no connection, a timeout, an unset variable, or the
MCP extra is not installed), it warns instead of failing:

- The source becomes an opaque `mcp:<name>` node, and each agent in `agents` gets a
  `remote, declared` edge to it.
- The registry's tools are still used, and the inventory drift is marked incomplete.
- Rules whose routes pass through the node are INCONCLUSIVE.

A source that connects and returns bad tools is still an error. Sources without `optional`
still fail with exit 2.

An optional server that connects and then never answers `tools/list` counts as a timeout: it only
warns, and the source is reported as unavailable. A server that answers with something unusable
is an error, because it is reachable and broken rather than absent.

### Snapshots

```bash
uv run lockwalk discover --save-snapshot tools-snapshot.json
uv run lockwalk coverage --tools-json tools-snapshot.json
```

A replay of a snapshot gives the same rule results, role x tool rows, opaque nodes, and
hidden tools as the live run it was saved from, with the same registry and spec. It never
gives a PASS where the live run did not. To do that, `discover --save-snapshot FILE` saves,
for every discovery source:

- its label, its kind, and whether it is `optional`;
- its `agents`;
- each tool's name, description, and hints;
- for a Python source, the agent graph that discovery found: its agents and their edges,
  with the flags that mark an agent opaque or its tools hidden. So an agent whose tools
  lockwalk could not read (an Agno tools factory, for example) is still opaque on replay;
- for an optional source that could not be read, only that fact. It replays as the same
  opaque `mcp:<name>` node, linked from its `agents`.

If any other source failed, `discover` writes no snapshot (and exits 2, as it does for any
failed source): `Snapshot not written to FILE: these sources failed: ...`. Leaving a source
out could make a replay pass where the live run did not, so fix it first, or make an MCP
server that may be down `optional = true`, with `agents`. An older snapshot at that path
is removed, so it is never taken for this run's snapshot; if it cannot be removed, a note
says so. A file that is not a lockwalk snapshot is never removed or overwritten:
`--save-snapshot` refuses it and exits 2, naming the file, so a mistyped flag cannot
destroy a registry or a spec. The path is relative to the current directory.

A snapshot never holds env or header values, errors, or warnings, and its labels and URLs
are redacted exactly as they are in `coverage.json`. Unlike `coverage.json`, it does hold
tool descriptions.

`--tools-json` (or `[[inventory.json]]`) reads it back as the sources it saved, each with
its own label (such as `mcp:finance-tools`) and its own `agents`. A saved `mcp:<name>`
source still matches the `mcp:<name>` node on an agent, by label, as live. A
`[[inventory.json]]` that reads a snapshot cannot set `agents`: that is an error, because
extra agents would get every saved tool and could hide that no agent is known to use one
(a plain JSON file of tools still takes `agents`). Like every source given on the command
line, it replaces the sources in `.lockwalk.toml`; a saved source and a live source with
the same label are an error, as two live sources would be. Warnings give the file, the
snapshot's date, and whether an agent graph came from it:

```text
  - json:tools-snapshot.json: snapshot captured at 2026-11-06T16:39:10Z from 1 source(s): mcp:finance-tools; it may be out of date
```

The time is UTC. lockwalk cannot tell whether your servers or your code changed after that,
so save a new snapshot when they do: the replay shows the system as it was then.

lockwalk trusts a snapshot as it trusts your code and your registry: it checks the file's
shape, but it cannot tell whether someone edited it. Clearing `opaque` or `tools_hidden` on
a node, or changing a source's `status` from `unavailable` to `ok`, changes the results.
Keep snapshots where only you can change them, and replay only ones you saved. A snapshot
whose version lockwalk does not support is rejected, and the message says to save the
snapshot again. Replaying a snapshot that lacks the agent graph or the sources that could not
be read could give a PASS that the live run would not.

## coverage.json

The report's `schema_version` is `"5"`. `coverage` and `test` write the same shape. The keys
that only `lockwalk test` fills are null or empty in a `coverage` report. The commands that read
a report (`diff`, `inspect`, and the side by side of `observe`) refuse another version.

Keys of every report:

| Key | Contents |
|---|---|
| `agent_graph` | Always present: `entry_agents`, `entry_inferred`, `nodes` (each with `opaque` and `tools_hidden`), `edges` (an `agent_as_tool` edge can list the tools that made it in `wrapped_by`), `cycles`, `opaque`, `unreachable` (the agents no entry agent reaches), and `drift` (`discovered_only_agents`, `declared_only_agents`, `undeclared_edges`, `complete`; null without a registry or without discovered agents) |
| `reachability` | The role x tool rows: `role`, `tool`, `risk`, `status` (`REACHABLE` or `INCONCLUSIVE`, upper case like a rule's `result`), `witness`, `delegation_mode`, `opaque_reached`, `covered_by`. Null without registry `roles` |
| `rules` | One row per `never_reaches` rule: `id`, `agent`, `role`, `tool`, `target_agent`, `result`, `witness`, `opaque_reached`, `problems`, `reason`. `problems` explains an ERROR, or an INCONCLUSIVE result that no opaque node explains |
| `cases[*].path` | The case's route. `cases[*].agent` is its last agent |
| `gate.violations[*]` | `rule`, plus `tool`, `risk`, `role`, `rule_id`, and `result`; the fields that do not apply are null |
| `inventory.sources[*]` | Adds `optional` and `unavailable` |

Keys that `lockwalk test` fills (empty for `coverage`), and the waivers:

| Key | Contents |
|---|---|
| `mode` | `"static"` for `coverage`, `"test"` for `test` |
| `policy_adapter` | The IAM that was asked, such as `python:iam_bridge.py:decide`; null for `coverage` |
| `cases[*].decision` | What the IAM said about the case; null for `coverage`. `verdict` is `allow`, `deny`, `unknown` (the two identities disagree), or `error`. `hops` has one entry per step asked, each with `caller`, `target`, `kind`, `mode`, `verdict`, and `answers` (the subject sent, `verdict`, `reason`, `error`, `latency_ms`). `denied_hop` names the first denied step, or is null |
| `cases[*].notes` | Why a case is FAIL_POLICY or INCONCLUSIVE. A case's own `reason` is the one you wrote, and does not change |
| `escalations` | One row per escalation check: its source (`case_id`, or the role x tool route), `role`, `tool`, `via`, `risk`, `mode`, `path`, `result` (`ESCALATION`, `NONE`, `INCONCLUSIVE`, `UNCHECKED`, or `ERROR`), `user_answer`, `path_answer`, and `notes` |
| `cases[*].door` | The door part of a case, when door tests ran: `status` (`OK`, `FAIL_EXECUTION`, `INCONCLUSIVE`, `ERROR`, or `NOT_TESTED`), `runs` (per mode: `mode`, `status`, `subject`, `side_effect_calls`, `door_calls`, `exception`, `notes`), and `notes`. Null without door tests |
| `identity_checks` | One row per case that has door evidence: `case_id`, `path`, `tool`, `result` (`MATCH`, `MISMATCH`, `OBSERVED`, or `NOT_RUN`), `observations` (per mode: `expected`, `observed`, `result`), and `notes`. Subjects are reduced to type, id, and the act chain |
| `door_controls` | One row per tool the door tests reached: `tool`, `proven`, and `proven_by`, the first run that counted its side effect |
| `controls` | One row per action and resource type that was asked: `allowed`, and `allowed_by`, the first question that was allowed |
| `waivers` | One row per waiver in the file: `id`, `owner`, `expires`, `reason`, `match`, `status` (`applied`, `expired`, `unmatched`, or `not_allowed`), `matched`, and `note`. Empty without a waivers file |
| `gate.waived` | The violations that waivers moved out of `gate.violations`, each with its `waiver_id`. `gate.passed` means no unwaived violation |
| `waived_by` | On the case, rule, escalation, identity and reachability rows a waiver covers: the waiver's id |
| `warnings` | Also holds the adapter's notes (such as the fall back to one-by-one requests) and the warnings about missing fixtures |
| `gate.violations[*]` | Extra `rule` values for the `test` gate keys, such as `fail_on_escalation` |

Keys that link to `evidence.jsonl` (null for `coverage`):

| Key | Contents |
|---|---|
| `run_id` | The id of the run, set by `lockwalk test`. It equals the `run` of `evidence.jsonl`. Null for `coverage`, and null when no evidence file was written |
| `evidence` | On the case, escalation, identity check, control and door control rows: the event ids in `evidence.jsonl` that show how the row came about. Null outside `lockwalk test` |
| `cases[*].actor`, `cases[*].role` | The actor and the role of the spec case |

The report never holds the IAM's raw responses, the `decide()` subprocess's stderr, or header
values. Environment values that lockwalk knows (those of its own process, which the `decide()`
subprocess inherits) are hidden in `decide()` exception text, but a secret that your code
hardcodes or reads from somewhere else can still appear there; see
[Exception text](lockwalk-security.md#exception-text).
