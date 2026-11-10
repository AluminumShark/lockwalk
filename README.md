# lockwalk

**Authorization test coverage for AI agent tools.** lockwalk tells you which tool permissions
nobody has tested, where your policy engine disagrees with what you expected, and where a denied
call ran anyway. It gives CI a clear pass or fail.

lockwalk does not give your agents permissions. It checks the permissions you already set up,
before you ship.

> Status: alpha. The report format and the configuration may still change before 1.0.

## Why

An agent acts through its tools, so the permission checks on those tools matter, though they are
not everything ([what it does not promise](#what-it-does-not-promise)). Four problems are easy
to miss:

1. **A tool with no rule and no test (`UNSPECIFIED`).** Your policy engine's own tests only cover
   rules that exist, so they can never say "this tool has no rule at all". lockwalk counts from
   the list of tools.
2. **A decision you did not expect (`FAIL_POLICY`).** You write down what the answer should be.
   lockwalk asks your real policy engine and compares.
3. **A deny that did not stop the tool (`FAIL_EXECUTION`).** The engine says no, but the code
   path skips the check. lockwalk can call the tool in a test subprocess, with its side effects
   replaced by counters, and see whether it ran.
4. **A route that goes too far (`never_reaches`, `ESCALATION`).** When agents call other agents, a
   role can reach a tool through a chain nobody planned, and an agent can be allowed what the user
   alone is not. lockwalk maps which roles reach which tools through which agents, checks the rules
   you write about what must never be reached, and compares the agent's answer with the user's.

## Where it fits

![A user with a role starts at an entry agent, which calls agent A and agent B. Agent A acts as the user and also calls agent B as a tool; agent B acts as itself. Before each tool runs, an enforcement point (PEP) asks a policy engine (PDP). lockwalk adds none of these. It checks five things: tools nobody tested (UNSPECIFIED, found by lockwalk coverage), routes that reach what they must never reach (never_reaches, found by lockwalk coverage), routes where the agent is allowed but the user alone is not (ESCALATION, found by lockwalk test), policy engine answers you did not expect (FAIL_POLICY, found by lockwalk test), and tools that ran after a deny (FAIL_EXECUTION, found by lockwalk test with a harness). lockwalk observe checks real traces against the same map.](https://raw.githubusercontent.com/AluminumShark/lockwalk/main/docs/images/where-lockwalk-sits.svg)

`lockwalk observe` compares what your agents really did, read from traces, with the map of who can
call what. It finds routes off the map, agents and tools the map does not know, the wrong identity,
and calls that skipped the check.

## Words you will see

- **IAM**: whatever answers "may this identity do this action on this resource?"
- **Policy engine**: decides allow or deny, such as Cerbos, OPA or Cedar. A **PDP** (policy
  decision point) is one you ask over a network.
- **Door**: the code in your app that asks before a tool runs. The same thing as a **PEP**
  (policy enforcement point).
- **AuthZEN**: an open standard for asking a PDP over HTTP if a call is allowed.
- **AuthN**: checking who someone is.
- **The map**: the graph of which agents and tools can call each other.
- **Fixture**: test data for a user, agent or resource, in `fixtures.yaml`.
- **Waiver**: an accepted risk, with an owner and an expiry.
- **Harness**: an optional `[harness]` section in `.lockwalk.toml`. It calls your tools in a test
  subprocess, with their side effects replaced by counters, to check that a denied call does not run.
- **Gate**: the pass or fail check at the end of a run. It sets the exit code.
- **Trace**: a record of what an agent really did, from your tracing tool.

## Who it is for

Developers and security engineers who build AI agents with tools, and want a CI check that says
what has not been tested. lockwalk reads tools from a registry file you write, from MCP servers,
from a JSON tool list, and from Python objects in LangChain / LangGraph, the OpenAI Agents SDK,
Pydantic AI, Agno and CrewAI. For Hermes Agent, it reads a JSON export of the tools, and the traces.

It asks your IAM (whatever answers allow or deny for your agents) through AuthZEN, or through a
small Python function you write for your engine. If your engine speaks AuthZEN you write no code.
If not, you write that one function; there are
[starting points](https://github.com/AluminumShark/lockwalk/blob/main/examples/recipes/README.md).

## Install

```bash
pip install lockwalk
```

Python 3.11 or newer. Two optional parts:

```bash
pip install "lockwalk[mcp]"    # needed only for --mcp, to read tools from MCP servers
pip install "lockwalk[otel]"   # needed only to write trace records; observe reads them without
```

Python objects need no extra, only your own agent framework.

## Quick start

You need two small files and nothing else. No agent runs, and no tool is called. Work in an empty
folder, because lockwalk writes a `.lockwalk` folder next to your files.

Save this as `registry.yaml`. It lists an agent and its tools. Risk is yours to declare, because
nothing else can know it.

<!-- quickstart:registry -->
```yaml
schema_version: '1'
agents:
  - id: support-agent
    entry: true
    calls: []
tools:
  - id: read_ticket
    action: ticket:read
    risk: low
    resource_type: ticket
    supported_agents: [support-agent]
  - id: delete_customer
    action: customer:delete
    risk: critical
    resource_type: customer
    supported_agents: [support-agent]
```

Save this as `security-spec.yaml`. It says what the answers should be. It has a case for
`read_ticket`, and nobody wrote one for `delete_customer`.

<!-- quickstart:spec -->
```yaml
schema_version: '1'
scenario_suite: quickstart
cases:
  - id: CASE-001
    actor: alice
    role: support
    agent: support-agent
    tool: read_ticket
    action: ticket:read
    resource_fixture: ticket-1
    expect: allow
```

Run it:

<!-- quickstart:run -->
```bash
lockwalk coverage --registry registry.yaml --spec security-spec.yaml
```

lockwalk finds the gap and exits 1, which is what makes a CI job fail. This is an excerpt; the
real output has more lines:

<!-- quickstart:output -->
```text
Tools without spec:                 1   (delete_customer, risk=critical, source=registry:registry.yaml)
High-risk tools without deny case:  1   (delete_customer)
Gate: FAIL (exit 1)
  - fail_on_unspecified_risk: delete_customer (risk=critical)
  - require_deny_case_for_risk: delete_customer (risk=critical)
```

The last two lines name the gate rules that failed: `fail_on_unspecified_risk` (a critical or
unknown-risk tool with no case) and `require_deny_case_for_risk` (a high-risk tool with no deny
case). You set both in the `[gate]` table; see
[Gate and exit codes](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-coverage.md#gate-and-exit-codes).

To fix it, add a case that says this call must be denied, at the end of `security-spec.yaml`.
Keep the two-space indent, so the new case lines up with `CASE-001`:

<!-- quickstart:fix -->
```yaml
  - id: CASE-002
    actor: alice
    role: support
    agent: support-agent
    tool: delete_customer
    action: customer:delete
    resource_fixture: customer-1
    expect: deny
    reason: Support staff never delete customers
```

Run the same command again, and it prints `Gate: PASS (exit 0)`. The full report is in
`.lockwalk/coverage.json`. Next to the pass you will see `Untested: 2` and
`Executed scenarios: 0/2`. That is expected: `coverage` runs no agent or tool, and never asks
your IAM. It only checks that every tool has an expected answer. To ask your IAM, use
`lockwalk test`.

## Next step: ask your policy

To ask an IAM, make two more changes in the same folder. First, save a small Python function as `my_iam.py`. It stands in for your IAM, and only `bob` may delete
a customer:

<!-- next:iam -->
```python
def decide(subject, action, resource, context):
    if action["name"] == "customer:delete":
        return subject["id"] == "bob"
    return True
```

Second, add an allow case at the end of `security-spec.yaml`. A deny proves little unless the
IAM allowed the same action once. `delegation_mode: user` says the agent acts as the user:

<!-- next:case -->
```yaml
  - id: CASE-003
    actor: bob
    role: admin
    agent: support-agent
    delegation_mode: user
    tool: delete_customer
    action: customer:delete
    resource_fixture: customer-1
    expect: allow
```

<!-- next:run -->
```bash
lockwalk test --registry registry.yaml --spec security-spec.yaml --policy python:my_iam:decide
```

<!-- next:output -->
```text
  CASE-002  PASS            support-agent -> delete_customer  (expect deny, IAM deny)
Gate: PASS (exit 0)
```

This is an excerpt too. The real output also lists warnings such as "actor 'alice' has no
fixture; sending only its id and role". They are expected here, because you wrote no
`fixtures.yaml`. With no fixture, lockwalk sends the IAM only the name, plus the role for a user,
and no other properties.

If `decide` let `alice` delete a customer, CASE-002 would be `FAIL_POLICY`. For a real engine,
see the [test guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-test.md#set-up-an-adapter)
or [`examples/iam_cedar`](https://github.com/AluminumShark/lockwalk/blob/main/examples/iam_cedar/README.md).

## How it works

![Your registry, your tool sources and your spec go into a map of who can reach what. lockwalk coverage, lockwalk test and lockwalk observe work from that map. Coverage and test write coverage.json and an exit code, and lockwalk diff compares two of those reports. Observe writes observe.json and an exit code.](https://raw.githubusercontent.com/AluminumShark/lockwalk/main/docs/images/how-lockwalk-works.svg)

`observe` also needs your traces. `discover` and `inspect` are not in the picture: they show what
lockwalk found, and do not judge it.

## Commands

`coverage`, `test` and `observe` exit 0 when they pass, 1 when a finding blocks, and 2 when the
result cannot be trusted, for example a bad configuration or an IAM that did not answer.
`discover`, `inspect` and `diff` only report: they exit 0, or 2 when they cannot do their job.

**`lockwalk discover`** lists the agents and tools from every source and draws the agent graph.
It never runs an agent or a tool, but it imports your Python modules and reads their properties,
which runs your code. The registry is yours to write; lockwalk does not generate one. Point
`--python` at `module:attribute` or `file.py:attribute`. The target can be a tool list or an
agent object, such as a LangChain tool list, an OpenAI Agents SDK `Agent` or a CrewAI `Crew`
(the [coverage guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-coverage.md#where-the-tool-list-comes-from)
has every form):

```bash
lockwalk discover --python my_app.agents:main_agent
```

**`lockwalk coverage`** checks the spec against the tool list and the roles against the routes,
and applies the gate. Like `discover`, it runs no agent or tool but imports your modules. It
writes `.lockwalk/coverage.json`; `--summary` shortens the output. See the
[coverage guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-coverage.md).

**`lockwalk test`** runs everything `coverage` runs, then asks your real IAM each question in your
spec. Choose the IAM with `--policy authzen:URL` or `--policy python:module:function`, as in the
quick start. Options can also live in a `.lockwalk.toml` file (see the
[coverage guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-coverage.md#where-the-tool-list-comes-from)).
With a `[harness]` in that file, it also calls your tools in a test subprocess, with their side
effects replaced by counters, to check that a denied call does not run. See the
[test guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-test.md).

**`lockwalk observe`** reads traces and compares the routes your agents really took with the map.
A route off the map, or an agent or tool the map does not know, blocks the gate. See the
[observe guide](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-observe.md).

**`lockwalk inspect`** shows the evidence behind one case (`--case CASE-001`), or how one trace was
read (`--trace <id>`).

**`lockwalk diff`** compares two `coverage.json` reports and lists what changed, as text, JSON or
Markdown for a pull request comment. See
[lockwalk in CI](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-ci.md).

## Use it in CI

[`examples/ci`](https://github.com/AluminumShark/lockwalk/blob/main/examples/ci/README.md) has a GitHub Actions
workflow to copy. On every pull request it runs `lockwalk coverage` and shows what changed against
the target branch. `coverage` never asks your IAM, so a policy change is not tested there. Only
`lockwalk test`, in the nightly run on the default branch, asks it. Read
[what a pull request can change](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-ci.md#what-a-pull-request-can-change)
first.

## How is this different from my policy engine's own tests?

Policy engines such as Cerbos and OpenFGA can unit-test their policies. lockwalk differs in three
ways. It counts from the list of tools, so it can say that a tool has no rule at all. With a
`[harness]`, it tests the path from your code to the engine to the tool, not only the engine. And
your `security-spec.yaml` stays the same if you change engines.

## What it does not promise

- **Passing does not mean secure.** It means the scope you declared has expected answers, and,
  with `test`, that your IAM gave them.
- **It does not stop prompt injection or data leaks.** A tricked agent can misuse a tool it may
  use, and an allowed tool can return data it should not. lockwalk checks permissions only.
- **It only sees what you point it at.** It does not find every tool or agent, and a source can
  hide one by not reporting it. Routes chosen at run time are invisible until a trace shows them.
- **It trusts your declarations.** Risk levels, roles and delegation modes are written by you. It
  cannot check them.
- **It is not a sandbox.** It imports your Python modules and starts your MCP servers, so only
  point it at code you trust.
- **It is not** an IAM system, a policy engine, a gateway or an observability platform, and it
  gives no security score.

Reports can contain agent and tool names, local file paths, exception messages from your own
code, and, in `coverage.json`, waiver owners and reasons. Keep that in mind before you upload
`coverage.json`, `evidence.jsonl` or a CI artifact. Read
[what lockwalk trusts and promises](https://github.com/AluminumShark/lockwalk/blob/main/docs/lockwalk-security.md)
before you rely on a result.

## Learn more

- [Documentation index](https://github.com/AluminumShark/lockwalk/blob/main/docs/README.md)
- [Examples](https://github.com/AluminumShark/lockwalk/tree/main/examples): demos, Cedar, Cerbos,
  Hermes Agent, IAM recipes
- [Changelog](https://github.com/AluminumShark/lockwalk/blob/main/CHANGELOG.md), [Contributing](https://github.com/AluminumShark/lockwalk/blob/main/CONTRIBUTING.md),
  [Reporting a vulnerability](https://github.com/AluminumShark/lockwalk/blob/main/SECURITY.md)

## License

Apache-2.0
