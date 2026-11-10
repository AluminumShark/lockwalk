# Cedar through decide()

This example asks a real Cedar engine, locally, whether the multi-agent demo's routes are
authorized. Cedar is the policy language behind Amazon Verified Permissions.

lockwalk's `decide()` adapter calls `iam_bridge.py:decide` with AuthZEN 1.0 fields. The
bridge turns them into a Cedar request and asks the `cedarpy` engine. The agents, spec,
and fixtures are the ones in `../multi_agent`. The Cedar policy in `policies.cedar` gives
exactly the same answers as the plain-Python reference policy used in lockwalk's own
tests, including one deliberate hole: `trade-agent`'s own service identity may trade on
any account.

## Config

This is the example's `.lockwalk.toml` (comments left out). Relative paths start at its
directory:

```toml
[lockwalk]
registry = "../multi_agent/registry.yaml"
spec = "../multi_agent/security-spec.yaml"
fixtures = "../multi_agent/fixtures.yaml"

[policy]
adapter = "python"
target = "iam_bridge.py:decide"

[[inventory.python]]
target = "../multi_agent/app.py:OPENAI_ENTRY_AGENTS"

[[inventory.python]]
target = "../multi_agent/app.py:pricing_agent"

[harness]
hooks = "lockwalk_hooks.py"
```

`[harness]` turns on the door tests (see [The door demo](#the-door-demo)). Add
`--no-harness` to `lockwalk test` to only ask the IAM.

## Run it

After `uv sync` at the repository root:

```bash
cd examples/iam_cedar
uv run lockwalk test
```

`cedarpy` is part of the dev dependency group, which `uv sync` installs.

The run exits 1, because it finds the hole. This is real output; whole blocks are left out (`...`: the agent graph, role
reachability, and warnings), and no line inside a case is cut. The `door (...)` lines come from the door tests;
with `--no-harness` they are gone and the case statuses are the same. A line like
`door (scripted): openai_agents hides tool exceptions, so the exception type is unknown` means the
framework swallowed an exception the tool raised, so lockwalk can judge only from the
counters and the door record, not from the exception:

```text
lockwalk test - multi-agent-demo-v1
Mode: test (asked the IAM through python:iam_bridge.py:decide)
...
Cases:
  CASE-001  PASS            supervisor -> finance-agent -> read_portfolio  (expect allow, IAM allow)
    door (scripted): OK, side effect ran 1 time(s), door saw user alice
    door (direct): OK, side effect ran 1 time(s), door saw user alice
  CASE-002  PASS            supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
    door (scripted): OK, side effect ran 0 time(s), door saw user alice
    door (direct): OK, side effect ran 0 time(s), door saw user alice
  CASE-003  PASS            supervisor -> finance-agent -> pricing-agent -> get_stock_price  (expect allow, IAM allow)
    door (direct): OK, side effect ran 1 time(s), door saw user alice via agent pricing-agent via agent finance-agent via agent supervisor
    door: scripted: the call from 'finance-agent' to 'pricing-agent' is declared with calls only, so lockwalk does not know which tool makes it; list that tool in the registry's delegation_tools, or provide run_path in the hooks file
  CASE-004  PASS            trade-desk -> trade-agent -> execute_trade  (expect allow, IAM allow)
    door (scripted): OK, side effect ran 1 time(s), door saw agent trade-agent
    door (direct): OK, side effect ran 1 time(s), door saw agent trade-agent
  CASE-005  FAIL_POLICY     trade-desk -> trade-agent -> execute_trade  (expect deny, IAM allow)
    expected deny, but the IAM allowed it
    door (scripted): OK, side effect ran 1 time(s), door saw agent trade-agent
    door (direct): OK, side effect ran 1 time(s), door saw agent trade-agent

Escalation checks: 2 ESCALATION, 7 NONE
  ESCALATION    CASE-005: trader -> execute_trade via trade-agent (agent)
    the IAM denies the user but allows the identity the route uses
  ESCALATION    analyst -> execute_trade via trade-agent (agent)
    the IAM denies the user but allows the identity the route uses

Identity checks: 5 MATCH
...
Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
  - case: CASE-005 (FAIL_POLICY)
  - fail_on_escalation: trader -> execute_trade via trade-agent (CASE-005)
  - fail_on_escalation: analyst -> execute_trade via trade-agent
```

## The door demo

`lockwalk test` can also check the door in the app. The demo app has a small door
(`../multi_agent/demo_door.py`, example code, not part of lockwalk): each tool asks the IAM before
it acts, and here the IAM is Cedar. `lockwalk_hooks.py` tells lockwalk how to reach it.
lockwalk replaces the side effects (`../multi_agent/demo_trading.py`) with counters, calls the
tools in a worker subprocess, and checks that the door agreed with the IAM and asked about
the right identity. The side effects raise if they ever really run. No model and no network
connection is used.

Two switches break the app on purpose. Set them in the environment of the command. In
bash:

```bash
cd examples/iam_cedar
uv run lockwalk test                                            # the default run, above
LOCKWALK_DEMO_BYPASS=read_portfolio uv run lockwalk test        # one tool skips the door
LOCKWALK_DEMO_OWN_IDENTITY=finance-agent uv run lockwalk test   # the handoff drops the user
```

(In PowerShell, set `$env:LOCKWALK_DEMO_BYPASS = "read_portfolio"` first, and remove it with
`Remove-Item Env:LOCKWALK_DEMO_BYPASS`.) All three runs exit 1, because of the Cedar hole. The
[guide](../../docs/lockwalk-test.md#door-tests) explains the hooks file, the isolation, and
how each run is judged.

### A tool skips the door

With `LOCKWALK_DEMO_BYPASS=read_portfolio` the tool runs its side effect without asking.
CASE-002 is the worst: the IAM denies Alice, and the side effect ran anyway. Real output;
whole blocks are left out (`...`), no line inside a case is cut:

```text
  CASE-001  FAIL_EXECUTION  supervisor -> finance-agent -> read_portfolio  (expect allow, IAM allow)
    door (scripted): the side effect of 'read_portfolio' ran before the door asked the IAM (the door was bypassed)
    door (scripted): openai_agents hides tool exceptions, so the exception type is unknown
    door (direct): the side effect of 'read_portfolio' ran before the door asked the IAM (the door was bypassed)
    door (direct): openai_agents hides tool exceptions, so the exception type is unknown
    door (scripted): FAIL_EXECUTION, side effect ran 1 time(s)
    door (direct): FAIL_EXECUTION, side effect ran 1 time(s)
  CASE-002  FAIL_EXECUTION  supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
    door (scripted): the IAM denied this, but the side effect of 'read_portfolio' ran 1 time(s) before the door asked the IAM
    door (scripted): openai_agents hides tool exceptions, so the exception type is unknown
    door (direct): the IAM denied this, but the side effect of 'read_portfolio' ran 1 time(s) before the door asked the IAM
    door (direct): openai_agents hides tool exceptions, so the exception type is unknown
    door (scripted): FAIL_EXECUTION, side effect ran 1 time(s)
    door (direct): FAIL_EXECUTION, side effect ran 1 time(s)
...
Identity checks: 2 NOT_RUN, 3 MATCH
  NOT_RUN   CASE-001: supervisor -> finance-agent -> read_portfolio
    direct: the door was not called
    scripted: the door was not called for the tool
  NOT_RUN   CASE-002: supervisor -> finance-agent -> read_portfolio
    direct: the door was not called
    scripted: the door was not called for the tool
...
Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
  - fail_on_escalation: trader -> execute_trade via trade-agent (CASE-005)
  - fail_on_escalation: analyst -> execute_trade via trade-agent
  - case: CASE-001 (FAIL_EXECUTION)
  - case: CASE-002 (FAIL_EXECUTION)
  - case: CASE-005 (FAIL_POLICY)
```

To see this in the timeline, use `lockwalk inspect`. It runs nothing; it reads the files the
last `lockwalk test` wrote (`--output-dir` is optional and defaults to `.lockwalk`):

```bash
LOCKWALK_DEMO_BYPASS=read_portfolio uv run lockwalk test
uv run lockwalk inspect --case CASE-002
```

Look at the timeline (real output, some lines left out):

```text
CASE-002  FAIL_EXECUTION
  timeline (lockwalk test, started ..., run c734bfd0):
      +8.954s  scripted  set identity: user:alice
      +8.985s  scripted  side effect of read_portfolio counted
     +12.656s  IAM       user:alice  portfolio:read portfolio:p-bob  -> deny  (0 ms, Q-0002)
```

The side effect is counted, and there is no `door asked` line before it: the door never
asked the IAM. lockwalk's own question (the `IAM` line) says deny. That is why the case is
FAIL_EXECUTION. Now run without the switch and inspect CASE-001:

```bash
uv run lockwalk test
uv run lockwalk inspect --case CASE-001
```

```text
CASE-001  PASS
      +7.031s  scripted  set identity: user:alice
      +7.078s  scripted  door asked: user:alice -> allow
      +7.078s  scripted  side effect of read_portfolio counted
  identity: MATCH
  gaps:
    none
```

Here `door asked: user:alice -> allow` comes first, then the side effect. The identity is
MATCH, and there are no gaps. (Times differ from run to run.)

### The handoff drops the user

With `LOCKWALK_DEMO_OWN_IDENTITY=finance-agent`, the handoff from `supervisor` to
`finance-agent` switches to finance-agent's own identity, so the door no longer knows the
user. lockwalk sees which identity the door received and reports MISMATCH (the same
framework note about swallowed exceptions appears; see above):

```text
  CASE-001  FAIL_POLICY     supervisor -> finance-agent -> read_portfolio  (expect allow, IAM deny)
    expected allow, but the IAM denied finance-agent -> read_portfolio
    door (scripted): no door control: the side effect of 'read_portfolio' was never counted in this run, so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; add a case the IAM allows, with tool_args
    door (scripted): openai_agents hides tool exceptions, so the exception type is unknown
    door (direct): no door control: the side effect of 'read_portfolio' was never counted in this run, so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; add a case the IAM allows, with tool_args
    door (direct): openai_agents hides tool exceptions, so the exception type is unknown
    door (scripted): INCONCLUSIVE, side effect ran 0 time(s), door saw agent finance-agent
    door (direct): INCONCLUSIVE, side effect ran 0 time(s), door saw agent finance-agent
  CASE-002  INCONCLUSIVE    supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
    door (scripted): no door control: the side effect of 'read_portfolio' was never counted in this run, so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; add a case the IAM allows, with tool_args
    door (scripted): openai_agents hides tool exceptions, so the exception type is unknown
    door (direct): no door control: the side effect of 'read_portfolio' was never counted in this run, so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; add a case the IAM allows, with tool_args
    door (direct): openai_agents hides tool exceptions, so the exception type is unknown
    door (scripted): INCONCLUSIVE, side effect ran 0 time(s), door saw agent finance-agent
    door (direct): INCONCLUSIVE, side effect ran 0 time(s), door saw agent finance-agent
...
Identity checks: 2 MISMATCH, 3 MATCH
  MISMATCH  CASE-001: supervisor -> finance-agent -> read_portfolio
    direct: expected agent finance-agent, the door received agent finance-agent
    scripted: expected user alice, the door received agent finance-agent
  MISMATCH  CASE-002: supervisor -> finance-agent -> read_portfolio
    direct: expected agent finance-agent, the door received agent finance-agent
    scripted: expected user alice, the door received agent finance-agent

Door controls missing:
  read_portfolio: its side effect was never counted
...
Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
  - fail_on_escalation: trader -> execute_trade via trade-agent (CASE-005)
  - fail_on_escalation: analyst -> execute_trade via trade-agent
  - case: CASE-001 (FAIL_POLICY)
  - fail_on_inconclusive_case: CASE-002
  - case: CASE-005 (FAIL_POLICY)
  - fail_on_identity_mismatch: CASE-001
  - fail_on_identity_mismatch: CASE-002
```

Because lockwalk then asks Cedar with the identity the door really received (the agent
`finance-agent`), other results change too: CASE-001 becomes `FAIL_POLICY` (Cedar denies the
agent), and CASE-002 becomes `INCONCLUSIVE`, because no run of `read_portfolio` was ever
allowed, so nothing shows that lockwalk replaced the right side effect.

Notes:

- CASE-003 is tested directly only. `finance-agent` reaches `pricing-agent` through a
  `calls` edge, and lockwalk cannot script a call it cannot see.
- `--policy` replaces the IAM that lockwalk asks, not the one the door asks. The door always
  asks the bridge set in `lockwalk_hooks.py`.
- The Cerbos example has no `[harness]`: the door demo runs with Cedar only.

## The broken policy

`policies-broken.cedar` drops the owner check on portfolios. Switch to it (with `--no-harness`, because the door still asks the correct policy):

```bash
uv run lockwalk test --no-harness --policy python:iam_bridge.py:decide_broken
```

CASE-002 (Alice reading Bob's portfolio, expected deny) becomes `FAIL_POLICY`.

## The deny-only spec

```bash
uv run lockwalk test --no-harness --spec ../multi_agent/deny-only-spec.yaml
```

This spec has only deny cases. Nothing proves that Cedar understood the questions, so
CASE-002 is `INCONCLUSIVE` (no positive control for `portfolio:read` on a portfolio).
CASE-005 is still `FAIL_POLICY`.

## Production

The policy text is plain Cedar. To run the same rules in Amazon Verified Permissions, load
it into a policy store with a matching schema. Entity data then comes from your own store.

Only the bridge (`iam_bridge.py`) is specific to this example. It maps each AuthZEN type to
a Cedar type through the `TYPES` table (`stock_symbol` to `StockSymbol`). The bridge raises
`ValueError` for a type that is not in the table, and for any error Cedar reports while it
evaluates a request (cedarpy itself answers "deny" and lists the errors). lockwalk shows
both as ERROR, never as a PASS.

## What lockwalk test cannot tell you

The [guide](../../docs/lockwalk-test.md#what-lockwalk-test-cannot-tell-you) lists the general limits.
These are the ones that matter for this example:

- It tests decisions in a test environment, not production traffic.
- If the policy tested is not the one deployed (for example someone edited it by hand in
  the console), a pass says nothing about production.
- A positive control only proves that Cedar understands "this action on this resource
  type". It does not prove that every attribute is judged correctly.
- The identity format and delegation chain are chosen by lockwalk. If your IAM uses
  another format, convert it inside `decide()`. This bridge ignores the chain (`act`).
- `agent:invoke` is only asked with `ask_every_hop = true`, which this example does not set.
