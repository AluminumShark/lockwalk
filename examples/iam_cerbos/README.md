# Cerbos through AuthZEN

This example asks a real Cerbos PDP, running in Docker, whether the multi-agent demo's
routes are authorized. lockwalk talks to Cerbos over AuthZEN 1.0 (tested with Cerbos 0.57.0;
Cerbos added AuthZEN 1.0 support in 0.48). The agents, spec, and fixtures are the ones in `../multi_agent`. The Cerbos
policies give the same answers as the plain-Python reference policy used in lockwalk's own
tests, for every question this demo sends, including one deliberate hole: `trade-agent`'s
own service identity may trade on any account (see the comment in
`cerbos/policies/order.yaml`).

The door demo (`lockwalk test` calling the app's tools) runs with Cedar only: see
[`examples/iam_cedar`](../iam_cedar/README.md#the-door-demo). This example has no
`[harness]`.

## Prerequisites

- Docker with Compose v2.
- The first `up` pulls `ghcr.io/cerbos/cerbos:0.57.0`, which needs network access.
- Ports 3592 and 3602 must be free. To change them, edit `docker-compose.yml`;
  `--policy authzen:URL` takes any URL.

## Config

This is the example's `.lockwalk.toml` (comments left out). Relative paths start at its
directory:

```toml
[lockwalk]
registry = "../multi_agent/registry.yaml"
spec = "../multi_agent/security-spec.yaml"
fixtures = "../multi_agent/fixtures.yaml"

[policy]
adapter = "authzen"
url = "http://127.0.0.1:3592"
roles_property = "cerbos.roles"

[[inventory.python]]
target = "../multi_agent/app.py:OPENAI_ENTRY_AGENTS"

[[inventory.python]]
target = "../multi_agent/app.py:pricing_agent"
```

## Run it

After `uv sync` at the repository root:

```bash
cd examples/iam_cerbos
docker compose up -d --wait
uv run lockwalk test
```

`--wait` returns once both PDPs pass their health check, so the first `lockwalk test`
does not race the start-up.

The compose file runs two PDPs from the pinned image `ghcr.io/cerbos/cerbos:0.57.0`, both
published on 127.0.0.1 only: the correct policies on port 3592 and a broken set on 3602.

The run exits 1, because it finds the hole. This is real output, shortened (the agent graph
and role reachability blocks are left out):

```text
lockwalk test - multi-agent-demo-v1
Mode: test (asked the IAM through authzen:http://127.0.0.1:3592)
...
Cases:
  CASE-001  PASS            supervisor -> finance-agent -> read_portfolio  (expect allow, IAM allow)
  CASE-002  PASS            supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
  CASE-003  PASS            supervisor -> finance-agent -> pricing-agent -> get_stock_price  (expect allow, IAM allow)
  CASE-004  PASS            trade-desk -> trade-agent -> execute_trade  (expect allow, IAM allow)
  CASE-005  FAIL_POLICY     trade-desk -> trade-agent -> execute_trade  (expect deny, IAM allow)
    expected deny, but the IAM allowed it

Escalation checks: 2 ESCALATION, 7 NONE
  ESCALATION    CASE-005: trader -> execute_trade via trade-agent (agent)
    the IAM denies the user but allows the identity the route uses
  ESCALATION    analyst -> execute_trade via trade-agent (agent)
    the IAM denies the user but allows the identity the route uses

...
Gate: FAIL (exit 1)
  - never_reaches: RULE-001 (FAIL)
  - never_reaches: RULE-002 (INCONCLUSIVE)
  - case: CASE-005 (FAIL_POLICY)
  - fail_on_escalation: trader -> execute_trade via trade-agent (CASE-005)
  - fail_on_escalation: analyst -> execute_trade via trade-agent
```

## The broken PDP

`cerbos/policies-broken/portfolio.yaml` drops the owner check. Ask the PDP on port 3602:

```bash
uv run lockwalk test --policy authzen:http://127.0.0.1:3602
```

CASE-002 (Alice reading Bob's portfolio, expected deny) becomes `FAIL_POLICY`. The
`--policy` option replaces only the adapter and URL of `[policy]`; `roles_property` stays.

## The deny-only spec

```bash
uv run lockwalk test --spec ../multi_agent/deny-only-spec.yaml
```

This spec has only deny cases. Nothing proves that Cerbos understood the questions, so
CASE-002 is `INCONCLUSIVE` (no positive control for `portfolio:read` on a portfolio).
CASE-005 is still `FAIL_POLICY`.

When you are done, clean up with `docker compose down`.

## How AuthZEN fields map to Cerbos

Read from the Cerbos 0.57.0 source (`internal/svc/authzen_svc.go`) and checked with real
requests:

| AuthZEN | Cerbos |
|---|---|
| `subject.id` | principal id |
| `subject.properties` | principal `attr` (all of it) |
| `subject.properties["cerbos.roles"]` | principal roles (a list of strings) |
| `subject.type` | the principal's only role, when `cerbos.roles` is absent or empty |
| `resource.type` | resource kind (`portfolio`, `order`, `stock_symbol`, `agent`) |
| `resource.id` | resource id |
| `resource.properties` | resource `attr` |
| `action.name` | the action (`trade:execute`; colons are fine) |

Endpoints: `POST /access/v1/evaluation` and the batch `POST /access/v1/evaluations`.
AuthZEN needs no configuration. Health is `GET /_cerbos/health`.

### `roles_property`

Cerbos does not read roles from `subject.properties.roles`; it reads the key
`cerbos.roles`. lockwalk puts a user's roles in the property named by `[policy]
roles_property` (default `roles`), so `.lockwalk.toml` sets:

```toml
[policy]
adapter = "authzen"
url = "http://127.0.0.1:3592"
roles_property = "cerbos.roles"
```

### Agent roles

`roles_property` applies to user subjects only. Agent entities are sent exactly as their
fixture properties say, and `../multi_agent/fixtures.yaml` gives `trade-agent` a plain
`roles: [service_agent]`, which Cerbos ignores. Cerbos then uses the subject type, so the
agent arrives with the role `agent`. The agent rules in `cerbos/policies` therefore name
the role `agent`.

### Batches

Cerbos builds one principal per subject id inside a batch, from the first item. lockwalk's
AuthZEN adapter therefore never puts two different subjects with the same id in one
request; it splits the batch. A test checks this against the real container.

## What lockwalk test cannot tell you

The [guide](../../docs/lockwalk-test.md#what-lockwalk-test-cannot-tell-you) lists the general limits.
These are the ones that matter for this example:

General limits:

- It tests decisions in a test environment, not production traffic.
- If the policy tested is not the one deployed, a pass says nothing about production.
- A positive control only proves that Cerbos understands "this action on this resource
  type". It does not prove that every attribute is judged correctly.
- The identity format and delegation chain (`properties.act`) are chosen by lockwalk.
  These policies ignore the chain.

Quirks of this demo policy:

- Cerbos binds each action to a resource kind. For example `market:read` on a portfolio is
  denied here, while the reference policy allows it. This demo never sends that question.
- `agent:invoke` is allowed only for the roles analyst, trader and agent. lockwalk asks it
  only with `ask_every_hop = true`, which this example does not set.
- In the broken set only `portfolio.yaml` differs from the normal one.
- Rules that depend on principal attributes other than the id and roles are not covered
  by this example.

## Development

The repository's docker tests skip unless the image is pulled first
(`docker pull ghcr.io/cerbos/cerbos:0.57.0`).
