# lockwalk test: the full guide

`lockwalk test` runs everything `lockwalk coverage` runs, then asks your real IAM the questions
your spec poses. This guide says what it does, shows real output and what each result means, how
to set up each adapter, what goes into a question, how the door tests work, and what the limits
are.

Contents:

1. [What lockwalk test does](#what-lockwalk-test-does)
2. [Set up an adapter](#set-up-an-adapter)
3. [Limits of each adapter](#limits-of-each-adapter)
4. [fixtures.yaml and probes](#fixturesyaml-and-probes)
5. [Which identity is asked](#which-identity-is-asked)
6. [`ask_every_hop`](#ask_every_hop)
7. [The escalation check](#the-escalation-check)
8. [Positive controls](#positive-controls)
9. [Door tests](#door-tests)
10. [Gate keys and exit codes](#gate-keys-and-exit-codes)
11. [Waivers](#waivers)
12. [Summary output](#summary-output)
13. [IAM recipes](#iam-recipes)
14. [Examples](#examples)
15. [Evidence and lockwalk inspect](#evidence-and-lockwalk-inspect)

Limits that apply to everything: [what `lockwalk test` cannot tell you](#what-lockwalk-test-cannot-tell-you)

## What lockwalk test does

`lockwalk test` runs everything `coverage` runs, then asks your real IAM (whatever answers
allow or deny for your agents) the questions your spec poses:

- **Spec cases.** Each case in `security-spec.yaml` becomes one question: who, which action,
  on which resource. You wrote the expected answer, `allow` or `deny`. lockwalk never derives
  an expectation from the IAM's answer.
- **Escalation check.** Each role x tool route gets one: does the identity the route uses
  (often the agent's own) get an allow that the user alone would not?
- **Positive controls.** lockwalk needs one allowed answer per action and resource type.
  Without it, a deny might only mean the IAM did not understand the question.

lockwalk asks the IAM you already run; it has no policy engine of its own. By itself it never
runs an agent or a tool; only the optional [door tests](#door-tests) do. Like `coverage`, it
imports your Python modules. Read
[what `test` cannot tell you](#what-lockwalk-test-cannot-tell-you) first. For how this differs from your engine's own tests, see
[How is this different from my policy engine's own tests?](lockwalk-security.md#how-is-this-different-from-my-policy-engines-own-tests).

| | `lockwalk coverage` | `lockwalk test` |
|---|---|---|
| Asks your IAM | No | Yes |
| Needs | Your registry, spec, and code | The same, plus a reachable IAM, and `fixtures.yaml` (set with `[lockwalk] fixtures`; see the [guide](#fixturesyaml-and-probes)) |
| Finds | Untested tools, routes, rules that fail | The same, plus wrong answers, escalations, and denies nobody proved meaningful |
| Speed | Fast, offline | Depends on your IAM; one run is a few batches of questions |

Run `coverage` on every pull request, and `test` where the IAM is reachable (before a merge,
or on a schedule). This is real output, shortened, from the Cedar example, which has one
deliberate hole: `trade-agent` may trade with its own service identity.

```text
lockwalk test - multi-agent-demo-v1
Mode: test (asked the IAM through python:iam_bridge.py:decide)
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

`(agent)` is the `delegation_mode` of the route's last agent, which says whose identity the
route uses. A row with a case id comes from that spec case. A row without one comes from the
role x tool table.

### Results at a glance

| Result | Meaning | What to do |
|---|---|---|
| Case PASS | The IAM answered as you expected (a deny also has a positive control) | Nothing |
| Case FAIL_POLICY | The IAM answered differently than you expected | Fix the policy, or the spec if the expectation was wrong |
| Case INCONCLUSIVE, no positive control | An expected deny got a deny, but no question about that action and type got an allow | Add an "expect allow" case for the same action and resource type |
| Case INCONCLUSIVE, identities differ | `delegation_mode` is not declared, and the user and the agent got different answers | Declare `delegation_mode` |
| Case ERROR | The question could not be built or answered: unreachable IAM, timeout, malformed reply, missing data | Fix the cause and run again (exit 2) |
| ESCALATION | The IAM denies the user but allows the identity the route uses | Fix the policy, or make the agent use the user's identity |
| NONE | No escalation. With a hint if the user is allowed but the route is denied: the agent has less power than the user, which may break normal use | Read the hint, if any |
| Escalation INCONCLUSIVE | Both answers are deny with no positive control, or `delegation_mode` is not declared and only the agent's own identity is allowed | Add a control, or declare `delegation_mode` |
| UNCHECKED | The route cannot be asked: no fixtures, no probe for the role or type, or too many questions | Add `probes` (the full list is in the [guide](#the-escalation-check)); critical and unknown tools fail the gate |
| Escalation ERROR | A question of the check failed | As for a case ERROR |

### What lockwalk test cannot tell you

- It tests decisions in a test environment, and it does not look at production traffic.
  `lockwalk observe` reads traces that you give it; see the [observe guide](lockwalk-observe.md).
- If the policy you test is not the one deployed (for example, someone edited it by hand in a
  console), a pass says nothing about production.
- It can only ask something that can be asked. If authorization is decided in scattered
  application code, with no endpoint or function to ask, `test` cannot see it. An identity
  provider that only signs users in (Okta, Entra ID, Auth0, Cognito) does not make these
  decisions.
- The escalation check covers only the combinations that `fixtures.yaml` gives a subject and a
  resource for, and it uses one stand-in user per role.
- A positive control proves only that the IAM understands "this action on this type of
  resource". It does not prove that every attribute is judged correctly.
- The identity format and the delegation chain are chosen by lockwalk. If your IAM uses
  another format, convert it in `decide()`. With AuthZEN, your policy reads lockwalk's format.
- The identity sent comes from the hand-written `delegation_mode`. Without door tests,
  whether the agent really sends it is not checked. With door tests, scripted mode records the
  identity your door receives, but only for the routes it can run.
- `test` asks only what the spec cases and the probes pose, so an untested tool or route stays
  untested.
- Without a `[harness]`, `test` does not check that a denied tool really does not run.
- Scripted mode is built in for Pydantic AI, LangChain/LangGraph, and the OpenAI Agents SDK.
  CrewAI and Agno need your `run_path`. A step declared only with `calls` cannot be scripted.
  A LangGraph agent that lockwalk cannot identify (for example a compiled graph without a
  name) cannot be scripted either. Direct mode cannot test the machinery that Pydantic AI
  wraps around a tool; scripted mode can.
- A tool does something that is not in `SIDE_EFFECTS`, such as writing a file? That really
  happens. The network guard works in Python only: a C extension, or another process, can
  bypass it. On Windows there is no file system isolation. Run door tests in a test
  environment, never in production.
- MCP tools are remote, so they get no door test.
- Cleanup of children has gaps: on Windows, a child started before the Job Object assignment
  survives; on macOS (no `os.waitid`), a child left by a worker that exited on its own may
  survive.
- An OpenAI Agents SDK agent that lockwalk did not find and that already holds a real `Model`
  is not covered by the fake models; only the network guard remains. For LangChain, only the
  listed model entry points are patched, so paths added by a newer langchain-core are covered
  by the network guard alone.
- Door tests use fake models. They do not test how a real LLM behaves, for example under
  prompt injection: lockwalk assumes the worst, that the LLM does call the tool.

Every run also writes `.lockwalk/evidence.jsonl`, and `lockwalk inspect --case <id>` shows
one case's timeline: what lockwalk asked the IAM, what the door received and answered, and
whether the side effect ran.

## Set up an adapter

Pick one in `[policy]`, or pass `--policy` on the command line.

```toml
# AuthZEN 1.0 over HTTP, for a policy decision point (PDP) such as Cerbos
[policy]
adapter = "authzen"
url = "http://localhost:3592"
```

```toml
# Your own Python function, which calls your IAM
[policy]
adapter = "python"
target = "my_iam:decide"      # def decide(subject, action, resource, context) -> bool
```

lockwalk talks to your IAM in one of two ways. Choose one in `[policy]`, or on the command
line with `--policy`. In this guide, IAM means whatever answers "may this identity do this
action on this resource?". A PDP (policy decision point) is the server that answers allow or
deny over AuthZEN.

### AuthZEN over HTTP

Any PDP that speaks [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) works
(tested with Cerbos 0.57.0; Cerbos added AuthZEN 1.0 support in 0.48):

```toml
[policy]
adapter = "authzen"
url = "http://localhost:3592"
headers = { Authorization = "Bearer ${PDP_TOKEN}" }   # optional; read from the environment
timeout_s = 2.0      # per request; the default for authzen
batch_size = 100
```

### A Python `decide()` function

You write a function that calls your IAM however it needs to:

```toml
[policy]
adapter = "python"
target = "my_iam:decide"      # or "my_iam.py:decide", or "iam_bridge.py:decide"
timeout_s = 5.0               # the default for python
```

`subject`, `action`, `resource`, and `context` are the four dicts of the question, in the
AuthZEN shape (see [the question](#what-a-question-looks-like) below). `decide` must return a
real `bool`, or `{"decision": bool, "reason": str}`. Anything else (`1`, `"yes"`) is an error,
and an error is never a PASS. It may be `async def`.

A small, complete `my_iam.py` that allows two things and denies the rest:

```python
ALLOWED = {("alice", "portfolio:read"), ("bob", "trade:execute")}


def decide(subject, action, resource, context):
    return (subject["id"], action["name"]) in ALLOWED


def decide_many(queries):  # optional; one answer per query, in the same order
    return [decide(q["subject"], q["action"], q["resource"], q["context"]) for q in queries]
```

If the module also defines `decide_many`, lockwalk gives it up to `batch_size` queries at a
time. Each query is one dict with the four keys `subject`, `action`, `resource`, and
`context`. This only happens when `target` is a plain module-level function (not
`Class.method`), and `decide_many` must be in the same module.

[`examples/iam_cedar/iam_bridge.py`](../examples/iam_cedar/iam_bridge.py) is a complete
bridge to a real engine (Cedar).

### On the command line

```bash
uv run lockwalk test --policy authzen:http://localhost:3592
uv run lockwalk test --policy python:my_iam:decide
```

`--policy` replaces `adapter` and `url` or `target`; `url`, `target`, and `headers` from the
file are ignored, so credentials never go to another host. The other `[policy]` settings
(`timeout_s`, `batch_size`, `roles_property`, and so on) still apply. With no adapter at all,
`test` is a configuration error (exit 2). `coverage` does not use `[policy]`, but it still
validates it when it loads the config, so a malformed `[policy]` breaks `coverage` too.

The report records the adapter in `policy_adapter` (for example
`authzen:http://localhost:3592`), with URL credentials and the query string removed.

### The `[policy]` settings

| Key | Default | Meaning |
|---|---|---|
| `timeout_s` | 2.0 (authzen), 5.0 (python) | Time limit in seconds; see [Limits of each adapter](#limits-of-each-adapter) |
| `batch_size` | 100 | Questions per request (authzen) or per `decide_many` call |
| `max_queries` | 5000 | Most distinct questions in one run; role x tool rows are dropped first (see [The escalation check](#the-escalation-check)) |
| `ask_every_hop` | false | Also ask about every agent-to-agent step (see [`ask_every_hop`](#ask_every_hop)) |
| `invoke_action` | `agent:invoke` | The action name for those steps |
| `roles_property` | `roles` | The key under `subject.properties` that holds a user's roles |

`roles_property` exists because IAMs differ. Cerbos, for example, reads roles only from
`cerbos.roles`, so its example sets `roles_property = "cerbos.roles"`. It applies to user
subjects only. lockwalk has no role data for agents, so an agent's properties are sent
exactly as written in `fixtures.yaml`: if your IAM reads agent roles from a property, put
that key in the agent's fixture yourself. A user's fixture must not set the same key, because
roles may only come from `roles` (the case is an ERROR if it does).

## Limits of each adapter

### AuthZEN

- lockwalk sends `POST /access/v1/evaluations` with up to `batch_size` questions. Each has all
  four fields written out. If the server answers 404 or 405, lockwalk sends the questions one
  by one to `POST /access/v1/evaluation` and notes that in `warnings`.
- A request never holds two different subjects with the same id. Some PDPs treat all items
  with one subject id as the same subject (Cerbos 0.57 uses the first item's), which would
  give wrong answers. lockwalk splits such a batch into separate requests.
- The reply is checked strictly. `decision` must be JSON `true` or `false`. A wrong number of
  answers fails the whole batch. The reason is the first non-empty string among `reason`,
  `reason_admin`, and `reason_user` (in that order) in the reply's `context`. Its secrets are
  masked first and then it is cut to 300 characters. Nothing else of the response is kept.
- AuthZEN 1.0 lets a PDP report an evaluation it could not perform as `"decision": false`
  with a `context.error`. That is not a deny. When `context.error` is present and not null,
  the answer is an error with the fixed message "the PDP reported an error for this
  question". The PDP's own error content is never copied.
- A failed connection, a timeout, a non-2xx status, or a reply that is not JSON is an error,
  not an answer. A connection that fails before any answer, and a 502, 503, or 504, are
  retried once. Nothing else is, including timeouts and TLS certificate failures.
- Each request has one deadline of `timeout_s`, shared with its retry. After the first
  timeout within one batch of up to `batch_size` questions (including the sub-batches that
  the subject split makes), the rest of that batch is skipped and reported as errors. Each
  batch can still cost one timeout, so the worst case is about
  ceil(questions / `batch_size`) timeouts.
- The deadline does not cover DNS lookups, and it does not stop a server that sends its
  headers very slowly. `HTTP_PROXY` and `HTTPS_PROXY` are not supported, so a PDP behind a
  proxy cannot be reached.

### `decide()`

- The function runs in a subprocess started with lockwalk's own Python interpreter
  (`sys.executable`). Whatever your module imports must be installed in the environment that
  runs lockwalk. One subprocess serves the whole run.
- `timeout_s` applies to each `decide` call. For `decide_many` it applies to each batch as
  `timeout_s` times the number of queries (20 queries x 5 s = 100 s). After a timeout or a
  crash, the subprocess is restarted. With `decide_many`, the whole batch is an error. With
  plain `decide()`, each question is sent alone. A crash only makes that question an error,
  and the next one gets a fresh subprocess. After the first timeout within one `decide()`
  call of the adapter (one batch of up to `batch_size` questions), the subprocess is killed
  and the rest of that batch is not sent: those questions are errors ("skipped: the decide
  worker timed out on an earlier question"). The next batch starts a fresh subprocess. The
  worst case is about one timeout per batch of `batch_size` questions, or `timeout_s` times
  the number of queries per batch with `decide_many`. An import failure is not retried.
- An exception is an error: lockwalk records its type and its message, cut to 300 characters.
  From the message it removes URL credentials, query strings, and fragments. It also hides the
  value of every environment variable of 8 or more characters, as `<hidden env 'NAME'>`. That
  is lockwalk's own environment, read when the subprocess starts, and the subprocess inherits
  it. This applies to exceptions, to reasons that `decide()` returns, and to worker failures.
  Other secrets in plain text cannot be recognized, so do not put them in exception messages.
  (The AuthZEN adapter has no such subprocess. It hides the expanded values of your
  `[policy] headers` instead, not the whole environment.) The subprocess's stderr is never
  shown.
- The 1 MiB cap is on the subprocess's whole reply line. With `decide_many` that is all the
  answers of one batch together; an oversized reply is an error for the batch and the
  subprocess is restarted. The subprocess does not cut anything. lockwalk masks URL
  credentials first and then cuts reasons and error messages to 300 characters.
- `decide()` may use the network: asking an IAM is its job. The `target` format is the one of
  `[[inventory.python]]`, without a trailing `()`.

## fixtures.yaml and probes

A question needs subjects and resources. `fixtures.yaml` (optional) describes them:

```yaml
schema_version: '1'
subjects:
  alice: {roles: [analyst]}
  bob:   {roles: [trader], properties: {desk: asia}}
agents:
  trade-agent: {properties: {service_account: svc-trade}}
resources:
  alice-portfolio: {type: portfolio, id: p-alice, properties: {owner: alice}}
  bob-order:       {type: order, id: o-1, properties: {amount: 5000}}
probes:
  subjects:  {analyst: alice, trader: bob}                   # role -> subject
  resources: {portfolio: alice-portfolio, order: bob-order}  # resource type -> resource
```

Set it with `[lockwalk] fixtures = "fixtures.yaml"` or `--fixtures`. Unknown keys are an
error.

| Key | Meaning |
|---|---|
| `subjects` | The key is a case's `actor`. `roles` is required. `properties` are sent as they are |
| `agents` | The key is an agent id from the registry. Its `properties` are used when an agent is the subject |
| `resources` | The key is a case's `resource_fixture`. `type`, `id`, and `properties` are optional. `tool_args` (a dict) is the arguments of the tool call in the [door tests](#direct-mode). The IAM questions do not use it |
| `probes` | One stand-in user per role (`subjects`) and one stand-in resource per resource type (`resources`). They give the stand-in user and resource for the role x tool rows of the escalation check |

When data is missing, lockwalk does not guess:

- An `actor` with no fixture is sent with just its id and the case's role, with a warning.
- A `resource_fixture` with no fixture is sent with the fixture name as its id and no
  properties, with a warning.
- The resource type comes from the fixture's `type`, then from the tool's `resource_type` in
  the registry. If neither is set, the case is an ERROR.
- A case whose `role` is not among its `actor`'s roles is an ERROR.

There is one warning per missing name, not one per case. It lists the cases that use the
name (at most 5). An agent that is asked as the subject but has no fixture gets the warning
`agent 'X' has no fixture; sending only its id`.

### What a question looks like

Every question has this shape. `context.lockwalk` is reserved for lockwalk, so a case's
`conditions` cannot use that key. Other `conditions` go straight into `context`.

```json
{
  "subject":  {"type": "user", "id": "alice", "properties": {"roles": ["analyst"]}},
  "action":   {"name": "trade:execute"},
  "resource": {"type": "order", "id": "o-1", "properties": {"amount": 5000}},
  "context":  {"lockwalk": {"case": "CASE-006",
                            "path": ["supervisor", "finance-agent", "trade-agent"],
                            "tool": "execute_trade"}}
}
```

## Which identity is asked

The last agent on the path is the one that calls the tool. Its `delegation_mode` decides the
subject (a `delegation_mode` on the case itself wins):

| `delegation_mode` | Subject sent to the IAM |
|---|---|
| `user` | The user: `{"type": "user", "id": "alice", ...}` |
| `agent` | The agent: `{"type": "agent", "id": "trade-agent", ...}`, with properties from the `agents` fixtures |
| `on_behalf_of` | The user, plus `properties.act`: a chain of the agents on the path (RFC 8693 style), the last agent outermost and the entry agent innermost. Only `type` and `id` are in the chain |
| not declared | Both of the above are asked. If the answers differ, the case is INCONCLUSIVE and says to declare `delegation_mode`. If they agree, the usual rules apply |

lockwalk chooses this format. If your IAM expects another one, convert it inside `decide()`.
With AuthZEN, your policy has to read this format.

lockwalk takes the mode from the hand-written `delegation_mode`. It does not check that the
agent really sends that identity.

## `ask_every_hop`

By default lockwalk asks one question per case: the last step, where the agent calls the
tool. The whole path is in `context.lockwalk.path`. With `ask_every_hop = true`, it also asks
one question per agent-to-agent step, with the action `agent:invoke` (change it with
`invoke_action`) on a resource of type `agent`. The caller of the first step is the user.
A middle step uses its caller's own `delegation_mode`. If any step is denied, the path is
denied, and `decision.denied_hop` in `coverage.json` names the step. The escalation check
still looks at the last step only.

## The escalation check

An agent often calls a tool with an identity that has more power than the user who started
the request. Whenever the identity the route uses is not the user (`agent`, `on_behalf_of`, or
not declared), lockwalk asks a second time, about the same action and resource, as the user
alone (no `act`). The results are listed, with what to do about each, in
[Results at a glance](#results-at-a-glance).

If `delegation_mode` is not declared and only the agent's own identity is allowed, the result
is INCONCLUSIVE: it is an escalation if the agent really uses its own identity.

The check covers two sources:

1. Every spec case, with the case's own subject and resource.
2. Every row of the role x tool table: for each agent that the role can reach and that holds
   the tool directly. These rows use `probes`: one stand-in user per role and one stand-in
   resource per resource type, with the `action` of the tool in the registry. An agent whose
   `delegation_mode` is `user` cannot escalate, so it makes no row.

A role x tool row is UNCHECKED when it cannot be asked:

- there is no fixtures file;
- there is no probe subject for the role;
- the tool has no `action` or no `resource_type` in the registry;
- there is no probe resource for that type;
- a user fixture sets the `roles_property` key;
- the question could not be built (for example, a delegation chain nested deeper than 64);
- `max_queries` was reached.

The default gate fails an UNCHECKED row when the tool's risk is `critical` or `unknown`
(`fail_on_unchecked_escalation`), and only warns for other risks. `max_queries` caps the
distinct questions in one run. The budget goes to the riskiest rows first (unknown,
critical, high, medium, low), so the lowest-risk rows are the ones dropped and become
UNCHECKED. Spec cases are never dropped.

## Positive controls

A system that denies everything would make every "expect deny" case look right. That happens
when the policy did not load, or when it cannot read lockwalk's questions. So for each pair of
action and resource type, the run needs at least one question that the IAM **allowed**. Any
question can supply it: an "expect allow" case, an escalation check, or an `agent:invoke`
step. It shows that the IAM understands that kind of question.

Without that control, an "expect deny" case that got a deny is INCONCLUSIVE, and so is an
escalation row where both answers are deny. The reason names the missing pair, and the
report lists every pair in `controls`. The reverse needs no control: if the IAM allows
everything, each "expect deny" case becomes FAIL_POLICY.

A spec with only deny cases usually ends up INCONCLUSIVE, because nothing else asked about the
same action and type got an allow. The demo's `examples/multi_agent/deny-only-spec.yaml`
shows it; this is real output from the Cedar example, shortened:

```text
  CASE-002  INCONCLUSIVE    supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
    no positive control: no question about portfolio:read on portfolio got an allow in this run, so lockwalk cannot tell that the IAM understood it; add a case the IAM should allow
```

## Door tests

The IAM answering "deny" is not enough. Does the tool really not run, and does your door ask
the IAM about the right identity? Add a `[harness]` and `lockwalk test` checks both. In a
test subprocess it imports your app, replaces the functions that do the real work
(`SIDE_EFFECTS`) with counters, and records your authorization check (the `DOOR`) without
replacing it. Then it calls each tool and judges the result against what the IAM said.

You write a hooks file, and set `hooks = "lockwalk_hooks.py"` in `[harness]`:

```python
# lockwalk_hooks.py
from my_app import auth


def set_identity(subject):  # required: how your app learns who is calling
    return auth.as_user(subject["id"])  # must return a context manager


SIDE_EFFECTS = {  # required: tool name -> the name the tool looks up
    "execute_trade": "my_app.trading.place_order",  # like unittest.mock.patch
}

DOOR = "my_app.authz.check"  # optional: the function your door asks the IAM with


def read_door_call(args, kwargs, result):  # needed with DOOR: who was asked, what came back
    return {"subject": args[0], "decision": result is True}


def run_path(path, subject, tool, tool_args):  # optional: run a route yourself
    ...
```

FAIL_EXECUTION means the door failed (the IAM denied but the side effect ran). MISMATCH means
the door was asked about another identity than the route should use.

Real output, shortened, from [`examples/iam_cedar`](../examples/iam_cedar/README.md#the-door-demo).
With `$env:LOCKWALK_DEMO_BYPASS = "read_portfolio"` (PowerShell), one tool skips the door:

```text
  CASE-002  FAIL_EXECUTION  supervisor -> finance-agent -> read_portfolio  (expect deny, IAM deny)
    door (scripted): the IAM denied this, but the side effect of 'read_portfolio' ran 1 time(s) before the door asked the IAM
    door (scripted): openai_agents hides tool exceptions, so the exception type is unknown
    door (direct): the IAM denied this, but the side effect of 'read_portfolio' ran 1 time(s) before the door asked the IAM
    door (direct): openai_agents hides tool exceptions, so the exception type is unknown
    door (scripted): FAIL_EXECUTION, side effect ran 1 time(s)
    door (direct): FAIL_EXECUTION, side effect ran 1 time(s)
```

With `$env:LOCKWALK_DEMO_OWN_IDENTITY = "finance-agent"`, the handoff drops the user:

```text
Identity checks: 2 MISMATCH, 3 MATCH
  MISMATCH  CASE-001: supervisor -> finance-agent -> read_portfolio
    direct: expected agent finance-agent, the door received agent finance-agent
    scripted: expected user alice, the door received agent finance-agent
  MISMATCH  CASE-002: supervisor -> finance-agent -> read_portfolio
    direct: expected agent finance-agent, the door received agent finance-agent
    scripted: expected user alice, the door received agent finance-agent
```

`--no-harness` skips the door tests and only asks the IAM. Run door tests in a test environment: whatever a
tool does that is not in `SIDE_EFFECTS` (writing a file, for example) really happens.

The IAM part of `lockwalk test` asks what your policy says. Door tests ask a second question:
does your application do what the policy says? lockwalk imports your app in a subprocess,
replaces the functions that do the real work (`SIDE_EFFECTS`) with counters, calls the tools,
and compares what happened with the IAM's answer. They are on only when `.lockwalk.toml` has a
`[harness]` section. `--no-harness` turns them off for one run.

The Cedar example runs all of this:
[`examples/iam_cedar`](../examples/iam_cedar/README.md#the-door-demo).

The words used here:

- **Side effect:** the function that does the real work of a tool (sends the order, reads the
  database). lockwalk replaces it with a counter that returns `None`.
- **Door:** your own authorization check, the function that asks the IAM before the side
  effect. lockwalk does not replace it. It only records its calls.
- **Direct mode:** lockwalk calls one tool the way its framework does. No model is involved.
- **Scripted mode:** lockwalk runs the real agent route (entry agent, handoffs, tools) with
  fake models that follow a script.

Contents:

- [The `[harness]` section](#the-harness-section)
- [The hooks file](#the-hooks-file)
- [Isolation](#isolation)
- [Direct mode](#direct-mode)
- [Scripted mode](#scripted-mode)
- [Judging](#judging)
- [Secrets](#secrets)
- [Limits of door tests](#limits-of-door-tests)

### The `[harness]` section

```toml
[harness]
hooks = "lockwalk_hooks.py"      # required; relative to the config file
modes = ["direct", "scripted"]   # default: both
timeout_s = 10.0                 # per run, after the app is imported
import_timeout_s = 30.0          # to import the app and the hooks file
allow_hosts = []                 # hosts the app may connect to; see Isolation
```

- `modes` must list `direct`, `scripted`, or both, each once.
- The tools and agents come from your `[[inventory.python]]` sources. The subprocess imports
  the same targets again. A tool that no Python source reports (for example an MCP tool) gets
  no door test, and the report says so.
- Door tests need a `[policy]`, like all of `test`. With `--policy`, the IAM that lockwalk
  asks changes, but the door still asks whatever your app is built to ask.
- `coverage` reads the section to check its format and does nothing else with it.

### The hooks file

The hooks file is a Python module. lockwalk imports it in the subprocess, so it may import
your app and set it up (the Cedar example plugs in its IAM there). Every problem in it is
reported at once, and then every door test is an ERROR.

```python
# lockwalk_hooks.py
from my_app import auth


def set_identity(subject):
    """How your app knows who is calling. Must return a context manager."""
    return auth.as_user(subject["id"], roles=subject["properties"].get("roles", []))


SIDE_EFFECTS = {
    "execute_trade": "my_app.trading.place_order",
    "read_portfolio": "my_app.db.fetch_portfolio",
}

DOOR = "my_app.authz.check"


def read_door_call(args, kwargs, result):
    """Who did the door ask about, and what was the answer?"""
    return {"subject": kwargs["subject"], "decision": result is True}


def run_path(path, subject, tool, tool_args): ...
```

| Hook | Needed | What it is |
|---|---|---|
| `set_identity(subject)` | yes | Gets the subject in the shape of [a question](#what-a-question-looks-like) (`type`, `id`, `properties`, and `properties.act` for a delegation chain). Returns a context manager. lockwalk enters it before a run and leaves it after. Make your app read the identity from there (a context variable, usually) |
| `SIDE_EFFECTS` | yes | A non-empty dict. The key is a tool name, the value is a `module.attribute` path to the function that does its work |
| `DOOR` | no | A `module.attribute` path to your authorization check. With it, lockwalk finds doors that were bypassed and doors that were asked about the wrong identity. The name must be exactly `DOOR`. A public string constant with `door` as a whole word in its name (`FRONT_DOOR`, `DOOR_TOKEN`, `Door`) while `DOOR` is missing is an error, because a misspelled `DOOR` would silently turn the door checks off. To keep such a name, start it with an underscore (`_FRONT_DOOR`) or set `DOOR = None`, which also drops `read_door_call` |
| `read_door_call(args, kwargs, result)` | with `DOOR` | Tells lockwalk how to read one call of the door. Returns `{"subject": {...}, "decision": bool}`. Defining it without `DOOR` is an error |
| `run_path(path, subject, tool, tool_args)` | no | Runs a route yourself, for frameworks with no built-in scripted mode |

A tool that is not in `SIDE_EFFECTS` is never called. The report marks it `NOT_TESTED`.

**The `SIDE_EFFECTS` path.** Write the name that the tool looks up, the same rule as
`unittest.mock.patch`. If the tool's module does `from my_app.trading import place_order`,
the name it uses is `my_app.tools.place_order` (the module that imported it), not
`my_app.trading.place_order`.

lockwalk also scans every loaded module. A module-level name that points at the same function
(what `from x import f` creates in another module) is replaced too. Once a tool's function is replaced, a call to it only counts.
If the function is `async`, the counter is `async` too. Several tools may name the same function.

The scan cannot see a function that is stored somewhere else:

- inside a container (a list, a dict, a registry of handlers);
- in a closure, or inside `functools.partial`;
- as a class attribute of a class other than the owner that the path names.

If the scan misses one, the real function runs and the counter stays 0. That would look like
"the door blocked it". This is why a [door control](#the-door-control) is needed before a
clean deny counts.

**`DOOR`.** lockwalk wraps the door and calls the original. Then it calls
`read_door_call(args, kwargs, result)` with the same arguments and the return value, and keeps
the answer. A door call made inside `read_door_call` itself is not recorded.

- If the door **raises**, `result` is the exception, and lockwalk then raises it again. Some
  doors deny by raising (`PermissionError`). Let `read_door_call` return `decision: False` for
  that. Only subclasses of `Exception` are recorded this way.
- A wrong return type is an ERROR for the run. A `read_door_call` that raises is an ERROR too;
  the report keeps only its exception type name, because the message may hold a secret.
- `decision` must be a real `bool`.
- **Subjects are reduced.** lockwalk keeps only the subject's `type` and `id`, and the same two
  fields for each link of the `act` chain. Property values are dropped, because they may hold
  secrets. The identity checks compare only those fields.

**`run_path`.** See [Scripted mode](#scripted-mode).

### Isolation

Door tests call your tools, so they run in a place where mistakes are small.

- **One subprocess for each job.** First one for the survey (import the app, find the tools and
  agents, replace the side effects). Then one for each scripted case. Then one for each direct
  run. A case whose identity is not declared has two direct runs, one for each identity that
  the IAM is asked about. Nothing carries over from one run to the next.
- **The subprocess is lockwalk's own Python** (`python -P -m lockwalk.harness._worker`), so
  whatever your app imports must be installed in the environment that runs lockwalk. It starts
  in the config file's directory, with your environment plus these variables:
  `LOCKWALK_HARNESS=1` (your app can read it to turn off integrations such as sending mail),
  `PYDANTIC_AI_NO_BANNER=1`, and `OPENAI_AGENTS_DISABLE_TRACING=1`.
- **Two time limits.** `import_timeout_s` covers importing the app. When the import is done,
  the clock restarts with `timeout_s` for the run. A run that is too slow is stopped and
  reported as an ERROR (`timed out after 10s while running the case`).
- **Nothing the app prints is shown.** The subprocess's stdout and stderr are discarded.
  lockwalk never reads them, because they may hold secrets.
- **Children are cleaned up.** On Windows the worker is put into a Job Object, so every process
  it started dies with it. On Linux and other POSIX systems the worker has its own process
  group, which is killed at the end. The limits:
  - On Windows, a child that the app starts before lockwalk has put the worker in the Job
    Object is outside it. The window is very small.
  - If Job Object setup fails, lockwalk falls back to `taskkill /T`.
  - macOS has no `os.waitid`. lockwalk cannot tell, without reaping the worker, that the
    group is still reserved, so it only kills a worker that is still running. A child left
    behind by a worker that exited on its own may survive there.
- **The network guard.** Door tests do not need the network, and a real model must never be
  reached. Before the app is imported, lockwalk patches Python's socket layer. A connection is
  allowed only to:
  - `localhost` and every loopback address;
  - the host of the `[policy]` URL, when the adapter is `authzen`;
  - the hosts in `[harness] allow_hosts` (names or IP addresses), and the addresses that an
    allowed name resolved to.

  Everything else raises `ConnectionRefusedError` ("lockwalk blocked a connection to ...").
  The run is an ERROR, and the report names the host (at most 20 of them, without credentials or
  ports): `the code tried to connect to api.example.com; door tests block the network`. In
  scripted mode it adds `so the fake model may not have taken effect`.

  What the guard patches: `socket.socket.connect`, `connect_ex`, `sendto`, `sendmsg` (where it
  exists), `socket.create_connection`, `socket.getaddrinfo`, `gethostbyname`,
  `gethostbyname_ex`, and `sock_connect` of the asyncio selector loop and, on Windows, of the
  `ProactorEventLoop`. The last one matters: on Windows the default loop connects without
  `socket.connect` and without a DNS lookup for an IP address.

  What it cannot stop:
  - reverse lookups (`gethostbyaddr`, `getnameinfo`);
  - `uvloop`;
  - unconnected UDP on the Windows Proactor loop;
  - C extensions that open sockets themselves, or code that uses the C `_socket` type directly;
  - other processes that the app starts.

  It is a safety net for mistakes, not a sandbox.
- **Files are not isolated.** Whatever a tool does that is not in `SIDE_EFFECTS` (writing a
  file, say) really happens. Windows offers no cheap file system isolation. Run door tests in
  a test environment, never against production data.

### Direct mode

Direct mode calls a tool the way its framework does, so decorators and middleware around the
tool are part of the test. The tool object comes from the same discovery that
`[[inventory.python]]` uses.

| Tool | How lockwalk calls it |
|---|---|
| LangChain / LangGraph tool | `tool.invoke(args)`; `ainvoke` when the tool has only a coroutine |
| OpenAI Agents SDK `FunctionTool` | `on_invoke_tool(ToolContext(...), json_args)` |
| CrewAI tool | `run(**args)` |
| Agno `Function` | `FunctionCall(function=f, arguments=args).execute()`; `aexecute()` for an async function |
| Pydantic AI tool | The tool's function, called directly (`Tool.function`) |
| A plain function | Called directly; an awaitable result is awaited |

Each call runs on a fresh event loop.

**Pydantic AI.** The framework has no public way to call a tool without running an agent. So
the machinery that Pydantic AI wraps around a tool (retries, argument validation) is not in
the test. A Pydantic AI tool that takes `RunContext` exists only inside a run. It gets no
direct test, and the report says `scripted mode tests it`.

**The arguments** come from the `tool_args` of the case's resource fixture in `fixtures.yaml`:

```yaml
resources:
  alice-portfolio: {type: portfolio, id: p-alice, tool_args: {portfolio_id: p-alice}}
```

- No `tool_args` key at all (`None`): the case is `NOT_TESTED` for the door. lockwalk never
  guesses arguments.
- `tool_args: {}`: the tool takes no arguments. lockwalk calls it with none.
- lockwalk first checks the arguments against the tool's input schema, top level only: every
  `required` key is present; no extra key when `additionalProperties` is `false`; and each
  argument has the right `type` when the schema names a plain type (or a list of plain
  types). A mismatch means the tool is not called and the case is an ERROR. If lockwalk cannot
  read a schema, it does not check, and the framework decides. Deeper checks are the
  framework's job.

**Generator tools are not run.** If a call returns a generator (or an async generator),
lockwalk closes it without iterating it: the tool body did not run, so nothing was proved.
The report says so.

**Hidden exceptions.** The OpenAI Agents SDK and Agno catch what a tool raises and turn it into
an error message for the model. lockwalk does not read their private attributes to undo that.
So when a run is not OK and lockwalk has no exception type, the report adds:
`openai_agents hides tool exceptions, so the exception type is unknown` (or `agno ...`). The
verdict is unaffected: it looks only at the counters and the door record. For other
frameworks, a not-OK run says `the tool raised <Type>: <message>`.

### Scripted mode

Scripted mode runs the real route: the entry agent, the handoffs, and the tools, with every
model replaced by a fake one. A fake model has one job. It gives the answer that its agent's
step needs, and after that a fixed final text (`lockwalk scripted run`). The user's own
code between the agents runs for real, which is the part that decides the identity.

Scripted mode:

- needs `DOOR` in the hooks file. Without it, every route is `NOT_RUN`
  (`no DOOR in the hooks file, so lockwalk cannot see which identity the door received`), and
  the report warns once;
- runs only the cases of the spec, not the other rows of the graph;
- enters `set_identity(user)` for the **user** and leaves the identity changes along the route
  to your code. That is the part under test;
- runs after the survey and before the IAM is asked, because the identity it observes goes
  into the questions (see [Judging](#judging)).

**How the script is made.** lockwalk reads the case's route (for example
`supervisor -> finance-agent -> trade-agent -> execute_trade`) and the agent graph from the
static discovery. For each pair of agents on the route it needs to know what makes the
call:

| The graph edge | What the fake model does |
|---|---|
| `handoff` (OpenAI Agents SDK) | Calls the handoff tool that the SDK offered for that target. The name is read from the SDK's own list |
| `agent_as_tool` found by discovery (an `as_tool` wrapper) | Calls that wrapper tool |
| `agent_as_tool` from the registry's `delegation_tools` | Calls that tool. It must take exactly one string parameter; lockwalk fills it with the fixed text |
| `handoff` or `team`, inside a LangGraph graph | Gives the final answer without a tool call (`pass`). The graph decides its own route |
| `calls` only | Not scripted. The route is `NOT_RUN` |
| The last agent | Calls the tool with the `tool_args` of the resource fixture |

A route that has only a `calls` edge is `NOT_RUN` with this reason, because lockwalk does not
know which tool makes the call and will not guess:
`the call from 'finance-agent' to 'pricing-agent' is declared with calls only, so lockwalk does
not know which tool makes it; list that tool in the registry's delegation_tools, or provide
run_path in the hooks file`.

**Other reasons for NOT_RUN** (shown in the case's door notes and, grouped by reason, in the
warnings; NOT_RUN warns and never fails the gate):

- the tool is not in `SIDE_EFFECTS`, or its resource fixture has no `tool_args`;
- the entry agent is not in the `[[inventory.python]]` targets, or its framework has no
  built-in scripted mode (CrewAI, Agno);
- the agent that should hold the tool does not hold it in the graph;
- a registry `delegation_tools` entry is ambiguous (several tools of one agent call the same
  agent);
- a handoff edge in a framework that cannot script it;
- the route leaves a LangGraph graph (a LangGraph route stays inside the entry graph);
- the route **repeats an agent** (for example the cycle `finance-agent -> trade-agent ->
  finance-agent`). A script gives each agent one step, so such a route is not run, even if the
  hooks file has `run_path`;
- the run ended without reaching the tool: `the scripted run did not reach 'x' (agents whose
  model was asked: ...)`, with the notes the fake models collected (for example `agent 'a' was
  not offered tool 'x'`).

**Frameworks.**

- **Pydantic AI.** Each agent on the route gets a `FunctionModel` through
  `Agent.override(model=...)`, so an agent with no model set works too. Pydantic AI has no
  handoffs; routes go through `agent_as_tool` edges. lockwalk also sets
  `pydantic_ai.models.ALLOW_MODEL_REQUESTS = False`, so an agent that lockwalk did not find
  cannot reach a real model.
- **LangChain / LangGraph.** lockwalk patches the common base class `BaseChatModel`
  (`_generate_with_cache`, `_agenerate_with_cache`, `_should_stream`), so every chat model is
  covered and callbacks still fire. Streaming calls take the normal path. v3 protocol
  streaming is refused (the case is `NOT_RUN`). Every agent's model node is called `agent`, so
  lockwalk finds the current agent from the checkpoint namespace (`langgraph_checkpoint_ns`),
  takes the node names, and puts the entry graph's id in front. That gives the same ids that
  discovery uses (for example `boss:researcher:agent`). If the id cannot be built, or is not
  on the route (an agent that runs inside a tool, for instance), the answer is final and
  the route is `NOT_RUN`. lockwalk never guesses an agent. The graph needs a `messages` input
  (`graph.get_input_jsonschema()`), and it decides its own routes: lockwalk cannot make a
  graph go from one node to another. If langchain-core changes the names lockwalk patches,
  scripted mode says so and the route is `NOT_RUN`.
- **OpenAI Agents SDK.** Every agent on the route gets a fake `Model`. `as_tool` agents run
  with their own fake model. Tracing is turned off (the SDK would send it over the network).
  A fallback model provider answers any agent that lockwalk did not find with a final
  answer. The limit: an agent that lockwalk did not find *and* that already holds a real
  `Model` instance (not `None` or a model name) is not covered by the fallback. The network
  guard is then the only protection.
- **CrewAI, Agno.** No built-in fake model. Give `run_path`.

**`run_path(path, subject, tool, tool_args)`.** If the hooks file has it, lockwalk uses it for
any route that it cannot script itself (CrewAI, Agno, a `calls`-only edge, and so on). lockwalk
enters `set_identity(user)` and calls it with the list of agent ids, the user subject, the tool
name, and the arguments. It may be `async`. Drive the route as your app does, with your own
fake model, and make it call the tool. The whole run counts as the tool's window. If neither
the door nor the side effect was reached, the route is `NOT_RUN`
(`run_path did not reach the door or the tool's side effect`). A route that repeats an agent
is still `NOT_RUN`.

### Judging

A case has two parts: what the IAM said (`PASS`, `FAIL_POLICY`, ...) and what the door did.
The case takes the more severe one: `FAIL_EXECUTION` > `FAIL_POLICY` > `ERROR` >
`INCONCLUSIVE` > `PASS`.

The door is judged against the **IAM's actual answer** for the tool step, not against the
spec. (The spec against the IAM is already judged by the first part.) If the case's identity
is not declared and the IAM's two answers differ, the run is not judged. If the IAM part is an
ERROR, no door test runs for the case.

Each run (a direct call or a scripted run) gets a row of this table. The first row that fits
wins:

| What happened | Result |
|---|---|
| The hooks file is wrong, the arguments do not match the schema, a timeout, a crash, an unreadable door record, or a blocked connection | ERROR |
| IAM **deny**, and the side effect ran (count above 0) | **FAIL_EXECUTION** (with `before the door asked the IAM` when the door was bypassed) |
| IAM deny, 0 calls, `DOOR` set, and the door was never asked | ERROR: the tool failed before it reached the door, so the door was not tested |
| IAM deny, 0 calls, `DOOR` set, and the door **allowed** | **FAIL_EXECUTION**: the door and the IAM disagree. The side effect did not run only because the tool failed for another reason |
| IAM deny, 0 calls, and the door denied (or no `DOOR`) | The door is right, if the tool has a [door control](#the-door-control). Otherwise INCONCLUSIVE |
| IAM **allow**, and the side effect ran | OK. With `DOOR`: **FAIL_EXECUTION** if some call of the side effect had no door call before it (the door was bypassed) |
| IAM allow, 0 calls, no `DOOR` | **FAIL_EXECUTION**. Without `DOOR`, lockwalk cannot tell a door that denied from a tool that failed earlier, so it prefers a false alarm to a false pass. The report adds the exception type, when it is known |
| IAM allow, 0 calls, `DOOR` set, and the door **denied** | **FAIL_EXECUTION**: the door and the IAM disagree. A common cause is a door that is sent the wrong identity |
| IAM allow, 0 calls, `DOOR` set, and the door allowed or was never asked | ERROR: the tool failed for another reason |

Direct and scripted runs use the same table. A case with both gets the more severe result, and
the case row lists the notes of every run that was not OK.

#### The door control

"The side effect ran 0 times" means something only if the counter works. If `SIDE_EFFECTS` has
a wrong path, the real function runs, the counter stays at 0, and a deny looks like a success.

So a tool needs a **door control**: at least one run in this `lockwalk test` (direct or
scripted, any case) in which the tool's side effect was counted above 0. It usually comes from
an "expect allow" case that the IAM allows. Without it, a clean "IAM deny, 0 calls" is
INCONCLUSIVE:

```text
door (direct): no door control: the side effect of 'read_portfolio' was never counted in this run, so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; add a case the IAM allows, with tool_args
```

The gate stops on it by default (`fail_on_inconclusive_case`). A run counts as proof only if it
reached the tool, counted the side effect, and was not blocked by the network guard and had no
unreadable door record. `door_controls` in `coverage.json` lists every tool, with `proven` and
the first run that proved it (`CASE-004 (direct)`). The text output lists the missing ones under
`Door controls missing:`.

#### Identity checks

With `DOOR`, each case that was door tested gets one row in `identity_checks`. It compares
the subject that `read_door_call` reported with the subject lockwalk expected. Only `type` and
`id` are compared, and the same fields of every link in the `act` chain.

- Direct mode expects the identity lockwalk gave to `set_identity`.
- Scripted mode expects the identity that the case declares (`delegation_mode`).
  If the case has no `delegation_mode`, there is nothing to compare, and the result is
  `OBSERVED`: the identity is recorded and the gate is not affected.
- `MATCH` / `MISMATCH`: all door calls of the tool were as expected, or one was not. A
  MISMATCH in either mode makes the row MISMATCH.
- `NOT_RUN`: no `DOOR`, or the door was never called for the tool (the note says which mode).

```text
Identity checks: 2 MISMATCH, 3 MATCH
  MISMATCH  CASE-001: supervisor -> finance-agent -> read_portfolio
    direct: expected agent finance-agent, the door received agent finance-agent
    scripted: expected user alice, the door received agent finance-agent
```

`fail_on_identity_mismatch` (default `true`, in `[gate]`) makes a MISMATCH fail the gate with
`fail_on_identity_mismatch: CASE-001`. FAIL_EXECUTION always fails the gate and cannot be
turned off.

**The observed identity asks the IAM.** Scripted mode runs before the IAM is asked. If it saw
the door receive one identity, the tool step of that case asks the IAM with that identity,
when the case declares no `delegation_mode` or when what was seen differs from the
declaration. The user alone is asked too, as the control for the [escalation
check](#the-escalation-check). The direct runs use the same identity. So a door that sends
the wrong identity can change the IAM part of the case. In the Cedar demo, the handoff that
drops the user makes Cedar deny `finance-agent`, and CASE-001 becomes `FAIL_POLICY` (and the
`CASE-002` deny has no door control, so it is INCONCLUSIVE). The report's `decision.hops[*].mode`
is `observed` for such a step.

#### What the report holds

- `cases[*].door`: `status`, and for each judged run its `mode`, `status`, the `subject`
  lockwalk used, `side_effect_calls`, `door_calls` (reduced subject and decision), the
  `exception` type, and `notes`. A case that was not door tested has `NOT_TESTED` with the
  reason in `notes` (for example `direct: tool 'x' is not in SIDE_EFFECTS`).
- `identity_checks` and `door_controls`, as above.
- In the text output, one line per run under the case: `door (direct): OK, side effect ran 1
  time(s), door saw user alice`.
- Exit codes: any door ERROR makes the exit code 2 (like any ERROR); FAIL_EXECUTION and a
  gate-blocking MISMATCH make it 1.

### Secrets

What door tests keep out of the report, the terminal, and `coverage.json`:

- the app's stdout and stderr, and the worker's;
- tool arguments (`tool_args` values);
- the properties of the subjects that the door and the identity check saw: door-call subjects
  and identity-check subjects are reduced to `type`, `id`, and the act chain. (`runs[*].subject`
  is different: it is the fixture subject that lockwalk itself sent, with its fixture
  properties, the same as `Answer.subject` in the IAM answers.);
- the message of an exception raised by `read_door_call` (only its type name is kept), and the
  host part is all that is kept of a blocked connection (no credentials, no port, no path);
- a door record that has the wrong shape (the report says only that it was unreadable).

What can appear: the type and the message of an exception that your tool raised. The message is
cut to 300 characters, and URL credentials, query strings, and fragments are removed. Unlike
`decide()` exceptions, environment values are not hidden here. Other secrets in plain text
cannot be recognized, so do not put them in exception messages. File
paths, tool names, and agent names can appear too. Keep that in mind before you upload
`coverage.json` as a CI artifact.

The subprocess inherits the environment of the process that runs lockwalk, because your app
needs it. Your app runs with those variables as it always does.

### Limits of door tests

- **Scripted mode support.** Built in for Pydantic AI, LangChain/LangGraph, and the OpenAI
  Agents SDK. For CrewAI and Agno you provide `run_path`. A step that is declared with `calls`
  only cannot be scripted. A LangGraph agent that lockwalk cannot identify (a compiled graph
  with no name, an agent inside a tool) cannot be scripted. A LangGraph graph picks its own
  routes. A route that repeats an agent is not run. v3 protocol streaming is not supported.
- **Direct mode** cannot test what Pydantic AI wraps around a tool. Scripted mode can.
- **Windows:** a child process started before the Job Object assignment is not cleaned up.
- **macOS:** there is no `os.waitid`, so a child left behind by a worker that exited on its own
  may survive.
- **OpenAI Agents SDK:** an undiscovered agent that already holds a real Model instance is not
  covered. Only the network guard remains.
- **LangChain:** only the listed entry points are patched. Model-call paths added in a newer
  langchain-core are not covered, and only the network guard remains.
- **What is not replaced really runs.** Anything a tool does outside `SIDE_EFFECTS` happens,
  in the test environment. Files are not isolated, and there is no isolation on Windows.
- **The reference scan** sees module-level names only. Containers, closures, `partial`, and
  class attributes of other classes are not scanned; a missed one shows up as a missing door
  control.
- **The network guard** works in Python. C extensions, `uvloop`, reverse lookups, unconnected
  UDP on the Windows Proactor loop, and other processes are not stopped.
- **MCP tools** are remote and get no door test.
- **Fake models only.** lockwalk does not test how a real LLM behaves, for example under
  prompt injection. It assumes the worst: the model does call the tool.
- **Size limits.** A run keeps at most 20 door calls for the tool; more than that is reported
  as an error, so a hidden deny cannot slip through. More than 10,000 side effect and door
  calls in one run is an ERROR. A result file above 8 MiB is an ERROR.
- A door that raises something that is not an `Exception` (for example `SystemExit`) is not
  recorded.

## Gate keys and exit codes

The `[gate]` keys that `test` adds, with their defaults:

```toml
[gate]
fail_on_inconclusive_case       = true                     # default
fail_on_escalation              = true                     # default
fail_on_inconclusive_escalation = true                     # default
fail_on_unchecked_escalation    = ["critical", "unknown"]  # default
fail_on_identity_mismatch       = true                     # default; needs door tests
```

A FAIL_POLICY or FAIL_EXECUTION case always fails the gate, and no setting turns that off. The
keys above cover INCONCLUSIVE cases, ESCALATION rows, INCONCLUSIVE rows, UNCHECKED rows of the
listed risks, and identity MISMATCH rows. Routes that scripted mode could not run (NOT_RUN)
and tools without a door test only warn. The keys of [Gate and exit codes](lockwalk-coverage.md#gate-and-exit-codes) still apply, and
so does its exit-code table: exit 2 for any ERROR or configuration error, even when there are
also FAILs.

## Waivers

A waiver accepts a known risk for a limited time. It has an owner and an expiry date. A waived
finding stays in the report, marked `[waived: ID]`, and stops blocking the gate. The rules are in
the [coverage guide](lockwalk-coverage.md#waivers), and a demo is in
[`examples/multi_agent`](../examples/multi_agent/README.md#waivers). `coverage` and `test` both apply the file.

### The file

```yaml
schema_version: '1'
waivers:
  - id: WAIVE-001
    match: {rule: RULE-002}
    reason: market-oracle is a third party; its contract was reviewed by security
    owner: alice@example.com
    expires: 2027-01-31
```

Set it with `--waivers PATH` or `waivers = "PATH"` under `[lockwalk]`. The flag wins. `id`,
`match`, `reason`, `owner` and `expires` are all required. Ids must be unique. An unknown key,
or a date with a time of day, is an error.

### What `match` can say

Exactly one kind, with plain names. There are no wildcards. The gate keys are the violations
the waiver can move.

| `match` | Gate keys it covers |
|---|---|
| `case: CASE-006` | `case`, `fail_on_inconclusive_case` |
| `rule: RULE-002` | `never_reaches` |
| `escalation: {case: CASE-006}` | `fail_on_escalation`, `fail_on_inconclusive_escalation`, `fail_on_unchecked_escalation`, for the row that comes from that case |
| `escalation: {role, tool, via}` | the same three, for a role x tool row (all three names are required) |
| `identity: CASE-006` | `fail_on_identity_mismatch` |
| `role_gap: {role, tool}` | `fail_on_unspecified_role_risk` |
| `tool_gap: TOOL` | `fail_on_unspecified_risk`, `require_deny_case_for_risk` |

An `escalation` takes either `case`, or all of `role`, `tool` and `via`; not a mix.

### Rules

- **A waiver acts on gate violations.** Its violations move from `gate.violations` to
  `gate.waived` in `coverage.json`, and the rows it covers get `waived_by`. The finding's own
  status (for example FAIL_POLICY) does not change. If a waiver covers all violations, the gate
  passes.
- **ERRORs cannot be waived.** An ERROR means the test itself is broken. A configuration error
  cannot be waived either.
- **Expiry.** `expires` is a UTC date, and that day still counts. After it the waiver is
  `expired`: it does nothing, and the finding blocks again.
- **`max_waiver_days`.** `expires` may not be later than today plus `[gate] max_waiver_days`
  (default 90, from 1 to 3650). A later date is a configuration error, exit 2. A date in the
  past is fine.
- **Static mode is quiet about test-only kinds.** `case`, `escalation` and `identity` waivers
  can only match something in `lockwalk test`. In `coverage` an unexpired waiver of these kinds gets no warning (an expired one still warns). Their
  waiver row says `checked only by lockwalk test`, and the text output adds one line
  (`N waiver(s) are checked only by lockwalk test`). `rule`, `role_gap` and `tool_gap` are
  checked in both modes.
- **Each violation is waived once.** If two waivers match the same violation, the first one
  in the file takes it.
- A bad waivers file (empty, not a mapping, a duplicate id, a date too far ahead) stops the
  run with exit 2 before any source is read.

### Statuses and warnings

Each waiver gets a row in `waivers` with one of four statuses. A waiver that needs attention
adds a warning, which is also listed under "Waivers needing attention".

| Status | When | Warning |
|---|---|---|
| `applied` | It moved at least one violation | none |
| `expired` | `expires` is before today | `waiver ID expired on DATE (owner OWNER); X blocks the gate again` when the finding exists, `waiver ID expired on DATE (owner OWNER); its findings are covered by OTHER` when another waiver in the file takes the finding, or `waiver ID expired on DATE (owner OWNER)` when it matches nothing |
| `not_allowed` | The finding it names is an ERROR | `waiver ID matches X, which is ERROR; an ERROR means the test itself is broken and cannot be waived` |
| `unmatched` | It matches no violation | `waiver ID matches nothing in this run; it may be stale (owner OWNER)` |
| `unmatched` | An earlier waiver already took every violation it matches | `waiver ID adds nothing: its findings are already waived by OTHER (owner OWNER)` |
| `unmatched` | A test-only kind, in `coverage` | none; the note says `checked only by lockwalk test` |

X is the case, rule, role/tool or tool the waiver names. `not_allowed` does not change the exit
code: the ERROR already makes it 2. An expired waiver is reported as `expired` first, even if
it names an ERROR finding.

## Summary output

`--summary` prints a short form of the `coverage` and `test` result. The agent tree, the role
x tool table and the full case list are left out. `coverage.json` is complete either way.

The layout:

```text
lockwalk coverage - SUITE
Cases: 5 (UNTESTED 5)
Tools: 5 registered, 2 without a case, 0 high-risk without a deny case
Gate: FAIL (exit 1)

Blocking (2):
  ...
```

- Line 1 names the command (`coverage` or `test`) and the suite. The next lines are counts:
  cases by status, tools, and the gate result with the exit code (`PASS`, `FAIL`, or `ERROR`
  for exit 2).
- Then up to five categories, each only if it has items, in this order: **Errors**,
  **Blocking** (the gate violations), **Waived** (with id, owner and expiry), **Waivers needing
  attention**, **Warnings**.
- A category shows at most 20 lines. More are cut to `... and N more; see coverage.json`. The
  count in the title, `Blocking (25):`, is the real total.
- A warning that a waiver already explains is shown once, under "Waivers needing attention".
- The test-only waiver line is shown right after the Waived category (with no title of its own
  if nothing is waived).
- **Error grouping.** Errors that differ only in their leading id are one line. If the IAM is
  down, every case has the same error. The summary then shows
  `- MESSAGE (300 cases: CASE-001, CASE-002, CASE-003, +297 more)`. Other errors keep one line
  each, in the order they happened.

## IAM recipes

`lockwalk test` asks your IAM through AuthZEN or a `decide()` function you write.
[`examples/recipes`](../examples/recipes/README.md) has `decide()` examples for common engines.
They are starting points: copy one, change it to your policy, and point `[policy]` at it.

| Engine | Where | Tested how |
|---|---|---|
| OPA | [`opa/`](../examples/recipes/README.md#the-table) | Fake server, and the real image in Docker |
| Casbin | [`casbin/`](../examples/recipes/README.md#the-table) | Real pycasbin, in process |
| OpenFGA | [`openfga/`](../examples/recipes/README.md#the-table) | Fake local server only |
| Keycloak Authorization Services | [`keycloak/`](../examples/recipes/README.md#the-table) | Fake local server only |
| Amazon Verified Permissions, AWS IAM policy simulator, GCP Policy Troubleshooter | [`CLOUD.md`](../examples/recipes/CLOUD.md) | Fake clients only |

No recipe has been run against a live OpenFGA, Keycloak, AWS or Google account. Try each on
a known allow and a known deny first. Azure has no recipe (see `CLOUD.md`).

**Proxies.** The HTTP recipes use Python's standard library, which honours the `HTTP_PROXY`
and `HTTPS_PROXY` environment variables. A proxy then sees the request, including a bearer
token. For a local PDP, set `NO_PROXY=127.0.0.1`. Use `https` for remote servers.

## Examples

- [`examples/iam_cedar`](../examples/iam_cedar/README.md): a local Cedar engine, asked
  through `decide()`. No Docker needed.
- [`examples/iam_cerbos`](../examples/iam_cerbos/README.md): a Cerbos PDP in Docker, asked
  through AuthZEN.
- [`examples/multi_agent`](../examples/multi_agent/README.md): the agents, spec, and fixtures
  that both use.

Their policies give the same answers, and each has a deliberate hole. They show a FAIL_POLICY,
an ESCALATION, and an INCONCLUSIVE once the "expect allow" cases are removed.

The Cedar example also runs [door tests](#door-tests) against a small demo door, with two
switches that break the door on purpose. They show a FAIL_EXECUTION (a tool that skips the
door) and a MISMATCH (a handoff that drops the user). See
[The door demo](../examples/iam_cedar/README.md#the-door-demo). The Cerbos example has no
`[harness]`.

## Evidence and lockwalk inspect

Every `lockwalk test` run writes `.lockwalk/evidence.jsonl` next to `coverage.json`. Each
line is one event, in time order:

| Event | From | What it records |
|---|---|---|
| `run.started` | the test runner | lockwalk version, adapter label, start time |
| `run.finished` | the test runner | exit code, number of cases |
| `authz.evaluated` | the adapter | one distinct question (`Q-0001`), the request sent, the answer, the time it took, the IAM's reason |
| `harness.job` | the door harness | one door run (`I-0001`): mode, tool, argument names (never values), result, duration |
| `door.identity_set` | the door harness | the identity lockwalk set for the run |
| `door.called` | the door harness | the identity the door received, and its answer |
| `effect.counted` | the door harness | a side effect function was called |
| `tool.raised`, `run.error` | the door harness | the exception type, or why the run is ERROR |

The first line is a header with the run id and the number of events. `coverage.json` has
the same `run_id`, and every case, escalation, identity check, control, and door control row
lists the events it was judged from in `evidence`. `lockwalk coverage` writes no evidence and
removes an old evidence file, so the two files always come from the same run.

A failure to build or write the evidence never loses the report. The report then gets a
warning, has no `run_id` and no `evidence` refs, and no evidence file is written.

`lockwalk inspect --case CASE-003` reads both files and prints the case's spec, its result
and why, its timeline, the related control, escalation, identity, and door control rows, and
any gaps (no door test, scripted mode not run, no positive control). It runs nothing. If
`coverage.json` comes from `lockwalk coverage`, there is no evidence, and inspect shows a gap
that tells you to run `lockwalk test`.

Limits of the output: the timeline shows at most 200 events per case, each door run keeps at
most 200 moments, and values are cut to 200 characters on screen. The two timeline limits are
listed under gaps ("N more events are not shown", "N more door or side effect moments were not
kept"); a value cut to 200 characters just ends in `...`. A string longer than 512 characters
is handled by kind of moment: a door call is recorded as unreadable ("door call unreadable");
an identity moment is not kept and counts toward the "not kept" gap; a side effect's tool name
is cut to 512 characters. Each event in `evidence.jsonl` has a size limit as well: if its
detail would make the line longer than 1 MiB, the event keeps only an error note ("the detail
was too large to keep"), so the file stays readable.

Exit codes of `lockwalk inspect`: 0 when it showed the case (even if the case is FAIL); 2 when
`--case` is missing, when `coverage.json` is missing, when the case does not exist (it suggests close ids), when the
evidence file is from another run, or when it is cut off or invalid.

What evidence.jsonl keeps as sent: the request in `authz.evaluated`, including subject and
resource properties and context, with URLs cleaned. In every string, each URL has its
credentials, query and fragment removed, so a URL value may differ from what the IAM
received; a malformed URL becomes `<invalid URL>`. Keys are cleaned the same way. These come
from your fixtures, which should hold fake identities and resources. Door and job events keep only the
type, id and act chain of a subject.

What evidence.jsonl does not hold: tool argument values, raw IAM responses, header values,
environment values, subprocess output. URL credentials are masked. Retries inside an
adapter are not separate events. The file is not a tamper-proof audit log.
