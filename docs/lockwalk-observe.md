# lockwalk observe: the full guide

`lockwalk observe` reads traces from a real environment (a staging system, a test run, an
export from your tracing tool) and compares what the agents really did with the map that
`lockwalk coverage` draws. This guide says what it checks, how a door (an authorization point)
leaves records in a trace, how to get a trace file out of each tracing setup, how spans are
recognized, and what it cannot tell you.

Contents:

1. [What was verified](#what-was-verified)
2. [What observe checks](#what-observe-checks)
3. [Try it on the demo](#try-it-on-the-demo)
4. [Door records and effect markers](#door-records-and-effect-markers)
5. [Which tool call a record belongs to](#which-tool-call-a-record-belongs-to)
6. [Identity checks](#identity-checks)
7. [Guard statuses](#guard-statuses)
8. [Untested paths](#untested-paths)
9. [Waivers and --summary](#waivers-and---summary)
10. [Get traces out of your system](#get-traces-out-of-your-system)
11. [How spans are recognized and named](#how-spans-are-recognized-and-named)
12. [Reader function](#reader-function)
13. [Limits and errors](#limits-and-errors)
14. [observe.json](#observejson)
15. [Gate keys and exit codes](#gate-keys-and-exit-codes)
16. [lockwalk inspect](#lockwalk-inspect)
17. [What observe cannot tell you](#what-observe-cannot-tell-you)

## What was verified

Read this before you trust a setup snippet below.

- **Real files:** OpenTelemetry Collector 0.165.0 (file exporter) and Jaeger 2.23.0 were run
  for real, in a test run and in the Docker test (`tests/test_observe_collector_docker.py`). The
  files they wrote were read by observe.
- **Span shapes from recorded test runs, not from a running setup:** Pydantic AI, OpenAI Agents SDK with
  OpenInference 2.7.1, Logfire 5.5, LangGraph with OpenInference 0.1.82, and LangGraph with
  LangSmith 0.14.17. The span shapes come from test runs that used fake models and an in-memory
  exporter. The fixture files in `tests/observe_data/` are that output. The setup snippets as
  written here (exporters, instrument calls, environment variables) were **not** run end to end
  in this release. Treat them as a starting point and check the first trace you export with
  `lockwalk observe` and `lockwalk inspect --trace`.
- **Door records:** the seven demo traces in `examples/multi_agent/traces/` are hand-written.
  `record_authz` and `record_effect` were run with the OpenTelemetry SDK and an in-memory
  exporter, and their spans are read by observe in tests. No agent framework was run end to
  end with them.
- **Langfuse:** the two rules load and match hand-made attributes in unit tests. No Langfuse
  span was exported to a file.

## What observe checks

Every trace is rebuilt into a tree of agent visits and tool calls. Each observed link is
compared with the map (the agent graph and the tool list from `discover`, plus your
`registry.yaml`).

| Link | On the map when |
|---|---|
| `user -> agent` (the agent at the top of a trace) | the agent is an entry agent |
| `agent -> agent` | the graph has a link between the two, of any kind (`handoff`, `agent_as_tool`, `calls`, ...) |
| `agent -> tool` | the graph has the agent using that tool directly |

Results:

- **ON_MAP**: counted only.
- **OFF_MAP**: the link is not on the map. The map was missing a route, so reachability and
  escalation analysis never looked at it. Each row has a one-line suggested declaration, for
  example `declare the call: add trade-agent to 'calls' of agent supervisor in registry.yaml`.
- **UNKNOWN**: a name in the trace matches no agent or tool (agent, tool), or a tool ran with
  no agent above it (caller). A link with an unknown end is not also reported as OFF_MAP.

Rows are grouped: every observation with the same cause is one row with a count and example
trace ids (the terminal shows the first; `observe.json` keeps up to three). The report also has totals (files, traces, spans, agent spans, tool
calls, incomplete traces) and the time range of the spans, in UTC. There are no scores or
percentages.

Door records (what the door sent to the IAM) add three more checks, described in their own
sections:

- **Identity:** was the IAM asked with the identity the agent's `delegation_mode` says it
  should use ([Identity checks](#identity-checks)): MATCH, MISMATCH, OBSERVED, INCONCLUSIVE.
- **Guard:** did every tool call have a door record, and was a denial respected
  ([Guard statuses](#guard-statuses)): GUARDED, DENIED, DENIED_UNVERIFIED, BYPASS, UNGUARDED,
  INCONCLUSIVE.
- **Untested paths:** does a case in your spec test the real path
  ([Untested paths](#untested-paths)): TESTED, TESTED_OTHER_PATH, UNTESTED.

Findings can be accepted with [waivers](#waivers-and---summary), and `--summary` prints a short
form. Read [Door records and effect markers](#door-records-and-effect-markers) first: **with no
door records in the traces, every call of a HIGH, CRITICAL or UNKNOWN risk tool is UNGUARDED,
and the run exits 1.**

## Try it on the demo

`examples/multi_agent/traces/` has seven small hand-written trace files for the demo app (see
the [demo README](../examples/multi_agent/README.md#watch-real-traffic)). One of them:

```bash
cd examples/multi_agent
uv run lockwalk observe --traces traces/off_map.jsonl    # exit 1
```

```text
lockwalk observe - multi-agent-demo-v1
Sources:      traces/off_map.jsonl
Read:         1 trace, 5 spans (2 agent spans, 1 tool call)
Door records: 1 (1 tool call(s) have one; 0 not tied to a tool call, 0 linked by time)
Window:       2026-11-08T02:35:44Z .. 2026-11-08T02:35:44Z
----------------------------------------
Routes not on the map (OFF_MAP):
  supervisor -> trade-agent (agent)  1 time(s), e.g. trace c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3
    fix: declare the call: add trade-agent to 'calls' of agent supervisor in registry.yaml
Routes on the map (ON_MAP): 2
Identity: 1 MATCH
Guarded calls: 1 GUARDED
Tested paths: 1 TESTED_OTHER_PATH
----------------------------------------
Gate: FAIL (exit 1) - 1 violation(s)
```

Each of the seven files shows one thing (all with the demo's `.lockwalk.toml`; run them from
`examples/multi_agent`):

| File | What it shows | Exit |
|---|---|---|
| `ok.jsonl` | Two traces, everything on the map: 9 routes ON_MAP, identity MATCH, GUARDED. `get_quote` has no door record and no case, but it is low risk, so UNGUARDED and UNTESTED are shown and do not block | 0 |
| `off_map.jsonl` | `supervisor` calls `trade-agent`, which is not on the map: OFF_MAP | 1 |
| `unknown.jsonl` | `supervisor` calls `refund-agent`, which is not in the app: UNKNOWN agent | 1 |
| `mismatch.jsonl` | `trade-agent` uses its own identity (`delegation_mode: agent`), but the door asked the IAM about the user: identity MISMATCH | 1 |
| `unguarded.jsonl` | `read_portfolio` (high risk) ran with no door record, and an effect marker: UNGUARDED | 1 |
| `bypass.jsonl` | The door denied `execute_trade` and the work was done anyway: BYPASS | 1 |
| `untested.jsonl` | `confirm_price` was called on a path no case tests: UNTESTED | 1 |

The demo's `.lockwalk.toml` widens `fail_on_untested_path` to `["medium", "high", "critical",
"unknown"]` (the default is critical and unknown), so that `confirm_price` (medium risk)
blocks. `waivers-observe.yaml` waives the finding of `untested.jsonl`, `unguarded.jsonl` and
`mismatch.jsonl`, and not the BYPASS (see [waivers](#waivers-and---summary)).

```bash
uv run lockwalk observe --traces traces/bypass.jsonl     # exit 1
```

```text
lockwalk observe - multi-agent-demo-v1
Sources:      traces/bypass.jsonl
Read:         1 trace, 5 spans (2 agent spans, 1 tool call)
Door records: 1 (1 tool call(s) have one; 0 not tied to a tool call, 0 linked by time)
Window:       2026-11-08T02:35:44Z .. 2026-11-08T02:35:44Z
----------------------------------------
Tool calls without a working door (BYPASS / UNGUARDED / INCONCLUSIVE):
  trade-agent / execute_trade: BYPASS 1
    e.g. trace a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7
Routes on the map (ON_MAP): 3
Identity: 1 MATCH
Tested paths: 1 TESTED
----------------------------------------
Gate: FAIL (exit 1) - 1 violation(s)
```

Here the door recorded `deny`, and an effect marker under the same tool call says the work ran.
Take the door record away (the same trace without its `lockwalk.door` span; the effect marker
stays) and the same call is UNGUARDED, and the row says that the effect had no record:

```text
Tool calls without a working door (BYPASS / UNGUARDED / INCONCLUSIVE):
  trade-agent / execute_trade: UNGUARDED 1
    effect without record 1, e.g. trace a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7
```

The `Door records:` line appears when the traces hold at least one door record. It gives the
number of records, how many tool calls have one, how many records belong to no tool call, and
how many were linked by time. It is also in `--summary`.

If you ran `lockwalk coverage` in the same folder, every `observe` run adds the warning `the
test report comes from lockwalk coverage; run lockwalk test for the side-by-side`. That is
expected and harmless: only `lockwalk test` writes the report the side by side needs.

`observe` needs the same inputs as `coverage` (registry, spec, and the inventory sources in
`.lockwalk.toml`), because the map is what the traces are compared with. If the map has
errors, observe reports them and exits 2. It writes `.lockwalk/observe.json` (or into
`--output-dir`).

`--traces` takes a file or a folder, and can be repeated. A folder is read without going into
sub-folders, in file name order. Files with another extension in a folder are skipped with a
warning; a file with another extension named directly is an error. Files are `.json` (one OTLP
document), `.jsonl` (one OTLP document per line), or either with `.gz` added (compressed by
you). Relative `--traces` paths count from the current directory. `[observe] traces` in
`.lockwalk.toml` is the default list; its paths count from the config file's folder. A
`--traces` on the command line replaces that list.

## Door records and effect markers

A door is the code that asks your IAM before a tool runs. For observe to judge it, the door
leaves a short record in the trace, and the function that really does the work leaves a marker.
Nothing is checked about doors until they leave records.

There are three ways to get records into a trace: the door sets the attributes itself, it calls
`lockwalk.record` (see below), or you describe existing spans with `door` and `effect` rules in
`.lockwalk.toml` (see [Door and effect rules](#door-and-effect-rules)). A rule-made record has
no subject, so it counts for guard checks only.

**What changes for you.** With no door records in the traces, observe cannot tell a guarded
tool call from an unguarded one. Every call of a tool with HIGH, CRITICAL or UNKNOWN risk is
then UNGUARDED, and the run exits 1 (`fail_on_unguarded_call` defaults to `["high",
"critical", "unknown"]`). Untested real paths of CRITICAL or UNKNOWN tools also block
(`fail_on_untested_path`). Decide what you want before you add observe to a pipeline:

```toml
[gate]
fail_on_unguarded_call = []      # route checks only: do not judge doors
fail_on_untested_path = []       # do not judge untested paths
```

BYPASS (a denied call that still ran) always blocks and has no key. A waiver can accept it
(see [waivers](#waivers-and---summary)).

### The attributes

OpenTelemetry has no standard for authorization, so lockwalk defines these attributes. The
door opens its own short span and sets them on it. (The names have no "auth" in them on
purpose: Logfire scrubs attribute names that contain it.)

| Attribute | Content | Required |
|---|---|---|
| `lockwalk.door.decision` | `allow`, `deny` or `error` | yes |
| `lockwalk.door.subject.type` | The kind of subject really sent to the IAM, for example `user` or `agent` | yes |
| `lockwalk.door.subject.id` | The id really sent. It may be a hash: lockwalk only compares it | yes |
| `lockwalk.door.action` | For example `trade:execute` | yes |
| `lockwalk.door.act` | The act (delegation) chain as a JSON string of nested `{"type", "id", "act"}` objects, outermost first | when acting for someone |
| `lockwalk.door.resource.type` | For example `order` | no |
| `lockwalk.door.tool_call_id` | The id of this tool call, when you have it | no |
| `lockwalk.effect` | The boolean `true`, set by the function that does the work (on a span of its own) | no |
| `user.id` (or the older `enduser.id`) | Who the run is for; read from the span of the record, then upward | for user checks |

You do not need to import lockwalk for this: open a span with OpenTelemetry and set the
attributes. Every `error` decision counts as a denial (a door must fail closed).

### record_authz and record_effect

`lockwalk.record` writes the attributes for you, so the names cannot be mistyped:

```bash
pip install 'lockwalk[otel]'
```

```python
from lockwalk.record import record_authz, record_effect


def execute_trade(order):
    decision = ask_the_iam(subject, "trade:execute", order)      # your code
    record_authz(
        subject=subject,                  # {"type": ..., "id": ..., "properties": {...}}
        action="trade:execute",
        resource={"type": "order", "id": order.id},
        decision="allow" if decision.allowed else "deny",
        tool_call_id=None,                # optional
    )
    if not decision.allowed:
        raise PermissionError("denied")
    record_effect()                       # inside the function that really does the work
    ...
```

Each call opens a short span (`lockwalk.door` and `lockwalk.effect`) under the current span,
using the global TracerProvider. lockwalk never creates a TracerProvider or changes yours.

- **Without OpenTelemetry** both functions check their arguments and then do nothing. A missing
  OpenTelemetry is remembered for the process, so it is not looked for again on every call.
- **Argument errors raise `ValueError` or `TypeError` at the first call**, so a coding mistake
  shows up in development and not in production traffic. They are: an empty string; any text
  longer than 512 characters (subject type and id, action, resource type, `tool_call_id`, and
  the type and id of every act link); text that is not valid text; a `decision` that is not
  `allow`, `deny` or `error`; and an act chain whose JSON is over 64 KiB (measured in UTF-8
  bytes). The messages name the argument, never the value.
- **An act chain of more than 64 links raises `ValueError`** (`act has more than 64 links`),
  like the other limits; so does a chain that loops back on itself. The chain is read from
  `subject["properties"]["act"]`, or else `subject["act"]`.
- **What is written:** the subject's type and id, the act chain (type and id of each link),
  the action, the resource type, the decision and the tool call id. **Never written:** the
  subject's `properties` (roles and the like), the resource id, and anything else.
- `import lockwalk.record` loads no other part of lockwalk.

### How records are read

Each span holds at most one door record. These rules decide what counts:

- **A partial or malformed door record is a read problem (exit 2), and the record is ignored.**
  This covers a missing required attribute, a `decision` that is not `allow`, `deny` or
  `error`, a text that is empty or over 512 characters, and an act that is not valid JSON, is
  not nested `{type, id, act}` objects, is nested more than 64 levels, repeats a key or is
  larger than 64 KiB. The message names the attribute key and never the value, for example
  `door record: lockwalk.door.subject.id is missing` or `door record: lockwalk.door.decision
  must be allow, deny or error`. An ignored record is not counted as a record, so its tool call
  looks unguarded.
- **`lockwalk.effect` counts only when it is the boolean `true`.** `false` means no marker.
  Any other value (the string `"true"`, a number) is a read problem
  (`effect marker: lockwalk.effect must be a boolean`, exit 2).
- **The user id** is `user.id`, and if that is absent or malformed, `enduser.id`. A malformed
  value (not a string, empty, over 512 characters) counts as absent. The nearest id at or
  above the record's span is used. If two different ids are found on the way up, the nearest
  wins, the row gets a note, and the run gets a warning (see below). Ids are compared, never
  shown.
- **`[observe.attributes]` replaces the default key, it does not add one.** If your door
  already writes its own attributes, map the lockwalk key to yours:

  ```toml
  [observe.attributes]
  "lockwalk.door.decision" = "authz.result"
  "lockwalk.door.subject.id" = "authz.principal"
  "user.id" = "app.user_id"
  ```

  The left side may be a `lockwalk.door.*` attribute, `lockwalk.effect` or `user.id`; another
  name is a config error. A target may not be an attribute lockwalk already reads with its own
  meaning, and two keys may not share a target. The values must still have lockwalk's form: a
  decision is still `allow`, `deny` or `error`, and a decision under `authz.result` is read
  only from there. Translating values belongs in a [reader function](#reader-function).
  `enduser.id` is always the fallback for the user id.

Reader functions give the same information through the `authz`, `effect`, `user_id` and
`tool_call_id` fields (see the [table](#reader-function)). An `authz` item becomes a child span
`<span_id>#door<n>` (n from 1) with the same times as its record, so a reader `span_id` and `parent_id` may not
contain `#`.

### Door and effect rules

Some systems record an authorization decision, or the fact that a function really ran, in
spans that have no `lockwalk.door.*` attributes. Two more kinds of `[[observe.rules]]` turn
such spans into door records and effect markers, without changing the app. They work with any
tracing tool. The `when` table matches as described in
[Langfuse and Logfire: rules](#langfuse-and-logfire-rules). The example is generic: an approval
span holds the decision, and the tool span holds the outcome.

```toml
[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "app.granted" = true }
decision = "allow"
tool_call_id = "gen_ai.tool.call.id"

[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "app.granted" = false }
decision = "deny"
tool_call_id = "gen_ai.tool.call.id"

[[observe.rules]]
kind = "effect"
when = { "app.outcome" = "completed" }
```

`app.granted` and `app.outcome` are placeholders. To find the real names, open one trace file
and look at the span that records the approval, or run
[`lockwalk inspect --trace`](#inspect---trace) and see which spans show as other. The
attributes in `when` must be on the exported span itself.

A record made by a rule is a **decision-only record**. It says that a decision was made
(`allow`, `deny` or `error`), and for which tool call if the id is known. It cannot say whom
the decision was for, so it has no subject (the user or agent the decision was made for), no
act chain, no action and no resource type. So:

- It counts for [guard statuses](#guard-statuses) as it is: `allow` makes a call GUARDED,
  `deny` and `error` make it denied (DENIED, DENIED_UNVERIFIED or BYPASS).
- It is not an identity row, and the run gets one warning (see
  [warnings from linking](#warnings-from-linking)). These records are not counted in the "no
  known calling agent" warning.
- Records made with `lockwalk.door.*` attributes, a reader function's `authz` items or
  `record_authz` always need a subject and an action.
- `inspect --trace` shows it as `<decision> (decision only, no subject)`, for example `door:
  deny (decision only, no subject) (linked by tool call id)`.
- The attributes that rules read, including the `tool_call_id` source, are added to the kept
  attributes (see [limits and errors](#limits-and-errors)).
- Rule-made records appear in `observe.json` in the existing format.

Which fields each kind takes (the `agent`, `tool` and `handoff` kinds are described in
[Langfuse and Logfire: rules](#langfuse-and-logfire-rules)):

| Field | `door` | `effect` | `agent`, `tool`, `handoff` |
|---|---|---|---|
| `when` | required | required | required |
| `decision` | required (`allow`, `deny` or `error`) | not allowed | not allowed |
| `tool_call_id` | optional: an attribute name, never `span.name` | not allowed | not allowed |
| `name`, `from`, `to` | not allowed | not allowed | `agent` and `tool`: `name`. `handoff`: `from` and `to`. Others not allowed |

The first matching `door` rule, in file order, wins. Any matching `effect` rule counts.

**Security note: keep `allow` rules narrow.** An allow record is what makes a tool call
GUARDED. A broad `when`, such as a common span name alone, would mark unrelated spans as
allowed doors and hide real UNGUARDED calls. Match on what only the approval or authorization
span carries, as the example does with `gen_ai.operation.name = "approval"` plus the decision
attribute.

**The span's own markers win.** A `door` rule applies only when none of the span's door
attributes (after `[observe.attributes]`) is present. A malformed record of the span's own
stays a read problem, and no rule replaces it. An `effect` rule applies only when the span has
no `lockwalk.effect` attribute: `false` stays `false`.

A rule does not change what kind of span it is. An approval span is still "other" in the
report, and a tool span can also carry a rule-made door record.

The `tool_call_id` value is read as text. If it is absent, empty or malformed, the record has
no tool call id and still counts. Linking then falls back to the
[other ways](#which-tool-call-a-record-belongs-to).

## Which tool call a record belongs to

The tracing tool does not always make the tool span the "current" span while the tool runs
(LangChain and LangGraph do not), so a door record is often not below its tool call. Observe
links each record and each effect marker to a tool call in this order; the first rule that
applies wins:

1. **Ancestry:** the record's span is a tool call, or below one. A tool call above an agent
   does not count for a record inside that agent: the agent is a different caller, so a door
   in a sub-agent is never credited to the tool call that started the sub-agent. (An agent
   span that only repeats the agent above it is the same visit and keeps the call.)
2. **Tool call id:** the record has `lockwalk.door.tool_call_id`, and exactly one tool span in
   the trace has the same `gen_ai.tool.call.id`. (Effect markers have no such id.)
3. **Covers tools:** the record's span has a tool call below it (for example the attributes
   were set on the span that wraps the whole run). The record is not tied to any call and is
   never linked by time, because its span is too wide.
4. **Time:** the tool calls whose time range contains the start of the record. A record
   inside a sub-agent that sits below a tool call looks only at the calls of its own agent;
   a call of the agent above is never a candidate, even when its time range contains the
   record.
   - exactly one: it is that call. The report counts it as "linked by time".
   - two or more (tools running at the same time): the record is **ambiguous**. It is not given
     to any call, and the calls that were running become INCONCLUSIVE instead of UNGUARDED.
   - none: the record belongs to no tool call. A record with no start time is never linked by
     time.

A tool call with a missing start, a missing end, or an end before its start counts as open for
time linking. Its records become ambiguous (INCONCLUSIVE) instead of
being given to another call, which would make that call look guarded.

Only real tool calls take part; an agent-as-tool wrapper is not a call.

A record that belongs to no tool call is still an identity row (with no tool) when a calling
agent is known: the first agent above it. If there is none, it is not an identity row and is
counted in a warning (a record with no subject is the exception: see
[Door and effect rules](#door-and-effect-rules)).

### Warnings from linking

These warnings count records and never show an id:

- `N door records sit on spans that contain tool calls; record them with
  lockwalk.record.record_authz or a span of their own`
- `N effect markers sit on spans that contain tool calls, so they are not tied to a tool call`
  (when both apply, they are one warning, joined with `. `)
- `N door records saw two different user ids; the nearest one was used`
- `N door records have no known calling agent, so they are not identity rows (see
  docs/lockwalk-observe.md)`
- `N door records have no subject (for example a person's approval); they count for guard
  checks only`

## Identity checks

For each door record, observe takes the calling agent's `delegation_mode` from the registry and
works out the identity the record should have (the same rules as `lockwalk test`):

| Mode | Expected |
|---|---|
| `user` | the subject is the user of the trace, with no act chain |
| `agent` | the subject is the calling agent itself, with no act chain |
| `on_behalf_of` | the subject is the user of the trace, and the act chain starts with the calling agent and goes back along the path to the entry agent |
| not declared | nothing to compare: the row is OBSERVED and never blocks |

| Result | When |
|---|---|
| MATCH | same as expected |
| MISMATCH | different from expected. A wrong subject type is a MISMATCH even if the user id is missing |
| OBSERVED | no mode declared |
| INCONCLUSIVE | the user is expected but the trace has no user id; an `on_behalf_of` chain cannot be compared because the path is incomplete; or the record cannot be tied to one tool call |

An unknown calling agent gets no identity row (its call is UNKNOWN). Decision-only records
(made by [door rules](#door-and-effect-rules)) have no subject and are not identity rows
either. Subject ids are compared exactly as written. An alias from `[observe.agents]` is not applied to a subject id.

**Shown forms.** The report never shows a user id. A subject is shown as `the trace's user`,
`another user` or `a user (cannot compare)`; an agent in your inventory as `agent:<id>`; anything
else as `<type>:hidden`. An act chain is shown as `acting through a < b`, with `?` for a link
that is not a known agent.

**Rows.** Records are grouped by (path, tool, mode, expected, observed, result), with a count
and up to three example trace ids. If the user ids conflict, the row says "the trace holds two
different user ids; the nearest one is used".

**A record that is ambiguous in time** has no tool in its row. If all candidate calls share
one agent and path, it is judged under that agent as usual. If they differ, it is INCONCLUSIVE
with the expected text `cannot be tied to one tool call`, and it is shown under the path of
the first candidate whose agent is known.

**Side by side with `lockwalk test`.** If `lockwalk test` left a report, a row shows the
results of the cases with the same path and tool (`test: CASE-003 direct: MATCH`; at most
ten lines, then one line `... and N more`). The report is `[observe] test_report`, by default `.lockwalk/coverage.json`
counted from the config file's folder. A missing file is ignored. A file that cannot be read
gives a warning. A report from `lockwalk coverage` (static) gives the warning `the test report
comes from lockwalk coverage; run lockwalk test for the side-by-side`. When the real result is
MISMATCH and every test check for that path and tool is MATCH, the row adds `the test
environment and the real environment behave differently`. The side by side is information; it
never changes a result.

## Guard statuses

Per tool call, grouped by (calling agent, tool):

| Status | When |
|---|---|
| GUARDED | a linked record, and every linked record is `allow` |
| DENIED | a linked `deny` or `error`, no effect marker, and an effect marker for this tool was seen somewhere in the run |
| DENIED_UNVERIFIED | the same, but no effect marker was ever seen for this tool. Observe cannot tell that markers are used at all, so it cannot know the denial held. It is a note, not a gate finding: it is listed under Notes in the full report and under Warnings in `--summary` |
| BYPASS | a linked `deny` or `error` and a linked effect marker: denied, and the work was done anyway. Always blocks |
| UNGUARDED | no linked record. If the call has an effect marker the row says `effect without record N` |
| INCONCLUSIVE | the call cannot be judged: a record or an effect marker that cannot be tied to one call may belong to it |

A denied call with no linked effect marker is INCONCLUSIVE when an ambiguous effect marker was
running at the same time (it may be the proof the call ran). A call that has no linked record
is INCONCLUSIVE rather than UNGUARDED when an ambiguous door record may belong to it. When a
call has several records, one `deny` or `error` makes it denied.

UNGUARDED blocks only for the risk levels in `fail_on_unguarded_call`; a low-risk read tool
is usually not guarded on purpose. The risk comes from the registry through the tool text as
it is shown (see [limits](#what-observe-cannot-tell-you)). INCONCLUSIVE blocks with
`fail_on_inconclusive_observation`.

## Untested paths

Every real combination of (path, tool) is compared with the cases in your spec. A `path:` case
is that path; an `agent:` case is a path of one agent.

| Status | When |
|---|---|
| TESTED | a case tests this tool on exactly this path |
| TESTED_OTHER_PATH | a case tests the same calling agent and tool, but on another path (or the real path is incomplete). Information only |
| UNTESTED | no case tests this calling agent with this tool |

Only calls with a known agent and a known tool are checked. An incomplete path is compared on
the calling agent and the tool only. UNTESTED blocks for the risk levels in
`fail_on_untested_path` (default CRITICAL and UNKNOWN).

## Waivers and --summary

Waivers work as in `coverage` and `test` (owner, reason and an expiry date at most
`max_waiver_days` away; see the [coverage guide](lockwalk-coverage.md#waivers)), with five more kinds of
`match` that only `observe` checks. Use the file with `--waivers`, or `waivers = "..."` under
`[lockwalk]`. A waivers file is read before any trace, and a bad one is a config error
(exit 2).

| `match` | Covers |
|---|---|
| `route: {from: supervisor, to: trade-agent}` | an OFF_MAP route (`from` can be `user`) |
| `unknown: {kind: agent, name: "Helper Bot"}` | an UNKNOWN name; `kind` is `agent`, `tool` or `caller` (for `caller`, `name` is the tool) |
| `unguarded: {agent: finance-agent, tool: read_portfolio}` | UNGUARDED, BYPASS and guard INCONCLUSIVE of that agent and tool. `agent: "(none)"` is a call with no calling agent |
| `observed_identity: {path: [trade-desk, trade-agent], tool: execute_trade}` | MISMATCH and INCONCLUSIVE identity rows. `tool: null` for records with no tool |
| `untested_path: {path: [trade-desk, trade-agent], tool: confirm_price}` | UNTESTED rows |

- **One key is one finding.** `match` can only say the key, so all
  blocking findings with one key are covered by one waiver: a MISMATCH row and an INCONCLUSIVE
  row of one path and tool, or UNGUARDED and BYPASS of one agent and tool.
- **A `[waived: ID]` mark appears only on the rows that were waived.** A row with the same key that did not block
  (a MATCH row, say) is not marked.
- **BYPASS can be waived.** The `unguarded` kind covers it. That is your decision to make and
  lockwalk does not recommend it; the demo file leaves BYPASS out on purpose.
- **Silent notes.** A waiver of a kind that another command checks is not an alarm, in both
  directions, so one waivers file can serve all three commands. In `observe` a `coverage` or
  `test` waiver (`case`, `rule`, `escalation`, `identity`, `role_gap`, `tool_gap`) gives one
  line, `N waiver(s) are checked only by lockwalk coverage or lockwalk test`. In `coverage` and
  `test` the five kinds above give one line, `N waiver(s) are checked only by lockwalk
  observe`. The row in the report is `unmatched` with that note, and there is no warning.
- A waiver of a kind the running command does not check stays silent even when it has
  expired. Only the kinds the command checks warn when they match nothing or have expired, as
  in `coverage`.
- **Paths are matched exactly.** `path` is the list of agents from the entry agent to the
  calling agent (no `user`), with no wildcards. A path with an unknown step is written with
  `?`, and `?` matches only that marker. `tool` is also matched exactly.
- **`inspect --trace` does not load waivers**, so a bad waivers file cannot block it.

On the demo, `uv run lockwalk coverage --waivers waivers-observe.yaml` ends with the quiet line

```text
  3 waiver(s) are checked only by lockwalk observe
```

and lists nothing under "Waivers needing attention".

`--summary` prints the short form: the totals, the counts of every status, and then the
categories Errors, Blocking, Waived, Waivers needing attention and Warnings (at most 20 lines
each; `observe.json` has everything). The full report lists only the findings, and the OK
statuses as counts.

## Get traces out of your system

observe reads OTLP JSON. The same trace can be spread over several files and lines; lockwalk
collects all spans first and then builds each trace.

### OpenTelemetry Collector

Use the `file` exporter with `format: json` (the default) and no compression. This is a
complete minimal config. It is the config the Docker test uses with
`otel/opentelemetry-collector-contrib:0.165.0`, and the files that test wrote are real
Collector output:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: /out/traces.jsonl
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
```

```bash
mkdir -p out && chmod 777 out    # Linux: the image runs as uid 10001
docker run -d --name collector --user "$(id -u):$(id -g)" -p 127.0.0.1:4318:4318 \
  -v "$PWD/collector.yaml:/etc/otelcol/config.yaml:ro" -v "$PWD/out:/out" \
  otel/opentelemetry-collector-contrib:0.165.0 --config /etc/otelcol/config.yaml
```

`--user` and `chmod 777 out` are for Linux, so the container can write to `out` and you can
read the file afterwards. On Windows or macOS with Docker Desktop leave `--user` out.

The file has one line per export request (not one span per line). **Stop the Collector, or
wait about a second, before reading the file**: it writes about once a second, so a file that
is still being written can end in half a line, which observe reports as an error for that line
(`docker stop collector` before `lockwalk observe`). In Git Bash on Windows, set
`MSYS_NO_PATHCONV=1` first so the paths are not rewritten. With `rotation`, a directory is the right
`--traces` value. With `group_by`, one trace can be spread over several files; that is fine.

Not supported: `compression: zstd` and `format: proto`. They write a binary format, not JSON
lines; observe says so and exits 2. Tempo's export format has not been tested.

### Jaeger v2

Save the response of the v3 API into a `.json` file. lockwalk unwraps the `{"result": ...}`
envelope:

```bash
curl -o trace.json http://localhost:16686/api/v3/traces/<trace id>
lockwalk observe --traces trace.json
```

The files in `tests/observe_data/` are real responses from `jaegertracing/jaeger:2.23.0`. The
`curl` command shape above is taken from the Jaeger v2 API v3 documentation and from those
saved responses; the command itself was not run in this release. A search response, which
merges several traces in one `result`, is read the same way.

### Pydantic AI

Pydantic AI has its own instrumentation. Turn it on for every agent, and always give each
agent `name=`: without it the name in the trace can be a Python variable name or just
`agent`, which will not match anything.

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic_ai import Agent
from pydantic_ai.agent import InstrumentationSettings
from pydantic_ai.models.test import TestModel

provider = TracerProvider(resource=Resource.create({"service.name": "my-app"}))
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces"))
)
trace.set_tracer_provider(provider)

Agent.instrument_all(InstrumentationSettings(include_content=False))

pricing_agent = Agent(TestModel(), name="pricing-agent")  # use your model; always set name=
# ... run your agents, then:
provider.force_flush()
```

(Needs `opentelemetry-sdk` and `opentelemetry-exporter-otlp-proto-http`. The span shape
comes from a test run with Pydantic AI 2.66, instrumentation versions 3 to 6 and OpenTelemetry
SDK 1.45.2, using `TestModel` (Pydantic AI's offline model) and an in-memory exporter; this
snippet was not run against the Collector. Put your own model in place of `TestModel`.)
`include_content=False` keeps prompts and tool arguments out of the file.
Agents are recognized by `invoke_agent` and `gen_ai.agent.name`, tools by `execute_tool` and
`gen_ai.tool.name`. When an agent calls another agent inside a tool, the spans nest and
observe sees the link. When your own code runs two agents one after the other, the trace has
no link between them (see [what observe cannot tell you](#what-observe-cannot-tell-you)).

### OpenAI Agents SDK

Use the OpenInference instrumentation (`openinference-instrumentation-openai-agents`; the
span shape is from a test run with 2.7.1 and `openai-agents` 0.24, fake models, in-memory
exporter):

```python
from openinference.instrumentation import TraceConfig
from openinference.instrumentation.openai_agents import OpenAIAgentsInstrumentor

OpenAIAgentsInstrumentor().instrument(
    tracer_provider=provider,
    config=TraceConfig(hide_inputs=True, hide_outputs=True),
)
```

`provider` is a `TracerProvider` that exports to your Collector, as above. Agents are
`AGENT` spans with `agent.name`, tools are `TOOL` spans with `tool.name`. The caller of a
handoff is read from `graph.node.parent_id` on the called agent's span. An `AGENT` span
without a name (`Agent workflow`) and a handoff `TOOL` span without a name are not errors:
they are counted as "other" spans. Several unnamed markers produce one warning.

Logfire's OpenAI Agents bridge works too, with [rules](#logfire). It keeps the SDK's default
exporter, which sends traces to OpenAI: call `agents.set_trace_processors([])` after
`logfire.instrument_openai_agents()` if you do not want that.

### LangGraph and LangChain

LangGraph agents leave only a span name behind, so observe finds an agent when the span name
is exactly an agent id or an [alias](#names-and-aliases). Name each graph with its lockwalk
agent id (`compile(name="trade-agent")`). Two ways to export:

- **OpenInference** (`openinference-instrumentation-langchain`; span shape from a test run with
  0.1.82):
  `LangChainInstrumentor().instrument(tracer_provider=provider, config=TraceConfig(...))`.
  Tools are `TOOL` spans with `tool.name`.
- **LangSmith's OTel mode** (span shape from a test run with `langsmith` 0.14.17; the
  environment variables below were not run end to end). Pitfalls:
  - Set your own `TracerProvider` as the global one **before** LangSmith starts. Otherwise
    LangSmith builds its own provider that sends to LangSmith's servers and replaces yours.
  - Install `langsmith[otel]`. Without it LangSmith falls back to its native mode and talks to
    its own servers.
  - Set `LANGSMITH_TRACING=true`, `LANGSMITH_OTEL_ENABLED=true` and
    `LANGSMITH_OTEL_ONLY=true`, so traces go to OTel only.
  - Tools are `execute_tool` spans with `gen_ai.tool.name`; no rule is needed.

A subgraph can show up as two nested spans with the same name; observe counts them as one
agent visit. A tool whose function runs another agent (`ask_trade_agent`) is not an UNKNOWN
tool: see [wrappers](#wrappers-and-self-nesting).

### Langfuse and Logfire: rules

These tools do not use the OTel GenAI or OpenInference markers, so tell observe how to
recognize their spans with `[[observe.rules]]` in `.lockwalk.toml`. Every rule is loaded and
checked when the config is read (a bad rule is a config error, exit 2). A `when` table lists
attributes that must all be equal to the given values. A value is a TOML string, boolean or
integer (int64 range); a float is a config error. The type must match exactly: `true` never
matches `1` or `"true"`, and `1` never matches `1.0`. The special key `span.name` is the span's
own name, and its value must be a string. `name` says where the agent or tool name is: an
attribute, or `span.name`. `name`, `from` and `to` read string attributes only: an int or bool
attribute counts as absent there.
Rules can also make door records and effect markers: see
[Door and effect rules](#door-and-effect-rules).

#### Langfuse

Langfuse (5.2) writes `langfuse.observation.type` and uses the span name as the name.
These two rules load, and they match attributes that were written by hand to look like
`@observe(as_type="agent")` and `as_type="tool"` spans (unit tests). No Langfuse span was
exported to a file. Langfuse creates a global `TracerProvider` itself if none exists; to send to
your Collector add a `BatchSpanProcessor` with an OTLP exporter to the provider.

```toml
[[observe.rules]]
kind = "agent"
when = { "langfuse.observation.type" = "agent" }
name = "span.name"

[[observe.rules]]
kind = "tool"
when = { "langfuse.observation.type" = "tool" }
name = "span.name"
```

#### Logfire

Logfire (5.5, OpenAI Agents SDK bridge; span shape from a test run) puts everything in templates in
`logfire.msg_template`. The handoff template has a real arrow (U+2192) between the names;
`→` in a TOML string is that character, so it can be copied as is:

```toml
[[observe.rules]]
kind = "agent"
when = { "logfire.msg_template" = "Agent run: {name!r}" }
name = "name"

[[observe.rules]]
kind = "tool"
when = { "logfire.msg_template" = "Function: {name}" }
name = "name"

[[observe.rules]]
kind = "handoff"
when = { "logfire.msg_template" = "Handoff: {from_agent} → {to_agent}" }
from = "from_agent"
to = "to_agent"
```

A `handoff` rule creates no agent or tool. It only says who handed over to whom (`from` and
`to` are attributes). Without rules, observe finds
nothing in a Logfire export and says so (error "no agent or tool spans were recognized").
Templates may change with the vendor's versions.

### Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research) has no
OpenTelemetry output of its own. The community plugin `hermes_otel` adds it, and lockwalk reads
the result with rules only; nothing Hermes specific is in lockwalk's code. A runnable example
with five recorded traces is in [`examples/hermes`](../examples/hermes/README.md).

A door is the check that lets a call through (here, the approval menu). An effect marker is
proof the tool really ran.

**Check this first.** Hermes needs Python 3.14 and runs on Linux or WSL only. Install it from
a git clone: PyPI's `hermes-agent` (0.19.0) is too old for the plugin, which needs Hermes 0.21
or later. If you cannot run Hermes, you cannot go on.

#### Steps

1. Install Hermes from a git clone (see above; the versions that were tried are in
   [What was verified with Hermes](#what-was-verified-with-hermes)).
2. [Install and configure the plugin](#install-and-configure-the-plugin).
3. [Stop any running gateway](#stop-the-gateway): `hermes gateway stop`.
4. [Start the Collector](#collect-the-spans) with the file exporter, and name the container
   `collector`. The plugin sends to its port 4318.
5. Run `hermes chat` and use it. For an approval span, run a command Hermes thinks is dangerous
   and answer the menu.
6. Stop the Collector (`docker stop collector`), so the file is complete.
7. [Put the rules in `.lockwalk.toml`](#rules-registry-and-tools), next to your registry, spec
   and tool list.
8. Run `lockwalk observe --traces <your file> --summary` (with `uv run` in front if you run it
   from a lockwalk checkout).

#### What was verified with Hermes

A real Hermes Agent at git commit `93c7aeebc816000a365e1ecd6df9bf53f45e842c` (it calls itself
`2026.9.24`), the `hermes_otel` plugin 1.18.2 (by Brian Caffey, not by Nous), and
OpenTelemetry Collector 0.165.0, with a fake model only. The recorder in `examples/hermes/record`
ran Hermes and the docker CLI inside WSL (with Docker Desktop), and lockwalk read the trace
files from Windows. Other setups were not tried.

#### Install and configure the plugin

```bash
hermes plugins install hermes_otel
hermes plugins enable hermes_otel
```

(`--yes-deps --no-enable` makes the install non-interactive; the recorder uses them.) Then
write `hermes_otel.yaml` in `$HERMES_HOME` (where that is: see the
[Hermes repository](https://github.com/NousResearch/hermes-agent)).

**Do this first: `content_capture: "off"`.** The default (`full`) writes prompts and tool
results into the trace file. lockwalk drops them when it reads, but the file keeps them.

```yaml
backends:
  - type: otlp
    endpoint: http://127.0.0.1:4318/v1/traces
content_capture: "off"
capture_sender_id: true
```

- `capture_sender_id: true` adds a user id. On the CLI it looks like `cli:<random>`.

#### Stop the gateway

Stop any running gateway (`hermes gateway stop`). `hermes chat` starts one in the background,
and it keeps the old config.

#### Collect the spans

The plugin only sends OTLP, so use the Collector `file` exporter, as in
[OpenTelemetry Collector](#opentelemetry-collector). Stop the Collector before you read the
file, or its last lines may be cut.

#### Rules, registry and tools

observe needs the rules, and also a registry, a spec and a tool list, because it judges the
traces against them. Use one `.lockwalk.toml` for all of it (the header is from
`examples/hermes/.lockwalk.toml`):

```toml
[lockwalk]
registry = "registry.yaml"
spec = "security-spec.yaml"
fixtures = "fixtures.yaml"

[[inventory.json]]
path = "tools.json"
```

The spec and fixtures are your test cases; start from the ones in `examples/hermes`.

Then add these five rules, copied from the same file. For what `door` and `effect` rules mean,
see [Door and effect rules](#door-and-effect-rules).

```toml
# A sub-agent's root span is named hermes-agent too; this names it by its role instead (leaf).
[[observe.rules]]
kind = "agent"
when = { "hermes.platform" = "subagent" }
name = "hermes.subagent.role"

# The user pressed allow in the approval menu.
[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "hermes.approval.granted" = true }
decision = "allow"
tool_call_id = "gen_ai.tool.call.id"

# The user pressed deny (or the menu timed out).
[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "hermes.approval.granted" = false }
decision = "deny"
tool_call_id = "gen_ai.tool.call.id"

# Any tool that Hermes reports as blocked (for example by itself in unattended mode, -q) is a
# deny. A deny can only make a call safer, so a broad match is fine here. This rule has no
# tool_call_id, so the record is linked to its tool call by ancestry.
[[observe.rules]]
kind = "door"
when = { "hermes.tool.outcome" = "blocked" }
decision = "deny"

# Hermes's own claim that the tool completed. Its hook writes it, not the tool, so it is only
# as good as that hook. It is what turns a denied call that still completed into a BYPASS.
[[observe.rules]]
kind = "effect"
when = { "hermes.tool.outcome" = "completed" }
```

**Registry.** Two agents: `hermes-agent` (the entry) and `leaf` (the sub-agent). Set the risk
of each tool yourself. Registry ids must equal the names in the tool list. This is a
fragment (one tool); see `examples/hermes/registry.yaml` for a full file:

```yaml
schema_version: '1'
roles: [operator]
agents:
  - {id: hermes-agent, entry: true, roles: [operator], delegation_mode: user, calls: [leaf]}
  - {id: leaf, delegation_mode: user, calls: []}
tools:
  - {id: terminal, action: "terminal:call", risk: critical, resource_type: terminal_target, supported_agents: [hermes-agent, leaf]}
```

**Tools.** Either run lockwalk inside the Hermes venv with
`--python 'model_tools:get_tool_definitions()'`, or export the tools to JSON once, like
`examples/hermes/tools.json`, and list the file under `[[inventory.json]]` as above (the flag
`--tools-json` does the same). `tools.registry:registry` is not recognized.

#### Output

The user answered once with deny and once with allow. `--summary` is used because the full
output has a `Window:` line with the times of the recording, which change whenever the traces
are recorded again; the `Report written to` line is left out for the same reason. From
`examples/hermes`:

```bash
uv run lockwalk observe --traces traces/approve_deny.jsonl --traces traces/approve_allow.jsonl --summary
```

```text
lockwalk observe - hermes-example-v1
Read: 2 traces, 12 spans (2 agent spans, 2 tool calls)
Door records: 3 (2 tool call(s) have one; 0 not tied to a tool call, 0 linked by time)
Routes: 2 ON_MAP, 0 OFF_MAP, 0 UNKNOWN
Guarded calls: 1 GUARDED, 1 DENIED
Tested paths: 2 TESTED
Gate: PASS (exit 0)

Warnings (1):
  - 3 door records have no subject (for example a person's approval); they count for guard checks only
```

Read it like this: the routes are on the map; the guarded calls show one allowed (GUARDED) and
one denied (DENIED); Gate PASS means no violation; the warning is expected, because Hermes does
not record who pressed the button.

DENIED (not DENIED_UNVERIFIED) is possible only because the second trace, where the user
allowed, shows the tool completing: that is the effect marker.

#### Hermes limits

- Hermes names sub-agents by depth, so every one is `leaf`. With several sub-agents, lockwalk
  cannot tell them apart.
- Approvals exist only in interactive mode. With `-q` there is no approval span, only the
  outcome `blocked`.
- Only dangerous commands ask for approval. Plain commands, file reads and `delegate_task`
  are UNGUARDED. That is a fact, not always a problem.
- The effect marker is inferred from the tool outcome Hermes writes. The tool does not set it.
- Identity checks cannot tell users apart here: the user id is `cli:` plus random characters,
  and the approval does not say who pressed the button.
- Verified with a fake model only. Chat platform (gateway) mode and smart approval were not
  tried.
- `hermes_otel` is a community plugin. Its attribute names may change between versions.
- The traceverse plugin (`traceverse_hermes_otel` 2.0.1) cannot show routes: it puts the child
  agent in a separate trace, and its spans have no tool call id, no approval spans and no user
  id. Use `hermes_otel`.

### Keep content out of the file

lockwalk never keeps prompts, tool arguments or results (see
[limits and errors](#limits-and-errors)), but the trace file still holds them. If you do not
need them, do not write them:

- Hermes (`hermes_otel`): `content_capture: "off"` in `hermes_otel.yaml`.
- OpenInference: `TraceConfig(hide_inputs=True, hide_outputs=True)`.
- Pydantic AI: `InstrumentationSettings(include_content=False)`.
- LangSmith: `LANGSMITH_HIDE_INPUTS=true` and `LANGSMITH_HIDE_OUTPUTS=true`.

## How spans are recognized and named

Each span is decided in this order (first match wins):

1. **Your rules** (`[[observe.rules]]`, first matching rule of a kind) and the built-in
   markers decide first:
   - **Tool**: `gen_ai.operation.name = execute_tool` with `gen_ai.tool.name`, or
     `tool.name` on an OpenInference `TOOL` or `AGENT` span, or a `tool` rule; and it has a
     name. **A tool marker with a name wins over an agent marker.** OpenInference marks a
     LangChain tool named `ask_trade_agent` as `AGENT`; it is still a tool.
   - **Handoff**: a `handoff` rule that matches and finds both names.
   - **Agent**: `gen_ai.operation.name = invoke_agent` with `gen_ai.agent.name` (or
     `gen_ai.agent.id`), or OpenInference `AGENT` with `agent.name`, or an `agent` rule.
2. **Name match**: if nothing above applies and the span's own name is exactly a known agent
   id or alias, it is that agent.
3. Anything else is "other": it is only used to connect parents and children and its content
   is never read.

A marker without a name is not an error. It is counted as "other", and the report warns once
with the count (it may be a tool that was not recognized).

### Names and aliases

A name in the trace is matched to an id: first an exact agent or tool id (auto-discovery uses
the framework's names, for example `Agent(name="trade-agent")`), then the aliases:

```toml
[observe.agents]
"Pricing Agent" = "pricing-agent"

[observe.tools]
"get_price_v2" = "get_stock_price"
```

An alias that points to an id that does not exist is a config error (exit 2), and so is the
same name in both tables. An alias whose key is already a real id is allowed only when it
maps to itself (an identity alias, `"supervisor" = "supervisor"`). It is an error when the key
is a different real agent id or a tool id (in `[observe.agents]`), and the reverse for
`[observe.tools]` (a different real tool id or an agent id). A name that
matches nothing is UNKNOWN. UNKNOWN names that came from an agent or tool marker are shown
(URL credentials masked, cut to 200 characters). A span name used only for name matching is
never shown unless it matched.

### Wrappers and self-nesting

- **Agent-as-tool wrappers.** A tool span whose name is not a known tool, and that either
  has an agent span below it (before any other tool span on the way down) or is named in the
  registry's `delegation_tools`, is the wrapper of an agent (for example the OpenAI SDK's
  `as_tool`). It is not counted as a tool call, and the link comes from the agent inside. The
  agent below it and that agent's tools are checked as for any other agent.
  A wrapper is known when its name is in the registry's `delegation_tools`, or when Python
  discovery found it as an agent-as-tool wrapper (for example
  `trade_agent.as_tool(tool_name="ask_trade_agent")`). Names are matched exactly, including
  case, and a wrapper name is known for every agent, not only the one that holds it. A known
  wrapper is not reported. A wrapper that is found only because an agent is below it, and that
  neither the registry nor discovery named, is a tool lockwalk was not told about: it is
  reported as an UNKNOWN tool (`lockwalk inspect --trace` shows it as `tool ? name`), and
  `fail_on_unknown_component` blocks it. An edge between the two agents on the map does not
  make the name known. To clear it, list the tool in `delegation_tools`. A snapshot saved by an
  older lockwalk does not hold the discovered names, so replaying it reports such a wrapper as
  UNKNOWN until the snapshot is saved again.
- **Same agent inside itself.** If the first agent span above an agent span is the same
  agent, the two are merged into one visit. There is no "agent calls itself" link.

### Calls that are not nested

Some frameworks write a handoff as two sibling agent spans. An explicit caller wins over
nesting: `graph.node.parent_id` on the called agent (OpenInference), or a `handoff` rule
(`from`, `to`). The path of the called agent then continues from the most recent span of the
caller that started before it. If no such span exists, the path is incomplete.

Paths are at most 32 agents; a longer path makes that trace an error. An agent that appears
twice on a path (A calls B, B calls A) is recorded as it happened. A trace whose parent
span ids point to spans that are not in the data is **incomplete**: the top agent of such a
part does not get a `user -> agent` link, because who called it is not known. The report
counts incomplete traces.

A tool call with no agent above it, in a complete trace, is UNKNOWN (caller).

## Reader function

For sources that are not OTLP (your own logs, a vendor's native export), write a function and
point `[observe]` at it:

```toml
[observe]
reader = "my_traces:read"
reader_timeout_s = 60.0
```

```python
import json
from collections.abc import Iterable


def read(paths: list[str]) -> Iterable[dict]:
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                yield {
                    "trace_id": row["trace"],
                    "span_id": row["id"],
                    "parent_id": row.get("parent"),
                    "kind": row["type"],  # "agent", "tool", "handoff" or "other"
                    "name": row.get("name"),
                    "start": row["started_at"],  # ISO 8601 with a time zone
                    "end": row["ended_at"],
                }
```

The module is imported from the reader's working directory (see below). Run `lockwalk observe --traces
export.jsonl`: with `reader` set, lockwalk does not read the files itself, it passes the
`--traces` values (or `[observe] traces`) to your function exactly as written.

Each record is a dict:

| Field | Meaning |
|---|---|
| `trace_id`, `span_id` | Non-empty strings (up to 256 characters). Kept exactly as written (OTLP ids are lower-cased; reader ids are not) |
| `parent_id` | The parent's `span_id`, or absent/`null` for the top span |
| `kind` | `agent`, `tool`, `handoff` or `other` |
| `name` | Required for `agent` and `tool`, and only for them. Matched like any other name |
| `caller` | Optional, agent only: the explicit caller's name |
| `from`, `to` | Required for `handoff`, and only for it |
| `start`, `end` | Optional ISO 8601 strings with a time zone (`2026-11-08T10:00:00.120Z`). Epoch numbers and times without a zone are refused |
| `user_id` | Optional: the user of the trace, as `user.id` would be |
| `authz` | Optional list of door records, each `{"decision": "allow"/"deny"/"error", "subject": {"type", "id", "act"}, "action", "resource_type", "tool_call_id"}`. `act` is the nested `{type, id, act}` object. A bad item is a record error. Each item becomes a child span `<span_id>#door<n>` (n from 1), so a reader `span_id` and `parent_id` may not contain `#` |
| `effect` | Optional boolean: only `true` counts as an effect marker |
| `tool_call_id` | Optional, tool only: the tool call's id, matched against a door record's `tool_call_id` |

Rules:

- The function runs in a subprocess, in the folder of the config file (or the current folder
  for `--traces` on the command line), so it can use the network (for a vendor export API).
  lockwalk does not restrict it. It has `reader_timeout_s` seconds (default 120). The records it
  returns are not shown, but the message of an exception it raises is (see the bullet on errors below).
- Every record is checked: a record that fails the check is an error naming the record number,
  and the other records are still used (exit 2). An exception or a timeout is an error, with
  the message cut, and URL credentials, queries and fragments removed from it.
- The limits in [limits and errors](#limits-and-errors) apply to the records.
- After the check, reader spans are treated exactly like spans read from OTLP.
- The reader is your code. lockwalk checks the shape of what it returns, not whether it read
  your logs correctly.

## Limits and errors

Settings in `[observe]` (all numbers are positive; the first three have hard maximums):

| Key | Default | Meaning |
|---|---|---|
| `max_spans` | 1,000,000 (at most 5,000,000) | Spans kept. Each kept span costs about 1 KB of memory |
| `max_line_mb` | 64 (at most 1024) | The longest line of a `.jsonl` file, or the longest `.json` file |
| `max_total_mb` | 4096 (at most 65,536) | All input together, counted after decompression |

A limit that is hit is an error, and lockwalk does not read on and call the result complete.

**Errors make the run exit 2.** The rest of the data is still checked and listed. An error says
the file and the line (or record), and never quotes the line. It is one problem per line; at
most 100 problems are collected, then one more line says how many were left out. The
terminal lists at most 20 of each of warnings and errors (`observe.json` has all of them). Errors are:

- no trace was read at all (zero traces is an error, not "no findings");
- traces were read but no agent or tool span was recognized (usually an instrumentation or
  rules problem; the message says so);
- a line that is not valid JSON, has a repeated key, or is not OTLP; ids that are not hex of
  the right length (an all-zero id is invalid); the old `instrumentationLibrarySpans` shape;
- a half-written last line (see the Collector note);
- more than 1000 blank lines in a row in a `.jsonl` file;
- a binary Collector file (`compression: zstd`, `format: proto`);
- a trace whose parent links form a loop, or that repeats a span id, or whose path is
  longer than 32 agents: that trace is an error, others are checked normally;
- a missing file, a file that cannot be read, an unknown extension;
- a partial or malformed door record or effect marker (see
  [Door records and effect markers](#door-records-and-effect-markers)); the record is ignored;
- a reader function that fails, times out, or returns bad records;
- an error from the map itself (the same as in `coverage`).

OTLP input details: a UTF-8 BOM is accepted; integers may be strings or numbers;
`doubleValue` may be the strings `NaN`, `Infinity`, `-Infinity`; a missing or empty
`parentSpanId` means top span; trace and span ids are compared in lower case.

**lockwalk keeps only what it needs.** While a line is parsed, every attribute that is not on
a short list is dropped. What is kept: trace id, span id, parent id, span name, times, and
these attributes:

- the built-in keys: `gen_ai.operation.name`, `gen_ai.agent.name`, `gen_ai.agent.id`,
  `gen_ai.tool.name`, `gen_ai.tool.call.id`, `openinference.span.kind`, `agent.name`,
  `tool.name`, `graph.node.parent_id`, `user.id`, `enduser.id`, the `lockwalk.door.*` keys
  and `lockwalk.effect`;
- the attributes your `[[observe.rules]]` name (in `when`, `name`, `from`, `to`, and the
  `tool_call_id` of a `door` rule);
- the targets of `[observe.attributes]`.

Observe uses `user.id`, `enduser.id`, the `lockwalk.door.*` keys and `lockwalk.effect` (or
the attributes you map them to in `[observe.attributes]`) for the door checks; they are kept in
memory only. Prompts, tool arguments and results, messages and metadata never reach memory,
the report or the terminal. Terminal output is plain ASCII.

## observe.json

`<output dir>/observe.json` is replaced on every run. It has `schema_version` `"2"` (a file of another version is refused: run `observe` again),
`lockwalk_version`, `generated_at` and `kind` `"observe"`, then:

| Field | Content |
|---|---|
| `scenario_suite` | The name from the spec |
| `sources` | The paths as you gave them: a folder as `<label> (N files)` (`(1 file)` for one); a named file as `<label>`; or `reader <target>`. A path that does not exist is not listed; it is an error. Never absolute paths you did not write |
| `totals` | `files`, `traces`, `spans`, `agent_spans`, `tool_calls`, `incomplete_traces`, `error_traces`, `unnamed_markers`, `door_records` (valid records read), `records_without_call` (records that belong to no tool call), `records_by_time` (records linked by time) and `calls_with_record` (tool calls with at least one linked record). `files` counts sources: a folder or a reader counts once, however many files it holds |
| `window` | `first`, `last`: earliest and latest span start, UTC |
| `routes` | Rows with `from_id` (`user` or an agent), `to_id`, `to_kind`, `status` (`ON_MAP` or `OFF_MAP`), `count`, up to 3 example `traces` (the terminal shows the first one), and `suggestion` (only for OFF_MAP) |
| `unknown` | Rows with `kind` (`agent`, `tool`, `caller`), `name` (for `caller`, the tool's name), `count`, `traces` |
| `identities` | Rows with `path`, `tool` (or null), `mode`, `expected`, `observed` (shown forms only), `result`, `count`, `traces`, `notes`, `test_results` |
| `guards` | Rows with `agent` (or null), `tool`, `tool_known`, `counts` (per status), `by_time`, `effect_without_record`, `traces` (examples that are not GUARDED) |
| `paths` | Rows with `path`, `tool`, `incomplete`, `status`, `count`, `traces` |
| `waivers` | One row per waiver, with its status (see [waivers](#waivers-and---summary)) |
| `gate` | `passed`, a list of `violations` (`rule`, and what it is about: route, name, agent and tool, or path and tool), and `waived` |
| `errors`, `warnings` | Messages |
| `exit_code` | 0, 1 or 2 |

The user id of a trace, subject ids that are not known agents, resource ids, other span
attributes, the records a reader returns and environment values are never written. A bad
record is reported by its number, not its content. The text of an exception is written,
though: when a reader function raises, the error line in `errors` holds the exception type
and its message (cut, with URL credentials removed). Keep secrets out of those messages.
A row that a waiver covers has `waived_by` with the waiver id.

The file can grow when a trace holds many distinct unknown names (one `unknown` row each, with
names cut to 200 characters). `observe.json` is written whole; a file over 256 MiB is refused
by `read_observe`, the function that reads it back.

## Gate keys and exit codes

These keys in `[gate]` decide what blocks. Every one of them can be changed in `.lockwalk.toml`;
the values here are the defaults:

```toml
[gate]
fail_on_off_map_route = true
fail_on_unknown_component = true
fail_on_identity_mismatch = true            # also used by lockwalk test
fail_on_inconclusive_observation = true
fail_on_unguarded_call = ["high", "critical", "unknown"]
fail_on_untested_path = ["critical", "unknown"]
```

| Key | Blocks on |
|---|---|
| (always, no key) | BYPASS |
| `fail_on_off_map_route` | an OFF_MAP row |
| `fail_on_unknown_component` | an UNKNOWN row (agent, tool or caller) |
| `fail_on_identity_mismatch` | an identity MISMATCH |
| `fail_on_inconclusive_observation` | an identity row or a guard row that is INCONCLUSIVE |
| `fail_on_unguarded_call` | UNGUARDED calls of tools with one of these risk levels. A tool whose risk is unknown counts as `unknown` |
| `fail_on_untested_path` | UNTESTED paths of tools with one of these risk levels |

The two risk lists take `low`, `medium`, `high`, `critical`, `unknown`. An empty list `[]`
turns the check off (it still shows the rows). **Without door records every HIGH, CRITICAL or
UNKNOWN tool call is UNGUARDED and blocks**; see
[Door records and effect markers](#door-records-and-effect-markers) for how to turn that off.

| Exit code | Meaning |
|---|---|
| 0 | nothing blocks |
| 1 | at least one finding blocks |
| 2 | a config error, or any error (see above). If there were also blocking findings, the exit code is still 2 and the findings are still listed |

A run with errors prints no gate line, only `Result: ERROR (exit 2)`. The other gate keys of
`coverage` and `test` are accepted but do not apply to `observe`. A waived finding does not
count (exit 0 if nothing else blocks), and an ERROR cannot be waived.

## lockwalk inspect

### inspect --trace

When a row says UNKNOWN or OFF_MAP, the question is what lockwalk made of that trace:

```bash
cd examples/multi_agent
uv run lockwalk inspect --trace c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3 --traces traces/off_map.jsonl
```

```text
lockwalk inspect - trace c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3 (complete)  user: present
  agent supervisor                  from user: ON_MAP
    agent trade-agent                 from supervisor: OFF_MAP
      tool execute_trade                used by trade-agent: ON_MAP
        door: allow for agent:trade-agent (linked by ancestry)
        effect marker (linked by ancestry)
  (2 other spans)
```

It runs the whole observe pipeline on the traces (same options as `observe`: `--traces`,
`--config`, `--registry`, `--spec`, `--mcp`, `--python`, `--tools-json`) and prints the tree of
that one trace. Only that trace's spans are kept in memory, but the whole input is still
read, so it costs as much as a full `observe` run. `--output-dir` has no effect on `inspect
--trace`, which writes no file. Trace ids from OTLP files match in any case. With a `reader`,
the id must match exactly.

The first line says whether the trace has a user: `user: present` when any span carries a user
id, `user: missing` when none does (never the id itself). A missing user is why identity rows
become INCONCLUSIVE.

Row types (names of other spans are never shown):

| Row | Meaning |
|---|---|
| `agent X   from Y: ON_MAP` or `OFF_MAP` | agent X was called by Y; the status is the link's |
| `agent X   from Y: caller not known` | the caller is unknown (an incomplete trace, or an unknown agent above) |
| `agent ? name   UNKNOWN agent` | the name matches no agent |
| `tool X   used by Y: ON_MAP` or `OFF_MAP` | tool X was used by agent Y |
| `tool ? name   UNKNOWN tool` | the name matches no tool |
| `tool X   no known calling agent` | a known tool with no known agent above it |
| `tool name   agent-as-tool wrapper` | a wrapper, not counted as a tool call |
| `(same agent again: X)` | a nested span of the same agent, merged into one visit |
| `(N other spans)` | spans that are neither agent nor tool, collapsed |
| `door: allow for agent:trade-agent (linked by ancestry)` | a door record under the tool call it belongs to. The subject is in the same [shown form](#identity-checks) as the identity rows: `the trace's user`, `another user`, `a user (cannot compare)`, `agent:<id>` for an agent in your inventory, `<type>:hidden` for anything else, and `, acting through a < b` for an act chain (`?` for a link that is not a known agent). Never a user id. `linked by` is `ancestry`, `tool call id` or `time` |
| `door: deny (decision only, no subject) (linked by tool call id)` | a record made by a [door rule](#door-and-effect-rules): the decision and how it was linked, with no subject. It is not an identity row |
| `effect marker (linked by ancestry)` | an effect marker, the same way |
| `door: ... (several tool calls match by time; not linked)` | an ambiguous record |
| `door record not linked to a tool call: ... (no tool call found)` | a record that belongs to no call, or `(its span contains tool calls)`. It is shown under the agent above it |
| `effect marker not linked to a tool call` | an effect marker that belongs to no call |

Exit codes: a usage error (neither or both of `--case` and `--trace`) exits 2. Otherwise exit 2 only when the trace id is not found (the message then also lists the
run's errors, such as a missing path, so a broken input is not hidden) or on a configuration
error. A trace that is found prints its tree and exits 0, even if other read errors exist;
those are listed under `errors:`. A trace that could not be walked (a loop, a repeated span
id) prints `(the trace could not be walked)` with its error and also exits 0. OFF_MAP does
not change the exit code. `inspect --trace` does not load waivers.

### inspect --case: real traffic

`lockwalk inspect --case CASE-004` reads `coverage.json` and `evidence.jsonl` from the output
folder (see the [test guide](lockwalk-test.md)) and, if `observe.json` is there, adds a
`real traffic` block. Identity and path rows are matched by the case's path and tool; guard
rows by the calling agent (the last agent of the path) and the tool. If no row matches, it says
`real traffic did not take this path`; if the last `observe` run had errors (exit 2), it says
`the last observe run had errors; real traffic may be incomplete` instead, because the data may
be missing. An `observe.json` from another lockwalk version gives one line in the gaps (run
`observe` again). An
`observe.json` that cannot be read gives one line in the gaps, not an error. After `lockwalk
coverage` and `lockwalk observe` on the demo:

```bash
uv run lockwalk coverage
uv run lockwalk observe --traces traces/untested.jsonl --traces traces/mismatch.jsonl
uv run lockwalk inspect --case CASE-004
```

```text
lockwalk inspect - CASE-004
CASE-004  UNTESTED
  spec:     bob (trader)  trade-desk -> trade-agent  execute_trade (trade:execute)  expect allow
  real traffic (observe, 2026-11-08T02:35:44Z .. 2026-11-08T02:35:44Z):
    identity (agent): MISMATCH 1, expected agent:trade-agent, saw the trace's user
    door: GUARDED 1
    path: TESTED 1
  gaps:
    - this coverage.json comes from lockwalk coverage; run lockwalk test to see the IAM's answers, the door runs, and the evidence
```

(The case is UNTESTED here because `coverage` does not run it; `lockwalk test` gives the
IAM's answers and the timeline.)

If you ran `lockwalk coverage` before `observe`, the observe run shows the warning `the test
report comes from lockwalk coverage; run lockwalk test for the side-by-side`. That is expected
and harmless.

## What observe cannot tell you

- **Only what was instrumented.** No span does not mean it did not happen. A path that
  appears in no trace is not shown, and "no OFF_MAP rows" says nothing about other traffic.
- **Only the traffic in the files.** If traces are sampled, rare paths may be missing or cut
  into incomplete traces. The result is about that traffic, not about all possible behavior.
- **Calls across services.** They link only when the trace context (`traceparent`) was passed
  on, for example a remote A2A agent or an HTTP MCP server. If not, the trace is incomplete.
- **Hand-offs depend on the framework.** What was tested is
  described per framework in [Get traces out of your system](#get-traces-out-of-your-system).
  Pydantic AI code that runs two agents one after the other leaves no link between them, so
  both look like starting points: each gets a `user -> agent` link, and one of them shows as
  OFF_MAP unless it is an entry agent. LangGraph `Command(goto=...)` leaves no hand-off
  record, but the supervisor's span contains the next agent's span, so nesting gives the link.
- **A known agent inside an unknown agent is not judged.** In `A -> ? -> B`, B has no known
  caller, so there is no link to compare. The unknown agent is the UNKNOWN row.
- **Name matching can be wrong.** A span that is not an agent but is named exactly like an
  agent id is taken as that agent. Unique agent ids make this unlikely.
- **An agent with the id `user` is refused.** lockwalk uses `user` for the person who starts a
  trace; rename the agent to use `observe`.
- **A call from an agent to itself is not visible**, because nested spans of one agent are
  merged.
- **The OTel GenAI conventions are still in development.** Attribute names may change. The
  versions the span shapes were taken from are named above.
- **Rule templates for Logfire and Langfuse** may need changes when those tools change.
- **Hermes Agent** has limits of its own: every sub-agent is `leaf`, approvals exist only in
  interactive mode, the effect marker is inferred, and identity checks cannot tell users
  apart. See [Hermes limits](#hermes-limits).
- **Trace files can hold personal data.** lockwalk keeps none of it, but how the files are
  stored is up to you.
- **A reader function is your code.** lockwalk checks its shape, not its correctness.
- **Observe trusts the door's own record.** If the door records `deny` and sends `allow`, or
  records one subject and sends another, observe cannot see it. It checks what the door says
  it did.
- **BYPASS needs the effect marker.** The marker is written by your code. Without it a denied
  call can only be DENIED_UNVERIFIED, and a call that skipped the door is only UNGUARDED.
- **Effect markers on spans that contain tool calls are not tied to a call.** They are counted
  in a warning, not used. Put the marker on a span of its own inside the function
  (`record_effect()`).
- **Clocks across machines.** Linking by time compares times written by different processes.
  Spans from one process can be trusted; spans from several machines can be wrong when the
  clocks differ, and a record may be given to the wrong call or become ambiguous.
- **The risk lookup uses the tool text as shown.** A tool id over 200 characters, or one whose
  text was masked (URL credentials), is not found in the registry and counts as UNKNOWN risk.
  That fails closed: UNGUARDED and UNTESTED then block for it under the default keys.
- **The agent `(none)` in an `unguarded` waiver means a call with no calling agent.** An agent
  that is really named `(none)` cannot be told apart from it.
- **A decision-only record says nothing about which identity was sent.** A record made by a
  `door` rule shows that a decision was made, not whom it was made for. Use it for guard
  checks; it cannot show a wrong subject.
- **Subject ids are compared as written.** An alias in `[observe.agents]` applies to span names,
  not to the `lockwalk.door.subject.id` of a record.
- **A door record whose span has no start time** is never linked by time.
- **A trace with a repeated span id is refused as a whole, and the run exits 2.** lockwalk does
  not guess which copy is right, because two spans with one id may not be the same span. This
  happens when an exporter retries a batch, or when `--traces` names a folder and also a file
  inside it. Other traces in the run are still checked. Give each file once, and remove
  duplicate spans from the export first.
