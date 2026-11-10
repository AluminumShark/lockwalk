# Hermes Agent example

Traces from [Hermes Agent](https://github.com/NousResearch/hermes-agent) with the community
`hermes_otel` plugin, read by `lockwalk observe` through configuration only. Nothing Hermes
specific is in lockwalk's code. The example shows:

- routes: `user -> hermes-agent -> leaf`, with the sub-agent named by an `agent` rule;
- guard statuses from the user's approval (GUARDED, DENIED, DENIED_UNVERIFIED, BYPASS) and from
  Hermes blocking a tool by itself in unattended mode;
- the honest result for a tool that has no door: a plain command is UNGUARDED.

This is an observe example, not a full test suite. The spec has cases for `terminal` only, so
`lockwalk coverage` exits 1 here on purpose, and lists the other tools as having no case.

| File | What it is |
|---|---|
| `registry.yaml` | The two agents and the tools in `tools.json`. The risks are an example: set your own |
| `security-spec.yaml`, `fixtures.yaml` | A few hand-written cases for `terminal` |
| `.lockwalk.toml` | The registry, spec, fixtures, `tools.json`, and the observe rules |
| `tools.json` | The tools, exported from Hermes |
| `traces/` | Five scrubbed traces (below) |
| `record/` | The recorder that made `traces/` and `tools.json` (see `record/README.md`) |

How to set up Hermes and the plugin is covered in the Hermes section of
[`docs/lockwalk-observe.md`](../../docs/lockwalk-observe.md#hermes-agent).

## How the traces were made

`record/` drives a real Hermes Agent against a fake model (no LLM, no API key), collects its
OpenTelemetry output with a local Collector, and scrubs it: only the attributes lockwalk needs
are kept, the user id becomes a fixed demo value, and events, links, paths and session ids are
dropped. `traces/bypass_edited.jsonl` is not a real run: it is `approve_deny` after
`scrub.py --edit-bypass` changed its `hermes.tool.outcome` from `blocked` to `completed`, to
show BYPASS. The same step gives the copy its own trace and span ids (a fixed salted hash of the
originals, so a re-record gives the same file), so all five files can be read together as one
folder. The other four are as recorded.

## Run it

From the repository root:

```bash
uv sync
cd examples/hermes
```

### A plain command through a sub-agent

```bash
uv run lockwalk observe --traces traces/delegate.jsonl
```

Exit 1. The main agent hands a task to a sub-agent, which runs an ordinary command. Both routes
are ON_MAP (the `agent` rule below is what names the sub-agent `leaf`). But Hermes asks for
approval only for dangerous commands, so `leaf / terminal` has no door record and is UNGUARDED.
The default gate fails on an UNGUARDED call of a tool whose risk is high, critical or unknown
(`fail_on_unguarded_call`, see [Guard statuses](../../docs/lockwalk-observe.md#guard-statuses)
and [Gate keys](../../docs/lockwalk-observe.md#gate-keys-and-exit-codes)), and `terminal` is
critical here. That is the line `Gate: FAIL (exit 1) - 1 violation(s)`.

`hermes-agent / delegate_task` is UNGUARDED too, but it is medium, so it is reported and does
not block. The line `Real paths no case tests (UNTESTED)` lists `hermes-agent / delegate_task`
because no case in the spec covers that path, and `Tested paths: 1 TESTED` is the path that
does have a case (`hermes-agent -> leaf` running `terminal`).

### The user presses allow

```bash
uv run lockwalk observe --traces traces/approve_allow.jsonl
```

Exit 0. The approval span becomes an `allow` door record linked to the `terminal` call by its
tool call id, so the call is GUARDED.

### The user presses deny

```bash
uv run lockwalk observe --traces traces/approve_deny.jsonl
```

Exit 0. The command did not run: `terminal` is DENIED_UNVERIFIED. lockwalk only calls a denial
DENIED when it has seen the tool really run somewhere else (an effect marker), because that
shows the marker works. This trace has none for `terminal`, so the denial is not proven. A
denial on its own, proven or not, never blocks.

```bash
uv run lockwalk observe --traces traces/approve_deny.jsonl --traces traces/approve_allow.jsonl
```

Exit 0. Now `terminal` shows 1 GUARDED and 1 DENIED. `approve_allow` carries a `completed`
outcome for `terminal`, which is the effect marker that proves the deny is real.

### Hermes blocks the tool by itself

```bash
uv run lockwalk observe --traces traces/unattended_block.jsonl
```

Exit 0. In unattended mode (`-q`) there is no approval span. Hermes only reports the tool
outcome `blocked`, and a rule turns that into a `deny`. Same result as the deny above:
DENIED_UNVERIFIED.

### A denied call that still ran

```bash
uv run lockwalk observe --traces traces/bypass_edited.jsonl
```

Exit 1. The call was denied and its outcome says `completed`, so it is a BYPASS. Only BYPASS
blocks among the denied statuses, and it needs an effect marker that proves the call ran. This
trace is the made-up one described above.

To read all five files at once, point `--traces` at the folder: `uv run lockwalk observe --traces traces`
exits 1 and reports this BYPASS next to the findings of the other traces.

Approvals have no subject (Hermes does not record who pressed the button), so each run warns
that the door records count for guard checks only, and there are no identity rows.

## The rules

`.lockwalk.toml` has these `[[observe.rules]]`, in this order:

1. `agent`: a span with `hermes.platform = "subagent"` is named by `hermes.subagent.role`
   (`leaf`). Without it the sub-agent's root span, also called `hermes-agent`, looks like a
   call from the sub-agent back to the main agent (a false OFF_MAP route).
2. `door`: an approval span with `hermes.approval.granted = true` is an `allow`.
3. `door`: an approval span with `hermes.approval.granted = false` is a `deny`.
4. `door`: a tool outcome of `blocked` is a `deny`. It matches any tool Hermes reports as
   blocked (for example in `-q` mode). It only denies, so it is safe. It has no
   `tool_call_id`, so it is linked to its tool call by ancestry.
5. `effect`: a tool outcome of `completed` is an effect marker. It is Hermes's own claim,
   written by its hook and not by the tool. It is what turns a denied call that completed into
   a BYPASS.

See [Door and effect rules](../../docs/lockwalk-observe.md#door-and-effect-rules).

## Adapt it to your setup

- **Attribute names.** Open one of your own trace files, or run
  `uv run lockwalk inspect --trace <trace id> --traces your.jsonl` and look for spans shown as
  "other". Change the `when` of each rule to the names you find. The attributes in `when` must
  be on the exported span itself.
- **Tools.** List your tools in `registry.yaml`, each with your own risk. Registry ids must
  equal the names in `tools.json` (or whatever tool source you use).
- **Actions and resource types.** Hermes gives lockwalk nothing finer than the tool name, which
  is why every tool here uses `<tool>:call` and `<tool>_target`.
- **Keep every allow rule narrow.** An allow record is what makes a call GUARDED. See the
  [security note](../../docs/lockwalk-observe.md#door-and-effect-rules) in the rules section
  (it starts "Security note: keep allow rules narrow").

## Limits

The limits (sub-agent names, approvals only in interactive mode, inferred effect markers, no
identity checks, fake model only, a community plugin) are listed in
[Hermes limits](../../docs/lockwalk-observe.md#hermes-limits).
