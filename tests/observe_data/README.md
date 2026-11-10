# observe test data

Real OTLP/JSON samples recorded on 2026-11-08, sanitized: each resource
keeps only `service.name`; span attributes starting with `code.`, `process.`, `host.`, `os.`,
`thread.` are dropped; `lockwalk.authz.*` is renamed `lockwalk.door.*`. Content-like
keys (prompts, tool arguments) stay: they are fake, and tests use them to prove observe drops
content.

The files are fixed. Do not regenerate them: trace ids, span ids and `service.instance.id`
differ on every run.

Scenario in every framework file: entry agent `supervisor` reaches `trade-agent`, which calls
the tool `execute_trade`. Only some files also record a door decision span (`authz-check`).

| File | Source | Real names |
|---|---|---|
| `pydantic_delegation.json` | Pydantic AI 2.66, OTel 1.45.2, built-in instrumentation (version 5). Delegation: `supervisor` calls tool `delegate_trade`, which runs `trade-agent` | agents `supervisor`, `trade-agent` (`invoke_agent` + `gen_ai.agent.name`); tools `delegate_trade`, `execute_trade` (`execute_tool` + `gen_ai.tool.name`); tool spans also carry the owning `gen_ai.agent.name`; model spans `chat`; no wrapper |
| `pydantic_handoff.json` | same, but the app runs the two agents in sequence | same names; the agent spans are not nested (no link) |
| `openai_oi_handoff.json` | OpenAI Agents SDK 0.24 + OpenInference 2.7.1, handoff | agents `supervisor`, `trade-agent` (AGENT + `agent.name`; `trade-agent` has `graph.node.parent_id=supervisor`); tool `execute_trade` (TOOL + `tool.name`); handoff span named `handoff to trade-agent` is a TOOL with no `tool.name`; an AGENT span `Agent workflow` has no name |
| `openai_oi_astool.json` | same bridge, agent-as-tool | wrapper `ask_trade_agent` (TOOL + `tool.name`); agents `supervisor`, `trade-agent`; tool `execute_trade`; nameless AGENT `Agent workflow` |
| `openai_logfire_handoff.json` | OpenAI Agents SDK 0.24 + Logfire 5.5, handoff | no gen_ai or OpenInference keys; span names are templates (`logfire.msg_template`: `Agent run: {name!r}`, `Function: {name}`, `Handoff: {from_agent} -> {to_agent}`, `Turn {turn} for agent <name>`); handoff span has `from_agent=supervisor`, `to_agent=trade-agent` |
| `openai_logfire_astool.json` | same bridge, agent-as-tool | same templates; wrapper `ask_trade_agent` appears as a `Function: {name}` span |
| `langgraph_oi_sub.json` | LangGraph 1.2.20 + OpenInference 0.1.82, subgraph | agent names only as span names (`supervisor` is CHAIN, `trade-agent` AGENT, inner `agent` AGENT); tool `execute_trade` (TOOL + `tool.name`); `route`, `tools` are CHAIN |
| `langgraph_oi_tool.json` | same bridge, agent-as-tool | wrapper `ask_trade_agent` has `tool.name` and kind AGENT; otherwise as above |
| `langgraph_ls_sub.json` | LangGraph 1.2.20 + LangSmith 0.14.17 OTel, subgraph | span names `supervisor`, `trade-agent` (`gen_ai.operation.name=chain`); tool `execute_trade` (`execute_tool` + `gen_ai.tool.name`) |
| `langgraph_ls_tool.json` | same bridge, agent-as-tool | wrapper `ask_trade_agent` is an `execute_tool` span with `gen_ai.tool.name`; tool `execute_trade` |
| `collector.jsonl` | OpenTelemetry Collector contrib 0.165.0 file exporter, 3 lines | generic spans (`root-1`, `root-2`, `raw-root`, `child2`, `child-llm`, `grandchild-tool`), no agent or tool markers; shows the file format (hex ids, string int64, absent root parent) |
| `jaeger_v3_trace.json` | Jaeger 2.23.0 `/api/v3/traces/<id>` (`{"result": ...}`) | one span `raw-root` |
| `jaeger_v3_search.json` | Jaeger v3 search, traces merged in one `result` | same generic spans as `collector.jsonl` |

Other files:

- `registry.yaml`: agents `supervisor` (entry, calls `trade-agent`) and `trade-agent`; tools
  `execute_trade` (high, `trade:execute`) and `delegate_trade` (low, `trade:delegate`). The
  wrapper `ask_trade_agent` is left out on purpose: it is an agent-as-tool wrapper, and tests
  pass it as `wrappers=("ask_trade_agent",)` to the catalog factory.
- `security-spec.yaml`: one case for `execute_trade` via `[supervisor, trade-agent]`.
- `observe.toml`: `[lockwalk]` registry and spec only, no inventory sources.

The `authz-check` spans and the `lockwalk.door.*` keys on some spans are door records from
the recording run (`lockwalk observe` reads them); `lockwalk.door.via_run_id` and `lockwalk.test.marker` are
attributes of that recording run only.
