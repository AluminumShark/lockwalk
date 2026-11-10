# Finance demo

A tiny, fake finance system. It is the sample project that the repository's own
`.lockwalk.toml` points at, so you can run `lockwalk` from a clone of this repository, and it
is the input of many of the tests. The quick start in the main README has its own files.
Nothing here touches real data, real trades, or any network service.

| File | What it is |
|---|---|
| `registry.yaml` | Hand-written agents and tools, with each tool's risk. Both agents talk to users directly (`entry: true`) and call no other agent (`calls: []`) |
| `security-spec.yaml` | Hand-written expected answers (four cases) |
| `mcp_server.py` | MCP server with four stub tools; `delete_portfolio` is missing from the registry and the spec on purpose |
| `langchain_tools.py` | The same tools written with LangChain `@tool` (needs `langchain-core`) |
| `tools.json` | The same tools as an OpenAI-style JSON export |

From the repository root:

```bash
uv run lockwalk discover   # uses ./.lockwalk.toml at the repository root: registry + MCP server
uv run lockwalk coverage   # exits 1: delete_portfolio has no spec and unknown risk
uv run lockwalk discover --python examples.finance_agent.langchain_tools:FINANCE_TOOLS
```

`discover` and `coverage` also draw the agent graph: a small tree for each agent, listing the tools
that `supported_agents` in the registry gives it. For agents that call other agents, see
the [multi-agent demo](../multi_agent/README.md).
