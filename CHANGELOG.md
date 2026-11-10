# Changelog

All notable changes to lockwalk are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

First release.

### Commands

- `lockwalk discover` lists the agents and tools lockwalk finds, from the registry and from
  MCP servers, Python tool objects and tool description files.
- `lockwalk coverage` maps which agents and roles can reach which tools, finds tools with no
  authorization spec, and applies a gate that exits 1 when a finding blocks. It never runs an
  agent or a tool, and writes `coverage.json`.
- `lockwalk test` runs everything `coverage` runs, then asks your own policy engine the
  questions in your spec. An optional `[harness]` also calls your tools in a test subprocess
  to check that a denied call does not run them.
- `lockwalk observe` reads real traces (OTLP JSON, or your own reader function) and compares
  the routes the agents took with the map. Records written at the enforcement point (the
  code that decides whether a tool may run) with `lockwalk.record` add identity,
  unguarded-call and bypass checks.
- `lockwalk inspect` shows how one trace was read, or the evidence behind one case.
- `lockwalk diff` compares two `coverage.json` reports and prints what changed, as text,
  JSON or Markdown for a pull request comment.

### Also included

- Waivers: accepted risks with an owner and an expiry date. A waived finding stays in the
  report and stops blocking the gate until the waiver expires.
- `lockwalk.record`: helpers that write the trace attributes `observe` reads
  (`record_authz` and `record_effect`; install `lockwalk[otel]`).
- Examples: a finance demo, a multi-agent demo, Hermes, Cedar and Cerbos setups, IAM recipes,
  and a GitHub Actions workflow to copy.
