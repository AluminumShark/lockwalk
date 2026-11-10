"""Test-only helpers for observe: a loose OTLP parser and a catalog factory.

loose_raw_spans is deliberately simple (no limits, no checks): it lets the recognition
and tree tests run on the real fixtures without depending on observe/otlp.py.
"""

import json
from pathlib import Path

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from typer.testing import CliRunner, Result

from lockwalk.cli import app
from lockwalk.models import DelegationMode, Risk
from lockwalk.observe.catalog import Catalog
from lockwalk.observe.results import OBSERVE_FILE_NAME
from lockwalk.observe.spans import RawSpan, ScalarValue

DATA = Path(__file__).resolve().parent / "observe_data"


def _value(any_value: dict) -> ScalarValue | None:
    for key in ("stringValue", "boolValue", "doubleValue"):
        if key in any_value:
            return any_value[key]
    if "intValue" in any_value:
        return int(any_value["intValue"])
    return None


def loose_raw_spans(name: str) -> list[RawSpan]:
    """Every span of tests/observe_data/<name>, keeping all scalar attributes."""
    text = (DATA / name).read_text(encoding="utf-8")
    if name.endswith(".json"):
        documents = [json.loads(text)]
    else:
        documents = [json.loads(line) for line in text.splitlines() if line.strip()]
    spans: list[RawSpan] = []
    for document in documents:
        spans.extend(loose_raw_spans_from_document(document.get("result", document), name))
    return spans


# delegate_trade is an ordinary tool in tests/observe_data/registry.yaml (not a wrapper), so
# its default tool edge below is right.
def catalog(
    *,
    agents: tuple[str, ...] = ("supervisor", "trade-agent"),
    tools: tuple[str, ...] = ("execute_trade", "delegate_trade"),
    entry: tuple[str, ...] = ("supervisor",),
    agent_edges: tuple[tuple[str, str], ...] = (("supervisor", "trade-agent"),),
    tool_edges: tuple[tuple[str, str], ...] = (
        ("trade-agent", "execute_trade"),
        ("supervisor", "delegate_trade"),
    ),
    wrappers: tuple[str, ...] = (),
    agent_alias: dict[str, str] | None = None,
    tool_alias: dict[str, str] | None = None,
    risks: dict[str, Risk] | None = None,
    modes: dict[str, DelegationMode | None] | None = None,
    case_routes: tuple[tuple[tuple[str, ...], str], ...] = (),
    case_agents: tuple[tuple[str, str], ...] = (),
) -> Catalog:
    return Catalog(
        agents=frozenset(agents),
        tools=frozenset(tools),
        wrappers=frozenset(wrappers),
        entry_agents=frozenset(entry),
        agent_alias=agent_alias or {},
        tool_alias=tool_alias or {},
        agent_edges=frozenset(agent_edges),
        tool_edges=frozenset(tool_edges),
        risks=risks or {},
        modes=modes or {},
        case_routes=frozenset(case_routes),
        case_agents=frozenset(case_agents),
    )


def _without_doors(value: object) -> object:
    """The JSON value with every lockwalk.door.* and lockwalk.effect attribute removed."""
    if isinstance(value, list):
        return [
            _without_doors(item)
            for item in value
            if not (
                isinstance(item, dict)
                and isinstance(item.get("key"), str)
                and (item["key"].startswith("lockwalk.door.") or item["key"] == "lockwalk.effect")
            )
        ]
    if isinstance(value, dict):
        return {key: _without_doors(item) for key, item in value.items()}
    return value


def copy_without_doors(source: Path, target_dir: Path) -> Path:
    """Copy an OTLP .json or .jsonl fixture into target_dir with the door attributes removed.

    Route tests check routes; the fixtures also carry a partial door record on purpose,
    which the door tests read. This keeps the route tests on routes.
    """
    text = source.read_text(encoding="utf-8")
    if source.suffix == ".jsonl":
        lines = [json.dumps(_without_doors(json.loads(x))) for x in text.splitlines() if x.strip()]
        out = "\n".join(lines) + "\n"
    else:
        out = json.dumps(_without_doors(json.loads(text)))
    target = target_dir / source.name
    target.write_text(out, encoding="utf-8")
    return target


def otlp_json_from_sdk_spans(spans) -> dict:
    """Convert finished OTel SDK spans (ReadableSpan) to an OTLP JSON document."""

    def any_value(value) -> dict:
        # Test-only: sequences are stringified (real OTLP has arrayValue), and a span with no
        # end time would be written as "None" (loose_raw_spans_from_document reads a missing
        # end time as None; the SDK always sets one for finished spans).
        if isinstance(value, bool):
            return {"boolValue": value}
        if isinstance(value, int):
            return {"intValue": str(value)}
        if isinstance(value, float):
            return {"doubleValue": value}
        return {"stringValue": str(value)}

    out = []
    for span in spans:
        context = span.get_span_context()
        item = {
            "traceId": format(context.trace_id, "032x"),
            "spanId": format(context.span_id, "016x"),
            "name": span.name,
            "startTimeUnixNano": str(span.start_time),
            "endTimeUnixNano": str(span.end_time),
            "attributes": [
                {"key": key, "value": any_value(value)}
                for key, value in (span.attributes or {}).items()
            ],
        }
        if span.parent is not None:
            item["parentSpanId"] = format(span.parent.span_id, "016x")
        out.append(item)
    return {"resourceSpans": [{"scopeSpans": [{"spans": out}]}]}


def loose_raw_spans_from_document(document: dict, where: str = "memory") -> list[RawSpan]:
    """Spans of an OTLP JSON document already in memory (loose_raw_spans uses this)."""
    spans: list[RawSpan] = []
    for resource in document["resourceSpans"]:
        for scope in resource.get("scopeSpans", []):
            for span in scope.get("spans", []):
                attributes: dict[str, ScalarValue] = {
                    item["key"]: value
                    for item in span.get("attributes", [])
                    if (value := _value(item.get("value", {}))) is not None
                }
                start = span.get("startTimeUnixNano")
                end = span.get("endTimeUnixNano")
                spans.append(
                    RawSpan(
                        trace_id=span["traceId"].lower(),
                        span_id=span["spanId"].lower(),
                        parent_id=(span.get("parentSpanId") or "").lower() or None,
                        name=span.get("name", ""),
                        start_ns=int(start) if start is not None else None,
                        end_ns=int(end) if end is not None else None,
                        attributes=attributes,
                        where=f"{where}:1",
                    )
                )
    return spans


REGISTRY = """\
schema_version: '1'
agents:
  - id: supervisor
    description: Entry agent; hands work to trade-agent.
    entry: true
    delegation_mode: user
    calls: [trade-agent]
  - id: trade-agent
    description: Executes trades with its own identity.
    delegation_mode: agent
tools:
  - id: execute_trade
    action: trade:execute
    risk: high
    resource_type: order
    supported_agents: [trade-agent]
  - id: delegate_trade
    action: trade:delegate
    risk: low
    supported_agents: [supervisor]
"""

runner = CliRunner()


def make_config(tmp_path: Path, extra: str = "") -> Path:
    (tmp_path / "registry.yaml").write_text(REGISTRY, encoding="utf-8")
    config = tmp_path / "doors.toml"
    spec = (DATA / "security-spec.yaml").as_posix()
    config.write_text(
        f'[lockwalk]\nregistry = "registry.yaml"\nspec = "{spec}"\n{extra}', encoding="utf-8"
    )
    return config


def observe(
    tmp_path: Path, *traces: Path, extra: str = "", args: tuple[str, ...] = ()
) -> tuple[Result, dict]:
    out = tmp_path / "out"
    command = ["observe", "--config", str(make_config(tmp_path, extra)), "--output-dir", str(out)]
    for item in traces:
        command += ["--traces", str(item)]
    result = runner.invoke(app, [*command, *args])
    path = out / OBSERVE_FILE_NAME
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return result, report


def rules(report: dict) -> list[str]:
    return [v["rule"] for v in report["gate"]["violations"]]


def only_guard(report: dict) -> dict[str, int]:
    (row,) = report["guards"]
    return row["counts"]


class Sdk:
    """A private provider and the spans it finished."""

    def __init__(self, provider: TracerProvider, exporter: InMemorySpanExporter) -> None:
        self.provider = provider
        self.exporter = exporter

    def get_tracer(self, name: str) -> trace.Tracer:
        return self.provider.get_tracer(name)

    def finished(self):
        return self.exporter.get_finished_spans()
