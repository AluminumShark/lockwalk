"""Keep only what lockwalk needs from a Collector file of hermes_otel traces.

Usage: python scrub.py IN.jsonl OUT.jsonl [--edit-bypass]
Every attribute not in KEEP_SPAN / KEEP_RESOURCE is dropped, span events and links are dropped,
and user.id becomes DEMO_USER. Every kept value must also pass VALUE_RULES (and the span name
SPAN_NAME_RULE): a value that does not is an error that names the key, never the value.
--edit-bypass also turns hermes.tool.outcome "blocked" into "completed" (a hand-made BYPASS;
the example says so). It also gives the copy new trace and span ids, derived from the original
ids by a fixed salted hash, so the edited file can sit next to its source in one folder without
repeating its ids. The same input always gives the same output.

The scrubber fails closed: input that is not shaped like an OTLP JSON trace document, or a
kept value that breaks its rule, ends with exit code 2 and no output file.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

KEEP_SPAN = frozenset(
    {
        "openinference.span.kind",
        "gen_ai.operation.name",
        "gen_ai.agent.name",
        "gen_ai.tool.name",
        "gen_ai.tool.call.id",
        "gen_ai.system",
        "gen_ai.request.model",
        "tool.name",
        "hermes.platform",
        "hermes.session.is_subagent",
        "hermes.subagent.role",
        "hermes.subagent.status",
        "hermes.tool.outcome",
        "hermes.approval.granted",
        "hermes.approval.choice",
        "hermes.approval.pattern_key",
        "hermes.approval.surface",
        "hermes.approval.timed_out",
        "user.id",
    }
)
KEEP_RESOURCE = frozenset(
    {
        "service.name",
        "service.version",
        "telemetry.sdk.language",
        "telemetry.sdk.name",
        "telemetry.sdk.version",
    }
)
DEMO_USER = "cli:demo0001"
# Salt of the id rewrite of --edit-bypass. Changing it changes the edited file's ids.
ID_SALT = "lockwalk-hermes-edit-bypass-v1"
SPAN_FIELDS = frozenset(
    {
        "traceId",
        "spanId",
        "parentSpanId",
        "name",
        "kind",
        "startTimeUnixNano",
        "endTimeUnixNano",
        "attributes",
        "status",
        "flags",
    }
)

# Letters, digits and a few separators; no slash, so no path and no URL can pass.
SHAPE = re.compile(r"[A-Za-z0-9_.: -]{1,80}")
ID_SHAPE = re.compile(r"[A-Za-z0-9_-]{1,64}")
SPAN_NAME_RULE = SHAPE

# Rule per kept attribute: a frozenset (the only values allowed), a compiled pattern (the value
# must match all of it) or bool (the value must be a boolean). The sets hold the values seen in
# the recorded traces plus those documented by hermes_otel 1.18.2: classify_approval_choice(),
# HOOK_STATUS_TO_OUTCOME and the surfaces passed by tools/approval.py in Hermes. user.id is not
# here: it is replaced by DEMO_USER before any rule runs.
VALUE_RULES: dict[str, frozenset[str] | re.Pattern[str] | type[bool]] = {
    "hermes.tool.outcome": frozenset(
        {"completed", "blocked", "error", "timeout", "cancelled", "partial"}
    ),
    "hermes.approval.choice": frozenset(
        {
            "once",
            "session",
            "always",
            "deny",
            "timeout",
            "smart_approve",
            "smart_deny",
            "smart_escalate",
        }
    ),
    "hermes.approval.surface": frozenset({"cli", "gateway"}),
    "hermes.subagent.status": frozenset(
        {
            "completed",
            "complete",
            "ok",
            "success",
            "done",
            "error",
            "failed",
            "cancelled",
            "timeout",
        }
    ),
    "gen_ai.tool.call.id": ID_SHAPE,
    "gen_ai.agent.name": SHAPE,
    "gen_ai.tool.name": SHAPE,
    "tool.name": SHAPE,
    "hermes.approval.pattern_key": SHAPE,
    "hermes.subagent.role": SHAPE,
    "gen_ai.request.model": SHAPE,
    "gen_ai.system": SHAPE,
    "gen_ai.operation.name": SHAPE,
    "hermes.platform": SHAPE,
    "openinference.span.kind": SHAPE,
    "hermes.approval.granted": bool,
    "hermes.approval.timed_out": bool,
    "hermes.session.is_subagent": bool,
    "service.name": SHAPE,
    "service.version": SHAPE,
    "telemetry.sdk.language": SHAPE,
    "telemetry.sdk.name": SHAPE,
    "telemetry.sdk.version": SHAPE,
}

VALUE_TYPES = ("stringValue", "boolValue", "intValue")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX16 = re.compile(r"[0-9a-f]{16}")
DIGITS = re.compile(r"[0-9]{1,20}")


class ScrubError(Exception):
    """The scrubber refuses its input; the message never contains a value."""


class NotOtlp(ScrubError):
    """The input is not shaped like an OTLP JSON trace document."""


class ValueRejected(ScrubError):
    """A kept attribute value or the span name breaks its rule."""


def _need_list(node: object, where: str) -> list:
    if not isinstance(node, list):
        raise NotOtlp(f"{where} is not a list")
    return node


def _need_dict(node: object, where: str) -> dict:
    if not isinstance(node, dict):
        raise NotOtlp(f"{where} is not an object")
    return node


def _typed(key: str, value: dict) -> tuple[str, object]:
    """Return (type key, payload) of an OTLP any-value that holds one of VALUE_TYPES."""
    if len(value) != 1 or next(iter(value)) not in VALUE_TYPES:
        raise NotOtlp(f"attribute {key} has a value of an unexpected type")
    kind = next(iter(value))
    return kind, value[kind]


def _check_value(key: str, value: dict) -> None:
    kind, payload = _typed(key, value)
    rule = VALUE_RULES.get(key)
    if rule is None:
        raise ValueRejected(f"attribute {key} has no value rule")
    if rule is bool:
        if kind != "boolValue" or not isinstance(payload, bool):
            raise ValueRejected(f"attribute {key} must be a boolean")
        return
    if kind != "stringValue" or not isinstance(payload, str):
        raise ValueRejected(f"attribute {key} must be a string")
    ok = payload in rule if isinstance(rule, frozenset) else rule.fullmatch(payload) is not None
    if not ok:
        raise ValueRejected(f"attribute {key} has a value its rule does not allow")


def _attrs(items: object, keep: frozenset[str], where: str) -> list[dict]:
    """Kept attributes, sorted by key. Every item must be well formed, kept or not."""
    out: list[dict] = []
    for item in _need_list(items, where) if items is not None else []:
        item = _need_dict(item, f"{where} item")
        if not isinstance(item.get("key"), str) or not isinstance(item.get("value"), dict):
            raise NotOtlp(f"{where} item lacks a key or a value")
        key, value = item["key"], item["value"]
        if key not in keep:
            continue
        if key == "user.id":
            _typed(key, value)
            out.append({"key": key, "value": {"stringValue": DEMO_USER}})
            continue
        _check_value(key, value)
        out.append({"key": key, "value": value})
    return sorted(out, key=lambda a: a["key"])


def _bypass(attrs: list[dict]) -> list[dict]:
    """The hand edit of --edit-bypass: a blocked tool outcome becomes completed."""
    blocked = {"stringValue": "blocked"}
    return [
        {"key": a["key"], "value": {"stringValue": "completed"}}
        if a["key"] == "hermes.tool.outcome" and a["value"] == blocked
        else a
        for a in attrs
    ]


def _rewrite_id(kind: str, value: str, length: int) -> str:
    """A deterministic lowercase hex id of `length` chars derived from `value`, `kind` and the salt.

    The same original id always maps to the same new id, so a parent link and a trace id stay
    consistent across spans and across documents."""
    digest = hashlib.sha256(f"{ID_SALT}:{kind}:{value}".encode("ascii")).hexdigest()
    return digest[:length]


def _match(field: str, value: object, pattern: re.Pattern[str], optional: bool = False) -> None:
    if optional and value == "":
        return
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise NotOtlp(f"span field {field} is malformed")


def _span(span: dict, edit_bypass: bool) -> dict:
    kept = {k: v for k, v in span.items() if k in SPAN_FIELDS}
    _match("traceId", span.get("traceId"), HEX32)
    _match("spanId", span.get("spanId"), HEX16)
    _match("parentSpanId", span.get("parentSpanId", ""), HEX16, optional=True)
    _match("startTimeUnixNano", span.get("startTimeUnixNano"), DIGITS)
    _match("endTimeUnixNano", span.get("endTimeUnixNano"), DIGITS)
    name = span.get("name")
    if not isinstance(name, str) or SPAN_NAME_RULE.fullmatch(name) is None:
        raise ValueRejected("the span name does not match its rule")
    attrs = _attrs(span.get("attributes"), KEEP_SPAN, "span attributes")
    kept["attributes"] = _bypass(attrs) if edit_bypass else attrs
    if edit_bypass:
        # gen_ai.tool.call.id is left alone: it only has to agree between the spans of one trace,
        # and it does, since every span keeps its value.
        kept["traceId"] = _rewrite_id("trace", span["traceId"], 32)
        kept["spanId"] = _rewrite_id("span", span["spanId"], 16)
        if span.get("parentSpanId", ""):
            kept["parentSpanId"] = _rewrite_id("span", span["parentSpanId"], 16)
    if "status" in span:
        status = _need_dict(span["status"], "span status")
        kept["status"] = {"code": status["code"]} if "code" in status else {}
        if "code" in status and not isinstance(status["code"], int | str):
            raise NotOtlp("span status code is malformed")
    return kept


def scrub_document(doc: object, edit_bypass: bool = False) -> dict:
    """Return the scrubbed copy of one OTLP ExportTraceServiceRequest document."""
    doc = _need_dict(doc, "document")
    resource_spans = []
    for rs in _need_list(doc.get("resourceSpans"), "resourceSpans"):
        rs = _need_dict(rs, "resourceSpans item")
        resource = rs.get("resource", {})
        resource = _need_dict(resource, "resource")
        scopes = []
        for ss in _need_list(rs.get("scopeSpans"), "scopeSpans"):
            ss = _need_dict(ss, "scopeSpans item")
            scope = _need_dict(ss.get("scope", {}), "scope")
            kept_scope = {k: scope[k] for k in ("name", "version") if k in scope}
            for field, value in kept_scope.items():
                if not isinstance(value, str) or SHAPE.fullmatch(value) is None:
                    raise ValueRejected(f"scope {field} does not match its rule")
            spans = [
                _span(_need_dict(s, "span"), edit_bypass)
                for s in _need_list(ss.get("spans"), "spans")
            ]
            spans.sort(key=lambda s: (int(s["startTimeUnixNano"]), s["spanId"]))
            scopes.append({"scope": kept_scope, "spans": spans})
        resource_spans.append(
            {
                "resource": {
                    "attributes": _attrs(
                        resource.get("attributes"), KEEP_RESOURCE, "resource attributes"
                    )
                },
                "scopeSpans": scopes,
            }
        )
    return {"resourceSpans": resource_spans}


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--edit-bypass"]
    edit_bypass = len(args) != len(argv)
    if len(args) != 2:
        print("usage: python scrub.py IN.jsonl OUT.jsonl [--edit-bypass]", file=sys.stderr)
        return 2
    lines: list[str] = []
    with open(args[0], encoding="utf-8") as src:
        for number, line in enumerate(src, 1):
            if not line.strip():
                continue
            try:
                doc = scrub_document(json.loads(line), edit_bypass)
            except json.JSONDecodeError:
                print(f"{args[0]}:{number}: not JSON", file=sys.stderr)
                return 2
            except ScrubError as err:
                print(f"{args[0]}:{number}: {err}", file=sys.stderr)
                return 2
            lines.append(json.dumps(doc, sort_keys=True, separators=(",", ":")))
    if not lines:
        print(f"{args[0]}: no documents", file=sys.stderr)
        return 2
    with open(args[1], "w", encoding="utf-8", newline="\n") as dst:
        dst.write("".join(line + "\n" for line in lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
