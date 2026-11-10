#!/usr/bin/env bash
# Record Hermes Agent traces with a fake model and scrub them into examples/hermes/traces/.
# Run it in WSL or Linux. See README.md. Nothing outside $WORK and the example folder is
# touched: ~/.hermes and shell rc files are never used, and no Docker image is ever pulled.
#
# Env read by this script (all optional):
#   LOCKWALK_HERMES_WORK        work folder (default ~/.cache/lockwalk-hermes-record); an
#                               absolute path without spaces, containing "lockwalk"
#   LOCKWALK_HERMES_MODEL_PORT  fake model port on 127.0.0.1 (default 18080)
set -euo pipefail

# --- pinned versions: edit these when upgrading (see README.md, "Upgrading") ------------------
HERMES_COMMIT=93c7aeebc816000a365e1ecd6df9bf53f45e842c
HERMES_URL=https://github.com/NousResearch/hermes-agent
PLUGIN_VERSION=1.18.2
COLLECTOR_IMAGE=otel/opentelemetry-collector-contrib:0.165.0

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXAMPLE=$(cd "$HERE/.." && pwd)
export PATH="$HOME/.local/bin:$PATH"  # uv, when the shell is not a login shell
WORK=${LOCKWALK_HERMES_WORK:-$HOME/.cache/lockwalk-hermes-record}
PORT=${LOCKWALK_HERMES_MODEL_PORT:-18080}
COLLECTOR_NAME=lockwalk-hermes-collector
COLLECTOR_PORT=4318

export HERMES_HOME=$WORK/home
export FAKE_LOG=$WORK/fake_model.log
HERMES_DIR=$WORK/hermes-agent
VENV=$WORK/venv
OUT=$WORK/out
SCRATCH=$WORK/scratch
STAMP=$WORK/pinned-versions
FAKE_PID=""
STAGE=""

say() { printf '== %s\n' "$*"; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but was not found"; }

cleanup() {
    set +e
    [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null
    docker rm -f "$COLLECTOR_NAME" >/dev/null 2>&1
    # Without --all, "gateway stop" only touches the gateway of the current HERMES_HOME.
    [ -x "$VENV/bin/hermes" ] && PATH="$VENV/bin:$PATH" hermes gateway stop >/dev/null 2>&1
    [ -n "$STAGE" ] && rm -rf "$STAGE"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- requirements ----------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "run this in WSL or on Linux"
for tool in docker uv git curl python3; do need "$tool"; done
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable ('docker info' failed)"
docker image inspect "$COLLECTOR_IMAGE" >/dev/null 2>&1 ||
    die "Docker image $COLLECTOR_IMAGE is missing. This script never pulls images: run 'docker pull $COLLECTOR_IMAGE' yourself, then start again."
case $WORK in
/*) ;;
*) die "LOCKWALK_HERMES_WORK must be an absolute path" ;;
esac
case $WORK in
*[!A-Za-z0-9_./-]*) die "LOCKWALK_HERMES_WORK may only hold letters, digits and _ . / - (no spaces)" ;;
esac
case $WORK in
*lockwalk*) ;;
*) die "LOCKWALK_HERMES_WORK must contain 'lockwalk' (the fake model removes a folder inside it)" ;;
esac
case $PORT in
'' | *[!0-9]*) die "LOCKWALK_HERMES_MODEL_PORT must be a number" ;;
esac

port_free() {
    python3 - "$1" <<'PY'
import socket
import sys

with socket.socket() as sock:
    try:
        sock.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        sys.exit(1)
PY
}

docker rm -f "$COLLECTOR_NAME" >/dev/null 2>&1 || true  # a leftover of an earlier run
port_free "$COLLECTOR_PORT" || die "port $COLLECTOR_PORT on 127.0.0.1 is in use"
port_free "$PORT" || die "port $PORT on 127.0.0.1 is in use (set LOCKWALK_HERMES_MODEL_PORT)"

mkdir -p "$WORK" "$HERMES_HOME" "$OUT" "$SCRATCH" "$WORK/cwd"
chmod 777 "$OUT"  # the Collector container writes here as a non-root user
STAGE=$(mktemp -d "$WORK/stage.XXXXXX")

# --- Hermes at the pinned commit, in its own venv --------------------------------------------
if [ "$(cat "$STAMP" 2>/dev/null || true)" != "$HERMES_COMMIT $PLUGIN_VERSION" ]; then
    say "pinned versions changed: rebuilding the venv and the plugin"
    rm -rf "$VENV" "$HERMES_HOME/plugins/hermes_otel" "$STAMP"
fi
if [ ! -d "$HERMES_DIR/.git" ]; then
    say "cloning Hermes"
    git clone --quiet "$HERMES_URL" "$HERMES_DIR"
fi
git -C "$HERMES_DIR" cat-file -e "$HERMES_COMMIT^{commit}" 2>/dev/null ||
    git -C "$HERMES_DIR" fetch --quiet origin
git -C "$HERMES_DIR" checkout --quiet "$HERMES_COMMIT"
if [ ! -x "$VENV/bin/hermes" ]; then
    say "installing Hermes (Python 3.14)"
    uv venv --quiet --python 3.14 "$VENV" ||
        die "'uv venv --python 3.14' failed; uv can download Python 3.14 itself, so check the network"
    # Run from inside the Hermes folder: its [tool.uv] overrides are needed.
    (cd "$HERMES_DIR" && uv pip install --quiet --python "$VENV/bin/python" -e .)
fi
export PATH="$VENV/bin:$PATH"

# --- the hermes_otel plugin, and its config --------------------------------------------------
PLUGIN_DIR=$HERMES_HOME/plugins/hermes_otel
if [ ! -d "$PLUGIN_DIR" ]; then
    say "installing hermes_otel"
    hermes plugins install hermes_otel --yes-deps --no-enable </dev/null
fi
hermes plugins enable hermes_otel </dev/null || true
grep -qx "version: $PLUGIN_VERSION" "$PLUGIN_DIR/plugin.yaml" ||
    die "hermes_otel $PLUGIN_VERSION is required; found: $(grep '^version:' "$PLUGIN_DIR/plugin.yaml")"
printf '%s %s\n' "$HERMES_COMMIT" "$PLUGIN_VERSION" >"$STAMP"
cat >"$HERMES_HOME/hermes_otel.yaml" <<EOF
project_name: lockwalk-hermes-example
backends:
  - type: otlp
    endpoint: http://127.0.0.1:$COLLECTOR_PORT/v1/traces
content_capture: "off"
capture_sender_id: true
EOF

# --- the model: a fake server on 127.0.0.1 ---------------------------------------------------
hermes config set model.provider custom
hermes config set model.base_url "http://127.0.0.1:$PORT/v1"
hermes config set model.default fake-model
hermes config set model.api_key dummy-key
hermes gateway stop >/dev/null 2>&1 || true  # a running gateway would keep the old config

: >"$FAKE_LOG"
python3 "$HERE/fake_model.py" "$PORT" "$SCRATCH" &
FAKE_PID=$!
up=""
for _ in $(seq 1 50); do
    kill -0 "$FAKE_PID" 2>/dev/null || die "the fake model exited at startup"
    if curl -fs "http://127.0.0.1:$PORT/v1/models" 2>/dev/null | grep -q lockwalk-fake-model; then
        up=yes
        break
    fi
    sleep 0.2
done
[ -n "$up" ] || die "the fake model did not answer on port $PORT"

# --- scenarios -------------------------------------------------------------------------------
write_collector_config() {
    cat >"$WORK/collector.yaml" <<EOF
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:$COLLECTOR_PORT
exporters:
  file:
    path: /out/$1.raw.jsonl
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
EOF
}

# wait_stable FILE SECONDS CAP: succeed once FILE is non-empty and has not grown for SECONDS.
wait_stable() {
    local file=$1 need_same=$2 cap=$3 last=-1 same=0 i=0 size
    while [ "$i" -lt "$cap" ]; do
        size=$(stat -c %s "$file" 2>/dev/null || echo 0)
        if [ "$size" -gt 0 ] && [ "$size" = "$last" ]; then same=$((same + 1)); else same=0; fi
        [ "$same" -ge "$need_same" ] && return 0
        last=$size
        i=$((i + 1))
        sleep 1
    done
    return 1
}

record() { # record NAME COMMAND...
    local name=$1 raw
    shift
    raw=$OUT/$name.raw.jsonl
    say "recording $name"
    rm -f "$raw"
    mkdir -p "$SCRATCH/victim"
    write_collector_config "$name"
    docker run --pull=never --rm -d --name "$COLLECTOR_NAME" -p "127.0.0.1:$COLLECTOR_PORT:$COLLECTOR_PORT" \
        -v "$WORK/collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
        -v "$OUT:/out" "$COLLECTOR_IMAGE" >/dev/null
    sleep 3
    if ! (cd "$WORK/cwd" && "$@") </dev/null; then
        die "the $name command failed"
    fi
    wait_stable "$raw" 4 60 || die "no spans were recorded for $name"
    hermes gateway stop >/dev/null 2>&1 || true
    wait_stable "$raw" 3 20 || true  # the gateway may export a last batch while it stops
    docker stop -t 10 "$COLLECTOR_NAME" >/dev/null
    while docker inspect "$COLLECTOR_NAME" >/dev/null 2>&1; do sleep 0.5; done  # --rm removes it late
    [ -s "$raw" ] || die "no spans were recorded for $name"
}

model_args=(--provider custom --base-url "http://127.0.0.1:$PORT/v1" --api-key dummy-key -m fake-model)

record delegate hermes chat -q "[DELEGATE] go" "${model_args[@]}"
record approve_allow python3 "$HERE/drive_approval.py" "[DANGER]" allow "$PORT"
record approve_deny python3 "$HERE/drive_approval.py" "[DANGER]" deny "$PORT"
record unattended_block hermes chat -q "[DANGER] go" "${model_args[@]}"

# --- scrub into a staging folder, validate, then move everything at once --------------------
for name in delegate approve_allow approve_deny unattended_block; do
    python3 "$HERE/scrub.py" "$OUT/$name.raw.jsonl" "$STAGE/$name.jsonl" || die "scrubbing $name failed"
done
python3 "$HERE/scrub.py" "$OUT/approve_deny.raw.jsonl" "$STAGE/bypass_edited.jsonl" --edit-bypass ||
    die "scrubbing bypass_edited failed"

# --- tool inventory: names and parameter shapes only, no Hermes text -------------------------
(cd "$HERMES_DIR" && "$VENV/bin/python" - "$STAGE/tools.json" <<'PY'
import json
import sys

from model_tools import get_tool_definitions


def strip(node, names=False):
    """Drop description annotations. Keys of a "properties" mapping are parameter names."""
    if isinstance(node, dict):
        return {
            k: strip(v, k == "properties" and not names)
            for k, v in node.items()
            if names or k != "description"
        }
    if isinstance(node, list):
        return [strip(v) for v in node]
    return node


tools = []
for item in get_tool_definitions(quiet_mode=True):
    fn = item.get("function", item)
    tools.append({"name": fn["name"], "description": "", "parameters": strip(fn.get("parameters", {}))})
tools.sort(key=lambda t: t["name"])
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as out:
    json.dump({"tools": tools}, out, indent=1, sort_keys=True)
    out.write("\n")
print(len(tools), "tools")
PY
) || die "the tool export failed"

python3 - "$STAGE" <<'PY' || die "a scrubbed trace does not look like its scenario"
import json
import sys
from pathlib import Path

stage = Path(sys.argv[1])
problems = []


def spans_of(name):
    out = []
    for line in (stage / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        for rs in json.loads(line)["resourceSpans"]:
            for ss in rs["scopeSpans"]:
                for span in ss["spans"]:
                    attrs = {a["key"]: next(iter(a["value"].values())) for a in span["attributes"]}
                    out.append((span["name"], attrs))
    return out


def check(ok, message):
    if not ok:
        problems.append(message)


def tool_outcome(spans):
    return [a.get("hermes.tool.outcome") for n, a in spans if n == "tool.terminal"]


for name, granted, outcome in (
    ("approve_allow", True, "completed"),
    ("approve_deny", False, "blocked"),
    ("bypass_edited", False, "completed"),
):
    spans = spans_of(name)
    approvals = [a for n, a in spans if n.startswith("approval.")]
    check(len(approvals) == 1, f"{name}: expected one approval span, found {len(approvals)}")
    check(all(a.get("hermes.approval.granted") is granted for a in approvals), f"{name}: wrong granted value")
    check(tool_outcome(spans) == [outcome], f"{name}: wrong terminal outcome")

spans = spans_of("unattended_block")
check(not [n for n, _ in spans if n.startswith("approval.")], "unattended_block: has an approval span")
check(tool_outcome(spans) == ["blocked"], "unattended_block: terminal outcome is not blocked")

spans = spans_of("delegate")
check(any(n == "subagent.leaf" for n, _ in spans), "delegate: no subagent.leaf span")
check(
    any(n == "agent" and a.get("hermes.platform") == "subagent" for n, a in spans),
    "delegate: no child agent span",
)
check(tool_outcome(spans) == ["completed"], "delegate: terminal outcome is not completed")

for problem in problems:
    print(problem, file=sys.stderr)
sys.exit(1 if problems else 0)
PY

mkdir -p "$EXAMPLE/traces"
mv "$STAGE"/*.jsonl "$EXAMPLE/traces/"
mv "$STAGE/tools.json" "$EXAMPLE/tools.json"
say "done: $EXAMPLE/traces and $EXAMPLE/tools.json"
