# Recording Hermes Agent traces

`record.sh` makes the scrubbed traces in `../traces/` and the tool list `../tools.json`.
It drives a real Hermes Agent against a fake model (no LLM, no API key), captures its
OpenTelemetry output with a local Collector, scrubs the result, checks that each trace looks
like its scenario, and only then writes the files (all of them, or none).

## Requirements

- WSL Ubuntu or Linux (Hermes runs there only; `drive_approval.py` needs a Linux pty).
- Docker, with the image `otel/opentelemetry-collector-contrib:0.165.0` already pulled.
  The script never pulls images; if the image is missing it stops and says so.
- `uv`, `git`, `python3`, `curl`, and network access to clone Hermes and install packages.
- Pinned versions (constants at the top of `record.sh`):
  - Hermes Agent at git commit `93c7aeebc816000a365e1ecd6df9bf53f45e842c`, on Python 3.14
    (PyPI's `hermes-agent` is too old);
  - the `hermes_otel` plugin, version 1.18.2 (the script stops if it finds another version);
  - Collector 0.165.0.

## Run

```bash
bash examples/hermes/record/record.sh
```

Do not run `uv` against the lockwalk checkout from WSL; run lockwalk checks from Windows or
from a separate Linux clone.

### Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `LOCKWALK_HERMES_WORK` | `record.sh` | Work folder, default `~/.cache/lockwalk-hermes-record`. Absolute, letters/digits/`_./-` only, and it must contain `lockwalk`. |
| `LOCKWALK_HERMES_MODEL_PORT` | `record.sh` | Fake model port on 127.0.0.1, default 18080. The Collector always uses 4318. Both must be free. |
| `FAKE_LOG` | `fake_model.py` | Log path (roles and tool names only). `record.sh` sets it inside the work folder. |
| `TRANSCRIPT` | `drive_approval.py` | Optional path for the pty transcript. It is raw output (command text, local paths): never commit it. |

Everything lives under the work folder: the Hermes clone, its venv, a private `HERMES_HOME`
and the raw Collector output. The script never touches `~/.hermes` or shell rc files. All
ports are bound to 127.0.0.1. A trap stops the fake model, the Collector container and the
Hermes gateway on every exit. `hermes gateway stop` is called without `--all`, so it only
stops the gateway of the private `HERMES_HOME`.

## What gets written

| File | Scenario |
|---|---|
| `traces/delegate.jsonl` | `delegate_task` starts a sub-agent that runs one harmless command |
| `traces/approve_allow.jsonl` | a dangerous command; the approval menu is answered "allow once" |
| `traces/approve_deny.jsonl` | the same, answered "deny" |
| `traces/unattended_block.jsonl` | the same in single-query mode, which denies on its own (no approval span) |
| `traces/bypass_edited.jsonl` | `approve_deny` after `scrub.py --edit-bypass` changed its `hermes.tool.outcome` from `blocked` to `completed`, with its own trace and span ids (a salted hash of the originals): a made-up BYPASS, not a real run |
| `tools.json` | the tool names and parameter shapes from `get_tool_definitions()`; all descriptions are emptied |

## Scrubbing

`scrub.py IN OUT [--edit-bypass]` keeps only the attributes listed in `KEEP_SPAN` and
`KEEP_RESOURCE` in that file (the one source of truth; this README does not copy the list).
Span events, links and status messages are dropped, and `user.id` becomes `cli:demo0001`.

It also checks values, not only names. `VALUE_RULES` gives each kept attribute either a set
of allowed values (`hermes.tool.outcome`, `hermes.approval.choice`, `hermes.approval.surface`,
`hermes.subagent.status`), a boolean type, or a strict shape (letters, digits and `_.: -`,
at most 80 characters, so no path or URL passes). A value that breaks its rule stops the run
with an error that names the key, never the value. Input that is not shaped like OTLP JSON
also stops the run. The plugin runs with `content_capture: "off"`, so prompts and tool output
never reach the Collector either.

## Upgrading

1. Edit `HERMES_COMMIT`, `PLUGIN_VERSION` and `COLLECTOR_IMAGE` at the top of `record.sh`
   (and pull the new Collector image yourself). When the first two change, the script
   notices (it keeps a stamp file in the work folder) and rebuilds the venv and the plugin
   itself. To force it, delete `$WORK/venv` and `$WORK/home/plugins/hermes_otel`.
2. Run `record.sh` again.
3. Review `git diff` of `traces/` and `tools.json`.
4. Re-check what an upgrade can change:
   - the approval menu text and order (`drive_approval.py` waits for "Dangerous Command" and
     "to select, Enter to confirm", and presses Down three times for "deny");
   - attribute keys against `KEEP_SPAN`/`KEEP_RESOURCE` and values against `VALUE_RULES`
     (a new `choice`, `surface`, `outcome` or `status` value stops the run until the set is
     extended on purpose);
   - new `hermes.approval.pattern_key` or `hermes.subagent.status` values;
   - span names and counts per trace (compare with the previous traces).
5. Update the pinned results in the example's tests only after you have read the diff.
