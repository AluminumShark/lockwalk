# Contributing to lockwalk

Issues and pull requests are welcome. For a change to behaviour, please open an issue first so we
can agree on it.

## Set up

lockwalk uses [uv](https://docs.astral.sh/uv/). Python 3.11 or newer.

```bash
uv sync
```

## Check your work

```bash
uv run ruff check
uv run ruff format --check
uv run ty check
uv run pytest -q -rs -m "not docker"
```

Tests never call a real model or the network, apart from 127.0.0.1 and local containers. Please
keep it that way.

### Docker tests

Some tests run real policy engines and an OpenTelemetry Collector in containers. They never pull
an image: a test skips itself when its image is missing, so pull the images first. The list is in
the `docker` job of [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

```bash
uv run pytest -q -rs -m docker --ignore=tests/crewai_env
```

### CrewAI tests

CrewAI cannot share an environment with the other frameworks: it pins `openai<3` and `mcp` 1.x,
while the dev group and the `mcp` extra need `mcp` 2.3 or later. So its tests have their own
virtual environment and need Python below 3.14.

```bash
UV_PROJECT_ENVIRONMENT=.venv-crewai uv run --no-default-groups --group crewai pytest -q tests/crewai_env
```

On PowerShell:

```powershell
$env:UV_PROJECT_ENVIRONMENT = ".venv-crewai"; uv run --no-default-groups --group crewai pytest -q tests/crewai_env
```

### Hermes Agent traces

The traces in [`examples/hermes`](examples/hermes/README.md) were recorded from a real Hermes Agent
against a fake model. Tests only read the recordings. To record them again, see
[`examples/hermes/record`](examples/hermes/record/README.md).

## How lockwalk is built

These rules decide most reviews.

- **Generic first.** Every source is normalized to one tool description, and an IAM is reached
  through AuthZEN or one Python function. Do not add a vendor adapter to the core. If something
  cannot be done generically, document the limit.
- **Unknown is never a pass.** When lockwalk cannot tell, the result is `INCONCLUSIVE`, `UNKNOWN` or
  `ERROR`, and the gate treats it that way.
- **A likely mistake fails or warns by one rule.** It fails the run when it silently weakens a check
  and no documented valid use looks the same. It warns when a documented valid use looks identical.
- **Input is hostile.** Anything read from a tool, a server, a trace or a report is untrusted: run
  in linear time on it, escape it before printing it, and never let it reach a shell or Markdown
  unquoted.
- **Secrets and user ids stay out.** Never put them in reports, output or error text on purpose,
  and mask every value lockwalk knows is secret. Masking is best effort: lockwalk cannot
  recognize a secret it was not told about, so do not add code that prints one. Mask first, then
  truncate.
- **Comments stand alone.** Write comments and docstrings in English, and explain why in the comment
  itself. A reader has nothing else to look at.

## Pull requests

- Write the failing test first, and keep each pull request to one change.
- Python files are ASCII. Write non-ASCII test input as escapes (for example `"\u522a"`).
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) for anything a user would notice.
- CI must be green. Workflow changes keep actions pinned to a full commit SHA.
