"""lockwalk test through the CLI against a fake PDP that echoes every secret it is given.

Header values, URL credentials, and URL query tokens must not appear in the terminal output
or in coverage.json, whatever the PDP puts into its reasons.
"""

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest
from lockwalk_authzen_server import FakePdp
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from typer.testing import CliRunner

from lockwalk import cli

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "multi_agent"
TOKEN = "TOK3N-ABCDEF123456"
SECRETS = (TOKEN, "ABCDEF123456", "URLTOKEN", "P4SS", "QSECRET")


def echoing(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
    reason = f"saw {headers.get('authorization', '')} and https://u:P4SS@x.example/p?k=QSECRET"
    items = body.get("evaluations", [body])
    answers = [{"decision": n % 3 != 0, "context": {"reason": reason}} for n in range(len(items))]
    if "evaluations" in body:
        return 200, {"evaluations": answers}, 0.0
    return 200, answers[0], 0.0


def test_no_secret_reaches_the_output_or_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PDP_TOKEN", TOKEN)
    out = tmp_path / "out"
    with FakePdp(echoing) as pdp:
        config = tmp_path / ".lockwalk.toml"
        config.write_text(
            textwrap.dedent(
                f"""\
                [lockwalk]
                registry = "{(EXAMPLE / "registry.yaml").as_posix()}"
                spec = "{(EXAMPLE / "security-spec.yaml").as_posix()}"
                fixtures = "{(EXAMPLE / "fixtures.yaml").as_posix()}"

                [[inventory.python]]
                target = "{(EXAMPLE / "app.py").as_posix()}:OPENAI_ENTRY_AGENTS"

                [[inventory.python]]
                target = "{(EXAMPLE / "app.py").as_posix()}:pricing_agent"

                [policy]
                adapter = "authzen"
                url = "{pdp.url}/pre?token=URLTOKEN"
                headers = {{ Authorization = "Bearer ${{PDP_TOKEN}}" }}
                """
            ),
            encoding="utf-8",
        )
        result = CliRunner().invoke(
            cli.app, ["test", "--config", str(config), "--output-dir", str(out)]
        )
        assert pdp.requests, "the PDP was never asked"
    assert result.exit_code in (0, 1), result.output
    text = result.output + (out / "coverage.json").read_text(encoding="utf-8")
    evidence_file = out / "evidence.jsonl"
    assert evidence_file.exists()
    text += evidence_file.read_text(encoding="utf-8")
    report: dict[str, Any] = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    assert report["mode"] == "test"
    for secret in SECRETS:
        assert secret not in text, secret
    reasons = [
        answer["reason"]
        for case in report["cases"]
        if case.get("decision")
        for hop in case["decision"]["hops"]
        for answer in hop["answers"]
        if answer.get("reason")
    ]
    assert reasons, "the echoed reasons should appear, masked"
