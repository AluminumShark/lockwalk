"""Run one scripted job: put in every fake model, then start the route."""

import contextlib

from lockwalk.harness import fake_langchain, fake_openai, fake_pydantic
from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import ScriptedJob
from lockwalk.harness.script import NotRun, Script

FAKES = {
    "openai_agents": fake_openai,
    "pydantic_ai": fake_pydantic,
    "langgraph": fake_langchain,
}


def run(job: ScriptedJob, script: Script, found: Found) -> None:
    """Start job.route[0] with every model replaced. NotRun says why it cannot run.

    Fakes go in for every framework, not just the entry agent's, so no agent the run
    reaches can call a real model.
    """
    entry = job.route[0]
    if entry not in found.agents:
        raise NotRun(f"agent {entry!r} was not found in the [[inventory.python]] targets")
    framework = found.frameworks.get(entry, "other")
    fake = FAKES.get(framework)
    if fake is None:
        raise NotRun(
            f"scripted mode does not support {framework} agents; provide run_path in the hooks file"
        )
    with contextlib.ExitStack() as stack:
        for module in FAKES.values():
            module.install(script, found, stack)
        fake.start(job, found)
