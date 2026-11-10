"""Load and validate security-spec.yaml: the hand-written expected answers.

The expected answers must never be derived from a policy engine. If they were, a wrong
policy would produce a wrong answer key, and the mistake could never be caught.
"""

from pathlib import Path

from pydantic import ValidationError

from lockwalk.errors import StructuralError, format_validation_error
from lockwalk.models import Frozen, NeverReachesRule, NonEmptyStr, SchemaVersion, TestScenario
from lockwalk.yamlio import load_yaml


class SpecFile(Frozen):
    schema_version: SchemaVersion
    scenario_suite: NonEmptyStr
    cases: tuple[TestScenario, ...]
    never_reaches: tuple[NeverReachesRule, ...] = ()

    def tool_names(self) -> set[str]:
        """Names of every tool that at least one case targets."""
        return {case.tool for case in self.cases}


def load_spec(path: Path) -> SpecFile:
    """Read and validate security-spec.yaml. Any problem raises StructuralError."""
    data = load_yaml(path)
    if data is None:
        raise StructuralError(str(path), ["the file is empty"])
    if not isinstance(data, dict):
        raise StructuralError(
            str(path),
            ["the file must contain a mapping with schema_version, scenario_suite, and cases"],
        )
    try:
        spec = SpecFile.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(str(path), format_validation_error(exc)) from exc
    problems: list[str] = []
    seen: set[str] = set()
    for index, case in enumerate(spec.cases):
        if case.id in seen:
            problems.append(f"cases[{index}].id: duplicate case id {case.id!r}")
        seen.add(case.id)
    seen_rules: set[str] = set()
    for index, rule in enumerate(spec.never_reaches):
        if rule.id in seen_rules:
            problems.append(f"never_reaches[{index}].id: duplicate rule id {rule.id!r}")
        elif rule.id in seen:
            problems.append(f"never_reaches[{index}].id: id {rule.id!r} is already used by a case")
        seen_rules.add(rule.id)
    if problems:
        raise StructuralError(str(path), problems)
    return spec
