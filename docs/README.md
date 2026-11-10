# lockwalk documentation

New here? Start with the [README](../README.md).

| Page | Read it when you want to |
|---|---|
| [lockwalk coverage](lockwalk-coverage.md) | describe your agents and tools, understand the map, set the gate, accept a risk with a waiver, or read `coverage.json` |
| [lockwalk test](lockwalk-test.md) | ask your real IAM, or check that a denied call really does not run |
| [lockwalk observe](lockwalk-observe.md) | compare real traces with the map |
| [lockwalk in CI](lockwalk-ci.md) | run lockwalk on pull requests and compare two reports |
| [Trust and limits](lockwalk-security.md) | decide how far to trust a result, and read the threat model |

## Words used in these guides

| Word | Meaning |
|---|---|
| IAM | Whatever answers "may this identity do this action on this resource?" |
| PDP | Policy decision point: a server that answers allow or deny, often over AuthZEN |
| PEP | Policy enforcement point: the code in your app that asks the PDP before a tool runs. lockwalk calls it the door |
| AuthZEN | An open standard for asking a PDP over HTTP |
| Door | Your own authorization check, the function that asks the IAM before a tool's side effect |
| Side effect | The function that does a tool's real work. Door tests replace it with a counter |
| Harness | The optional `[harness]` section of `.lockwalk.toml`. It turns on door tests |
| Map | Which agents and roles can reach which tools, built from your registry and your code |
| Witness | The route that breaks a `never_reaches` rule, shown under the rule |
| Opaque | An agent or server whose calls or tools lockwalk cannot see inside, so a rule through it is INCONCLUSIVE |
| Positive control | One allowed answer for an action and resource type. Without it, a deny may only mean the IAM did not understand the question |
| Gate | The pass or fail check at the end of a run. It sets the exit code |
| Waiver | An accepted finding, with an owner and an expiry date. It stops blocking the gate and stays in the report |
| UNSPECIFIED | A tool that no valid case targets |
| UNTESTED | A case that has not been run: `coverage` leaves every valid case here, and only `test` runs them. In `observe`, a real path that no case tests |
| NOT_TESTED | A case with no door test, for example because its tool is not in `SIDE_EFFECTS` |
| NOT_RUN | A route that scripted mode could not run (one declared with `calls` only, for example), or an identity check with no door record. It warns and never fails the gate |
| UNGUARDED | In `observe`: a tool call with no door record |
| UNKNOWN | A tool with no declared risk (`risk=unknown`). In `observe`, a name in a trace that matches no agent or tool |
| INCONCLUSIVE | lockwalk cannot tell. It fails the gate by default |
| FAIL_POLICY | The IAM answered differently than the spec expected |
| FAIL_EXECUTION | The IAM said deny, but the tool's side effect ran |

Runnable examples are in [`examples/`](../examples): a
[finance demo](../examples/finance_agent/README.md), a
[multi-agent demo](../examples/multi_agent/README.md),
[Cedar](../examples/iam_cedar/README.md) and [Cerbos](../examples/iam_cerbos/README.md) setups,
[Hermes Agent](../examples/hermes/README.md), [IAM recipes](../examples/recipes/README.md), and a
[GitHub Actions workflow](../examples/ci/README.md).
