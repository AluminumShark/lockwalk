# lockwalk in CI

How to run lockwalk on pull requests: exit codes, comparing two reports with `lockwalk diff`,
and the example workflow that posts the comparison as a pull request comment.

## Continuous integration

[`examples/ci/`](../examples/ci/README.md) has a GitHub Actions workflow to copy. It checks every
pull request and shows what changed against the target branch (see
[Compare two reports](#compare-two-reports-lockwalk-diff)), and runs `lockwalk test` every night.
Try it on a test repository before you rely on it; the comment, the fork limits and the
permissions are explained in [`examples/ci/README.md`](../examples/ci/README.md).

| Exit code | CI status | Meaning |
|---|---|---|
| 0 | green | Pass |
| 1 | red | A finding blocks the gate |
| 2 | red | The run cannot be trusted: configuration, IAM, an ERROR, or a bad waivers file. Fix the setup first |

When every violation is waived, `coverage.json` has `gate.passed` true. But `exit_code` is 2
whenever there are errors, even then. CI and tools that read the JSON must use `exit_code` (or
check that `errors` is empty), not only `gate.passed`.

## Compare two reports: lockwalk diff

`lockwalk diff` compares two `coverage.json` reports, for example the target branch's and a
pull request's, and lists what changed. It only reads the two files. It runs no tool and asks
no IAM.

```bash
uv run lockwalk coverage --output-dir base      # on the target branch
uv run lockwalk coverage --output-dir head      # on the pull request
uv run lockwalk diff --base base/coverage.json --head head/coverage.json
```

- `--head` is the report to check. `--base` is the one to compare with. Without `--base`, the
  output shows the head only and warns that there is nothing to compare with.
- It lists new gate problems, newly waived problems, problems no longer reported, waivers that
  were added, removed or changed, tools that are new or gone, tools whose risk or spec changed,
  rules that were added, removed or changed, changes to what a case checks (such as its expected
  answer), and cases that were added, removed, or changed status (for example PASS to FAIL, when
  both reports come from `lockwalk test`).
- "No longer reported" does not mean fixed. lockwalk cannot tell a real fix from a removed tool or
  case, or from a gate rule that was switched off. A problem that is now waived is listed under
  "Newly waived" instead, because a waiver hides it from the gate without fixing it.
- `diff` does not compare the agent graph, the reachability rows, the rows that only `lockwalk
  test` writes, or the metrics. It cannot compare the gate settings either, because a report does
  not hold them, so read changes to `.lockwalk.toml` in the pull request too.
- When nothing it compares has changed, it prints `No changes in gate problems, waivers, tools,
  rules or cases.`
- `--format` is `text` (the default), `json` (complete, for tools) or `markdown` (for a
  pull request comment). In Markdown, non-ASCII characters in names are shown as escape codes, so a
  look-alike letter cannot pass for the real name. No format shows a waiver's owner or reason, or
  a case's actor, because they may name a person.
- If a report has errors, the output says the comparison is not reliable, and problems that went
  away are not listed. It never says "No changes" then.
- Exit code: 0 when it could compare the two reports, whatever it found. 2 when a report
  cannot be read (missing, not JSON, or from another schema version), or when stdout fails for a
  reason other than a closed pipe.

`diff` is not a gate. Red or green still comes from `lockwalk coverage` or `lockwalk test` on
the head. A text example, where the head found a tool the base did not know:

```text
lockwalk diff - head gate: FAIL (2 violation(s))
----------------------------------------
New problems (2):
  - fail_on_unspecified_risk: delete_portfolio (risk=unknown)
  - require_deny_case_for_risk: delete_portfolio (risk=unknown)

New tools without spec (1):
  - delete_portfolio (risk=unknown)
```

`risk=unknown` means the registry does not declare a risk for that tool.

To run it on every pull request, see [Continuous integration](#continuous-integration).

## What a pull request can change

On a pull request, the code being checked also decides the checks. The author of the pull
request controls these files, and they decide what runs and what passes:

- `.lockwalk.toml`, including the `[gate]` keys, the `[policy]` and `[harness]` sections, and
  the paths of the other files;
- the registry and the spec;
- the waivers file;
- the hooks file, which `lockwalk test` imports and runs;
- the policy files and the `decide()` function that `lockwalk test` asks, and the Python
  modules that lockwalk imports.

So a pull request can add a case that matches what the policy now says, switch a gate rule off,
add a waiver, or change what a tool is declared to be. The gate then passes because the
pull request changed the rules, not because the problem is gone.

`lockwalk diff` compares two reports, not the sources behind them. It shows what the reports
say changed. It cannot show a gate setting that changed, because a report does not hold the
gate settings (see [Compare two reports](#compare-two-reports-lockwalk-diff)).

What to do:

- **Ask the owners of these files to review changes to them.** That means every file in the
  list above. Treat a change there like a change to the security policy itself.
- **Keep secrets out of the job that runs pull request code.** `lockwalk` imports your
  modules and, with `test`, runs your hooks and `decide()` with the job's whole environment.
  The example `coverage` job has a read-only token for that reason (see
  [Permissions](../examples/ci/README.md#permissions)). Do not give a job that runs pull
  request code any secret or write token. The example `test` job runs on every event except
  `pull_request`: the nightly schedule, which GitHub runs on the default branch, and a manual
  run, which runs on whichever branch the person who starts it picks. If you also run `test`
  on pull requests, the same rule applies to it.
- **Read the comment.** A new waiver turns a failing gate green, and the pull request
  comment is where that shows: under "Newly waived" and "Waiver changes". The comment
  gives the waiver's id and expiry date, not its owner or reason, so open the waivers file too.
  A green gate with a new waiver is visible only there. Make reading the comment part of review.
