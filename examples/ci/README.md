# lockwalk in GitHub Actions

`github-actions.yml` is an example. Copy it to `.github/workflows/lockwalk.yml` in your own
repository and adapt it. lockwalk never creates a repository or any CI for you.

## Installing lockwalk

The workflow assumes lockwalk is a locked dev dependency of your project, so its version only
changes when you choose. Add it, and commit `uv.lock`:

```
uv add --dev lockwalk
```

A repo without `pyproject.toml` and `uv.lock` needs its own install step in place of
`uv sync --locked`.

## What each job does

| job | runs on | what it does | needs |
|---|---|---|---|
| `coverage` | every pull request | `lockwalk coverage --summary` on the pull request and on its base, then `lockwalk diff` on the two reports | registry and spec only |
| `comment` | pull requests from this repository | posts the comparison as one pull request comment, and updates it on later pushes | `coverage` has finished (also when it failed) |
| `test` | nightly and manual runs | `lockwalk test --summary` | a reachable IAM; door tests run unless you add `--no-harness` |

The `coverage` and `test` jobs install lockwalk with `astral-sh/setup-uv` (pinned to a major
version) and `uv sync --locked`. `test` uploads `.lockwalk/coverage.json` and
`.lockwalk/evidence.jsonl` as an artifact, also when the gate fails. To look at one case,
unzip the artifact into a folder and run
`lockwalk inspect --case <id> --output-dir <folder>`; the case id comes from the report or
the job log. `coverage` uploads `comment.md` and the two reports (from `.lockwalk-head/`
and `.lockwalk-base/`) as the artifact `lockwalk-diff`. `--summary` only shortens the log;
the JSON file is always complete.

The gate is lockwalk's own pass/fail check, set in the `[gate]` table of `.lockwalk.toml`.
When it fails, the command exits 1.

Scheduled workflows run only on the default branch, and GitHub disables them on public repos
after 60 days without repository activity.

## The pull request comment

On a pull request, `coverage` never asks your IAM, so it cannot see that a policy change now
allows a call that was denied. Only `test` can (see
[Use `test` when the policy is in the repository](#use-test-when-the-policy-is-in-the-repository)).

The `coverage` job checks the pull request, then checks the base with the same lockwalk,
and runs `lockwalk diff` on the two reports. The base is the first parent of the merge commit
that GitHub built for the pull request (`HEAD^1`), which is exactly what the pull request was
merged onto. It is not the current tip of the target branch, so changes that landed on the
target branch later are not shown as the pull request's. If the base has no lockwalk setup
yet, it writes no report, and the comparison shows the pull request only, with a warning.

The base is read with its own `.lockwalk.toml` and code, but with the pull request's
Python environment. If the base needs very different dependencies, its report can be
incomplete or missing. The diff then warns that the comparison is not reliable, or shows the
pull request only.

The comparison lists what changed: new problems, problems that are newly waived, problems
that are no longer reported, changes to waivers, rules, tools, and to what each case checks,
and cases that got worse or better. "No longer reported" is not "fixed": lockwalk cannot tell a
real fix from a removed tool or case, or from a gate rule that was switched off. A newly
waived problem is listed on its own, because a waiver hides it from the gate. See
[Compare two reports](../../docs/lockwalk-ci.md#compare-two-reports-lockwalk-diff) in the CI
guide.

`diff` does not compare the agent graph, the reachability rows, the rows that only
`lockwalk test` writes, or the metrics. It cannot compare the gate settings either, because a
report does not hold them. A problem can disappear because a gate rule was switched off, so read
the changes to `.lockwalk.toml` in the pull request too. The comment never shows a waiver's owner
or reason, or a case's actor, because they may name a person. Non-ASCII characters in names are
shown as escape codes, so a look-alike letter cannot pass for the real name; the trade-off is that
agent names in other scripts are hard to read in the comment.

- **The job summary always has it.** The `Compare` step adds it to the run's summary page.
  That works for every pull request, including pull requests from forks.
- **Anyone who can push a branch here can post any Markdown as the bot.** The comment is
  written in the job that runs the pull request's code and posted by a separate job with write
  access. Someone who can push a branch to this repository can already change this workflow in
  that branch, so this adds no new power, but do not treat the comment as proof of anything.
- **The comment is only for pull requests from this repository, and not from Dependabot.** For
  a pull request from a fork, GitHub gives the workflow a read-only token, so a job cannot
  post a comment. Dependabot pull requests also get a read-only token, so the `comment` job
  skips them. Those pull requests get the job summary and the artifact only. (The common workaround,
  `pull_request_target`, gives code from the pull request a token that can write. This
  example does not use it, on purpose.)
- **The comment is updated, not repeated.** The job looks for an earlier comment written by
  `github-actions[bot]` that starts with `<!-- lockwalk-diff -->`, and edits it. If there is
  none, it posts a new one. It never touches other comments. The workflow also cancels an
  older run when you push again, so two runs cannot post two comments or put an older
  comparison over a newer one. The comment stays under GitHub's size limit: long lists are
  cut, with a line saying how many rows are left out.
- **Red or green comes from the pull request's own gate, never from `diff`.** `lockwalk diff`
  is not a gate: it exits 0 whenever it could compare the two reports. The last step of the
  `coverage` job exits with the exit code of the pull request's `lockwalk coverage` run, so
  the check turns red exactly when the gate fails. The `comment` job still runs in that case.

### Use `test` when the policy is in the repository

`lockwalk coverage` is static, so the diff can show new tools without a spec and gate
changes, but not changes in what the policy decides. If your policy is in the repository (a
`decide()` function or Cedar files) and `lockwalk test` can run without a separate service,
put `lockwalk test --summary` in place of `lockwalk coverage --summary` in **both** the pull
request step and the target branch step. Then the diff also shows cases that went from PASS to
FAIL. Use the same command for both: reports from `coverage` and `test` cannot compare case
results with each other, and the diff then says so in a warning.

## If `.lockwalk.toml` is in a subfolder

lockwalk reads `.lockwalk.toml` from the working directory. If yours is in a subfolder, add
`--config path/.lockwalk.toml` to every lockwalk command in the workflow (both `coverage`
steps and the `test` step). Relative paths inside that file, such as `registry`, start at the
file's own folder. `--output-dir` starts at the working directory, so keep the steps at the
repository root and the `.lockwalk-head` and `.lockwalk-base` paths stay valid. If you do set
`working-directory` on the steps, change those paths to match. The target branch step uses
the same relative `--config` path, so the file must be at the same place on the target branch.

## Permissions

| job | permissions | why |
|---|---|---|
| `coverage` | `contents: read` | It runs code from the pull request, so it gets no write token. Its checkout also sets `persist-credentials: false`, so no token stays in the checkout. |
| `comment` | `pull-requests: write` | It only downloads the Markdown file and posts it. It has no checkout and runs no code from the pull request. |
| `test` | `contents: read` (workflow default) | Runs on every event except `pull_request`: the nightly schedule (default branch) and manual runs (any branch the person picks). |

## Why two commands

- `lockwalk coverage` is static and fast. It reads the registry, the spec and the tool list,
  and runs no agent or tool. It does import your Python modules. It never asks the IAM. That makes it cheap enough for every pull request, and cheap enough to
  run twice (pull request and target branch) for the comparison.
- `lockwalk test` asks the real IAM about every case and can run door tests, which call tool
  code in a subprocess. It needs a running IAM and takes longer, so it runs nightly.

## Exit codes and CI status

| exit code | meaning | CI status |
|---|---|---|
| 0 | pass | green |
| 1 | findings, or the gate failed | red |
| 2 | the test itself is broken (bad config, IAM unreachable, bad waivers file) | red |

A red run with exit code 1 means a policy or spec problem. A red run with exit code 2 means
fix the setup first; the result says nothing about your policy.

## Waivers

To accept a known finding for a limited time, add `--waivers waivers.yaml` to the lockwalk
commands in the workflow (both the pull request and the target branch step), or set
`waivers` under `[lockwalk]` in `.lockwalk.toml`. Waived findings leave the gate but stay in
the report. When a waiver expires, the gate turns red again.

## Testing against Cerbos

The `test` job has two commented options.

- **A. Service container.** A service container starts before checkout, so it cannot mount
  your repository's policies. It only works with an image that already contains the policies
  and config.
- **B. A step after checkout (recommended).** Start Cerbos with `docker run` once the code is
  checked out, then wait until it is ready, before `lockwalk test`.
  This goes in a `run:` step.

```
docker run -d --name cerbos -p 127.0.0.1:3592:3592 \
  -v "$PWD/<policies>:/policies:ro" -v "$PWD/<conf.yaml>:/conf.yaml:ro" \
  ghcr.io/cerbos/cerbos:0.57.0 server --config=/conf.yaml
for i in $(seq 1 30); do
  docker exec cerbos /cerbos healthcheck --config=/conf.yaml && exit 0
  sleep 1
done
docker logs cerbos; exit 1
```

See `examples/iam_cerbos/cerbos/` for the conf and policy layout. Point `[policy]` in
`.lockwalk.toml` at it, as in `examples/iam_cerbos/.lockwalk.toml`:

```toml
[policy]
adapter = "authzen"
url = "http://127.0.0.1:3592"
roles_property = "cerbos.roles"
```
