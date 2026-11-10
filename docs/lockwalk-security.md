# What lockwalk trusts, and what it promises

What lockwalk checks, what a hostile module or server can do to you, what it trusts without
checking, what can end up in each output, how it handles URLs and secrets, what it does not
promise, and its threat model. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What lockwalk checks

| Layer | Question | Available |
|---|---|---|
| Tool discovery | Which tools exist, and which have no authorization spec at all? | **available** |
| Agent graph | Which tools can each entry agent and each role reach, and through which agents? | **available** |
| Authorization | Does the policy engine answer the way the spec expects? | **available**, with `lockwalk test` |
| Enforcement | When the engine says deny, does the tool really not run? | **available**, with `lockwalk test` and a `[harness]` (see [Door tests](lockwalk-test.md#door-tests)) |
| Real traffic | Did real agents take routes that are not on the map, skip the door, or use another identity? | **available**, with `lockwalk observe`, on traces you give it (see [observe](lockwalk-observe.md#what-observe-checks)). Some setup snippets were not run end to end: see [what was verified](lockwalk-observe.md#what-was-verified) |

Around these layers: [waivers](lockwalk-coverage.md#waivers) for accepted risks, [`--summary`](lockwalk-coverage.md#summary-output)
for short output, [IAM recipes](lockwalk-test.md#iam-recipes), [`lockwalk diff`](lockwalk-ci.md#compare-two-reports-lockwalk-diff)
to compare two reports, and a [CI example](lockwalk-ci.md#continuous-integration).

Not covered: verifying identity tokens, and per-identity tool visibility. Without a
`[harness]`, lockwalk only uses the identities you declare. With one, it also records the
identity your door receives; see [Identity and IAM](#identity-and-iam).

## What a hostile module or server can do

lockwalk is not a sandbox. Point it only at code and servers you trust. This is what happens
when you do not.

**Code that runs, and who it runs as.** When lockwalk imports a module or starts a server, that
code runs as you, or as your CI job. It has your files and your network. These are the places
where lockwalk starts your code:

| What starts | Environment it gets |
|---|---|
| A Python source (`--python`, `[[inventory.python]]`): lockwalk imports the module in a subprocess and reads the attributes of the objects, which runs their property code | all of yours |
| The `[harness]` door tests: a subprocess imports your app and your hooks file, then calls your tools | all of yours, plus `LOCKWALK_HARNESS=1` and two framework switches |
| Your `decide()` function (`[policy] adapter = "python"`) | all of yours. It may use the network |
| A reader function (`[observe] reader`) | all of yours. It may use the network and lockwalk does not restrict it |
| An MCP server given as `stdio://script.py`: lockwalk runs the script with its own Python | a short list (such as `PATH` and `HOME`) plus the `env` you set on the source |
| An MCP server given as `[[inventory.mcp]] command`: lockwalk starts the program that `command` names, with its `args` | the same short list plus `env` |

The short list comes from the MCP library, and it can change with that library. An `http(s)`
MCP source is not started, but lockwalk connects to it and sends your `headers`. A hostile
server of any kind can also return false data. In particular, it can hide a tool by not listing
it. lockwalk cannot see what a source leaves out.

The door tests add a guard against network connections to other hosts. It is a safety net for
mistakes, and it has gaps (see [Isolation](lockwalk-test.md#isolation)). Files are not
isolated. See also [Where the tool list comes from](lockwalk-coverage.md#where-the-tool-list-comes-from).

**What lockwalk does defend.** It treats the data a source returns as untrusted:

- Names are validated: control, format and private-use characters are refused, and a name has
  a length limit. Everything lockwalk itself prints on a terminal is plain ASCII, with other
  characters escaped. This does not cover the usage error that the command line library prints
  for a bad option or argument: it repeats what you typed, as you typed it.
- Reads are bounded. Every subprocess and server has a time limit. What comes back has a size
  limit, for example 1 MiB for a `decide()` reply, 8 MiB for a door test result, and the
  `[observe]` limits for traces. lockwalk never calls MCP `tools/call`.
- URL credentials are removed from what it shows, and values you put in MCP `env` and
  `headers` are hidden when a server echoes them back (see [Secrets](#secrets-in-mcp-configuration)).
- Remote agent objects are never read (see [What lockwalk never reads](#what-lockwalk-never-reads)).

## What lockwalk trusts without checking

A result is only as good as these inputs. lockwalk cannot check them.

- **`risk`.** It comes only from your registry. A wrong risk changes which tools the gate cares
  about. Anything undeclared is `unknown`.
- **`roles`, `delegation_mode`.** They are written by you. See [Identity and IAM](#identity-and-iam).
- **`calls` and `supported_agents`.** A route you leave out is invisible. A stale entry keeps a
  removed route (see [Declarations](lockwalk-coverage.md#declarations)).
- **Snapshots.** The file's shape is checked, not its content. Someone who edits one can change
  the results (see [Snapshots](lockwalk-coverage.md#snapshots)).
- **The door's own trace records and effect markers.** `observe` believes what the door says it
  did. If the door records `deny` and sends `allow`, `observe` cannot see it. Your code writes the
  effect markers (see [what observe cannot tell you](lockwalk-observe.md#what-observe-cannot-tell-you)).
- **Reader functions.** lockwalk checks the shape of what they return, not whether it is true
  (see [Reader function](lockwalk-observe.md#reader-function)).
- **Hooks and fixtures.** The hooks file is code you wrote. `SIDE_EFFECTS` and `DOOR` say what
  lockwalk replaces and watches. The fixtures say who and what is asked. A wrong one gives a
  wrong result (see [The hooks file](lockwalk-test.md#the-hooks-file)).
- **That the policy you tested is the policy you deploy.** If someone edits the deployed policy
  by hand, a pass says nothing about production.
- **That fake models stand in for a real LLM.** Door tests use fake models. They do not show
  how a real model behaves, for example under prompt injection. lockwalk assumes the worst, that
  the model does call the tool.

More are in [what `test` cannot tell you](lockwalk-test.md#what-lockwalk-test-cannot-tell-you).

## What can end up where

A report is data from your own code and files. This table says which output can hold what.
"Names" means agent, tool, role, rule, case and waiver ids.

| Output | Can hold | Does not hold |
|---|---|---|
| `.lockwalk/coverage.json` (`coverage`, `test`) | Names. Local file paths (in source labels as you wrote them, and in exception text). Exception text from your code, cut to 300 characters. Each waiver's owner, reason, expiry and match. Each case's `actor`, `role` and own `reason`. With `test`: the subject sent to the IAM (type, id, fixture properties) and the IAM's reason | Tool descriptions and schemas. Tool arguments. Raw IAM responses. Subprocess output. `env` and `headers` values. URL credentials |
| `.lockwalk/evidence.jsonl` (`test`) | The full question sent to the IAM: subject, resource and context, including fixture properties. Reasons and error text. Argument names. The exception type a tool raised in a door test, and why a run was an ERROR (the message of that exception is in `coverage.json`, not here) | Tool argument values. Raw IAM responses. Subprocess output. `env` and `headers` values |
| A snapshot (`discover --save-snapshot`) | Source labels, agents, tool names, **tool descriptions**, hints, and the agent graph | `env` and `headers` values. Errors. Warnings |
| `.lockwalk/observe.json` (`observe`) | Agent and tool names. Routes and counts. Example trace ids. The time window. Each waiver's owner and reason. Error messages, which can hold exception text from a reader function or from importing your code, and file paths in it | User ids. Resource ids. Other span attributes. The records a reader function returned (a bad record is reported by its number, not its content) |
| The terminal | Names, file paths, exception text, and waiver owners in the `Waived` list and in waiver warnings. The [example workflow](../examples/ci/README.md) runs `lockwalk` in plain job steps, so the CI logs hold waiver owners too, even though the pull request comment leaves them out. `--summary` still prints them | The same things the files leave out |
| The pull request comment (`lockwalk diff --format markdown`) | Names, risk, waiver ids and expiry dates. Non-ASCII characters in names appear as escape codes | A waiver's owner and reason. A case's actor |
| CI artifacts of the [example workflow](../examples/ci/README.md): `lockwalk-diff` and `lockwalk-test` | `lockwalk-diff` holds the comment and the full head and base `coverage.json`. `lockwalk-test` holds `coverage.json` and `evidence.jsonl`. So they hold everything in those files, including waiver owners, reasons and case actors | |

The comment leaves out the owner, the reason and the actor, because they may name a person. The
artifact with the full reports holds them. Anyone who can download the artifact can read them.

Redaction is best effort. lockwalk recognizes URLs and the secret values it was told about. It
cannot recognize a secret written in plain text in an exception message (see
[Exception text](#exception-text) and [Known redaction limits](#known-redaction-limits)). Keep
real secrets, real personal data and real customer identifiers out of fixtures, specs, tool
names and exception messages.

**Before you upload a report as a CI artifact, a pull request attachment or a bug report, read it.**
That includes `coverage.json`, `evidence.jsonl`, snapshots, `observe.json`, and the `lockwalk-diff`
artifact with its two reports.

## Before you rely on it

- Run it only on code and servers you trust
  ([what a hostile module or server can do](#what-a-hostile-module-or-server-can-do)).
- Keep secrets out of any job that runs pull request code
  ([what a pull request can change](lockwalk-ci.md#what-a-pull-request-can-change)).
- Have the owners of the config, registry, spec, waivers file, hooks file and policy files review
  changes to them (same page).
- Read the "Newly waived" and "Waiver changes" parts of the pull request comment
  ([the comment](../examples/ci/README.md#the-pull-request-comment)).
- Check `risk`, roles and delegation modes yourself. lockwalk cannot
  ([what lockwalk trusts without checking](#what-lockwalk-trusts-without-checking)).
- Check the registry against your real tools
  ([what lockwalk cannot see](lockwalk-coverage.md#what-lockwalk-cannot-see-and-how-to-fill-the-gap)).
- Try the workflow on a test repository first ([CI example](../examples/ci/README.md)).
- Check the first trace you export with `lockwalk inspect --trace`
  ([what was verified](lockwalk-observe.md#what-was-verified)).
- Pin the version ([installing lockwalk](../examples/ci/README.md#installing-lockwalk)).
- Treat reports and CI logs as sensitive ([what can end up where](#what-can-end-up-where)).
  That includes `observe.json`: an error message in it can hold the text of an exception.

What backs this up, and what does not:

- The repository's tests include hostile input. For example,
  `test_hostile_values_stay_in_code` in `tests/test_diff_markdown.py` feeds names such as
  `@octocat`, `<script>` and a Markdown link into the pull request comment, and checks that none
  of them becomes live Markdown.
- No outside party has audited lockwalk.
- lockwalk is alpha. The report format and the configuration may still change before 1.0.

## Identity and IAM

`coverage` only reads the identities you declare and warns. `lockwalk test` asks your IAM
with them (see [Ask your IAM](lockwalk-test.md#what-lockwalk-test-does)), but it does not check them.

- `roles` on entry agents say which roles may start where. `delegation_mode` says whose
  identity each agent sends with its tool calls. Both are hand-written. lockwalk uses them
  for the static checks, and `test` uses `delegation_mode` to choose the identity it asks with.
- When a role can reach a high, critical, or unknown-risk tool through an agent that calls
  it directly, and that agent's `delegation_mode` is `agent`, lockwalk warns that your IAM
  will not see the user. When the agent declares no `delegation_mode`, it warns that the IAM
  may not see the user. It gives one warning per agent; the `reachability` rows in
  `coverage.json` have every detail.
- `lockwalk test` asks your IAM, through an AuthZEN endpoint or a Python `decide` function that
  you write, as if the agent used the identity that `delegation_mode` declares. Without door
  tests it cannot tell whether your agents really send that identity. With them, scripted mode
  records the identity your door receives, reports MISMATCH when it differs from the
  declaration, and asks the IAM with the identity it saw. `test` does not look at real traffic.
  `lockwalk observe` reads traces that you give it, and checks the identity in the door's own
  records (see [observe](lockwalk-observe.md#identity-checks)).

## Security notes

### URLs

These rules apply to `remote` in the registry and to MCP targets:

- Only http and https, with a real host name.
- Percent-encode the URL: no spaces or control characters. In a user name or password, write
  `/`, `?`, and `#` as `%2F`, `%3F`, and `%23`.
- A raw `@` after the host is rejected; write it as `%40`. This includes MCP targets such as
  `?email=a@b.com`, which must be written `?email=a%40b.com`.
- The port must be a number.
- lockwalk removes the user info (`user:password@`), the query, and the fragment from the
  URLs it shows or stores. The host, port, and path are kept as written, so never put a
  token there. Better still, keep tokens out of URLs and send them in `headers`: in an MCP
  connection error, lockwalk only recognizes the URL exactly as you wrote it, so a client
  that quotes it in another form can still show its query.

### Secrets in MCP configuration

- Put secrets only in `env` or `headers`, as `${VAR}`. Never put them in `command` or `args`.
- lockwalk keeps `args` out of every label and message, but an error that the server cannot
  start shows `command` as you wrote it.
- A `command` source without a `name` is labeled with the server's own name, or else its program
  name, such as `mcp:npx`.
- The program name is the first word of `command`. The exception is an unquoted path to a
  `.exe`, `.cmd`, or `.bat` file, which may contain spaces, such as
  `C:\Program Files\nodejs\npx.cmd`. Write it without quotes, because `command` is launched as
  one program name.
- If you write an argument inside `command`, which you should not, a path-like word in it that
  ends in `.exe`, `.cmd`, or `.bat` may be shown.
- lockwalk never shows `env` or `headers` values itself. It also hides values that a server
  echoes back verbatim (in its name, its tool descriptions, or its errors), including their
  repr and escaped forms, as `<hidden env 'NAME'>`. It cannot hide a value that the server
  changed, for example cut short, and it does not hide values shorter than 8 characters in
  server text. A tool whose name contains a value of 16 or more characters is left out, and
  the source fails.
- An MCP server found on an agent gets its node id from its name. When the framework built
  that name from the command line, lockwalk uses the program name instead, and a server with
  neither is named after its URL without credentials. Arguments never appear.

### Exception text

What lockwalk hides in a message that comes from your code depends on where the message
comes from. Every path cuts the message to 300 characters and removes the user info, query and
fragment of URLs. These are the extra values each path hides:

| Message from | Also hidden |
|---|---|
| Importing a module or reading an object's attributes (Python sources) | Nothing |
| `decide()`: exceptions, reasons and worker failures | The value of every environment variable of 8 or more characters, as `<hidden env 'NAME'>`. It is lockwalk's own environment, read when the worker starts, and the worker inherits it |
| The reply of an AuthZEN server | The expanded values of your `[policy] headers`. Not the rest of the environment |
| Door tests: what a tool or the run raised | Nothing |
| A reader function | Nothing |
| An MCP server: names, descriptions, errors | The values of your MCP `env` and `headers` (see below) |

lockwalk cannot hide a secret that it was never told: one written in your code, one your code
reads from a file or a service, or one that a path above does not cover. Keep secrets out of
exception messages and out of the attributes of the objects lockwalk walks. The message reaches
`coverage.json`, `evidence.jsonl`, `observe.json` and the terminal. A reader function that
raises with a secret in its message puts that secret in the error line of `lockwalk observe`
and in `observe.json`.

### What lockwalk never reads

Reading the attributes of an Agno `RemoteAgent` or `RemoteTeam`, or calling a LangGraph
`RemoteGraph`'s `get_graph()`, calls the network, so lockwalk never does either. It
recognizes these objects without running their code and shows them as opaque remote nodes.
It never connects to an MCP server that it finds on an agent; it only connects to the
servers you configure as sources.

### Known redaction limits

- A URL inside a longer text ends at the first whitespace. A no-break space (or other Unicode
  space) inside a password ends the URL there, and the rest of the password stays visible.
- Only the `scheme://` form is recognized. `https:/host` (one slash) and backslash forms such
  as `https:\\host` are not redacted.

## How is this different from my policy engine's own tests?

Policy engines such as Cerbos and OpenFGA can unit-test their policies. lockwalk is different:

1. **What is counted.** Policy tests only cover rules that exist. They can never say
   "this tool has no rule at all". lockwalk counts from the tool inventory.
2. **The whole path.** Policy tests ask only the engine. With a `[harness]`, `lockwalk test` also
   tests the path from the enforcement point to the engine to the tool, and catches "the
   engine said deny but the tool ran anyway" (see [Door tests](lockwalk-test.md#door-tests)). Without one,
   it asks the engine only.
3. **Engine independent.** Your `security-spec.yaml` stays the same if you change engines.

## What lockwalk does not promise

- Passing lockwalk does not mean an agent is secure. Coverage only describes the declared scope.
- lockwalk does not stop prompt injection. An agent that a prompt tricked can misuse any tool it
  is allowed to use, and lockwalk checks only whether it is allowed.
- lockwalk does not stop data from leaking through allowed tools. A tool that is allowed to
  read can still return data that should not leave. lockwalk checks permissions, not what
  tools return.
- lockwalk only sees the sources you point it at. It does not scan for every dynamic tool or
  agent.
- A `never_reaches` PASS covers only the routes lockwalk can see and the ones you declare.
  lockwalk trusts your declarations; it cannot check them.
- There is no security score, on purpose.
- lockwalk is not an IAM system, a policy engine, a gateway, or an observability platform.

## Threat model and limitations

**Threat model.** lockwalk is a pre-deployment check that developers and CI run. It assumes
the code and configuration you point it at are your own. It is not a sandbox: a malicious
module or MCP server can still do harm when lockwalk imports or starts it, and reading an
object's attributes runs its property code. lockwalk does treat the data those sources return
(names, descriptions, errors) as untrusted: names are validated and everything printed is
escaped. A source can still hide a tool or an agent simply by not reporting it; lockwalk
cannot see what a source leaves out. The details are in
[What a hostile module or server can do](#what-a-hostile-module-or-server-can-do).

**Limitations.**

- The inventory is only as complete as the sources you configure. Tools registered
  dynamically, or living in sources you did not list, are invisible.
- `risk` comes only from your registry. Anything undeclared is `unknown`.
- `coverage` is static. `lockwalk test` asks your IAM, but neither verifies identities or
  checks that a denied tool really does not run (unless you add a `[harness]`, see
  [Door tests](lockwalk-test.md#door-tests)). `roles` and `delegation_mode` are declarations. See also
  [What lockwalk test cannot tell you](lockwalk-test.md#what-lockwalk-test-cannot-tell-you).
- Routes chosen at run time are invisible: a call inside tool code, an undeclared LangGraph
  `Command(goto=...)`, your own router. Declare them with `calls`. A route chosen at run time
  is seen only if a trace shows it (`lockwalk observe`).
- Remote agents and MCP servers are boundaries: lockwalk cannot see inside them.
- Inferred edges can report a route that does not exist. Declaring `calls` removes the
  inferred edges to other agents, but not inferred `uses_tool` edges; those go away only
  when the code says where the route goes (a LangGraph path map or `Literal` return type,
  or an agent on the CrewAI task).
- Some discovery relies on private framework attributes; see
  [What discovery can see](lockwalk-coverage.md#what-discovery-can-see).
- The graph only works at the level of roles. Rules about data, such as "alice may read only
  her own portfolio", are checked only by `lockwalk test`, which asks your policy engine.
- A tool with at least one valid case counts as specified. That says nothing about whether
  the case is a good test.
- `coverage.json` never contains tool descriptions, schemas, server or worker stderr, MCP
  `env` or `headers` values, or URL credentials. It can contain exception messages raised by
  your own code (with URLs redacted), agent and tool names, local file paths, waiver owners
  and reasons, and case actors. See [What can end up where](#what-can-end-up-where) before
  uploading it, or `evidence.jsonl`, as a CI artifact.
- lockwalk is tested on Windows and on Linux (WSL Ubuntu).
