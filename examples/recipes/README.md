# decide() recipes

`lockwalk test` asks your real IAM through [AuthZEN](../../docs/lockwalk-test.md) or through a
function you write: `decide(subject, action, resource, context) -> bool`. These recipes are
examples of that function for common engines. They are starting points, not products: copy
one, change it to your policy, and point lockwalk at it:

```toml
[policy]
adapter = "python"
target = "decide.py:decide"
```

or `lockwalk test --policy python:path/to/decide.py:decide`.

The contract of every recipe:

- `decide` returns a real `bool`, or raises. An exception shows up as ERROR in the report, never
  as a PASS.
- Endpoints and credentials come from environment variables, never from the code. They do not
  appear in error messages.
- HTTP calls use the standard library with a timeout.
- A third-party SDK is imported lazily, so reading a recipe never needs it.
- **Proxies.** The standard library honours the `HTTP_PROXY` and `HTTPS_PROXY` environment
  variables, so a proxy sees each request and its bearer token. For a local PDP, set
  `NO_PROXY=127.0.0.1`. Use `https` for remote servers.

## The table

| Engine | Recipe | You provide | Set | Tested how |
|---|---|---|---|---|
| OPA | [`opa/decide.py`](opa/decide.py) | A running OPA server with a policy that defines `data.lockwalk.allow`. `opa/policy.rego` and `opa/docker-compose.yml` run the demo policy. | `OPA_URL` (default `http://127.0.0.1:8181`) | Fake server for the request shape; the real OPA image in Docker for the demo results |
| Casbin | [`casbin/decide.py`](casbin/decide.py) | `model.conf` and `policy.csv` (the ones here reproduce the demo), and `pip install casbin`. | `CASBIN_MODEL`, `CASBIN_POLICY` (both optional) | pycasbin in process, against the demo results |
| OpenFGA | [`openfga/decide.py`](openfga/decide.py) | A running server, a store, an authorization model, and the tuples. The recipe writes none of them. Relation names must match your actions (see `RELATIONS`). | `OPENFGA_STORE` (required), `OPENFGA_URL`, `OPENFGA_MODEL_ID`, `OPENFGA_API_TOKEN` | Fake 127.0.0.1 server that checks the request shape. Not run against a real OpenFGA. |
| Keycloak Authorization Services | [`keycloak/decide.py`](keycloak/decide.py) | A realm and a resource server client with resources, scopes and permissions, and **a function that returns an access token for each test identity**. How to get those tokens is your job and your risk. | `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` (required), `KEYCLOAK_URL` | Fake 127.0.0.1 server that checks the request shape. Not run against a real Keycloak. |

Amazon Verified Permissions, the AWS IAM policy simulator and GCP Policy Troubleshooter are in
[`CLOUD.md`](CLOUD.md).

## What each recipe needs from you

- **OPA.** The recipe posts `{"input": {subject, action, resource, context}}` and reads
  `result`. Your policy must define `data.lockwalk.allow` and return a boolean. A policy that
  leaves `allow` undefined makes OPA answer without `result`, and the recipe raises instead of
  guessing a deny. Run the demo with `docker compose up -d` in `opa/`, `OPA_URL` unset, and
  `docker compose down` when done. The container is published on 127.0.0.1 only.
- **Casbin.** The model is ABAC: each row of `policy.csv` names a subject type, an action, a
  resource type and a condition over `r_sub` and `r_obj`. Conditions are evaluated by Casbin.
  The attributes they read must exist; `ATTRIBUTE_DEFAULTS` in the recipe lists the demo's, and
  you add yours. A condition that reads an attribute nobody defined raises.
  **Trust the policy file.** The conditions in `policy.csv` are code that Casbin runs through
  its `eval()` (simpleeval). Simpleeval is a restricted evaluator, not a sandbox you should rely
  on. Load the file only from a path you control (the path comes from `CASBIN_POLICY`), and
  never build it from user input.
- **OpenFGA.** The tuple is `user:<id>`, a relation from the action name (`portfolio:read`
  becomes `portfolio_read`, because relations cannot contain `:`), and `<type>:<id>`. The
  tuples that make the answer true must already be in the store. lockwalk's fixtures describe
  attributes (an owner, roles); OpenFGA answers from relationships. You write that mapping.
  Ids with `:`, `#`, `@`, `*` or whitespace are refused, so userset and wildcard checks cannot
  be expressed, and `contextual_tuples` and conditions are not sent. Building the model and
  writing the tuples are your job.
- **Keycloak.** Keycloak answers for the holder of an access token, so lockwalk's identities
  need tokens. The default `subject_token()` raises until you write it. The permission is
  `<resource id>#<action name>`, so your Keycloak resources and scopes must be named that way,
  or you change `permission()`.

## Run the OPA and Casbin demos

The demos use the multi-agent example and give the same results as the Cedar and Cerbos
examples, including the two deliberate holes. After `uv sync` at the repository root:

```bash
cd examples/iam_cedar
uv run lockwalk test --no-harness --policy python:../recipes/casbin/decide.py:decide
```

For OPA, start the server first (`docker compose up -d` in `examples/recipes/opa`), then run the
same command with `decide.py` from `../recipes/opa/`. `--no-harness` asks only the IAM: the
door tests of that example ask Cedar.

## Limits

- A recipe answers the question you give it. It does not check that your policy is the one
  deployed, and a pass says nothing about production traffic.
- The AuthZEN `context` is passed to OPA and ignored by the other recipes.
- The identity format and the delegation chain (`act`) are lockwalk's. If your engine models
  them differently, convert inside `decide()`.
