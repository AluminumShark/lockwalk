# Cloud IAM recipes

Three `decide()` recipes for cloud IAMs. Copy one next to your project and point
`[policy] target` at it (see [Set up an adapter](../../docs/lockwalk-test.md#set-up-an-adapter)). `README.md` in this folder has the
recipes for self-hosted engines.

| Service | Adapter | What to set | Tested how |
|---|---|---|---|
| Amazon Verified Permissions | `verified_permissions/decide.py` (`decide`, `decide_many`) | `AVP_POLICY_STORE_ID`, optional `AVP_NAMESPACE`; edit `TYPES`; AWS credentials and region | Fake boto3 client only |
| AWS IAM policy simulator | `aws_iam_simulator/decide.py` (`decide`) | AWS credentials and region; subject property `arn`, resource property `arn`, action name = IAM action | Fake boto3 client only |
| GCP Policy Troubleshooter | `gcp_troubleshooter/decide.py` (`decide`) | Application Default Credentials; subject property `principal`, resource property `full_resource_name`, action name = permission | Fake client only |

## Setup

1. Install the SDK in the environment that runs lockwalk: `boto3` for the two AWS recipes,
   `google-cloud-policy-troubleshooter` for GCP. lockwalk does not depend on them. The
   recipes import them lazily, inside `_client()`.
2. Set the environment variables and credentials in the table. Nothing is logged.
3. Make the specs carry the properties the recipe reads (for example in the fixtures
   or the identity definitions): an ARN, a GCP principal, a full resource name.
4. In `lockwalk.toml`:

   ```toml
   [policy]
   adapter = "python"
   target = "decide.py:decide"
   timeout_s = 5.0
   ```

   The Verified Permissions recipe also defines `decide_many`, which lockwalk uses
   automatically. `BatchIsAuthorized` needs the same principal (or the same resource) in
   every request of one call, so the recipe groups queries by principal, sends each group
   in chunks of at most 30, and returns the answers in the original order.

## Read this before you trust a result

- **Tested with fake responses only.** The tests replace the client with a fake that
  records the request and returns a canned response. They check lockwalk's side: field
  names as documented, bool results, fail-closed errors. No recipe has been run against
  a live AWS or Google account. Try each one on a known allow and a known deny first.
- **Unknown answers raise.** An unknown decision state becomes an ERROR in the report,
  never a PASS or a FAIL. GCP `UNKNOWN_CONDITIONAL` and `UNKNOWN_INFO_DENIED` raise too.
- **The IAM simulator needs context.** The recipe sends none. When a policy condition
  needs a context key, the simulator reports it as missing and the recipe raises (it gives
  the number of keys, not their names) instead of treating the implicit deny as a deny.
- **The IAM simulator answers IAM identity policies only.** It does not know
  application-level rules such as ownership. Use it when the tool's authorization really
  is an IAM permission on an AWS resource.
- **GCP Policy Troubleshooter** judges one principal, permission, and full resource
  name. Conditional bindings that need request context come back as an UNKNOWN state,
  which raises. The v1 API answers from allow policies only: if you use IAM deny policies
  or Principal Access Boundaries, a GRANTED answer may be wrong (too permissive). Use the
  IAM v3 troubleshooter instead. The principal is the account email (for example `a@example.com`), without
  a `user:` prefix. The recipe uses the v1 API. Google also has a newer Policy
  Troubleshooter for IAM v3 API (package `google-cloud-policy-troubleshooter-iam`,
  `google.cloud.policytroubleshooter_iam_v3.PolicyTroubleshooterClient`). Prefer it when you
  use deny policies, because it explains them and v1 does not. This recipe does not use it.

## Azure

There is no recipe for Azure. No public API for checking the
permissions of an arbitrary identity has been confirmed. It is left open,
not guessed.
