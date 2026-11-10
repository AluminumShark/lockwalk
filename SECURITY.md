# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting: go to
<https://github.com/AluminumShark/lockwalk/security> and choose **Report a vulnerability**.

Say what you found, how to reproduce it, and what an attacker gains. This is a small project, so
replies are on a best-effort basis.

## Supported versions

Only the latest release gets fixes while lockwalk is in alpha.

## What counts

lockwalk is a check that developers and CI run on their own code. The
[threat model](docs/lockwalk-security.md#threat-model-and-limitations) says what it defends against.
For example, these are in scope:

- a false PASS: lockwalk says something passed when it should have reported a problem
- a secret or user id reaching a report, the terminal or a pull request comment
- crafted output from a tool, server, trace or report that breaks out of its quoting, or makes
  lockwalk hang

This is out of scope: a malicious Python module or MCP server doing harm when lockwalk imports or
starts it. lockwalk is not a sandbox, and its documentation says so.
