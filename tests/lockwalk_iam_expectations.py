"""What lockwalk test must report for the multi-agent demo, whichever IAM answers."""

# examples/multi_agent/security-spec.yaml with the correct demo policy.
CASES = {
    "CASE-001": "PASS",
    "CASE-002": "PASS",
    "CASE-003": "PASS",
    "CASE-004": "PASS",
    "CASE-005": "FAIL_POLICY",  # trade-agent's own identity may trade on Alice's account
}
# (case_id or None, role, tool, via) -> result
ESCALATIONS = {
    ("CASE-003", "analyst", "get_stock_price", "pricing-agent"): "NONE",
    ("CASE-004", "trader", "execute_trade", "trade-agent"): "NONE",
    ("CASE-005", "trader", "execute_trade", "trade-agent"): "ESCALATION",
    (None, "analyst", "execute_trade", "trade-agent"): "ESCALATION",
    (None, "analyst", "confirm_price", "trade-agent"): "NONE",
    (None, "analyst", "get_stock_price", "pricing-agent"): "NONE",
    (None, "trader", "execute_trade", "trade-agent"): "NONE",
    (None, "trader", "confirm_price", "trade-agent"): "NONE",
    (None, "trader", "get_stock_price", "pricing-agent"): "NONE",
}
# The same spec with the broken policy: the owner check on portfolios is gone.
BROKEN_CASES = {**CASES, "CASE-002": "FAIL_POLICY"}
# examples/multi_agent/deny-only-spec.yaml with the correct policy.
DENY_ONLY_CASES = {"CASE-002": "INCONCLUSIVE", "CASE-005": "FAIL_POLICY"}


def escalations(report: dict) -> dict:
    """The escalation table of a coverage.json document, keyed like ESCALATIONS."""
    return {
        (row["case_id"], row["role"], row["tool"], row["via"]): row["result"]
        for row in report["escalations"]
    }


def case_statuses(report: dict) -> dict:
    return {case["id"]: case["status"] for case in report["cases"]}
