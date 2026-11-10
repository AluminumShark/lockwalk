"""A decide() whose reason is far longer than lockwalk shows."""


def decide(subject, action, resource, context):
    if subject["id"] == "long":
        return {"decision": True, "reason": "x" * 5000}
    return True
