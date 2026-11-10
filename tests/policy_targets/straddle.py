"""A decide() whose reason and error carry a URL with credentials past the 300th character."""

URL = "https://Sup3rS3cretT0ken99@host.example/x"


def decide(subject, action, resource, context):
    if subject["id"] == "boom":
        raise ValueError("a" * 270 + URL)
    return {"decision": True, "reason": "a" * 270 + URL}
