"""
ExfilWatch — drop-in LLM gateway logic.

The /v1/chat/completions endpoint speaks the OpenAI chat-completions wire
format, so an existing app adopts ExfilWatch by changing ONE line (the
client's base_url). This module holds the pure, testable part: given the
model's response, scan every completion and withhold anything that isn't
ALLOW. Enforcement lives in the gateway, not in the caller's good manners.
"""

WITHHELD_MESSAGE = (
    "[ExfilWatch] This response was withheld by security policy "
    "(possible covert-channel or sensitive-data leak). Request ID logged for review."
)


def guard_completion(data: dict, scan) -> dict:
    """
    `scan(text)` must return an object with .action, .risk_score, .verdict.
    Mutates and returns `data`, adding an `exfilwatch` summary block.
    """
    findings = []
    withheld = False
    for choice in data.get("choices", []):
        msg = choice.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, str) or not content:
            continue
        r = scan(content)
        findings.append({"index": choice.get("index", 0), "action": r.action,
                         "risk_score": r.risk_score, "verdict": r.verdict})
        if r.action != "ALLOW":
            msg["content"] = WITHHELD_MESSAGE
            choice["message"] = msg
            choice["finish_reason"] = "content_filter"
            withheld = True
    data["exfilwatch"] = {
        "withheld": withheld,
        "max_risk_score": max((f["risk_score"] for f in findings), default=0),
        "findings": findings,
    }
    return data
