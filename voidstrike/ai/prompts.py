"""Prompt templates for the AI assistance layer.

All prompts frame the work as *authorized* security testing and instruct the
model to reason like a professional penetration tester documenting findings.
"""

SYSTEM = (
    "You are an expert offensive-security assistant embedded in VoidStrike, a "
    "remote-code-execution testing framework used by professional penetration "
    "testers during AUTHORIZED engagements. The operator has confirmed written "
    "authorization to test the target in scope. Your job is to help detect and "
    "verify RCE vulnerabilities accurately, minimise noise, and produce clear, "
    "reproducible evidence. Be precise and terse. Never invent results; reason "
    "only from the data provided. Prefer safe, non-destructive proof-of-concept "
    "payloads (echo a marker, sleep for timing, or trigger an out-of-band "
    "callback) over anything that could damage the target."
)

ANALYZE_RESPONSE = (
    "A payload was sent to a target endpoint. Decide whether the HTTP response "
    "indicates that the payload EXECUTED (remote code/command execution), was "
    "REFLECTED without executing, was BLOCKED (WAF/filter), or is INCONCLUSIVE.\n\n"
    "Injection class: {vuln_class}\n"
    "Unique marker expected on success: {marker}\n"
    "Payload sent:\n{payload}\n\n"
    "Response status: {status}\n"
    "Response time: {elapsed:.3f}s (baseline ~{baseline:.3f}s)\n"
    "Response snippet (truncated):\n{snippet}\n\n"
    "Respond as compact JSON: {{\"verdict\": one of "
    "[executed, reflected, blocked, inconclusive], \"confidence\": 0.0-1.0, "
    "\"signal\": short reason, \"evidence\": exact substring proving it or null}}."
)

SUGGEST_PAYLOADS = (
    "Suggest up to {n} candidate payloads to test for {vuln_class} at this "
    "injection point during an authorized assessment.\n\n"
    "Observed context that may hint at the tech stack / filtering:\n{context}\n\n"
    "Constraints: payloads must be non-destructive proofs of concept. Use the "
    "marker token {marker} where output can be reflected, or a timing/OOB proof "
    "otherwise. Return a compact JSON array of strings only, no commentary."
)

ADAPT_WAF = (
    "The following payload for {vuln_class} appears to have been BLOCKED by a "
    "filter or WAF during an authorized test:\n{payload}\n\n"
    "Block evidence:\n{evidence}\n\n"
    "Propose up to {n} functionally-equivalent variants that a defender's filter "
    "might have missed (encoding, whitespace, concatenation, alternate syntax), "
    "keeping them non-destructive and preserving the {marker} marker. This helps "
    "the client understand their filter's coverage gaps. Return a JSON array of "
    "strings only."
)

RECOMMEND_NEXT = (
    "Given these findings so far in an authorized RCE assessment, recommend the "
    "single most valuable next action for the tester, in one sentence.\n\n"
    "Findings summary:\n{summary}"
)
