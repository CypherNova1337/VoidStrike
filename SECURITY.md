# Security & Responsible Use

VoidStrike is a remote-code-execution **testing** framework built for
professional penetration testers and red teams. It sends real attack payloads,
so responsible use is not optional.

## Authorized use only

Use VoidStrike **only** against systems that you own or for which you hold
explicit, written authorization to test (a signed contract, rules-of-engagement,
or bug-bounty program scope). Unauthorized testing is illegal and unethical.

## Built-in safety controls

VoidStrike is designed to fail closed:

- **Scope enforcement.** Every request is checked against an engagement scope
  file. Hosts not listed in `in_scope` are refused, and `out_of_scope` carve-outs
  and a hard blocklist (`.gov`/`.mil`/`.int` and reserved names) are always
  rejected. See `voidstrike/authorization.py`.
- **Explicit consent.** No payloads are sent until you affirm authorization
  (interactively or with `--i-am-authorized`). The decision is written to an
  audit log alongside every scope decision.
- **Non-destructive proofs.** Detection relies on benign proofs of concept:
  echoing a random marker, a short `sleep` for timing, or an out-of-band
  callback to infrastructure you control. Modules do not run destructive
  commands, and payload volume is capped per module.
- **Single-target focus.** VoidStrike tests the specific endpoints you define.
  It does not perform mass/internet-wide scanning, self-propagation, or
  worm-like behavior.
- **Cleanup reminders.** Any artifact left on a target (e.g. a benign file-upload
  test file) is flagged in the run log and report so it can be removed.

## Reporting a vulnerability in VoidStrike itself

If you find a security issue in this tool, please open a private report to the
maintainers rather than a public issue.

## Disclaimer

The authors provide this software "as is" and accept no liability for misuse.
You are solely responsible for operating within the law and your authorization.
