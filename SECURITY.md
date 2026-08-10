# Security & Responsible Use

**Only use this on authorized targets. Unauthorized testing is illegal.**

VoidStrike is a remote-code-execution testing framework for security
professionals. It sends real attack payloads, so use it only against systems you
own or are authorized to test.

## Good to know

- **Non-destructive proofs.** Detection uses benign proofs of concept — echoing a
  random marker, a short `sleep` for timing, or an out-of-band callback. Modules
  do not run destructive commands, and payload volume is capped per module.
- **Single-target focus.** VoidStrike tests the specific URLs you give it. It does
  not do mass/internet-wide scanning or self-propagation.
- **Optional scope enforcement.** For engagements where you want a guardrail, pass
  `--scope scope.yaml` and VoidStrike will refuse to touch hosts outside it and
  write an audit log. It's optional and off by default.
- **Cleanup reminders.** Any artifact left on a target (e.g. a benign file-upload
  test file) is flagged in the run log and report so you can remove it.

## Reporting a vulnerability in VoidStrike itself

Please report issues privately to the maintainers rather than in a public issue.

## Disclaimer

The authors provide this software "as is" and accept no liability for misuse.
