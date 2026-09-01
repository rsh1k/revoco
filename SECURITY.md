# Security policy

## Reporting a vulnerability

Report privately through GitHub's advisory form:
**https://github.com/rsh1k/revoco/security/advisories/new**

Please do not open a public issue for anything exploitable. You will get an
acknowledgement within 72 hours and an assessment within seven days. If a fix
takes longer than that, you will be told why rather than left waiting.

There is no bug bounty. Credit in the advisory and the release notes is offered
unless you would rather stay anonymous.

## What is in scope

Revoco decides whether an action can be undone and enforces policy on that
basis, so the interesting failures are the ones that make it wrong rather than
the ones that make it stop:

- A classification that reports an action as recoverable when it is not — the
  phantom rollback this project exists to catch, arriving through the front door.
- Any path that lets a rule be skipped, reordered, or matched when it should not
  be, including reversibility postures falling out of an allow rule.
- Forging, replaying, or silently truncating the hash-chained ledger, or
  producing an evidence pack that verifies against tampered contents.
- Delegation escapes: widening a scope through a chain, or surviving revocation.
- A drill that reports a proof it did not earn.

## What is not in scope

- The inverse specifications in `src/revoco/adapters/`, other than `workstation`,
  are **written from vendor documentation and not validated against live
  systems**. That is stated in [docs/ADAPTERS.md](docs/ADAPTERS.md), so a spec
  that turns out wrong against a real SAP or Workday tenant is a bug report, not
  a vulnerability. Please file it as an issue.
- Denial of service against your own control plane by your own agents.
- Findings that require an attacker who already controls the host process.

## Supported versions

Pre-1.0. Only the latest released version gets fixes.
