---
inclusion: always
---

# Milestone delivery workflow

- Continue improving this repository through small, reviewable milestones toward a mature iPad network tool.
- Prioritize a working Packet Tunnel data path, correctness, stability, DNS/UDP behavior, observability, configuration, and performance before optional toolbox features.
- Finish and validate one scoped milestone at a time. Do not expand a milestone until its tests and documented release gates pass.
- After a milestone is complete, reviewed, and fully validated, commit it, push the current feature branch, and update the existing pull request promptly without waiting for another reminder.
- Never push partially edited, failing, unreviewed, or misleading code. Keep incomplete work local until it reaches a coherent milestone.
- Preserve the user's original exclusions: no HTTPS MITM, browser fingerprint impersonation, active-probe evasion, or custom cryptography.
- Report what was implemented, validation evidence, and platform limitations after each pushed milestone.
