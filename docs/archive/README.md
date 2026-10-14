# Archive: historical planning documents

These documents were written while the product was being planned and built (August to early October 2026). They record **why** things were decided and how the product was assessed at the time. They are **not kept up to date** and parts of them are wrong today (for example they describe a Raspberry Pi appliance, Windows-first installers, a 64-character fingerprint, and problems that have since been fixed).

For the current state read:

- [`../../README.md`](../../README.md): what Veritas is and how to start
- [`../../PROJECT_OVERVIEW.md`](../../PROJECT_OVERVIEW.md): status, architecture, how it works
- [`../../INSTALL.md`](../../INSTALL.md), [`../MACOS.md`](../MACOS.md), [`../OPERATIONS.md`](../OPERATIONS.md): installing and running it
- [`../../IMPLEMENTATION_ORDER.md`](../../IMPLEMENTATION_ORDER.md): what was done, what is open

| Document | What it was |
|---|---|
| `dpdpa-agent-implementation-plan-v2.md`, `...-v3-generic-layer.md` | The first implementation plans for the server and the generic (org-agnostic) layer |
| `dpdpa-compliance-agent-reference-repos.md` | Reference projects looked at during design |
| `PRODUCT_COMPLETION_PLAN.md`, `FINALS_PROGRESS.md`, `Veritas_Finals_Plan-4.md` | The finals-period plan and progress log (this is where the Raspberry Pi reference unit appears; it was later repositioned as an optional edge option and then dropped from the product) |
| `Veritas — On-Premise Productization & Production Implementation Plan.md` | The long plan for turning the pipeline into an on-premise product |
| `WINDOWS_PRODUCT_ROADMAP.md` | The Windows-first installer roadmap |
| `VERITAS_TECHNICAL_AUDIT.md`, `veritas_production_readiness.md` | Technical audit and production-readiness review from early September |
| `BLOCK5_SIMULATION_PLAN.md` | An earlier simulation plan (the current one is `veritas-demo/SIMULATION_PLAN.md`) |
| `LINUX_TEST_FINDINGS.md` | Findings from the first Ubuntu test of v1.0.15 (all fixed) |
| `LICENSE_PORTAL_REVIEW.md` | Review of the license portal before version 2.1 (the problems listed there are resolved; see `IMPLEMENTATION_ORDER.md`) |
| `HOW_TO_DEPLOY_TO_CLIENT.md` | The old Windows 1.0.0 customer onboarding steps (replaced by `../CUSTOMER_ONBOARDING.md`) |
