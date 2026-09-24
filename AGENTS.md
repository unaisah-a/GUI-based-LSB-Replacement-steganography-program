# Repository work instructions

Before making changes, read [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md). It records the agreed scope, current authorization, task dependencies, acceptance criteria and handoff state.

- Respect the user's latest authorized task scope. The current handoff is T01 only; do not start T02-T09 without a subsequent user instruction authorizing further work.
- Maintain the task ledger after completed tasks and before handoff. Use TODO, IN_PROGRESS, BLOCKED and DONE; record actual changes, evidence and remaining work.
- Mark DONE only when acceptance criteria are met. For BLOCKED, record the specific blocker and what would resolve it.
- Record commands, environment and tested revision/working-tree state. Distinguish historical branch evidence from current results, and planned checks from executed checks.
- Preserve the original gin and Tristan branches and unrelated work. Use this integration worktree for consolidation.
- Never record secrets, private keys, invented test results, contribution percentages or signatures.
- Keep instructions concise; the implementation guide is the source of detailed project decisions and progress.
