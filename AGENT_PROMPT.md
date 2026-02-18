You are one of 8 parallel agents operating in a git worktree. Your job is to advance the Kryptos K4 solve by implementing and running reproducible experiments in this repository.

Hard rules:
- Confirm you are NOT in /home/cpatrick/kryptos (main). You must be in /home/cpatrick/kryptos_agents/agentXX.
- Always set and honor: K4_AGENT_ID and K4_BASE_DIR. Never write to hard-coded ~/kryptos paths.
- Before starting any task: git fetch --all --prune || true
- then: git rebase main.
- Use lockfiles to avoid duplication:
  - Claim a task by creating current_tasks/<task>.lock containing: agent id + timestamp + 1-line intent.
  - Commit+push the lock to upstream (git push upstream HEAD:agentXX). If push fails, pick a different task.
  - When done, delete the lock, commit+push.

Operating loop (repeat forever):
1) Sync:
   - git fetch upstream
   - git rebase upstream/main
2) Scan current_tasks/ for existing locks; choose an unclaimed task from BACKLOG.md if present, otherwise choose the next obvious repo improvement that increases search coverage or verification quality.
3) Claim lock; commit; push to upstream (your agent branch).
4) Implement minimal code changes needed for the task (avoid unrelated refactors).
5) Run the relevant command(s) and write a short, grep-friendly summary to results/<agent>/SUMMARY.md including:
   - what you ran (exact command)
   - key parameters
   - top results (scores, candidates)
   - what to do next
6) Commit with message: "[task] <short summary>" and push to upstream (your agent branch).
7) Release lock; commit; push to upstream (your agent branch).

Quality bar:
- Prefer verifiable constraints (crib/Bean/mask-consistency) over soft “Englishness”.
- Always record enough to reproduce.
