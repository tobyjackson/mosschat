# state.json

The resume point. Any new session, human or agent, reads `state.json`
at the repository root first, before anything else here.

## Keys
- `updated_at`: ISO 8601 timestamp with UTC offset, last write time.
- `phase`: the current plan phase number, as a string.
- `task`: what is being worked on right now, in plain language.
- `next_step`: the single next action, and who takes it.
- `blocked_on`: what has to happen before `next_step` can proceed.
- `where`: this repo, the plan revision, and the authority when the
  plan and `decisions.md` disagree.
- `open_decisions`: array of open decisions and who makes each.
- `notes_for_next_step`: standing facts a cold session needs, found
  nowhere better.

## Rule
Rewritten after every work order, to current values only. Never
appended to, carries no history. Section 7 of PLAN.md is the source.

## Ownership
Zephyrine owns `state.json` and writes it. Xavier merges the pull
request that changes it, alongside the work order that changed it.
