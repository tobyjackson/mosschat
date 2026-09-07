# Git and pull request process

This document is derived from PLAN.md section 7 ("Team process"). It is the
one source for how work orders become branches, worktrees, commits and pull
requests in this repository. Read it before opening a branch; nothing here
requires asking anyone first.

## Worktrees

One worktree per agent. Two agents never share a tree. Xavier creates the
worktree for a work order's owner; an agent otherwise creates its own.

```
git -C ~/code/mosschat worktree add ~/code/mosschat-wt/<agent> -b <branch> main
```

`<agent>` is the agent's name, lowercase (for example `jerome`, `cassia`,
`wystan`). The worktree lives at `~/code/mosschat-wt/<agent>`.

When the work order's pull request merges, the worktree is removed:

```
git -C ~/code/mosschat worktree remove ~/code/mosschat-wt/<agent>
```

## Branches

Branch names follow `phase-N/wo-N.M-slug`, where `N` is the phase number,
`N.M` is the work order number from PLAN.md, and `slug` is a short
hyphenated description. Example: `phase-1/wo-1.1-workspace-and-ci`.

One work order equals one branch equals one pull request, with exactly one
owner. Konrad specifies and delegates and does not implement; Jerome
implements the order and nothing adjacent; Wystan tests and never fixes;
Yseult reviews and never edits application code; Cassia owns schema and
transactions; Ursula owns CI, packaging and release; Octavia owns interface
design; Eulalia owns `docs/`; Zephyrine owns `state.json` and the backlog;
Xavier owns branches and merges; Dmitri is called before a decision freezes,
not after.

## Commits

Every commit message ends with the line:

```
Claude-Session: https://claude.ai/code/session_01JhkHdEWtjg7WVCLjek3AWV
```

## Pull requests

The PR body carries the work order number (for example `WO-1.1`) and the
verification output pasted in full, not summarized or described. A work
order is done when its verification was run and that output is pasted into
the pull request.

Before merge, a pull request needs:

- CI green.
- One review from the owning role's reviewer: Konrad for implementation,
  Cassia for store changes, Yseult for keys, invites or untrusted parsing.
- A linked work order number.

Xavier merges. Nobody merges their own pull request.

Merges are squash merges. The source branch is deleted immediately after
merge, and the corresponding worktree is removed with `git worktree remove`.

## Bootstrap exception

This document itself is an exception to the process it describes: it is a
process document landing before the first work order exists, so there is no
work order to attach it to and no branch protection yet requiring review.
Xavier commits it straight to `main`, once. Every change after this one,
including any future edit to this file, goes through a branch, a worktree
and a pull request as described above.

## Branch protection status

As of this document, `main` requires pull requests, blocks force pushes and
branch deletion, and requires at least one approving review before merge.
It does not yet require any status check, because no CI exists until WO-1.1
merges. Once WO-1.1's CI workflow lands, Xavier adds the required check
names to branch protection; this note stays until that is done.
