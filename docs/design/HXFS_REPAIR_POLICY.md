# Hxfs repair policy

Status: accepted
Stage: W5 (prerequisite for destructive `fsck --repair`)

## Why this document exists before the code

Detection and repair fail differently. A scrub that is wrong prints a
line nobody acts on. A repair that is wrong destroys the only copy of
the data it was asked to save, and it does so with the user's explicit
permission, which makes it worse than the corruption it was fixing.

Stage W therefore shipped detection first and blocked repair until the
destructive semantics were written down and reviewed. This document is
that review. It defines, per finding, what repair is permitted to do,
what it is forbidden to do, and what it must have proof of before it
does anything at all.

## Classification

Every finding falls into exactly one class. The class, not the
finding, decides what repair may do.

### Class A — derivable

The correct value is recomputable from data the filesystem still
holds, and the recomputation does not depend on the damaged value.

Repair rewrites the damaged value from the recomputed one. No user
data is discarded. These repairs are safe to apply automatically.

- `QuotaMismatch` — quota totals are a sum over live objects. The
  objects are authoritative; the totals are a cache of them. Recompute
  and overwrite.
- `ReferenceMismatch` where the allocation tree and the backref tree
  agree with each other and only the refcount total disagrees. The
  refcount is then a derived count of existing backrefs.

### Class B — destructive, consent required

Repair must discard something to make the volume consistent. What is
discarded may be live data. These repairs are refused unless the
caller passes explicit destructive consent, and each one is reported
individually before it is applied.

- `UnexpectedRoot` — a tree root exists without the feature bit that
  gives it meaning. The tree cannot be interpreted, so its blocks
  cannot be validated or migrated; repair detaches the root and lets
  the allocator reclaim the region. If the feature bit was lost rather
  than the root spuriously written, this destroys a real tree. That is
  the trade, and it is why consent is required.
- `ReferenceMismatch` where the trees disagree in a way that is not
  derivable — repair rebuilds refcount and backref state from the
  allocation tree, dropping references it cannot attribute to a live
  owner. Unattributable references are usually leaked blocks, but an
  orphaned-yet-live extent would be freed.

### Class C — never repaired automatically

The damage is to something repair has no independent source of truth
for. Rewriting it would be a guess with a checksum on it: the volume
would stop reporting the problem without the problem being fixed.

- `MissingRequiredRoot` — a required tree root is absent. Synthesising
  an empty tree makes every object it indexed unreachable while
  presenting a clean volume. Refuse; the answer is a restore, or a
  journal replay if one is pending.
- `BadFeatureSet` — the volume declares a base feature combination
  this build does not implement. Repair cannot know whether the volume
  is from a newer version or corrupt. Clearing the bits would mount an
  unknown on-disk format with code that does not understand it.
- `NeedsJournalReplay` — not corruption. The volume is mid-recovery
  and the journal holds the correct values. Replay is the repair;
  fsck must not pre-empt it. Repairing anything else on a volume in
  this state is forbidden, because the journal is about to overwrite
  it.

## Ordering rules

1. **Replay before repair.** If `NeedsJournalReplay` is present, no
   other repair may run in the same pass. Whatever else the scrub
   found may be an artefact of the un-replayed state.
2. **Refuse before repair.** If any Class C finding is present, the
   pass refuses as a whole rather than repairing the Class A findings
   around it. Partial repair of a volume with an unexplained structural
   fault produces a volume that looks healthier than it is, and the
   next scrub has less evidence to work with.
3. **Report before applying.** Every action is recorded in the plan
   before it executes, so a caller can print the plan and stop.
4. **Fail closed.** An action that cannot complete leaves the volume in
   its pre-action state and aborts the pass. Half-applied repair is
   the one outcome worse than no repair.

## Consent

Destructive consent is a distinct argument, not a flag on a struct
that a caller can set by copying an example. A caller that has not
thought about Class B actions cannot accidentally authorise them.

Consent authorises the *class*, not the pass: a plan containing Class B
actions still reports each one, and a caller that wants a dry run gets
the plan without applying it.

## What repair never touches

- File contents. Repair reconciles metadata about extents; it does not
  rewrite the extents themselves.
- The volume UUID, generation counters, or checkpoint chain history.
  These identify the volume; rewriting them to satisfy a consistency
  check would break the thing the check exists to protect.
- Anything on a volume whose superblock does not decode. If the
  superblock is unreadable, no repair has a trustworthy starting
  point.
