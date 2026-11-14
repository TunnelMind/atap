# Plan: orgact-04-atap-readme-links

## Constitution check

atap has no `.specify/memory/constitution.md`; the crew constitution applies through `constitution-accepted.json`.
README prose only, no behaviour change, no decision-issuing code: no ADR, no gate besides GATE 0 (open-PR check the
planner could not run) and GATE F.

## Where the change goes

| File | Change | Task |
|---|---|---|
| `README.md:180` | Origin cell `[`github.com/TunnelMind/atap-profiles`](https://github.com/TunnelMind/atap-profiles)` → `` `TunnelMind/atap-profiles` (archived; see [R-06](./docs/RETIREMENT-R-06.md)) `` | T001 |
| `README.md:181` | Origin cell `[`github.com/TunnelMind/eat-profile`](https://github.com/TunnelMind/eat-profile)` → `` `TunnelMind/eat-profile` (archived; see [R-06](./docs/RETIREMENT-R-06.md)) `` | T001 |

Nothing else. Tree and Contents cells unchanged.

## Approach

One task: run the check-after on the unchanged tree and quote it failing (prints 180 and 181), edit the two cells,
run the verify and quote it passing.

## Risks

- Dropping the origin fact: guarded by SC-002 in the verify.
- Silent widening (CHANGELOG, R-06, other files): guarded by the `git diff --name-only` clause in the verify.
- No CI runs on a README-only PR (every workflow has path filters that exclude `README.md`; `publish.yml` runs on
  `v*` tags only). "CI green where CI exists" is therefore vacuous for this PR; the reviewer confirms the PR shows no
  required check rather than a red one.

## Verify (every task)

The repo has CI but none of it triggers on `README.md`, so the verify is the item's check-after, inverted to exit 0
on success (`if … then exit 1`, because `! grep` is exempt from `set -e`), plus the guards above:

```bash
bash -c 'set -e; if grep -nE "\]\(https://github\.com/TunnelMind/(atap-profiles|eat-profile)" README.md; then exit 1; fi; grep -q "TunnelMind/atap-profiles" README.md; grep -q "TunnelMind/eat-profile" README.md; test -f docs/RETIREMENT-R-06.md; test "$(git diff --name-only origin/main -- . ":!specs")" = README.md'
```

On `main` today it fails at the first clause (grep prints `180:` and `181:`).

## Closeout (for the coordinator's PR body)

- What changed: `README.md:180`, `README.md:181`.
- Check-after output before (lines 180, 181) and after (no line).
- Not done: `docs/RETIREMENT-R-06.md:12-13` dead links and `README.md:173-175` wording (outside item 4); no tag, version bump, publish.
- Owner steps after merge: none. The item has no host, database, registry or other-repo step; no release is needed
  for a README edit (npm package READMEs come from `packages/*`, not the root README).
