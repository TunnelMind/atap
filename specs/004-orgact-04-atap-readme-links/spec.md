# Spec 004: orgact-04-atap-readme-links

Org review action item 4 (tunnelmind-spec#15, `docs/ORG-REVIEW-2026-11.md` §(d) item 4), approved as written by
the owner on 2026-11-13: "approve A2, A3, A4, A9, A10, A14" and "Merge nothing and deploy nothing."

## Intent

atap's README links two private, archived repos (`TunnelMind/atap-profiles`, `TunnelMind/eat-profile`) as the
origin of `profiles/` and `eat/`, so an outside reader of this public repo hits two dead links. Drop the two link
targets, keep the origin fact in words, README only: "no tag, no version bump, no publish".

Item 4, quoted: "Reword the two README lines that link the archived profile repos — atap … The lines also record the
origin of the two directories; keep that fact in words (it is also written in `docs/RETIREMENT-R-06.md`) and drop
only the dead links." Fable's line: "APPROVE | Outside readers of a public protocol repo hit two dead links today;
README-only, no tag, no version bump." Order and coupling: "Item 4 stands alone."

## Re-verification against the default branch (planner, 2026-11-13)

`HEAD` = `origin/main` = `0d1f2cabcf8b8cbb9998840693bbb6e7fb1486f9`.

| Cited fact | Now | Holds |
|---|---|---|
| `README.md:180-181` link atap-profiles and eat-profile | `README.md:180` `[github.com/TunnelMind/atap-profiles](https://github.com/TunnelMind/atap-profiles)`, `README.md:181` `[github.com/TunnelMind/eat-profile](https://github.com/TunnelMind/eat-profile)` | yes |
| Check-after "today it prints lines 180 and 181" | the grep prints exactly lines 180 and 181, exit 0 | yes |
| Origin also written in `docs/RETIREMENT-R-06.md` | `docs/RETIREMENT-R-06.md:1,12-13` | yes |
| 0 open PRs in atap | NOT re-verified: `gh pr list` was denied to the planner | → GATE 0 |

## User Scenarios

**US1 — outside reader.** A reader of the public atap README sees where `profiles/` and `eat/` came from without a
link that 404s.

- Given the README on this branch, when `grep -nE '\]\(https://github\.com/TunnelMind/(atap-profiles|eat-profile)' README.md`
  runs, then it prints no line (exit 1). On `main` today it prints lines 180 and 181 (the check can fail).
- Given the README on this branch, the words `TunnelMind/atap-profiles` and `TunnelMind/eat-profile` still appear in
  the Profiles table, and the row points at `docs/RETIREMENT-R-06.md` (a link inside this repo) for the history.

## Functional Requirements

- FR-001: `README.md:180-181` no longer contain a Markdown link whose target is `https://github.com/TunnelMind/atap-profiles` or `https://github.com/TunnelMind/eat-profile`.
- FR-002: The Origin column of both rows still names the origin repo as plain text (`TunnelMind/atap-profiles`, `TunnelMind/eat-profile`), says it is archived, and links `./docs/RETIREMENT-R-06.md`.
- FR-003: The Tree and Contents columns of both rows are unchanged byte for byte.
- FR-004: No file other than `README.md` changes outside this spec directory. No tag, no version bump, no CHANGELOG entry, no publish.

## Success Criteria

- SC-001: `! grep -nE '\]\(https://github\.com/TunnelMind/(atap-profiles|eat-profile)' README.md` exits 0 (fails on `main` today).
- SC-002: `grep -c 'TunnelMind/atap-profiles' README.md` ≥ 1 and `grep -c 'TunnelMind/eat-profile' README.md` ≥ 1.
- SC-003: `git diff --name-only origin/main -- . ':!specs'` prints exactly `README.md`.
- SC-004: `test -f docs/RETIREMENT-R-06.md` (the new relative link resolves).

## Edge Cases

- The grep only matches a link *target* `](https://github.com/TunnelMind/…`; the plain words are allowed (the item says so).
- Line numbers may shift if another PR lands first; GATE 0 checks that no open PR touches `README.md`.
- `README.md:173-175` says the origin repos "are being archived"; item 4 names only lines 180-181, so that sentence stays (see Out of Scope).

## Assumptions

- The two origin repos are private and archived (the org review and R-06 say so; not re-checked here, no GitHub query beyond read-only PR listing is in scope).
- No CI workflow triggers on `README.md` (`.github/workflows/*.yml` path filters: packages, profiles, verify.sh, actions/witness, tags), so the PR will show no checks; the verify is the item's check-after.

## Out of Scope

- `docs/RETIREMENT-R-06.md:12-13` also link the two archived repos. It is the retirement record; item 4 is README only. Listed for the owner as a possible follow-up, not done.
- Other mentions (`CHANGELOG.md`, `eat/README.md`, `eat/EAT-PROFILE-v0.1.md`, `packages/eat-js/*`, `profiles/package*.json`) — not item 4.
- Rewording `README.md:173-175` ("are being archived").
- Any tag, version bump, npm publish, GitHub setting, comment on any issue/PR, or merge.
