# Retirement R-06: atap-profiles and eat-profile folded into atap

Date: 2026-10-07

## What moved where

Two repos were folded into this one with `git subtree add`. Their history
came across in full; nothing was squashed.

| Origin repo (branch `main`) | Now at | Source commit | Subtree merge commit |
|---|---|---|---|
| [TunnelMind/atap-profiles](https://github.com/TunnelMind/atap-profiles) | `profiles/` | `0ee45b963802ff06e82a5ea195ec1ed0cacc4283` | `6f3f0d3601678d1277f6b58177f04fc680b37866` |
| [TunnelMind/eat-profile](https://github.com/TunnelMind/eat-profile) | `eat/` | `2dee03f4d0f878f8b3850954de8414605056a373` | `f3b25899f5d3dfaf664df00473dd95ee668ee525` |

The source commit is the second parent of each merge commit
(`git rev-parse 6f3f0d3^2 f3b2589^2`). The README's "Profiles" section
points to both trees.

## CI

GitHub only runs workflows from the repo-root `.github/workflows`, so the
folded `profiles/.github/workflows/validate.yml` never runs here. The root
`.github/workflows/profiles-validate.yml` runs the same steps (`npm install`,
`npm run validate`, `npm run verify` on Node 20) in `profiles/`, on any push
or pull request that touches `profiles/**`. The folded file is left as is so
the subtree stays a clean copy of its origin.

## Follow-ups

`profiles/registry.json:5` (`source`) still names
https://github.com/TunnelMind/atap-profiles. It should become
https://github.com/TunnelMind/atap/tree/main/profiles once the coordinator
approves an edit inside the subtree.

## Left for Josh

The crew has pushed nothing and archived nothing. Two clicks and one
decision remain, after the merge is approved:

1. Archive the GitHub repo `TunnelMind/atap-profiles` (Settings → Archive).
2. Archive the GitHub repo `TunnelMind/eat-profile` (Settings → Archive).
3. Decide on the normative spec. `ATAP-v0.1.md` still names
   `github.com/TunnelMind/atap-profiles` as the profile registry's source of
   truth and as the place for profile-proposal PRs and objection issues, at
   lines 600, 611, 727, 729 and 836. Once that repo is archived it can no
   longer take PRs or issues, so those processes have nowhere to go. The
   crew did not edit the spec; Josh decides whether to issue an erratum or
   make the change in a v0.1.1.

The site docs paths `archive/public-atap` and `archive/public-eat` are
already archived copies and need no change.
