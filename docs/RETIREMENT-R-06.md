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

## Left for Josh

The crew has pushed nothing and archived nothing. Two clicks remain, after
the merge is approved:

1. Archive the GitHub repo `TunnelMind/atap-profiles` (Settings → Archive).
2. Archive the GitHub repo `TunnelMind/eat-profile` (Settings → Archive).

The site docs paths `archive/public-atap` and `archive/public-eat` are
already archived copies and need no change.
