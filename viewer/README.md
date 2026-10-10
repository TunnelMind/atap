# ATAP receipt viewer

One HTML file that checks an ATAP Receipt ZIP in the browser. The file is
read locally and never sent anywhere.

## Open it

1. Download [`dist/atap-viewer.html`](./dist/atap-viewer.html). It is the
   built file, committed to this repo, with every script inlined.
2. Open it in a browser. It works from `file://`; no server is needed.
3. Choose a Receipt ZIP with the file picker, or drop it anywhere on the
   window.

The page makes no network requests. Its Content-Security-Policy is
`default-src 'none'` and `connect-src 'none'`, and allows only the page's
own inline script and style (by sha256 hash), so nothing else can load or
run.

The ZIP may hold the receipt at its root (the CLI's own `receipt.zip`) or
under one top folder (`zip -r x.zip dir`). It must contain exactly one
`manifest.json`.

## What "Verified: yes" means

The page runs the same checks as `atap-witness verify DIR`
(`packages/atap-cli/src/cli.ts`), in the same order and with the same
reason strings, so the page and the CLI agree:

1. Every file listed in `manifest.json` is present and matches its sha256.
2. The AIT witness signature, and the attestation block chain and its
   signatures, via `verifyReceipt` from `@tunnelmindai/atap`, bundled into
   the page.
3. When the manifest lists `profile_artifacts/witness_events.json`: each
   event's `self_hash`, the `prev_event_hash` chain from genesis, the
   witness signature on each event (did:key witnesses), and that the blocks
   cover the events exactly (first event, last event, chain head hash,
   count).

It reads v0.1 receipts (OAI witness) and v0.2 receipts (did:key witness).

What it does **not** mean: a "yes" proves the receipt is internally
consistent and signed by the key it names. It does not prove the witness is
trustworthy. For a did:key witness the key is self-asserted, so a "yes"
shows integrity only.

A receipt that fails shows "Verified: no" and the reason, nothing else.
A ZIP that cannot be read shows "Could not read this ZIP" and the reason.

## What it shows

For a verified receipt:

- Witness (marked `did:key` or `OAI`), operator, attestation strength,
  profile, AIT, receipt id, period, block count, event count, chain head
  hash.
- Warnings, if the verifier returned any.
- The event list: event type, evidence tier (the profile's
  `payload.evidence`, or "no tier"), and witnessed time.
- The manifest's file list with each sha256. Hashes are shown as hashes.

Receipt strings are only ever set as text, never parsed as HTML.

## Limits

The ZIP is treated as hostile input (`src/zip.js`):

| Limit | Value |
|---|---|
| ZIP size | 20 MiB |
| One entry, uncompressed | 10 MiB (enforced on bytes actually inflated, not the declared size) |
| Entries | 64 |

Refused outright: entry names with `..` segments, absolute paths, drive
letters, backslashes or NUL; duplicate names; ZIP64; multi-disk archives;
encrypted entries; compression methods other than stored and deflate.

## Browser support

The page needs WebCrypto Ed25519 (`crypto.subtle` with `Ed25519`) and
`DecompressionStream('deflate-raw')`. It tests Ed25519 against an RFC 8032
test vector before reading the ZIP. If that fails it gives no verdict and
shows only:

> This browser can't verify Ed25519 signatures, so it can't check this
> receipt. Use a current Chrome, Edge, Firefox or Safari, or the
> atap-witness CLI.

It never shows an unverified view of a receipt.

## Build and test

The build inlines `packages/atap-js/dist` (build that first:
`npm install && npm run build` in `packages/atap-js`) and `src/*.js` into
`src/index.html`, writing `dist/atap-viewer.html`. No dependencies; the
output is byte-for-byte reproducible.

```bash
cd viewer
npm run build   # writes dist/atap-viewer.html
npm test        # builds, then node --test test/*.test.mjs
```
