#!/usr/bin/env bash
#
# ATAP v0.1 Receipt Verifier
# Standard:   https://tunnelmind.ai/atap/standard
# License:    Apache-2.0
#
# Usage: verify.sh [RECEIPT_DIR]
#   RECEIPT_DIR defaults to the current directory. The directory MUST contain
#   an unpacked ATAP Receipt ZIP (manifest.json, ait.json, attestation_chain.json,
#   public_keys.json, plus any optional files listed in manifest.files[]).
#
# Requirements: bash 4+, jq 1.6+, openssl 3.0+ (or 1.1.1 with -rawin), python3.
# python3 is used only for RFC 8785 (JSON Canonicalization Scheme) canonicalization.

set -euo pipefail

RECEIPT_DIR="${1:-.}"
cd "$RECEIPT_DIR"

err() { echo "FAIL: $*" >&2; exit 1; }
ok()  { echo "  OK   $*"; }

command -v jq      >/dev/null || err "jq is required"
command -v openssl >/dev/null || err "openssl is required"
command -v python3 >/dev/null || err "python3 is required"

[ -f manifest.json         ] || err "manifest.json not found"
[ -f ait.json              ] || err "ait.json not found"
[ -f attestation_chain.json ] || err "attestation_chain.json not found"
[ -f public_keys.json      ] || err "public_keys.json not found"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# RFC 8785 (JCS) canonicalizer via python3 stdlib. Reads JSON on stdin, writes
# canonical bytes on stdout. This implements the JCS subset that covers v0.1
# artifacts (no NaN/Infinity, finite numbers).
canonicalize() {
  python3 -c '
import json, sys
def canon(o):
    if isinstance(o, dict):
        return "{" + ",".join(json.dumps(k) + ":" + canon(v) for k,v in sorted(o.items())) + "}"
    if isinstance(o, list):
        return "[" + ",".join(canon(x) for x in o) + "]"
    if isinstance(o, bool) or o is None:
        return json.dumps(o)
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        # RFC 8785 §3.2.2.3 number serialization is the ECMAScript
        # Number->String algorithm: the shortest string that round-trips.
        # Python repr() provides that; an integer-valued float serializes
        # with no fractional part. (An earlier ".17g" form was non-conformant
        # — it expanded 0.7 to 0.69999999999999996 and broke verification.)
        if o == int(o) and abs(o) < 1e21:
            return str(int(o))
        return repr(o)
    return json.dumps(o, ensure_ascii=False)
print(canon(json.load(sys.stdin)), end="")
'
}

# Build a PEM-encoded Ed25519 public key from a 32-byte raw key (hex, no 0x).
pem_from_raw_ed25519() {
  local hex="$1" out="$2"
  # Ed25519 SubjectPublicKeyInfo prefix: 302a300506032b6570032100
  { printf '302a300506032b6570032100%s' "$hex" | xxd -r -p; } > "$TMP/.pub.der"
  openssl pkey -pubin -inform DER -in "$TMP/.pub.der" -out "$out" 2>/dev/null
}

# Verify an Ed25519 signature over $msgfile using PEM pubkey $pemfile and raw signature hex $sighex.
verify_sig() {
  local msgfile="$1" pemfile="$2" sighex="$3"
  printf '%s' "$sighex" | xxd -r -p > "$TMP/.sig"
  openssl pkeyutl -verify -pubin -inkey "$pemfile" -rawin -in "$msgfile" -sigfile "$TMP/.sig" >/dev/null
}

# Look up the public key (hex, no 0x) for a given witness OAI at a given RFC-3339 timestamp.
lookup_key() {
  local witness="$1" t="$2"
  jq -r --arg w "$witness" --arg t "$t" '
    .keys[] |
    select(.witness == $w and .valid_from <= $t and .valid_until > $t) |
    select(.status != "compromised" or (.compromise_notice and $t < .compromise_notice.disclosed_at)) |
    .public_key
  ' public_keys.json | head -1 | sed 's/^0x//'
}

##############################################################################
# 1. File integrity
##############################################################################
echo "==> Verifying file integrity (manifest.files[])"
jq -c '.files[] | select(.sha256 != null)' manifest.json | while IFS= read -r entry; do
  path=$(jq -r '.path' <<<"$entry")
  want=$(jq -r '.sha256' <<<"$entry" | sed 's/^0x//')
  [ -f "$path" ] || err "$path missing"
  got=$(openssl dgst -sha256 -binary "$path" | xxd -p -c 256)
  [ "$got" = "$want" ] || err "$path sha256 mismatch (want $want, got $got)"
  ok "$path"
done

##############################################################################
# 2. AIT signature
##############################################################################
echo "==> Verifying AIT witness signature"
AIT_WIT=$(jq -r '.witness'     ait.json)
AIT_TS=$(jq  -r '.issued_at'   ait.json)
AIT_SIG=$(jq -r '.witness_signature' ait.json | sed 's/^ed25519:0x//')
[[ "$AIT_SIG" =~ ^[0-9a-f]{128}$ ]] || err "AIT witness_signature malformed"
AIT_KEY=$(lookup_key "$AIT_WIT" "$AIT_TS")
[ -n "$AIT_KEY" ] || err "no key for AIT witness $AIT_WIT at $AIT_TS"
pem_from_raw_ed25519 "$AIT_KEY" "$TMP/ait.pub.pem"
jq 'del(.witness_signature)' ait.json | canonicalize > "$TMP/ait.canon"
verify_sig "$TMP/ait.canon" "$TMP/ait.pub.pem" "$AIT_SIG"
ok "AIT $(jq -r '.id' ait.json)"

##############################################################################
# 3. Block chain
##############################################################################
echo "==> Walking block chain"
WITNESS=$(jq -r '.witness' manifest.json)
PREV="0x0000000000000000000000000000000000000000000000000000000000000000"
COUNT=0
while IFS= read -r block; do
  pb=$(jq -r '.prev_block_hash' <<<"$block")
  [ "$pb" = "$PREV" ] || err "block chain break (want prev=$PREV, got $pb)"

  # self_hash check
  jq 'del(.self_hash, .witness_signature)' <<<"$block" | canonicalize > "$TMP/blk.canon"
  want_self=$(jq -r '.self_hash' <<<"$block" | sed 's/^0x//')
  got_self=$(openssl dgst -sha256 -binary "$TMP/blk.canon" | xxd -p -c 256)
  [ "$got_self" = "$want_self" ] || err "self_hash mismatch on $(jq -r '.id' <<<"$block")"

  # witness signature over the raw self_hash bytes
  ts=$(jq -r '.period_end' <<<"$block")
  key_hex=$(lookup_key "$WITNESS" "$ts")
  [ -n "$key_hex" ] || err "no key for $WITNESS at $ts"
  pem_from_raw_ed25519 "$key_hex" "$TMP/blk.pub.pem"
  printf '%s' "$got_self" | xxd -r -p > "$TMP/blk.selfhash"
  sig=$(jq -r '.witness_signature' <<<"$block" | sed 's/^ed25519:0x//')
  verify_sig "$TMP/blk.selfhash" "$TMP/blk.pub.pem" "$sig"

  PREV="0x$want_self"
  COUNT=$((COUNT + 1))
  ok "$(jq -r '.id' <<<"$block")"
done < <(jq -c '.[]' attestation_chain.json)

# 4. chain_head_hash in manifest matches last block
MANIFEST_HEAD=$(jq -r '.chain_head_hash' manifest.json)
[ "$MANIFEST_HEAD" = "$PREV" ] || err "manifest chain_head_hash $MANIFEST_HEAD != last block self_hash $PREV"

##############################################################################
# 5. Attestation strength (ATAP §7.4.1 — optional in v0.1.x, required at v0.2)
##############################################################################
RCPT_STRENGTH=$(jq -r '.attestation_strength // "MISSING"' manifest.json)
if [ "$RCPT_STRENGTH" = "MISSING" ]; then
  echo "WARN: manifest.attestation_strength missing — treating as 'self-asserted' (ATAP §7.4.1). Required at v0.2." >&2
  RCPT_STRENGTH="self-asserted"
fi
case "$RCPT_STRENGTH" in
  self-asserted|software|tee-tpm|silicon-root) ;;
  *) err "manifest.attestation_strength has unrecognized value '$RCPT_STRENGTH' (expected self-asserted | software | tee-tpm | silicon-root)";;
esac
# Cross-check against the matching key entry, if the key declares a strength.
KEY_STRENGTH=$(jq -r --arg w "$WITNESS" --arg t "$AIT_TS" '
  .keys[] |
  select(.witness == $w and .valid_from <= $t and .valid_until > $t) |
  select(.status != "compromised" or (.compromise_notice and $t < .compromise_notice.disclosed_at)) |
  .attestation_strength // empty
' public_keys.json | head -1)
if [ -n "$KEY_STRENGTH" ]; then
  STRENGTH_RANK() { case "$1" in self-asserted) echo 0;; software) echo 1;; tee-tpm) echo 2;; silicon-root) echo 3;; *) echo -1;; esac; }
  R_RANK=$(STRENGTH_RANK "$RCPT_STRENGTH")
  K_RANK=$(STRENGTH_RANK "$KEY_STRENGTH")
  [ "$R_RANK" -le "$K_RANK" ] || err "manifest.attestation_strength=$RCPT_STRENGTH exceeds key.attestation_strength=$KEY_STRENGTH"
  ok "attestation_strength=$RCPT_STRENGTH (key-attested)"
else
  echo "WARN: matching key entry omits attestation_strength — receipt's $RCPT_STRENGTH claim is not key-attested (ATAP §8.1). Required at v0.2." >&2
  ok "attestation_strength=$RCPT_STRENGTH (self-attested by receipt)"
fi

echo "==> Receipt verifies (blocks=$COUNT, attestation_strength=$RCPT_STRENGTH)"
exit 0
