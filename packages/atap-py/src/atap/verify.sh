#!/usr/bin/env bash
#
# ATAP v0.1/v0.2 Receipt Verifier
# Standard:   https://tunnelmind.ai/atap/standard
# License:    Apache-2.0
#
# Usage: verify.sh [RECEIPT_DIR]
#   RECEIPT_DIR defaults to the current directory. The directory MUST contain
#   an unpacked ATAP Receipt ZIP (manifest.json, ait.json, attestation_chain.json,
#   public_keys.json, plus any optional files listed in manifest.files[]).
#
# Requirements: bash 4+, jq 1.6+, openssl 3.0+ (or 1.1.1 with -rawin), python3.
# python3 is used only for RFC 8785 (JSON Canonicalization Scheme) canonicalization
# and for the base58btc decode of did:key witnesses (ATAP-v0.2 §3).

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

# Raw Ed25519 key (hex) encoded in a did:key, via python3 stdlib. Exits non-zero
# unless the input is did:key:z + base58btc(0xed 0x01 || 32-byte key); mirrors
# packages/atap-js/src/didkey.ts.
didkey_to_hex() {
  python3 -c '
import re, sys
d = sys.argv[1]
if not re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}", d):
    sys.exit(1)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in d[len("did:key:z"):]:
    n = n * 58 + B58.index(c)
# "z6Mk" rules out leading 1s (zero bytes), so the big-int bytes are the whole decode.
b = n.to_bytes((n.bit_length() + 7) // 8, "big")
if len(b) != 34 or b[:2] != b"\xed\x01":
    sys.exit(1)
print(b[2:].hex())
' "$1"
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
# With no valid entry this prints an empty line and the caller fails "no key for ...".
lookup_key() {
  local witness="$1" t="$2"
  if [[ "$witness" =~ ^did:key: ]]; then lookup_did_key "$witness" "$t"; return; fi
  jq -r --arg w "$witness" --arg t "$t" '
    .keys[] |
    select(.witness == $w and .valid_from <= $t and .valid_until > $t) |
    select(.status != "compromised" or (.compromise_notice and $t < .compromise_notice.disclosed_at)) |
    .public_key
  ' public_keys.json | head -1 | sed 's/^0x//'
}

# A did:key witness's key is the one its identifier encodes (ATAP-v0.2 §3.1), so
# it has no validity window: valid_from/valid_until are ignored. An entry is
# still required (the did:key alone does not replace it), every entry for the
# witness must carry that same key and declare 'self-asserted' (§3.2), and a
# compromise notice on any of them in force at $t voids the key. Mirrors
# pickDidKeyKey in packages/atap-js/src/verify.ts.
lookup_did_key() {
  local witness="$1" t="$2" did_hex pk strength first=""
  did_hex=$(didkey_to_hex "$witness") || err "witness $witness is not an Ed25519 did:key (ATAP-v0.2 §3)"
  while IFS=$'\t' read -r pk strength; do
    [ "${pk,,}" = "$did_hex" ] \
      || err "key entry for $witness carries a public_key other than the key it encodes (ATAP-v0.2 §3.1)"
    [ "$strength" = "self-asserted" ] \
      || err "key entry for $witness must declare attestation_strength 'self-asserted', got '$strength' (ATAP-v0.2 §3.2)"
    first="${first:-$pk}"
  done < <(jq -r --arg w "$witness" '
    .keys[] | select(.witness == $w) |
    [(.public_key | sub("^0x"; "")), (.attestation_strength // "absent")] | @tsv
  ' public_keys.json)
  jq -e --arg w "$witness" --arg t "$t" '
    any(.keys[]; .witness == $w and .status == "compromised"
      and ((.compromise_notice and $t < .compromise_notice.disclosed_at) | not))
  ' public_keys.json >/dev/null && first=""
  printf '%s\n' "$first"
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
MAN_WIT=$(jq -r '.witness' manifest.json)
# For a did:key witness the manifest and AIT must name the same witness (same
# rule as verifyReceipt): that is what binds the manifest and blocks to the key
# the AIT was signed with (ATAP-v0.2 §3.1). OAI-witnessed v0.1 records are not
# held to it (ATAP-v0.2 §3.4).
if [[ "$AIT_WIT" =~ ^did:key: || "$MAN_WIT" =~ ^did:key: ]]; then
  [ "$MAN_WIT" = "$AIT_WIT" ] || err "manifest witness $MAN_WIT != AIT witness $AIT_WIT"
fi
# ATAP-v0.2 §3.3: an AIT with a did:key witness or operator declares 0.2, and
# so does every block under it (checked in step 3). The operator is otherwise
# an identifier only (§3.5), but must still be a well-formed Ed25519 did:key.
DID_AIT=""
for id in "$AIT_WIT" "$(jq -r '.operator' ait.json)"; do
  if [[ "$id" =~ ^did:key: ]]; then
    didkey_to_hex "$id" >/dev/null || err "AIT identifier $id is not an Ed25519 did:key (ATAP-v0.2 §3)"
    DID_AIT=1
  fi
done
if [ -n "$DID_AIT" ]; then
  AIT_VER=$(jq -r '.ait_version' ait.json)
  [ "$AIT_VER" = "0.2" ] || err "AIT with a did:key witness or operator declares ait_version '$AIT_VER', want '0.2' (ATAP-v0.2 §3.3)"
fi
[[ "$AIT_SIG" =~ ^[0-9a-f]{128}$ ]] || err "AIT witness_signature malformed"
AIT_KEY=$(lookup_key "$AIT_WIT" "$AIT_TS")
[ -n "$AIT_KEY" ] || err "no key for AIT witness $AIT_WIT at $AIT_TS"
pem_from_raw_ed25519 "$AIT_KEY" "$TMP/ait.pub.pem"
jq 'del(.witness_signature)' ait.json | canonicalize > "$TMP/ait.canon"
verify_sig "$TMP/ait.canon" "$TMP/ait.pub.pem" "$AIT_SIG" || err "AIT signature invalid"
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
  if [ -n "$DID_AIT" ]; then
    abv=$(jq -r '.ab_version' <<<"$block")
    [ "$abv" = "0.2" ] || err "block $(jq -r '.id' <<<"$block") declares ab_version '$abv' under a did:key AIT (ATAP-v0.2 §3.3)"
  fi

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
  verify_sig "$TMP/blk.selfhash" "$TMP/blk.pub.pem" "$sig" || err "block signature invalid on $(jq -r '.id' <<<"$block")"

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
# ATAP-v0.2 §3.2: a did:key witness is self-asserted by definition. The receipt
# must say so explicitly (no v0.1 default); lookup_key holds key entries to the same.
if [[ "$WITNESS" =~ ^did:key: ]]; then
  [ "$RCPT_STRENGTH" = "self-asserted" ] \
    || err "did:key witness receipt must carry attestation_strength 'self-asserted', got '$RCPT_STRENGTH' (ATAP-v0.2 §3.2)"
fi
if [ "$RCPT_STRENGTH" = "MISSING" ]; then
  echo "WARN: manifest.attestation_strength missing — treating as 'self-asserted' (ATAP §7.4.1). Required at v0.2." >&2
  RCPT_STRENGTH="self-asserted"
fi
case "$RCPT_STRENGTH" in
  self-asserted|software|tee-tpm|silicon-root) ;;
  *) err "manifest.attestation_strength has unrecognized value '$RCPT_STRENGTH' (expected self-asserted | software | tee-tpm | silicon-root)";;
esac
# Cross-check against the matching key entry, if the key declares a strength.
if [[ "$WITNESS" =~ ^did:key: ]]; then
  # No validity window for a did:key's key (ATAP-v0.2 §3.1, as lookup_did_key).
  KEY_STRENGTH=$(jq -r --arg w "$WITNESS" --arg t "$AIT_TS" '
    .keys[] |
    select(.witness == $w) |
    select(.status != "compromised" or (.compromise_notice and $t < .compromise_notice.disclosed_at)) |
    .attestation_strength // empty
  ' public_keys.json | head -1)
else
  KEY_STRENGTH=$(jq -r --arg w "$WITNESS" --arg t "$AIT_TS" '
    .keys[] |
    select(.witness == $w and .valid_from <= $t and .valid_until > $t) |
    select(.status != "compromised" or (.compromise_notice and $t < .compromise_notice.disclosed_at)) |
    .attestation_strength // empty
  ' public_keys.json | head -1)
fi
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

##############################################################################
# 6. did:key manifest and event signatures
##############################################################################
# For a did:key witness every witness_signature must verify under its key
# (ATAP-v0.2 §3.1): the manifest's, and each Witness Event's when the receipt
# carries them. After step 5 so a §3.2 failure reports as such. OAI-witnessed
# v0.1 records are not checked here (§3.4).
if [[ "$WITNESS" =~ ^did:key: ]]; then
  echo "==> Verifying did:key manifest and event signatures"
  MAN_TS=$(jq -r '.generated_at' manifest.json)
  key_hex=$(lookup_key "$WITNESS" "$MAN_TS")
  [ -n "$key_hex" ] || err "no key for $WITNESS at $MAN_TS"
  pem_from_raw_ed25519 "$key_hex" "$TMP/man.pub.pem"
  jq 'del(.witness_signature)' manifest.json | canonicalize > "$TMP/man.canon"
  sig=$(jq -r '.witness_signature' manifest.json | sed 's/^ed25519:0x//')
  verify_sig "$TMP/man.canon" "$TMP/man.pub.pem" "$sig" || err "manifest signature invalid"
  ok "manifest"

  # tunnelmind:code_crew:v1 receipts list their events here (atap-cli WITNESS_EVENTS).
  EVENTS=profile_artifacts/witness_events.json
  if jq -e --arg p "$EVENTS" 'any(.files[]?; .path == $p)' manifest.json >/dev/null; then
    [ -f "$EVENTS" ] || err "$EVENTS missing"
    while IFS= read -r ev; do
      id=$(jq -r '.id' <<<"$ev")
      # The signature is over self_hash, so self_hash must be the event's own
      # hash, or a signature over some other hash would pass.
      jq 'del(.self_hash, .witness_signature)' <<<"$ev" | canonicalize > "$TMP/ev.canon"
      want_self=$(jq -r '.self_hash' <<<"$ev" | sed 's/^0x//')
      got_self=$(openssl dgst -sha256 -binary "$TMP/ev.canon" | xxd -p -c 256)
      [ "$got_self" = "$want_self" ] || err "self_hash mismatch on event $id"
      ts=$(jq -r '.witnessed_at' <<<"$ev")
      key_hex=$(lookup_key "$WITNESS" "$ts")
      [ -n "$key_hex" ] || err "no key for $WITNESS at $ts"
      pem_from_raw_ed25519 "$key_hex" "$TMP/ev.pub.pem"
      printf '%s' "$got_self" | xxd -r -p > "$TMP/ev.selfhash"
      sig=$(jq -r '.witness_signature' <<<"$ev" | sed 's/^ed25519:0x//')
      verify_sig "$TMP/ev.selfhash" "$TMP/ev.pub.pem" "$sig" || err "event signature invalid on $id"
    done < <(jq -c '.[]' "$EVENTS")
    ok "$EVENTS signatures"
  fi
fi

echo "==> Receipt verifies (blocks=$COUNT, attestation_strength=$RCPT_STRENGTH)"
exit 0
