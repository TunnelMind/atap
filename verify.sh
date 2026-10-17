#!/usr/bin/env bash
#
# ATAP v0.1/v0.2 Receipt Verifier
# Standard:   https://tunnelmind.ai/atap/standard
# License:    Apache-2.0
#
# Usage: verify.sh [RECEIPT_DIR] [--keys FILE_OR_URL]
#   RECEIPT_DIR defaults to the current directory. The directory MUST contain
#   an unpacked ATAP Receipt ZIP (manifest.json, ait.json, attestation_chain.json,
#   public_keys.json, plus any optional files listed in manifest.files[]).
#   --keys names the witness public keys you trust (a local file, or an https://
#   URL fetched with curl). It replaces the receipt's own public_keys.json for
#   OAI witnesses: that copy ships inside the receipt, so whoever made the
#   receipt chose it. Without --keys an OAI receipt still verifies, with a
#   WARNING. A did:key witness's key is its identifier, so --keys never applies.
#
# Requirements: bash 4+, jq 1.6+, openssl 3.0+ (or 1.1.1 with -rawin), python3.
# python3 is used only for RFC 8785 (JSON Canonicalization Scheme) canonicalization
# and for the base58btc decode of did:key witnesses (ATAP-v0.2 §3).

set -euo pipefail

# Messages echo ids and paths from the receipt, which is attacker-controlled:
# control characters (C0, incl. ESC and newline, and DEL) are stripped so a
# message cannot drive the terminal or forge an extra output line.
# (verify.ts's clean() also strips C1, U+0080-U+009F; tr works on bytes here.)
clean() { printf '%s' "$*" | tr -d '\000-\037\177'; }
err() { echo "FAIL: $(clean "$*")" >&2; exit 1; }
ok()  { echo "  OK   $(clean "$*")"; }

# Never cd into the receipt: it is untrusted content, and python3 puts the cwd
# on sys.path, so a planted json.py or re.py would run. Every receipt file is
# read through this absolute path instead, and python3 runs with -I.
RECEIPT_ARG="" KEYS_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keys)   [ $# -ge 2 ] || err "--keys needs a FILE or https:// URL"; KEYS_ARG=$2; shift 2 ;;
    --keys=*) KEYS_ARG=${1#--keys=}; shift ;;
    *)        [ -z "$RECEIPT_ARG" ] || err "usage: verify.sh [RECEIPT_DIR] [--keys FILE_OR_URL]"; RECEIPT_ARG=$1; shift ;;
  esac
done
RECEIPT_ARG=${RECEIPT_ARG:-.}
RECEIPT_DIR=$(cd -- "$RECEIPT_ARG" 2>/dev/null && pwd -P) || err "receipt directory $RECEIPT_ARG not found"

command -v jq      >/dev/null || err "jq is required"
command -v openssl >/dev/null || err "openssl is required"
command -v python3 >/dev/null || err "python3 is required"

[ -f "$RECEIPT_DIR/manifest.json"         ] || err "manifest.json not found"
[ -f "$RECEIPT_DIR/ait.json"              ] || err "ait.json not found"
[ -f "$RECEIPT_DIR/attestation_chain.json" ] || err "attestation_chain.json not found"
[ -f "$RECEIPT_DIR/public_keys.json"      ] || err "public_keys.json not found"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# KEYS_FILE is where every OAI witness key lookup reads from: the trusted
# --keys file when given, else the receipt's own copy (warned about below,
# once we know the witness is an OAI). did:key lookups always read the bundled
# file, since the key they accept is fixed by the identifier anyway.
if [ -n "$KEYS_ARG" ]; then
  if [[ "$KEYS_ARG" =~ ^https:// ]]; then
    command -v curl >/dev/null || err "curl is required to fetch --keys $KEYS_ARG"
    curl -fsS --proto =https -o "$TMP/keys.json" -- "$KEYS_ARG" || err "cannot fetch --keys $KEYS_ARG"
    KEYS_FILE="$TMP/keys.json"
  else
    [ -f "$KEYS_ARG" ] && [ -r "$KEYS_ARG" ] || err "cannot read --keys $KEYS_ARG"
    KEYS_FILE=$KEYS_ARG
  fi
  jq -e '.keys | type == "array"' "$KEYS_FILE" >/dev/null 2>&1 || err "--keys $KEYS_ARG is not JSON with a .keys array"
  KEYS_SRC="--keys $KEYS_ARG"
else
  KEYS_FILE="$RECEIPT_DIR/public_keys.json"
  KEYS_SRC="receipt's bundled public_keys.json"
fi

# RFC 8785 (JCS) canonicalizer via python3 stdlib. Reads JSON on stdin, writes
# canonical bytes on stdout. Matches packages/atap-js/src/canonicalize.ts
# byte-for-byte (finite numbers only; no NaN/Infinity in ATAP artifacts).
canonicalize() {
  python3 -I -c '
import json, sys
def num(o):
    # RFC 8785 §3.2.2.3 is the ECMAScript Number->String algorithm. repr()
    # gives the shortest round-trip digits; only the layout differs from ES
    # (repr writes 1e-07 and 1.5e-05, ES writes 1e-7 and 0.000015). An earlier
    # ".17g" form expanded 0.7 to 0.69999999999999996 and broke verification.
    if o == 0:
        return "0"
    m, _, e = repr(abs(o)).partition("e")
    i, _, f = m.partition(".")
    d = (i + f).lstrip("0")
    n = len(i) + int(e or 0) - (len(i + f) - len(d))
    d = d.rstrip("0")
    k = len(d)
    # value = 0.d * 10**n; branches follow ECMA-262 Number::toString steps.
    if k <= n <= 21:
        s = d + "0" * (n - k)
    elif 0 < n <= 21:
        s = d[:n] + "." + d[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * -n + d
    else:
        x = n - 1
        s = d[0] + ("." + d[1:] if k > 1 else "") + "e" + ("+" if x >= 0 else "-") + str(abs(x))
    return "-" + s if o < 0 else s
def canon(o):
    if isinstance(o, dict):
        # JS .sort() compares UTF-16 code units: astral keys sort before
        # U+E000..U+FFFF, unlike a code point sort. Keys are emitted raw.
        items = sorted(o.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(canon(k) + ":" + canon(v) for k,v in items) + "}"
    if isinstance(o, list):
        return "[" + ",".join(canon(x) for x in o) + "]"
    if isinstance(o, bool) or o is None:
        return json.dumps(o)
    if isinstance(o, int):
        # JS parses JSON numbers as doubles, so past 2**53 an int is whatever
        # the nearest double prints as (9007199254740993 -> ...992).
        return str(o) if abs(o) <= 2**53 else num(float(o))
    if isinstance(o, float):
        return num(o)
    return json.dumps(o, ensure_ascii=False)
print(canon(json.load(sys.stdin)), end="")
'
}

# Raw Ed25519 key (hex) encoded in a did:key, via python3 stdlib. Exits non-zero
# unless the input is did:key:z + base58btc(0xed 0x01 || 32-byte key); mirrors
# packages/atap-js/src/didkey.ts.
didkey_to_hex() {
  python3 -I -c '
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

# The OAI key entries for witness $1 in force at RFC 3339 time $2, as a JSON
# array of at most one (ATAP §8.2): valid_from <= t < valid_until, and not
# compromised unless t is before the notice's disclosed_at. Times compare as
# instants, not strings, so "+00:00" vs "Z" or fractional seconds cannot flip
# the verdict; a time that does not parse is a failure. Two entries in force
# at once is a failure too: taking the first would let file order pick the key.
oai_keys_at() {
  local out n
  out=$(jq -c --arg w "$1" --arg t "$2" '
    def instant:
      (capture("^(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?<f>[.][0-9]+)?(?<z>Z|(?<s>[+-])(?<h>[0-9]{2}):(?<m>[0-9]{2}))$")
        // error("not an RFC 3339 time")) |
      (.d + "Z" | fromdateiso8601) + ("0" + (.f // "") | tonumber)
        - (if .z == "Z" then 0 else (.s + "1" | tonumber) * ((.h | tonumber) * 3600 + (.m | tonumber) * 60) end);
    ($t | instant) as $at |
    [ .keys[] |
      select(.witness == $w and (.valid_from | instant) <= $at and $at < (.valid_until | instant)) |
      select(.status != "compromised" or (.compromise_notice and $at < (.compromise_notice.disclosed_at | instant))) ]
  ' "$KEYS_FILE" 2>/dev/null) || err "cannot compare key validity for $1 at $2 as RFC 3339 times"
  n=$(jq length <<<"$out")
  [ "$n" -le 1 ] || err "ambiguous: $n keys for $1 valid at $2 (ATAP §8.2)"
  printf '%s\n' "$out"
}

# Look up the public key (hex, no 0x) for a given witness at a given RFC-3339 timestamp.
# With no valid entry this prints an empty line and the caller fails "no key for ...".
lookup_key() {
  local witness="$1" t="$2" keys
  if [[ "$witness" =~ ^did:key: ]]; then lookup_did_key "$witness" "$t"; return; fi
  keys=$(oai_keys_at "$witness" "$t") || exit 1
  jq -r '.[0].public_key // empty' <<<"$keys" | sed 's/^0x//'
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
  ' "$RECEIPT_DIR/public_keys.json")
  jq -e --arg w "$witness" --arg t "$t" '
    any(.keys[]; .witness == $w and .status == "compromised"
      and ((.compromise_notice and $t < .compromise_notice.disclosed_at) | not))
  ' "$RECEIPT_DIR/public_keys.json" >/dev/null && first=""
  printf '%s\n' "$first"
}

##############################################################################
# 0. Which keys an OAI witness is checked against
##############################################################################
AIT_WIT=$(jq -r '.witness'     "$RECEIPT_DIR/ait.json")
WITNESS=$(jq -r '.witness' "$RECEIPT_DIR/manifest.json")
if [[ ! "$AIT_WIT" =~ ^did:key: || ! "$WITNESS" =~ ^did:key: ]]; then
  ok "keys file sha256=$(openssl dgst -sha256 -r "$KEYS_FILE" | cut -d' ' -f1) (from $KEYS_SRC)"
  if [ -z "$KEYS_ARG" ]; then
    cat >&2 <<'WARN'
WARNING: this receipt has an OAI witness and no --keys was given, so its
WARNING: signatures were checked against the public_keys.json inside the
WARNING: receipt itself. Whoever made the receipt chose those keys: a pass
WARNING: proves the receipt is self-consistent, NOT who signed it. Re-run with
WARNING: --keys FILE_OR_URL naming the witness keys you trust.
WARN
  fi
fi

##############################################################################
# 1. File integrity
##############################################################################
echo "==> Verifying file integrity (manifest.files[])"
# Every entry's path is checked; only those with a sha256 are hashed.
jq -c '.files[]' "$RECEIPT_DIR/manifest.json" | while IFS= read -r entry; do
  path=$(jq -r '.path' <<<"$entry")
  want=$(jq -r '.sha256' <<<"$entry" | sed 's/^0x//')
  # The manifest is untrusted: a path must stay inside the receipt, or it could
  # make us hash (and vouch for) any file on this host. No absolute path,
  # backslash, drive letter or .. segment, and no symlink at or above it.
  case "$path" in /*|*\\*|[A-Za-z]:*) err "$path is not a relative path inside the receipt";; esac
  case "/$path/" in */../*) err "$path has a .. segment";; esac
  p=$path
  while :; do
    [ ! -L "$RECEIPT_DIR/$p" ] || err "$path is or is under a symlink"
    [[ "$p" == */* ]] || break
    p=${p%/*}
  done
  [ "$want" != null ] || continue
  [ -f "$RECEIPT_DIR/$path" ] || err "$path missing"
  got=$(openssl dgst -sha256 -binary "$RECEIPT_DIR/$path" | xxd -p -c 256)
  [ "$got" = "$want" ] || err "$path sha256 mismatch (want $want, got $got)"
  ok "$path"
done

##############################################################################
# 2. AIT signature
##############################################################################
echo "==> Verifying AIT witness signature"
AIT_TS=$(jq  -r '.issued_at'   "$RECEIPT_DIR/ait.json")
AIT_SIG=$(jq -r '.witness_signature' "$RECEIPT_DIR/ait.json" | sed 's/^ed25519:0x//')
MAN_WIT=$(jq -r '.witness' "$RECEIPT_DIR/manifest.json")
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
for id in "$AIT_WIT" "$(jq -r '.operator' "$RECEIPT_DIR/ait.json")"; do
  if [[ "$id" =~ ^did:key: ]]; then
    didkey_to_hex "$id" >/dev/null || err "AIT identifier $id is not an Ed25519 did:key (ATAP-v0.2 §3)"
    DID_AIT=1
  fi
done
if [ -n "$DID_AIT" ]; then
  AIT_VER=$(jq -r '.ait_version' "$RECEIPT_DIR/ait.json")
  [ "$AIT_VER" = "0.2" ] || err "AIT with a did:key witness or operator declares ait_version '$AIT_VER', want '0.2' (ATAP-v0.2 §3.3)"
fi
[[ "$AIT_SIG" =~ ^[0-9a-f]{128}$ ]] || err "AIT witness_signature malformed"
AIT_KEY=$(lookup_key "$AIT_WIT" "$AIT_TS")
[ -n "$AIT_KEY" ] || err "no key for AIT witness $AIT_WIT at $AIT_TS"
pem_from_raw_ed25519 "$AIT_KEY" "$TMP/ait.pub.pem"
jq 'del(.witness_signature)' "$RECEIPT_DIR/ait.json" | canonicalize > "$TMP/ait.canon"
verify_sig "$TMP/ait.canon" "$TMP/ait.pub.pem" "$AIT_SIG" || err "AIT signature invalid"
# Strings only, so a missing id/profile can't match a block's missing one ("null").
AIT_ID=$(jq -er '.id | strings' "$RECEIPT_DIR/ait.json") || err "AIT id is not a string"
AIT_PROFILE=$(jq -er '.profile | strings' "$RECEIPT_DIR/ait.json") || err "AIT profile is not a string"
ok "AIT $AIT_ID"
# The manifest and every block (step 3) must belong to this AIT: a record
# validly signed by the witness for another AIT or profile attests nothing here.
# A missing field reads as "null", which never equals a real id.
MAN_AIT=$(jq -r '.ait' "$RECEIPT_DIR/manifest.json")
[ "$MAN_AIT" = "$AIT_ID" ] || err "manifest ait $MAN_AIT != AIT id $AIT_ID"

##############################################################################
# 3. Block chain
##############################################################################
echo "==> Walking block chain"
# The loop below reads jq through a process substitution, which drops jq's exit
# status: a chain that is not JSON, or not an array, or is empty would walk zero
# blocks and leave PREV at genesis. A receipt with no blocks attests nothing.
jq -e 'type == "array" and length > 0' "$RECEIPT_DIR/attestation_chain.json" >/dev/null 2>&1 \
  || err "attestation_chain.json is not a non-empty JSON array"
PREV="0x0000000000000000000000000000000000000000000000000000000000000000"
COUNT=0
while IFS= read -r block; do
  pb=$(jq -r '.prev_block_hash' <<<"$block")
  [ "$pb" = "$PREV" ] || err "block chain break (want prev=$PREV, got $pb)"
  bid=$(jq -r '.id' <<<"$block")
  bait=$(jq -r '.ait' <<<"$block")
  [ "$bait" = "$AIT_ID" ] || err "block $bid ait $bait != AIT id $AIT_ID"
  bprof=$(jq -r '.profile' <<<"$block")
  [ "$bprof" = "$AIT_PROFILE" ] || err "block $bid profile $bprof != AIT profile $AIT_PROFILE"
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
  LAST_END=$ts
  COUNT=$((COUNT + 1))
  ok "$(jq -r '.id' <<<"$block")"
done < <(jq -c '.[]' "$RECEIPT_DIR/attestation_chain.json")

# 4. chain_head_hash in manifest matches last block
MANIFEST_HEAD=$(jq -r '.chain_head_hash' "$RECEIPT_DIR/manifest.json")
[ "$MANIFEST_HEAD" = "$PREV" ] || err "manifest chain_head_hash $MANIFEST_HEAD != last block self_hash $PREV"

##############################################################################
# 5. Attestation strength (ATAP §7.4.1 — optional in v0.1.x, required at v0.2)
##############################################################################
RCPT_STRENGTH=$(jq -r '.attestation_strength // "MISSING"' "$RECEIPT_DIR/manifest.json")
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
  ' "$RECEIPT_DIR/public_keys.json" | head -1)
else
  KEY_STRENGTH=$(oai_keys_at "$WITNESS" "$AIT_TS" | jq -r '.[0].attestation_strength // empty')
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
# 6. Manifest signature
##############################################################################
# The manifest's witness_signature must verify under the witness's key, or
# its period, counts, files[] and summary could be edited freely. A did:key's
# key has no validity window (ATAP-v0.2 §3.1), so generated_at serves. An OAI
# key's valid_until is often the AIT's expires_at, and a receipt of an expired
# AIT is generated after it, so the key is the one in force at the last
# block's period_end (generated_at only for a receipt with no blocks). Each
# After step 5 so a §3.2 failure reports as such.
echo "==> Verifying manifest signature"
if [[ "$WITNESS" =~ ^did:key: || -z "${LAST_END:-}" ]]; then
  MAN_TS=$(jq -r '.generated_at' "$RECEIPT_DIR/manifest.json")
else
  MAN_TS=$LAST_END
fi
key_hex=$(lookup_key "$WITNESS" "$MAN_TS")
[ -n "$key_hex" ] || err "no key for $WITNESS at $MAN_TS"
pem_from_raw_ed25519 "$key_hex" "$TMP/man.pub.pem"
jq 'del(.witness_signature)' "$RECEIPT_DIR/manifest.json" | canonicalize > "$TMP/man.canon"
sig=$(jq -r '.witness_signature' "$RECEIPT_DIR/manifest.json" | sed 's/^ed25519:0x//')
verify_sig "$TMP/man.canon" "$TMP/man.pub.pem" "$sig" || err "manifest signature invalid"
ok "manifest signature"

##############################################################################
# 7. The manifest describes this receipt (ATAP §7.5)
##############################################################################
# After step 6, so an edit to an unsigned manifest reports as a bad signature.
# Every file in the receipt is listed in files[] (step 1 hashed the listed
# ones), or a file could ride along with no hash covering it; scitt/ is left
# out, since scitt-export writes it after the receipt is sealed. The §7.5
# mandatory files are listed, with a sha256 for all but manifest.json. Paths
# are normalised as atap-js normaliseReceiptPath does. python3 -I only reads
# here; nothing from the receipt is run.
echo "==> Checking manifest against the receipt"
PROBLEM=$(python3 -I -c '
import json, os, posixpath, sys
root = sys.argv[1]
def out(msg):
    print(msg)
    sys.exit(1)
files = json.load(open(os.path.join(root, "manifest.json"))).get("files")
if not isinstance(files, list):
    out("manifest.files is not an array")
listed = {}
for f in files:
    p = f.get("path") if isinstance(f, dict) else None
    if not isinstance(p, str):
        out("manifest.files[] entry has no string path")
    listed[posixpath.normpath(p)] = f.get("sha256")
for m in ("manifest.json", "ait.json", "attestation_chain.json", "public_keys.json", "verify.sh"):
    if m not in listed:
        out(m + " is not listed in manifest.files[] (ATAP §7.5)")
    if m != "manifest.json" and not isinstance(listed[m], str):
        out(m + " is listed with no sha256 (ATAP §7.5)")
for d, dirs, names in os.walk(root):
    rel = os.path.relpath(d, root)
    if rel == ".":
        dirs[:] = [x for x in dirs if x != "scitt"]
    # A symlink to a directory is an entry too; os.walk does not descend it.
    for x in names + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
        p = posixpath.normpath(posixpath.join(rel.replace(os.sep, "/"), x))
        if p not in listed:
            out(p + " is in the receipt but not listed in manifest.files[]")
' "$RECEIPT_DIR") || err "${PROBLEM:-cannot read manifest.files[]}"
ok "files[] lists every file in the receipt"
# Period, counts and ends as the chain has them. Typed comparison, so "3" is
# not 3; a non-numeric event_count makes jq fail, which fails here.
PROBLEM=$(jq -r --slurpfile c "$RECEIPT_DIR/attestation_chain.json" '
  . as $m | $c[0] as $c |
  [ ["period_start", $c[0].period_start], ["period_end", $c[-1].period_end],
    ["block_count", ($c | length)], ["event_count", ($c | map(.event_count) | add)],
    ["first_block", $c[0].id], ["last_block", $c[-1].id] ][] |
  select($m[.[0]] != .[1]) | "manifest \(.[0]) mismatch (want \(.[1] | tojson), got \($m[.[0]] | tojson))"
' "$RECEIPT_DIR/manifest.json" | head -1) || err "cannot compare manifest with attestation_chain.json"
[ -z "$PROBLEM" ] || err "$PROBLEM"
ok "manifest period and counts match the chain"

##############################################################################
# 8. Witness Event chain (ATAP §7.3, §10)
##############################################################################
# tunnelmind:code_crew:v1 receipts carry their events here (atap-cli
# WITNESS_EVENTS); checked when present (step 7 made sure it is listed),
# listed, or required by the profile. As checkWitnessEvents in atap-js: every event's
# self_hash is its own hash, it is under this AIT, prev_event_hash links from
# genesis, and the blocks, in order, cover the events exactly, each ending on
# the event whose self_hash is its chain_head_hash. That pins every event to a
# signed block, so the per-event signature is checked for a did:key witness
# only (ATAP-v0.2 §3.1).
EVENTS=profile_artifacts/witness_events.json
if [ -e "$RECEIPT_DIR/$EVENTS" ] || [ "$AIT_PROFILE" = "tunnelmind:code_crew:v1" ] \
  || jq -e --arg p "$EVENTS" 'any(.files[]?; .path == $p)' "$RECEIPT_DIR/manifest.json" >/dev/null; then
  echo "==> Walking witness event chain"
  [ -f "$RECEIPT_DIR/$EVENTS" ] || err "$EVENTS missing"
  jq -e 'type == "array"' "$RECEIPT_DIR/$EVENTS" >/dev/null 2>&1 || err "$EVENTS is not a JSON array"
  EV_PREV="0x0000000000000000000000000000000000000000000000000000000000000000"
  EV_IDS=() EV_HASHES=()
  i=0
  while IFS= read -r ev; do
    jq -e 'type == "object"' <<<"$ev" >/dev/null || err "event $i is not an object"
    id=$(jq -r '.id' <<<"$ev")
    eait=$(jq -r '.ait' <<<"$ev")
    [ "$eait" = "$AIT_ID" ] || err "event $i ($id) ait $eait != AIT id $AIT_ID"
    jq 'del(.self_hash, .witness_signature)' <<<"$ev" | canonicalize > "$TMP/ev.canon"
    want_self=$(jq -r '.self_hash' <<<"$ev")
    got_self=$(openssl dgst -sha256 -binary "$TMP/ev.canon" | xxd -p -c 256)
    [ "0x$got_self" = "$want_self" ] || err "self_hash mismatch on event $id"
    pe=$(jq -r '.prev_event_hash' <<<"$ev")
    [ "$pe" = "$EV_PREV" ] || err "event $i ($id) prev_event_hash breaks the chain (want $EV_PREV, got $pe)"
    if [[ "$WITNESS" =~ ^did:key: ]]; then
      # The signature is over self_hash, checked above to be the event's own.
      ts=$(jq -r '.witnessed_at' <<<"$ev")
      key_hex=$(lookup_key "$WITNESS" "$ts")
      [ -n "$key_hex" ] || err "no key for $WITNESS at $ts"
      pem_from_raw_ed25519 "$key_hex" "$TMP/ev.pub.pem"
      printf '%s' "$got_self" | xxd -r -p > "$TMP/ev.selfhash"
      sig=$(jq -r '.witness_signature' <<<"$ev" | sed 's/^ed25519:0x//')
      verify_sig "$TMP/ev.selfhash" "$TMP/ev.pub.pem" "$sig" || err "event signature invalid on $id"
    fi
    EV_IDS+=("$id") EV_HASHES+=("$want_self")
    EV_PREV=$want_self
    i=$((i + 1))
  done < <(jq -c '.[]' "$RECEIPT_DIR/$EVENTS")
  at=0
  # Unit-separated, not @tsv: read collapses empty tab fields, which would shift them.
  while IFS=$'\x1f' read -r bid n first last head; do
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || err "block $bid event_count is not a positive integer"
    end=$((at + n - 1))
    [ "$end" -lt "${#EV_IDS[@]}" ] || err "block $bid covers events $at..$end; only ${#EV_IDS[@]} present"
    [ "${EV_IDS[$at]}" = "$first" ] || err "event $at (${EV_IDS[$at]}) is not block $bid's first_event"
    [ "${EV_IDS[$end]}" = "$last" ] || err "event $end (${EV_IDS[$end]}) is not block $bid's last_event"
    [ "${EV_HASHES[$end]}" = "$head" ] || err "event $end (${EV_IDS[$end]}) does not match block $bid's chain_head_hash"
    at=$((end + 1))
  done < <(jq -r '.[] | [.id, .event_count, .first_event, .last_event, .chain_head_hash] | map(tostring) | join("\u001f")' "$RECEIPT_DIR/attestation_chain.json")
  [ "$at" -eq "${#EV_IDS[@]}" ] || err "${#EV_IDS[@]} events but the blocks cover $at"
  ok "$EVENTS (${#EV_IDS[@]} events)"
fi

echo "==> Receipt verifies (blocks=$COUNT, attestation_strength=$RCPT_STRENGTH)"
exit 0
