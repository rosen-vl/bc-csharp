#!/usr/bin/env bash
#
# RFC 9580 / RFC 9980 interoperability matrix: Bouncy Castle (bcsop) against rsop (rPGP), gosop (GopenPGP),
# sop-openpgpjs (OpenPGP.js), pgpainless-cli (PGPainless on Bouncy Castle Java) and Sequoia sq. The rows (I-01 to
# I-17) are described in the README; every row has an expected outcome (PASS, UNSUPPORTED-PEER or PEER-DEVIATION), and
# the script exits non-zero on any deviation. The version 4 rows (I-12) are in run-matrix.sh.
#
# Requirements: bash, .NET SDK 8+, Docker, perl. Works on Linux and on Windows (Git Bash with Docker Desktop).
# Usage: tools/pgp-interop/scripts/run-full-matrix.sh [--no-sq] [--only PEER]... [--rows REGEX]
#   --rows REGEX  run only the rows whose names match the regular expression
#
# Peers: rsop, gosop, ojs, pgpainless (all four speak the Stateless OpenPGP CLI) and sq.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
RUN_SQ=1
ONLY=""
ROWS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-sq) RUN_SQ=0 ;;
        --only) shift; ONLY="$ONLY $1" ;;
        --rows) shift; ROWS="$1" ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
wanted() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }

RSOP_IMAGE="bc-interop-rsop:0.12.0"
SQ_IMAGE="bc-interop-sq:1.4.1"
GOSOP_IMAGE="bc-interop-gosop:1.1.0"
OJS_IMAGE="bc-interop-ojs:2.2.0"
PGPAINLESS_IMAGE="bc-interop-pgpainless:2.0.4"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$TOOL/results"
WORK="$RESULTS/full-work-$STAMP"
REPORT="$RESULTS/full-$STAMP.md"
mkdir -p "$WORK"

if command -v cygpath > /dev/null 2>&1; then
    native() { cygpath -m "$1"; }
    export MSYS_NO_PATHCONV=1
else
    native() { echo "$1"; }
fi
HOST_WORK="$(native "$WORK")"

log() { echo "$*" >&2; }

# ---------------------------------------------------------------- build

log "Building bcsop..."
dotnet build "$(native "$TOOL/BcSop/BcSop.csproj")" -c Release -v q -nologo > "$WORK/bcsop-build.log" 2>&1 \
    || { log "bcsop build failed, see $WORK/bcsop-build.log"; exit 2; }
BCSOP_DLL="$(native "$TOOL/BcSop/bin/Release/net8.0/bcsop.dll")"

build_image() {
    local image="$1" dockerfile="$2"
    if ! docker image inspect "$image" > /dev/null 2>&1; then
        log "Building $image (this takes a few minutes)..."
        docker build -t "$image" -f "$(native "$TOOL/docker/$dockerfile")" "$(native "$TOOL/docker")" \
            > "$WORK/$image.build.log" 2>&1 \
            || { log "docker build failed, see $WORK/$image.build.log"; exit 2; }
    fi
}
wanted rsop && build_image "$RSOP_IMAGE" rsop.Dockerfile
wanted gosop && build_image "$GOSOP_IMAGE" gosop.Dockerfile
wanted ojs && build_image "$OJS_IMAGE" openpgpjs.Dockerfile
wanted pgpainless && build_image "$PGPAINLESS_IMAGE" pgpainless.Dockerfile
[ $RUN_SQ = 1 ] && wanted sq && build_image "$SQ_IMAGE" sq.Dockerfile

bcsop() { dotnet "$BCSOP_DLL" "$@"; }
rsop() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$RSOP_IMAGE" "$@"; }
gosop() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$GOSOP_IMAGE" "$@"; }
ojs() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$OJS_IMAGE" "$@"; }
pgpainless() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$PGPAINLESS_IMAGE" "$@"; }
sq() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$SQ_IMAGE" --home none "$@"; }

flip() { perl -e 'local $/; open F, "+<", $ARGV[0] or die; binmode F; my $d = <F>;
    my $o = $ARGV[1] < 0 ? length($d) + $ARGV[1] : $ARGV[1]; die "offset $o outside the file\n" if $o >= length($d);
    substr($d, $o, 1) ^= "\x01";
    seek F, 0, 0; print F $d; close F' "$1" "$2"; }

# ---------------------------------------------------------------- expectations

# Rows whose names match one of these patterns (bash regular expressions) are expected to fail cleanly because the
# peer does not support the algorithm or the format: the outcome is recorded as UNSUPPORTED-PEER.
UNSUPPORTED_PEER=(
    # OpenPGP.js (pqc branch) has no ML-KEM-1024+X448 and no ML-DSA-87+Ed448
    '^I-0[1-9]/ojs/bcp?-rfc9980-high'
    '^I-0[1-9]/ojs/bcp?-rfc9980-slh'
    '^I-1[0-9]/ojs/bc-rfc9980-high'
    '^I-1[0-9]/ojs/bc-rfc9980-slh'
    # OpenPGP.js (pqc branch) has no ML-KEM-1024+X448 (RFC 9980 A.4)
    '^I-05/ojs/rfc9980-a4'
    # PGPainless (Bouncy Castle Java) has none of the RFC 9980 algorithms; the RFC 9980 test keys have ML-KEM subkeys
    '^I-0[12]/pgpainless/bcp?-rfc9980'
    '^I-05/pgpainless/'
    '^I-07/pgpainless/bc-rfc9980-slh-'
    # Sequoia (with OpenSSL) has no EAX
    '^I-17/sq/.*/bc-encrypts-eax$'
    # rsop and sq encrypt with AES-256/OCB, the second of the preferences, which RFC 9580 5.2.3.15 and 12.2 allow;
    # they cannot be made to write GCM
    '^I-17/(rsop|sq)/bc-rfc9580-gcm/peer-chooses-gcm$'
)

# Rows that fail because of a known deviation of the peer from the RFCs: the outcome is recorded as PEER-DEVIATION.
PEER_DEVIATION=(
    # PGPainless 2.0.4 only accepts an Intended Recipient Fingerprint that names the decryption subkey, not the
    # recipient's primary key that RFC 9580 5.2.3.36 specifies: it ignores the signature of a signed message from BC
    '^I-06/pgpainless/.*/bc-signs$'
    # The version 6 keys of PGPainless 2.0.4 have no direct-key signature, which RFC 9580 10.1.1 requires, so BC does
    # not use their certificates: it does not encrypt to them or accept their signatures (decrypting with the secret
    # keys and re-exporting the certificates still work)
    '^I-(03|16)/pgpainless/pgpainless-(performance|rfc9580-curve448)/'
    '^I-(06|07)/pgpainless/pgpainless-(performance|rfc9580-curve448)/.*peer-signs$'
    '^I-08/pgpainless/pgpainless-rfc9580-curve448\+pgpainless-performance/bc-encrypts$'
)

expected_for() {
    local name="$1" pattern
    for pattern in "${PEER_DEVIATION[@]}"; do
        if [[ "$name" =~ $pattern ]]; then
            echo PEER-DEVIATION
            return
        fi
    done
    for pattern in "${UNSUPPORTED_PEER[@]}"; do
        if [[ "$name" =~ $pattern ]]; then
            echo UNSUPPORTED-PEER
            return
        fi
    done
    echo PASS
}

# ---------------------------------------------------------------- inputs

cd "$WORK" || exit 2
printf 'Hello from the RFC 9980 interop matrix\n' > msg.txt
printf 'line one\nline two\r\nline three\rend' > mixed.txt
printf 'line one\nline two\n' > lf.txt
printf 'line one\r\nline two\r\n' > crlf.txt
printf 'interop-password' > pw.txt
printf 'message-password' > mpw.txt
: > p0.bin
head -c 1 /dev/urandom > p1.bin
head -c 4095 /dev/urandom > p4095.bin
head -c 4096 /dev/urandom > p4096.bin
head -c 4097 /dev/urandom > p4097.bin
head -c 262144 /dev/urandom > p256k.bin
head -c 1048576 /dev/urandom > p1m.bin
PAYLOADS="p0.bin p1.bin p4095.bin p4096.bin p4097.bin p256k.bin p1m.bin mixed.txt"

V="$ROOT/crypto/test/data/openpgp/rfc9980"
for n in a1 a2 a3 a4; do
    cp "$V/$n-secret-key.asc" "$n.sec"; cp "$V/$n-public-key.asc" "$n.pub"
done

# ---------------------------------------------------------------- recording

pass=0; fail=0; total=0
{
    echo "# RFC 9580 and RFC 9980 interop matrix ($STAMP)"
    echo
    echo "- Bouncy Castle: $(git -C "$(native "$ROOT")" rev-parse --short HEAD) ($(bcsop version))"
    wanted rsop && echo "- rsop: $(rsop version --extended 2>/dev/null | head -4 | tr '\n' ' ')"
    wanted gosop && echo "- gosop: $(gosop version --extended 2>/dev/null | head -4 | tr '\n' ' ')"
    wanted ojs && echo "- sop-openpgpjs: $(ojs version --extended 2>/dev/null | head -3 | tr '\n' ' ')"
    wanted pgpainless && echo "- pgpainless-cli: $(pgpainless version --extended 2>/dev/null \
        | grep -E '^(PGPainless|Based on)' | tr '\n' ' ')"
    [ $RUN_SQ = 1 ] && wanted sq && echo "- sq: $(sq version 2>&1 | head -3 | tr '\n' ' ')"
    echo
    echo "| Row | Expected | Result | Detail |"
    echo "|---|---|---|---|"
} > "$REPORT"

# row NAME COMMAND: runs the command (a shell snippet) and compares its outcome with the expectation
row() {
    local name="$1" command="$2" expected result rc detail
    if [ -n "$ROWS" ] && ! [[ "$name" =~ $ROWS ]]; then
        return
    fi
    expected="$(expected_for "$name")"
    eval "$command" > "$WORK/row.out" 2> "$WORK/row.err"
    rc=$?
    if [ "$expected" = PASS ]; then
        if [ $rc = 0 ]; then result=PASS; else result=FAIL; fi
    else
        if [ $rc = 0 ]; then result=UNEXPECTED-PASS; else result="$expected"; fi
    fi
    total=$((total + 1))
    if [ "$result" = "$expected" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
    detail="$(tail -c 200 "$WORK/row.err" | tr '\n|' ' /')"
    echo "| $name | $expected | $result | $detail |" >> "$REPORT"
    log "[$result] $name"
}

shape() { bcsop x-packets < "$1" 2>/dev/null | grep -E '^(PKESK|SKESK|SEIPD)' | tr '\n' ';'; }

# ---------------------------------------------------------------- Bouncy Castle keys

BC_PROFILES="rfc4880 rfc9580 rfc9980 rfc9980-high rfc9980-slh-128f rfc9980-slh-256s"
for p in $BC_PROFILES; do
    bcsop generate-key --profile "$p" "BC $p <bc@example.org>" > "bc-$p.sec"
    bcsop extract-cert < "bc-$p.sec" > "bc-$p.pub"
done
for p in rfc9580 rfc9980 rfc9980-high; do
    bcsop generate-key --profile "$p" --with-key-password pw.txt "BC $p protected <bcp@example.org>" > "bcp-$p.sec"
    bcsop extract-cert < "bcp-$p.sec" > "bcp-$p.pub"
done
bcsop generate-key --profile default "BC v4 <bc4@example.org>" > bc-v4.sec
bcsop extract-cert < bc-v4.sec > bc-v4.pub
# a version 6 key whose preferences put AES-256/GCM first (I-17)
bcsop generate-key --profile rfc9580-gcm "BC GCM <bcg@example.org>" > bc-rfc9580-gcm.sec
bcsop extract-cert < bc-rfc9580-gcm.sec > bc-rfc9580-gcm.pub

# ---------------------------------------------------------------- peers and their keys

# peer: the profiles of generate-key that the peer's keys are made with (the interesting ones)
declare -A PEER_PROFILES
PEER_PROFILES[rsop]="performance security rfc9980-v4"
PEER_PROFILES[gosop]="performance security rfc9980 rfc9980-high-security"
PEER_PROFILES[ojs]="performance security rfc9980"
PEER_PROFILES[pgpainless]="performance rfc9580-curve448 default rfc6637-nist-p384 rfc4880-rsa4096"

# The profile of each peer that makes post-quantum keys (version 6)
declare -A PQ_PROFILE
PQ_PROFILE[rsop]=security
PQ_PROFILE[gosop]=rfc9980
PQ_PROFILE[ojs]=rfc9980
# PGPainless makes no post-quantum keys; its other version 6 key takes that place in the mixed-recipient rows
PQ_PROFILE[pgpainless]=rfc9580-curve448

SOP_PEERS=""
for peer in rsop gosop ojs pgpainless; do
    wanted "$peer" && SOP_PEERS="$SOP_PEERS $peer"
done

# The BC keys used with each peer for signing, mixed recipients and tampering: the post-quantum ones, except for a
# peer without post-quantum support, which gets the keys of the RFC 9580 (v6) and RFC 4880 (v4) profiles instead.
declare -A BC_SIGNER BC_V4
for peer in rsop gosop ojs pgpainless; do
    BC_SIGNER[$peer]=rfc9980
    BC_V4[$peer]=v4
done
BC_SIGNER[pgpainless]=rfc9580
BC_V4[pgpainless]=rfc4880

for peer in $SOP_PEERS; do
    for p in ${PEER_PROFILES[$peer]}; do
        if "$peer" generate-key --profile "$p" "$peer $p <$peer@example.org>" > "$peer-$p.sec" 2> "$peer-$p.err" \
            && "$peer" extract-cert < "$peer-$p.sec" > "$peer-$p.pub" 2>> "$peer-$p.err"; then
            :
        else
            log "$peer cannot generate profile $p: $(tail -c 200 "$peer-$p.err")"
            rm -f "$peer-$p.sec" "$peer-$p.pub"
            continue
        fi
        # protected variant
        if "$peer" generate-key --profile "$p" --with-key-password /w/pw.txt "$peer $p protected" \
                > "$peer-$p.psec" 2> /dev/null \
            && "$peer" extract-cert < "$peer-$p.psec" > "$peer-$p.ppub" 2> /dev/null; then
            :
        else
            rm -f "$peer-$p.psec" "$peer-$p.ppub"
        fi
    done
done

# ---------------------------------------------------------------- I-01, I-02: BC keys with each peer

for peer in $SOP_PEERS; do
    for p in $BC_PROFILES; do
        for payload in $PAYLOADS; do
            [ "$p" != rfc9980 ] && [ "$payload" != p4097.bin ] && [ "$payload" != p0.bin ] && continue
            row "I-01/$peer/bc-$p/$payload" \
                "rm -f out; $peer encrypt /w/bc-$p.pub < $payload > m.asc && bcsop decrypt bc-$p.sec < m.asc > out \
                    && cmp -s $payload out"
            row "I-02/$peer/bc-$p/$payload" \
                "rm -f out; bcsop encrypt bc-$p.pub < $payload > m.asc && $peer decrypt /w/bc-$p.sec < m.asc > out \
                    && cmp -s $payload out"
        done
    done
    for p in rfc9580 rfc9980 rfc9980-high; do
        row "I-02/$peer/bcp-$p/protected" \
            "rm -f out; bcsop encrypt bcp-$p.pub < msg.txt > m.asc \
                && $peer decrypt --with-key-password /w/pw.txt /w/bcp-$p.sec < m.asc > out && cmp -s msg.txt out"
    done
done

# ---------------------------------------------------------------- I-03, I-04, I-06, I-07: peer keys

for peer in $SOP_PEERS; do
    signer="bc-${BC_SIGNER[$peer]}"
    for p in ${PEER_PROFILES[$peer]}; do
        [ -f "$peer-$p.pub" ] || continue
        key="$peer-$p"
        row "I-03/$peer/$key/msg" \
            "rm -f out; bcsop encrypt $key.pub < msg.txt > m.asc && $peer decrypt /w/$key.sec < m.asc > out \
                && cmp -s msg.txt out"
        row "I-04/$peer/$key/msg" \
            "rm -f out; $peer encrypt /w/$key.pub < msg.txt > m.asc && bcsop decrypt $key.sec < m.asc > out \
                && cmp -s msg.txt out"
        if [ -f "$key.psec" ]; then
            row "I-04/$peer/$key/protected" \
                "rm -f out; $peer encrypt /w/$key.ppub < msg.txt > m.asc \
                    && bcsop decrypt --with-key-password pw.txt $key.psec < m.asc > out && cmp -s msg.txt out"
        fi
        row "I-06/$peer/$key/peer-signs" \
            "rm -f out ver.txt; $peer encrypt --sign-with /w/$key.sec /w/$signer.pub < msg.txt > m.asc \
                && bcsop decrypt --verify-with $key.pub --verifications-out ver.txt $signer.sec < m.asc > out \
                && cmp -s msg.txt out && [ -s ver.txt ]"
        row "I-06/$peer/$key/bc-signs" \
            "rm -f out ver.txt; bcsop encrypt --sign-with $signer.sec $key.pub < msg.txt > m.asc \
                && $peer decrypt --verify-with /w/$signer.pub --verifications-out /w/ver.txt /w/$key.sec \
                    < m.asc > out && cmp -s msg.txt out && [ -s ver.txt ]"

        for mode in binary text; do
            row "I-07/$peer/$key/detached-$mode-peer-signs" \
                "$peer sign --as $mode /w/$key.sec < lf.txt > t.sig && bcsop verify t.sig $key.pub < lf.txt"
            row "I-07/$peer/$key/detached-$mode-bc-signs" \
                "bcsop sign --as $mode $signer.sec < lf.txt > t.sig \
                    && $peer verify /w/t.sig /w/$signer.pub < lf.txt"
        done
        row "I-07/$peer/$key/inline-peer-signs" \
            "$peer inline-sign /w/$key.sec < msg.txt > i.asc && bcsop inline-verify $key.pub < i.asc | cmp -s - msg.txt"
        row "I-07/$peer/$key/inline-bc-signs" \
            "bcsop inline-sign $signer.sec < msg.txt > i.asc \
                && $peer inline-verify /w/$signer.pub < i.asc | cmp -s - msg.txt"
        row "I-07/$peer/$key/cleartext-peer-signs" \
            "$peer inline-sign --as clearsigned /w/$key.sec < lf.txt > c.asc && bcsop inline-verify $key.pub < c.asc"
        row "I-07/$peer/$key/cleartext-bc-signs" \
            "bcsop inline-sign --as clearsigned $signer.sec < lf.txt > c.asc \
                && $peer inline-verify /w/$signer.pub < c.asc"
    done
done

# ---------------------------------------------------------------- I-05: the RFC 9980 test keys

for peer in $SOP_PEERS; do
    for n in a1 a2 a3 a4; do
        row "I-05/$peer/rfc9980-$n/bc-encrypts" \
            "rm -f out; bcsop encrypt $n.pub < msg.txt > m.asc && $peer decrypt /w/$n.sec < m.asc > out \
                && cmp -s msg.txt out"
        row "I-05/$peer/rfc9980-$n/peer-encrypts" \
            "rm -f out; $peer encrypt /w/$n.pub < msg.txt > m.asc && bcsop decrypt $n.sec < m.asc > out \
                && cmp -s msg.txt out"
    done
done

# ---------------------------------------------------------------- I-07: SLH-DSA signatures made by BC

for peer in $SOP_PEERS; do
    for slh in bc-rfc9980-slh-128f bc-rfc9980-slh-256s; do
        row "I-07/$peer/$slh/detached-bc-signs" \
            "bcsop sign $slh.sec < msg.txt > s.sig && $peer verify /w/s.sig /w/$slh.pub < msg.txt"
        row "I-07/$peer/$slh/inline-bc-signs" \
            "bcsop inline-sign $slh.sec < msg.txt > s.asc \
                && $peer inline-verify /w/$slh.pub < s.asc | cmp -s - msg.txt"
        row "I-07/$peer/$slh/cleartext-bc-signs" \
            "bcsop inline-sign --as clearsigned $slh.sec < lf.txt > s.asc && $peer inline-verify /w/$slh.pub < s.asc"
    done
done

# ---------------------------------------------------------------- I-08: mixed recipients

for peer in $SOP_PEERS; do
    pq="$peer-${PQ_PROFILE[$peer]}"; classic="$peer-performance"
    signer="bc-${BC_SIGNER[$peer]}"; v4="bc-${BC_V4[$peer]}"
    [ -f "$pq.pub" ] && [ -f "$classic.pub" ] || continue
    row "I-08/$peer/$pq+$classic/bc-encrypts" \
        "rm -f o1 o2; bcsop encrypt $pq.pub $classic.pub < msg.txt > m.asc \
            && $peer decrypt /w/$pq.sec < m.asc > o1 && $peer decrypt /w/$classic.sec < m.asc > o2 \
            && cmp -s msg.txt o1 && cmp -s msg.txt o2"
    row "I-08/$peer/$pq+$v4/peer-encrypts" \
        "rm -f o1 o2; $peer encrypt /w/$pq.pub /w/$v4.pub < msg.txt > m.asc \
            && bcsop decrypt $pq.sec < m.asc > o1 && bcsop decrypt $v4.sec < m.asc > o2 \
            && cmp -s msg.txt o1 && cmp -s msg.txt o2"
    row "I-08/$peer/$signer+$v4/bc-encrypts" \
        "rm -f o1 o2; bcsop encrypt $signer.pub $v4.pub < msg.txt > m.asc \
            && $peer decrypt /w/$signer.sec < m.asc > o1 && $peer decrypt /w/$v4.sec < m.asc > o2 \
            && cmp -s msg.txt o1 && cmp -s msg.txt o2"
done

# ---------------------------------------------------------------- I-09: symmetric encryption

for peer in $SOP_PEERS; do
    for profile in seipdv1 seipdv2; do
        row "I-09/$peer/password/bc-encrypts-$profile" \
            "rm -f out; bcsop encrypt --profile $profile --with-password mpw.txt < msg.txt > m.asc \
                && $peer decrypt --with-password /w/mpw.txt < m.asc > out && cmp -s msg.txt out"
    done
    row "I-09/$peer/password/peer-encrypts" \
        "rm -f out; $peer encrypt --with-password /w/mpw.txt < msg.txt > m.asc \
            && bcsop decrypt --with-password mpw.txt < m.asc > out && cmp -s msg.txt out"
done

# ---------------------------------------------------------------- I-10: tampering

for peer in $SOP_PEERS; do
    signer="bc-${BC_SIGNER[$peer]}"
    bcsop encrypt --no-armor $signer.pub < msg.txt > tamper.bin
    size=$(wc -c < tamper.bin)
    # 700 is inside the ciphertext of a post-quantum message; smaller messages are flipped in their middle
    for spot in 120 $((size > 800 ? 700 : size / 2)) $((size - 40)) $((size - 3)); do
        cp tamper.bin tamper.mod
        flip tamper.mod "$spot"
        row "I-10/$peer/$signer/flip-$spot" \
            "rm -f out; ! $peer decrypt /w/$signer.sec < tamper.mod > out 2> /dev/null \
                && rm -f out && ! bcsop decrypt $signer.sec < tamper.mod > out 2> /dev/null && [ ! -s out ]"
    done
done

# ---------------------------------------------------------------- I-11: certificates

for peer in $SOP_PEERS; do
    for p in ${PEER_PROFILES[$peer]}; do
        [ -f "$peer-$p.sec" ] || continue
        row "I-11/$peer/$peer-$p/bc-re-exports" \
            "bcsop extract-cert < $peer-$p.sec | bcsop dearmor > re.bin && $peer extract-cert < $peer-$p.sec | bcsop dearmor > orig.bin \
                && cmp -s re.bin orig.bin"
    done
done

# ---------------------------------------------------------------- I-13 to I-16: message formats

for peer in $SOP_PEERS; do
    for profile in seipdv1 seipdv2; do
        for p in ${PEER_PROFILES[$peer]}; do
            [ -f "$peer-$p.pub" ] || continue
            row "I-16/$peer/$peer-$p/bc-$profile" \
                "rm -f out; bcsop encrypt --profile $profile $peer-$p.pub < msg.txt > m.asc \
                    && $peer decrypt /w/$peer-$p.sec < m.asc > out && cmp -s msg.txt out"
        done
    done
done

# ---------------------------------------------------------------- I-17: AEAD modes

# BC encrypts with GCM and EAX (v2 SEIPD, AES-256) to its version 6 key, over several chunks, and the peer decrypts;
# the peer encrypts to a BC key whose preferences put AES-256/GCM first, and may choose it (RFC 9580 5.2.3.15)
for peer in $SOP_PEERS; do
    for mode in gcm eax; do
        row "I-17/$peer/bc-rfc9580/bc-encrypts-$mode" \
            "rm -f out; bcsop encrypt --profile seipdv2-$mode bc-rfc9580.pub < p1m.bin > m.asc \
                && $peer decrypt /w/bc-rfc9580.sec < m.asc > out && cmp -s p1m.bin out"
    done
    row "I-17/$peer/bc-rfc9580-gcm/peer-encrypts" \
        "rm -f out; $peer encrypt /w/bc-rfc9580-gcm.pub < msg.txt > gcm.asc \
            && bcsop decrypt bc-rfc9580-gcm.sec < gcm.asc > out && cmp -s msg.txt out"
    row "I-17/$peer/bc-rfc9580-gcm/peer-chooses-gcm" \
        "rm -f gcm.asc; $peer encrypt /w/bc-rfc9580-gcm.pub < msg.txt > gcm.asc \
            && bcsop x-packets < gcm.asc | grep -q '^SEIPD v2 .*aead=Gcm '"
done

if wanted ojs && [ -f ojs-rfc9980.pub ]; then
    row "I-15/ojs/ojs-rfc9980/format" \
        "bcsop encrypt ojs-rfc9980.pub < msg.txt > m.asc && bcsop x-packets < m.asc | grep -q '^PKESK v3 ' \
            && bcsop x-packets < m.asc | grep -q '^SEIPD v1\$'"
fi

# ---------------------------------------------------------------- Sequoia sq

if [ $RUN_SQ = 1 ] && wanted sq; then
    for cs in cv25519 mldsa65-ed25519 mldsa87-ed448; do
        if sq key generate --own-key --userid "SQ $cs <sq@example.org>" --cipher-suite "$cs" --profile rfc9580 \
                --without-password --output "/w/sq-$cs.sec" --rev-cert "/w/sq-$cs.rev" > /dev/null 2>&1 \
            && sq key delete --cert-file "/w/sq-$cs.sec" --output "/w/sq-$cs.pub" > /dev/null 2>&1; then
            row "I-03/sq/sq-$cs/msg" \
                "rm -f out; bcsop encrypt sq-$cs.pub < msg.txt > m.asc \
                    && sq decrypt --recipient-file /w/sq-$cs.sec --output /w/out /w/m.asc && cmp -s msg.txt out"
            row "I-04/sq/sq-$cs/msg" \
                "rm -f out m.asc; sq encrypt --without-signature --for-file /w/sq-$cs.pub --output /w/m.asc /w/msg.txt \
                    && bcsop decrypt sq-$cs.sec < m.asc > out && cmp -s msg.txt out"
            row "I-06/sq/sq-$cs/sq-signs" \
                "rm -f out ver.txt m.asc; sq encrypt --signer-file /w/sq-$cs.sec --for-file /w/bc-rfc9980.pub \
                    --output /w/m.asc /w/msg.txt \
                    && bcsop decrypt --verify-with sq-$cs.pub --verifications-out ver.txt bc-rfc9980.sec < m.asc > out \
                    && cmp -s msg.txt out && [ -s ver.txt ]"
            row "I-06/sq/sq-$cs/bc-signs" \
                "rm -f out; bcsop encrypt --sign-with bc-rfc9980.sec sq-$cs.pub < msg.txt > m.asc \
                    && sq decrypt --recipient-file /w/sq-$cs.sec --signer-file /w/bc-rfc9980.pub \
                        --output /w/out /w/m.asc \
                    && cmp -s msg.txt out"
        else
            log "sq cannot generate cipher suite $cs"
        fi
    done
    for p in $BC_PROFILES; do
        row "I-01/sq/bc-$p/msg" \
            "rm -f out m.asc; sq encrypt --without-signature --for-file /w/bc-$p.pub --output /w/m.asc /w/msg.txt \
                && bcsop decrypt bc-$p.sec < m.asc > out && cmp -s msg.txt out"
        row "I-02/sq/bc-$p/msg" \
            "rm -f out; bcsop encrypt bc-$p.pub < msg.txt > m.asc \
                && sq decrypt --recipient-file /w/bc-$p.sec --output /w/out /w/m.asc && cmp -s msg.txt out"
    done
    if [ -f sq-cv25519.pub ]; then
        for mode in gcm eax; do
            row "I-17/sq/sq-cv25519/bc-encrypts-$mode" \
                "rm -f out; bcsop encrypt --profile seipdv2-$mode sq-cv25519.pub < p1m.bin > m.asc \
                    && sq decrypt --recipient-file /w/sq-cv25519.sec --output /w/out /w/m.asc && cmp -s p1m.bin out"
        done
        row "I-17/sq/bc-rfc9580-gcm/peer-encrypts" \
            "rm -f out gcm.asc; sq encrypt --without-signature --for-file /w/bc-rfc9580-gcm.pub --output /w/gcm.asc \
                /w/msg.txt && bcsop decrypt bc-rfc9580-gcm.sec < gcm.asc > out && cmp -s msg.txt out"
        row "I-17/sq/bc-rfc9580-gcm/peer-chooses-gcm" \
            "rm -f gcm.asc; sq encrypt --without-signature --for-file /w/bc-rfc9580-gcm.pub --output /w/gcm.asc \
                /w/msg.txt && bcsop x-packets < gcm.asc | grep -q '^SEIPD v2 .*aead=Gcm '"
    fi
    for n in a1 a2 a3 a4; do
        row "I-05/sq/rfc9980-$n/bc-encrypts" \
            "rm -f out; bcsop encrypt $n.pub < msg.txt > m.asc \
                && sq decrypt --recipient-file /w/$n.sec --output /w/out /w/m.asc && cmp -s msg.txt out"
        row "I-05/sq/rfc9980-$n/peer-encrypts" \
            "rm -f out m.asc; sq encrypt --without-signature --for-file /w/$n.pub --output /w/m.asc /w/msg.txt \
                && bcsop decrypt $n.sec < m.asc > out && cmp -s msg.txt out"
    done
fi

{
    echo
    echo "**$pass of $total rows matched their expected outcome.**"
} >> "$REPORT"
log ""
log "$pass of $total rows matched their expected outcome. Report: $REPORT"
[ $fail -eq 0 ]
