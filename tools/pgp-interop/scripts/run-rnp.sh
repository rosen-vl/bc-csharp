#!/usr/bin/env bash
#
# Bouncy Castle C# (bcsop) against RNP (the OpenPGP library of Thunderbird) at a pinned commit of main, built with its
# experimental support for RFC 9580 version 6 formats and all RFC 9980 algorithms (docker/rnp.Dockerfile). RNP has no
# Stateless OpenPGP CLI, so the script runs one RNP container for the whole run and drives rnp and rnpkeys with docker
# exec. Every row has an expected outcome (PASS, UNSUPPORTED-PEER or PEER-DEVIATION); the script exits non-zero on any
# deviation.
#
# Requirements: bash, .NET SDK 8+, Docker. Works on Linux and on Windows (Git Bash with Docker Desktop).
# Usage: tools/pgp-interop/scripts/run-rnp.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
IMAGE="bc-interop-rnp:96f35e3"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$TOOL/results"
WORK="$RESULTS/rnp-work-$STAMP"
REPORT="$RESULTS/rnp-$STAMP.md"
mkdir -p "$WORK"

if command -v cygpath > /dev/null 2>&1; then
    native() { cygpath -m "$1"; }
    export MSYS_NO_PATHCONV=1
else
    native() { echo "$1"; }
fi
HOST_WORK="$(native "$WORK")"
log() { echo "$*" >&2; }

log "Building bcsop..."
dotnet build "$(native "$TOOL/BcSop/BcSop.csproj")" -c Release -v q -nologo > "$WORK/bcsop-build.log" 2>&1 \
    || { log "bcsop build failed, see $WORK/bcsop-build.log"; exit 2; }
BCSOP_DLL="$(native "$TOOL/BcSop/bin/Release/net8.0/bcsop.dll")"
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    log "Building $IMAGE (this takes a few minutes)..."
    docker build -t "$IMAGE" -f "$(native "$TOOL/docker/rnp.Dockerfile")" "$(native "$TOOL/docker")" \
        > "$WORK/rnp.build.log" 2>&1 || { log "docker build failed, see $WORK/rnp.build.log"; exit 2; }
fi

CONTAINER="bc-interop-rnp-$STAMP"
docker run -d --rm --name "$CONTAINER" -v "$HOST_WORK:/w" -w /w --entrypoint sleep "$IMAGE" infinity > /dev/null \
    || exit 2
trap 'docker rm -f "$CONTAINER" > /dev/null 2>&1' EXIT
docker exec "$CONTAINER" mkdir -p /root/.rnp

bcsop() { dotnet "$BCSOP_DLL" "$@"; }
rnp() { docker exec -i "$CONTAINER" rnp --homedir /root/.rnp "$@"; }
rnpkeys() { docker exec -i "$CONTAINER" rnpkeys --homedir /root/.rnp "$@"; }

UNSUPPORTED_PEER=(
)
# Known deviations of RNP (main at 96f35e3) from RFC 9580
PEER_DEVIATION=(
    # With --aead, RNP writes LibrePGP OCB encrypted data (packet type 20) for v4 recipients, which is not an RFC 9580
    # format (a v4 key without the SEIPDv2 feature gets a v1 SEIPD); Bouncy Castle refuses it
    '^R-03/rnp-encrypts/bc-(rfc4880|rfc9980-v4)/aead-'
    # RNP does not verify version 6 cleartext signatures of other implementations, not even RFC 9580 A.6
    '^R-05/bc-(rfc9580|rfc9980|rfc9980-high|rfc9980-slh-128f|rfc9980-slh-256s)/cleartext-bc-signs$'
    '^R-01/rfc9580/a6-cleartext$'
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

pass=0; fail=0; total=0
{
    echo "# Bouncy Castle C# against RNP ($STAMP)"
    echo
    echo "- Bouncy Castle C#: $(git -C "$(native "$ROOT")" rev-parse --short HEAD) ($(bcsop version))"
    echo "- RNP: $(rnp --version | head -1), main at 96f35e3, $(rnp --version | grep 'Backend version')"
    echo
    echo "| Row | Expected | Result | Detail |"
    echo "|---|---|---|---|"
} > "$REPORT"

row() {
    local name="$1" command="$2" expected result rc detail
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
    detail="$(tail -c 240 "$WORK/row.err" | tr '\n|' ' /')"
    echo "| $name | $expected | $result | $detail |" >> "$REPORT"
    log "[$result] $name"
}

cd "$WORK" || exit 2
printf 'Hello from Bouncy Castle C# and RNP\n' > msg.txt
printf 'line one\r\nline two\n' > text.txt
printf 'Testing\n' > testing.txt
printf 'interop-password' > pw.txt
head -c 70000 /dev/urandom > big.bin

# ---------------------------------------------------------------- R-01: RNP and the RFC 9980 test vectors

V="$ROOT/crypto/test/data/openpgp/rfc9980"
cp "$V"/*.asc .
for n in a1 a2 a3 a4 a5 a6 a7; do
    rnpkeys --import "/w/$n-secret-key.asc" > /dev/null 2>&1
done
for m in a1-message a2-seipdv1-message a2-seipdv2-message a3-message a4-message a5-message; do
    row "R-01/rfc9980/$m" "rnp -d --password '' --output - < $m.asc > out 2> sig.txt \
        && grep -q 'Signature(s) verified successfully' sig.txt && cmp -s out testing.txt"
done
for n in a3 a4 a5 a6 a7; do
    row "R-01/rfc9980/$n-signature" "rnp -v /w/$n-signature.asc --source /w/testing.txt"
done
R9580="$ROOT/crypto/test/data/openpgp/rfc9580"
cp "$R9580/a3-v6-certificate.asc" "$R9580/a6-cleartext-signed.asc" .
rnpkeys --import /w/a3-v6-certificate.asc > /dev/null 2>&1
row "R-01/rfc9580/a6-cleartext" "rnp -v /w/a6-cleartext-signed.asc"

# ---------------------------------------------------------------- keys

BC_PROFILES="rfc4880 rfc9980-v4 rfc9580 rfc9980 rfc9980-high rfc9980-slh-128f rfc9980-slh-256s"
for p in $BC_PROFILES; do
    bcsop generate-key --profile "$p" "BC $p <bc-$p@example.org>" > "bc-$p.sec"
    bcsop extract-cert < "bc-$p.sec" > "bc-$p.pub"
    rnpkeys --import "/w/bc-$p.sec" > /dev/null 2>&1
done
bcsop generate-key --profile rfc9580 --with-key-password pw.txt "BC protected <bcp-rfc9580@example.org>" \
    > bcp-rfc9580.sec
bcsop extract-cert < bcp-rfc9580.sec > bcp-rfc9580.pub
rnpkeys --import /w/bcp-rfc9580.sec > /dev/null 2>&1

# RNP keys, by the number of the key type in "rnpkeys --generate-key --expert"
declare -A RNP_TYPE=(
    [rnp-v6]=23 [rnp-v6-mlkem]=24 [rnp-mldsa65]=25 [rnp-mldsa87]=26 [rnp-slh128f]=31 [rnp-slh128s]=32
    [rnp-v4-mlkem]=34 [rnp-slh256s]=33
)
RNP_KEYS="rnp-v6 rnp-v6-mlkem rnp-mldsa65 rnp-mldsa87 rnp-slh128f rnp-slh128s rnp-v4-mlkem"
for k in $RNP_KEYS; do
    printf '%s\n' "${RNP_TYPE[$k]}" | rnpkeys --generate-key --expert --userid "RNP $k <$k@example.org>" \
        --password '' > /dev/null 2>&1
    rnpkeys --export-key --secret "$k@example.org" > "$k.sec" 2> /dev/null
    rnpkeys --export-key "$k@example.org" > "$k.pub" 2> /dev/null
done
# RNP pairs SLH-DSA-SHAKE-256s with an ML-KEM-1024+ECDH-NIST-P-521 subkey, a composite of the drafts that RFC 9980
# does not have, so this key is only used for signatures
printf '%s\n' "${RNP_TYPE[rnp-slh256s]}" | rnpkeys --generate-key --expert \
    --userid "RNP rnp-slh256s <rnp-slh256s@example.org>" --password '' > /dev/null 2>&1
rnpkeys --export-key --secret rnp-slh256s@example.org > rnp-slh256s.sec 2> /dev/null
rnpkeys --export-key rnp-slh256s@example.org > rnp-slh256s.pub 2> /dev/null
printf '23\n' | rnpkeys --generate-key --expert --userid "RNP protected <rnpp@example.org>" \
    --password interop-password > /dev/null 2>&1
rnpkeys --export-key --secret rnpp@example.org > rnpp.sec 2> /dev/null
rnpkeys --export-key rnpp@example.org > rnpp.pub 2> /dev/null

# ---------------------------------------------------------------- R-02, R-03: encryption to BC keys

for p in $BC_PROFILES; do
    key="bc-$p"
    for payload in msg.txt big.bin; do
        row "R-02/bc-encrypts/$key/$payload" \
            "rm -f out; bcsop encrypt $key.pub < $payload > m.asc \
                && rnp -d --password '' --output - < m.asc > out && cmp -s $payload out"
    done
    for variant in default aead-ocb aead-eax v3-pkesk; do
        case $variant in
            default) options="" ;;
            aead-ocb) options="--aead=OCB" ;;
            aead-eax) options="--aead=EAX" ;;
            v3-pkesk) options="--v3-pkesk-only" ;;
        esac
        row "R-03/rnp-encrypts/$key/$variant" \
            "rm -f out; rnp -e -r $key@example.org $options --armor --output - < big.bin > m.asc \
                && bcsop decrypt $key.sec < m.asc > out && cmp -s big.bin out"
    done
done

# ---------------------------------------------------------------- R-04: keys made by RNP

for k in $RNP_KEYS; do
    row "R-04/$k/bc-encrypts" \
        "rm -f out; bcsop encrypt $k.pub < big.bin > m.asc && rnp -d --password '' --output - < m.asc > out \
            && cmp -s big.bin out"
    row "R-04/$k/rnp-encrypts" \
        "rm -f out; rnp -e -r $k@example.org --armor --output - < msg.txt > m.asc \
            && bcsop decrypt $k.sec < m.asc > out && cmp -s msg.txt out"
    row "R-04/$k/bc-re-exports" \
        "bcsop extract-cert < $k.sec | bcsop dearmor > re.bin && bcsop dearmor < $k.pub > orig.bin \
            && cmp -s re.bin orig.bin"
done

# ---------------------------------------------------------------- R-05: signatures

for p in rfc4880 rfc9580 rfc9980 rfc9980-high rfc9980-slh-128f rfc9980-slh-256s; do
    key="bc-$p"
    for mode in binary text; do
        row "R-05/$key/detached-$mode-bc-signs" \
            "bcsop sign --as $mode $key.sec < text.txt > s.sig && rnp -v /w/s.sig --source /w/text.txt"
    done
    row "R-05/$key/inline-bc-signs" \
        "bcsop inline-sign $key.sec < msg.txt > i.asc && rnp --verify-cat --output - < i.asc > out \
            && cmp -s msg.txt out"
    row "R-05/$key/cleartext-bc-signs" \
        "bcsop inline-sign --as clearsigned $key.sec < text.txt > c.asc && rnp -v /w/c.asc"
done
row "R-04/rnp-slh256s/bc-re-exports" \
    "bcsop extract-cert < rnp-slh256s.sec | bcsop dearmor > re.bin && bcsop dearmor < rnp-slh256s.pub > orig.bin \
        && cmp -s re.bin orig.bin"
for k in rnp-v6 rnp-mldsa65 rnp-mldsa87 rnp-slh128f rnp-slh128s rnp-slh256s rnp-v4-mlkem; do
    row "R-05/$k/detached-rnp-signs" \
        "rm -f s.sig; rnp -s --detach -u $k@example.org --password '' --armor --output /w/s.sig /w/text.txt \
            && bcsop verify s.sig $k.pub < text.txt"
    row "R-05/$k/inline-rnp-signs" \
        "rnp -s -u $k@example.org --password '' --armor --output - < msg.txt > i.asc \
            && bcsop inline-verify $k.pub < i.asc | cmp -s - msg.txt"
    row "R-05/$k/cleartext-rnp-signs" \
        "rnp --clearsign -u $k@example.org --password '' --output - < text.txt > c.asc \
            && bcsop inline-verify $k.pub < c.asc"
done

# ---------------------------------------------------------------- R-06: sign and encrypt

for pair in "rnp-mldsa65:bc-rfc9980" "rnp-mldsa87:bc-rfc9980-high" "rnp-v6:bc-rfc9580" "rnp-v4-mlkem:bc-rfc9980-v4"; do
    signer="${pair%%:*}"; recipient="${pair#*:}"
    row "R-06/$signer+$recipient/rnp-signs-and-encrypts" \
        "rm -f out ver.txt; rnp -e -s -u $signer@example.org -r $recipient@example.org --password '' --armor \
            --output - < msg.txt > m.asc \
            && bcsop decrypt --verify-with $signer.pub --verifications-out ver.txt $recipient.sec < m.asc > out \
            && cmp -s msg.txt out && [ -s ver.txt ]"
    row "R-06/$recipient+$signer/bc-signs-and-encrypts" \
        "rm -f out; bcsop encrypt --sign-with $recipient.sec $signer.pub < msg.txt > m.asc \
            && rnp -d --password '' --output - < m.asc > out 2> sig.txt && cmp -s msg.txt out \
            && grep -q 'Signature(s) verified successfully' sig.txt"
done

# ---------------------------------------------------------------- R-07: passwords

for profile in seipdv1 seipdv2; do
    row "R-07/bc-encrypts/$profile" \
        "rm -f out; bcsop encrypt --profile $profile --with-password pw.txt < msg.txt > m.asc \
            && rnp -d --password interop-password --output - < m.asc > out && cmp -s msg.txt out"
done
for variant in default aead-v6-skesk; do
    options=""
    [ $variant = aead-v6-skesk ] && options="--aead=OCB --enable-v6-skesk"
    row "R-07/rnp-encrypts/$variant" \
        "rm -f out; rnp -c --password interop-password $options --armor --output - < msg.txt > m.asc \
            && bcsop decrypt --with-password pw.txt < m.asc > out && cmp -s msg.txt out"
done

# ---------------------------------------------------------------- R-08, R-09: protected keys

row "R-08/rnpp/bc-unlocks" \
    "rm -f out; rnp -e -r rnpp@example.org --armor --output - < msg.txt > m.asc \
        && bcsop decrypt --with-key-password pw.txt rnpp.sec < m.asc > out && cmp -s msg.txt out"
row "R-09/bcp-rfc9580/rnp-unlocks" \
    "rm -f out; bcsop encrypt bcp-rfc9580.pub < msg.txt > m.asc \
        && rnp -d --password interop-password --output - < m.asc > out && cmp -s msg.txt out"

{
    echo
    echo "**$pass of $total rows matched their expected outcome.**"
} >> "$REPORT"
log ""
log "$pass of $total rows matched their expected outcome. Report: $REPORT"
[ $fail -eq 0 ]
