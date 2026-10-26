#!/usr/bin/env bash
#
# Bouncy Castle C# (bcsop) against GnuPG 2.5.24 in its RFC 9980 mode (--allow-9980), which has the ML-KEM encryption
# of RFC 9980 and the v6 Ed25519/X25519 keys of RFC 9580, but no ML-DSA or SLH-DSA. GnuPG keeps its keys in a keyring,
# so the script runs one GnuPG container for the whole run and drives it with docker exec.
# Every row has an expected outcome (PASS, UNSUPPORTED-PEER or PEER-DEVIATION); the script exits non-zero on any
# deviation.
#
# Requirements: bash, .NET SDK 8+, Docker. Works on Linux and on Windows (Git Bash with Docker Desktop).
# Usage: tools/pgp-interop/scripts/run-gnupg.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
IMAGE="bc-interop-gnupg:2.5.24"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$TOOL/results"
WORK="$RESULTS/gnupg-work-$STAMP"
REPORT="$RESULTS/gnupg-$STAMP.md"
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
    log "Building $IMAGE..."
    docker build -t "$IMAGE" -f "$(native "$TOOL/docker/gnupg.Dockerfile")" "$(native "$TOOL/docker")" \
        > "$WORK/gnupg.build.log" 2>&1 || { log "docker build failed, see $WORK/gnupg.build.log"; exit 2; }
fi

CONTAINER="bc-interop-gnupg-$STAMP"
docker run -d --rm --name "$CONTAINER" -v "$HOST_WORK:/w" -w /w -e GNUPGHOME=/root/.gnupg --entrypoint sleep \
    "$IMAGE" infinity > /dev/null || exit 2
trap 'docker rm -f "$CONTAINER" > /dev/null 2>&1' EXIT
docker exec "$CONTAINER" sh -c 'mkdir -m 700 -p /root/.gnupg'

bcsop() { dotnet "$BCSOP_DLL" "$@"; }
# gpg in RFC 9980 mode, without prompts, trusting every key (this is not a test of the web of trust)
gpg() { docker exec -i "$CONTAINER" gpg --batch --allow-9980 --trust-model always --pinentry-mode loopback "$@"; }
# gpg in its default mode (LibrePGP)
gpg_default() { docker exec -i "$CONTAINER" gpg --batch --trust-model always --pinentry-mode loopback "$@"; }
fpr() { gpg --with-colons --list-keys "$1" | awk -F: '/^fpr/ { print $10; exit }'; }

UNSUPPORTED_PEER=(
    # GnuPG has no ML-DSA or SLH-DSA, so it cannot use certificates with such a primary key
    '/bc-rfc9980/'
    '/bc-rfc9980-high/'
    # GnuPG has no v6 SKESK
    '^G-07/bc-encrypts/seipdv2$'
    # The default (LibrePGP) Kyber of GnuPG is a v5 key of algorithm 8, not RFC 9980: neither side reads the other's
    '^G-04/gpg-libre/'
)
# Known deviations of GnuPG 2.5.24 from RFC 9580 and RFC 9980 (Sequoia agrees with Bouncy Castle on each of them)
PEER_DEVIATION=(
    # In RFC 9980 mode GnuPG writes a v6 PKESK followed by a v1 SEIPD, which RFC 9580 5.1 forbids (and for a v4
    # recipient key the PKESK names public key algorithm 0); Bouncy Castle and Sequoia discard such a PKESK
    '^G-03/gnupg-encrypts/(rfc9980-a1|rfc9980-a2|bc-rfc9980-v4|bc-rfc9580)/'
    '^G-06/gpg-v6\+bc-rfc9980-v4/'
    # GnuPG fails on v6 PKESKs for X25519 keys ("Checksum error"), also for messages of Sequoia and RFC 9580 A.8
    '^G-02/bc-encrypts/bc-rfc9580/'
    '^G-08/rfc9580/a8-'
    # GnuPG does not take the secret part of v4 Curve25519 ECDH subkeys made by other implementations (it keeps a stub)
    '^G-02/bc-encrypts/bc-rfc4880/'
    # GnuPG cannot verify v6 Ed25519 detached and cleartext signatures, also the RFC 9580 A.6 and A.7 vectors
    '^G-05/bc-rfc9580/(detached|cleartext)'
    '^G-08/rfc9580/a[67]-'
    # The self-signatures of v6 keys made by GnuPG do not verify (Sequoia: "Bad Signatures"), and its ML-KEM-768+X25519
    # subkey is a version 5 key packet under a v6 primary key, so no encryption key and no signature of it is usable
    '^G-04/gpg-(pq|v6)/'
    '^G-05/gpg-(pq|v6)/'
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
    echo "# Bouncy Castle C# against GnuPG ($STAMP)"
    echo
    echo "- Bouncy Castle C#: $(git -C "$(native "$ROOT")" rev-parse --short HEAD) ($(bcsop version))"
    echo "- $(gpg --version | head -2 | tr '\n' ' ')"
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
printf 'Hello from Bouncy Castle C# and GnuPG\n' > msg.txt
printf 'line one\r\nline two\n' > text.txt
printf 'interop-password' > pw.txt
head -c 70000 /dev/urandom > big.bin
V="$ROOT/crypto/test/data/openpgp/rfc9980"
for n in a1 a2; do
    cp "$V/$n-secret-key.asc" "rfc9980-$n.sec"; cp "$V/$n-public-key.asc" "rfc9980-$n.pub"
done

# ---------------------------------------------------------------- keys

# BC keys: v4 with ML-KEM-768+X25519, v6 Ed25519/X25519, the post-quantum v6 profiles, and a classic v4 key
BC_PROFILES="rfc9980-v4 rfc9580 rfc4880 rfc9980 rfc9980-high"
for p in $BC_PROFILES; do
    bcsop generate-key --profile "$p" "BC $p <bc-$p@example.org>" > "bc-$p.sec"
    bcsop extract-cert < "bc-$p.sec" > "bc-$p.pub"
    gpg --import "/w/bc-$p.sec" > /dev/null 2>&1
done
for n in a1 a2; do
    gpg --import "/w/rfc9980-$n.sec" > /dev/null 2>&1
done

# GnuPG keys: v6 Ed25519 with an ML-KEM-768+X25519 subkey (GnuPG writes it as a version 5 packet), v6 Ed25519/X25519,
# and the LibrePGP default (Kyber of draft-wussler, not RFC 9980)
gpg --passphrase= --quick-gen-key "GnuPG pq <gpg-pq@example.org>" ietf27 cert,sign never > /dev/null 2>&1
gpg --passphrase= --quick-add-key "$(fpr gpg-pq@example.org)" mlk768 encr never > /dev/null 2>&1
gpg --passphrase= --quick-gen-key "GnuPG v6 <gpg-v6@example.org>" ietf27 cert,sign never > /dev/null 2>&1
gpg --passphrase= --quick-add-key "$(fpr gpg-v6@example.org)" ietf25 encr never > /dev/null 2>&1
gpg_default --passphrase= --quick-gen-key "GnuPG LibrePGP <gpg-libre@example.org>" pqc default never > /dev/null 2>&1
for k in gpg-pq gpg-v6 gpg-libre; do
    gpg --armor --export "$k@example.org" > "$k.pub"
done

# ---------------------------------------------------------------- G-01: GnuPG reads the RFC 9980 test messages

V9580="$ROOT/crypto/test/data/openpgp/rfc9980"
cp "$V9580/a1-message.asc" a1-message.asc; cp "$V9580/a2-seipdv1-message.asc" a2-v1.asc
cp "$V9580/a2-seipdv2-message.asc" a2-v2.asc
for m in a1-message a2-v1 a2-v2; do
    row "G-01/rfc9980/$m" "gpg --decrypt /w/$m.asc > out 2> sig.txt && grep -q 'Good signature' sig.txt"
done

# ---------------------------------------------------------------- G-02, G-03: encryption between BC and GnuPG

for key in rfc9980-a1 rfc9980-a2 bc-rfc9980-v4 bc-rfc9580 bc-rfc4880 bc-rfc9980 bc-rfc9980-high; do
    for payload in msg.txt big.bin; do
        row "G-02/bc-encrypts/$key/$payload" \
            "rm -f out; bcsop encrypt $key.pub < $payload > m.asc && gpg --decrypt /w/m.asc > out \
                && cmp -s $payload out"
        row "G-03/gnupg-encrypts/$key/$payload" \
            "rm -f out; gpg --armor --encrypt --recipient-file /w/$key.pub < $payload > m.asc \
                && bcsop decrypt $key.sec < m.asc > out && cmp -s $payload out"
    done
done

# ---------------------------------------------------------------- G-04: keys made by GnuPG

for key in gpg-pq gpg-v6; do
    row "G-04/$key/bc-encrypts" \
        "rm -f out; bcsop encrypt $key.pub < msg.txt > m.asc && gpg --decrypt /w/m.asc > out && cmp -s msg.txt out"
done
row "G-04/gpg-libre/bc-encrypts" \
    "rm -f out; bcsop encrypt gpg-libre.pub < msg.txt > m.asc && gpg_default --decrypt /w/m.asc > out \
        && cmp -s msg.txt out"

# ---------------------------------------------------------------- G-05: signatures

for key in bc-rfc9580 bc-rfc4880 bc-rfc9980-v4; do
    for mode in binary text; do
        row "G-05/$key/detached-$mode-bc-signs" \
            "bcsop sign --as $mode $key.sec < text.txt > s.sig && gpg --verify /w/s.sig /w/text.txt"
    done
    row "G-05/$key/inline-bc-signs" "bcsop inline-sign $key.sec < msg.txt > i.asc && gpg --decrypt /w/i.asc > out \
        && cmp -s msg.txt out"
    row "G-05/$key/cleartext-bc-signs" "bcsop inline-sign --as clearsigned $key.sec < text.txt > c.asc \
        && gpg --verify /w/c.asc"
done
for key in gpg-v6 gpg-pq; do
    row "G-05/$key/detached-gnupg-signs" \
        "gpg --local-user $key@example.org --detach-sign --armor < text.txt > s.sig \
            && bcsop verify s.sig $key.pub < text.txt"
    row "G-05/$key/inline-gnupg-signs" \
        "gpg --local-user $key@example.org --sign --armor < msg.txt > i.asc \
            && bcsop inline-verify $key.pub < i.asc | cmp -s - msg.txt"
    row "G-05/$key/cleartext-gnupg-signs" \
        "gpg --local-user $key@example.org --clear-sign < text.txt > c.asc && bcsop inline-verify $key.pub < c.asc"
done
row "G-06/gpg-v6+bc-rfc9980-v4/sign-and-encrypt" \
    "rm -f out ver.txt; gpg --local-user gpg-v6@example.org --sign --encrypt --armor \
        --recipient-file /w/bc-rfc9980-v4.pub \
        < msg.txt > m.asc && bcsop decrypt --verify-with gpg-v6.pub --verifications-out ver.txt bc-rfc9980-v4.sec \
        < m.asc > out && cmp -s msg.txt out && [ -s ver.txt ]"
row "G-06/bc-rfc9580+rfc9980-a1/sign-and-encrypt" \
    "rm -f out; bcsop encrypt --sign-with bc-rfc9580.sec rfc9980-a1.pub < msg.txt > m.asc \
        && gpg --decrypt /w/m.asc 2> sig.txt > out && cmp -s msg.txt out && grep -q 'Good signature' sig.txt"

# ---------------------------------------------------------------- G-07: passwords

for profile in seipdv1 seipdv2; do
    row "G-07/bc-encrypts/$profile" \
        "rm -f out; bcsop encrypt --profile $profile --with-password pw.txt < msg.txt > m.asc \
            && gpg --passphrase interop-password --decrypt /w/m.asc > out && cmp -s msg.txt out"
done
row "G-07/gnupg-encrypts" \
    "rm -f out; gpg --passphrase interop-password --symmetric --armor < msg.txt > m.asc \
        && bcsop decrypt --with-password pw.txt < m.asc > out && cmp -s msg.txt out"

# ---------------------------------------------------------------- G-08: GnuPG on the RFC 9580 test vectors

R9580="$ROOT/crypto/test/data/openpgp/rfc9580"
cp "$R9580/a3-v6-certificate.asc" "$R9580/a4-v6-secret-key.asc" "$R9580/a6-cleartext-signed.asc" \
    "$R9580/a7-inline-signed.asc" "$R9580/a8-x25519-ocb-message.asc" .
gpg --import /w/a4-v6-secret-key.asc > /dev/null 2>&1
row "G-08/rfc9580/a6-cleartext" "gpg --verify /w/a6-cleartext-signed.asc 2> sig.txt; grep -q 'Good signature' sig.txt"
row "G-08/rfc9580/a7-inline" "gpg --decrypt /w/a7-inline-signed.asc > out 2> sig.txt; grep -q 'Good signature' sig.txt"
row "G-08/rfc9580/a8-x25519" "gpg --decrypt /w/a8-x25519-ocb-message.asc > out && [ -s out ]"

{
    echo
    echo "**$pass of $total rows matched their expected outcome.**"
} >> "$REPORT"
log ""
log "$pass of $total rows matched their expected outcome. Report: $REPORT"
[ $fail -eq 0 ]
