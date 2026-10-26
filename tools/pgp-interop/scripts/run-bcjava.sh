#!/usr/bin/env bash
#
# Bouncy Castle C# (bcsop) against Bouncy Castle Java 1.86 (bcjava/BcJavaCheck.java), which supports the version 6
# formats of RFC 9580 but not the algorithms of RFC 9980. Besides encryption and signatures in both directions, the
# Java side parses the keys and signatures that C# makes and encodes them again, which must give the same octets.
# Every row has an expected outcome (PASS, UNSUPPORTED-PEER or PEER-DEVIATION); the script exits non-zero on any
# deviation.
#
# Requirements: bash, .NET SDK 8+, Docker. Works on Linux and on Windows (Git Bash with Docker Desktop).
# Usage: tools/pgp-interop/scripts/run-bcjava.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
IMAGE="bc-interop-bcjava:1.86"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$TOOL/results"
WORK="$RESULTS/bcjava-work-$STAMP"
REPORT="$RESULTS/bcjava-$STAMP.md"
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
    docker build -t "$IMAGE" "$(native "$TOOL/bcjava")" > "$WORK/bcjava.build.log" 2>&1 \
        || { log "docker build failed, see $WORK/bcjava.build.log"; exit 2; }
fi

bcsop() { dotnet "$BCSOP_DLL" "$@"; }
bcjava() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$IMAGE" "$@"; }

# Rows that need an algorithm of RFC 9980 on the Java side
UNSUPPORTED_PEER=(
    '/bc-rfc9980'
)

# Rows that fail because of a known deviation of Bouncy Castle Java from the RFCs
PEER_DEVIATION=(
    # Bouncy Castle Java 1.86 appends the 20-octet SHA-1 checksum of S2K usage 254 to the cleartext of AEAD protected
    # (S2K usage 253) secret keys; RFC 9580 5.5.3 has only the authentication tag there, and Bouncy Castle C# requires
    # the key material to account for the whole cleartext of a version 6 key
    '^J-06/javap-'
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
    echo "# Bouncy Castle C# against Bouncy Castle Java ($STAMP)"
    echo
    echo "- Bouncy Castle C#: $(git -C "$(native "$ROOT")" rev-parse --short HEAD) ($(bcsop version))"
    echo "- $(bcjava version)"
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
    detail="$(cat "$WORK/row.out" "$WORK/row.err" | tail -c 200 | tr '\n|' ' /')"
    echo "| $name | $expected | $result | $detail |" >> "$REPORT"
    log "[$result] $name"
}

cd "$WORK" || exit 2
printf 'Hello from Bouncy Castle C# and Java\n' > msg.txt
printf 'line one\r\nline two\n' > text.txt
printf 'interop-password' > pw.txt
head -c 70000 /dev/urandom > big.bin

# ---------------------------------------------------------------- keys

BC_PROFILES="rfc4880 rfc9580 rfc9980"
for p in $BC_PROFILES; do
    bcsop generate-key --profile "$p" "BC $p <bc@example.org>" > "bc-$p.sec"
    bcsop extract-cert < "bc-$p.sec" > "bc-$p.pub"
done
bcsop generate-key --profile rfc9580 --with-key-password pw.txt "BC protected <bcp@example.org>" > bcp-rfc9580.sec
bcsop extract-cert < bcp-rfc9580.sec > bcp-rfc9580.pub
# a version 6 key whose preferences put AES-256/GCM first (J-10)
bcsop generate-key --profile rfc9580-gcm "BC GCM <bcg@example.org>" > bcg-rfc9580.sec
bcsop extract-cert < bcg-rfc9580.sec > bcg-rfc9580.pub

JAVA_PROFILES="v4-25519 v6-25519 v6-448"
for p in $JAVA_PROFILES; do
    bcjava generate "$p" "Java $p <java@example.org>" "java-$p.sec" "java-$p.pub" > /dev/null
done
bcjava generate v6-25519 "Java protected <javap@example.org>" javap-v6-25519.sec javap-v6-25519.pub interop-password \
    > /dev/null

# ---------------------------------------------------------------- J-01, J-02: Java parses what C# makes

for key in bc-rfc4880 bc-rfc9580 bcp-rfc9580 bc-rfc9980; do
    row "J-01/$key/certificate" "bcjava inspect $key.pub"
    row "J-01/$key/secret-key" "bcjava inspect $key.sec"
done
for key in bc-rfc4880 bc-rfc9580 bc-rfc9980; do
    for mode in binary text; do
        bcsop sign --as $mode $key.sec < text.txt > $key-$mode.sig 2> /dev/null
        row "J-02/$key/$mode-signature-re-encoding" "bcjava inspect $key-$mode.sig"
        row "J-03/$key/$mode-signature-verifies" "bcjava verify $key.pub $key-$mode.sig text.txt"
    done
done

# ---------------------------------------------------------------- J-04: Java decrypts what C# encrypts

for key in bc-rfc4880 bc-rfc9580 bc-rfc9980; do
    for profile in seipdv1 seipdv2 seipdv2-gcm seipdv2-eax; do
        for payload in msg.txt big.bin; do
            row "J-04/$key/$profile/$payload" \
                "rm -f out; bcsop encrypt --profile $profile $key.pub < $payload > m.asc \
                    && bcjava decrypt $key.sec m.asc out && cmp -s $payload out"
        done
    done
    row "J-04/$key/signed" \
        "rm -f out; bcsop encrypt --sign-with $key.sec $key.pub < msg.txt > m.asc \
            && bcjava decrypt $key.sec m.asc out $key.pub && cmp -s msg.txt out"
done
row "J-04/bcp-rfc9580/protected-key" \
    "rm -f out; bcsop encrypt bcp-rfc9580.pub < msg.txt > m.asc \
        && bcjava decrypt bcp-rfc9580.sec m.asc out - - interop-password && cmp -s msg.txt out"
for profile in seipdv1 seipdv2; do
    row "J-04/password/$profile" \
        "rm -f out; bcsop encrypt --profile $profile --with-password pw.txt < msg.txt > m.asc \
            && bcjava decrypt - m.asc out - interop-password && cmp -s msg.txt out"
done

# ---------------------------------------------------------------- J-10: Java encrypts to a key that prefers GCM

row "J-10/bcg-rfc9580/java-encrypts" \
    "rm -f out; bcjava encrypt bcg-rfc9580.pub msg.txt g.asc && bcsop decrypt bcg-rfc9580.sec < g.asc > out \
        && cmp -s msg.txt out"
row "J-10/bcg-rfc9580/java-chooses-gcm" \
    "bcjava encrypt bcg-rfc9580.pub msg.txt g.asc && bcsop x-packets < g.asc | grep -q '^SEIPD v2 .*aead=Gcm '"

# ---------------------------------------------------------------- J-05 to J-08: C# reads what Java makes

for key in java-v4-25519 java-v6-25519 java-v6-448 javap-v6-25519; do
    row "J-05/$key/certificate-re-export" \
        "bcsop extract-cert < $key.sec | bcsop dearmor > re.bin && bcsop dearmor < $key.pub > orig.bin \
            && cmp -s re.bin orig.bin"
done
for key in java-v4-25519 java-v6-25519 java-v6-448; do
    row "J-06/$key/decrypt" \
        "rm -f out; bcjava encrypt $key.pub msg.txt m.asc && bcsop decrypt $key.sec < m.asc > out && cmp -s msg.txt out"
    row "J-06/$key/decrypt-and-verify" \
        "rm -f out ver.txt; bcjava encrypt $key.pub msg.txt m.asc $key.sec \
            && bcsop decrypt --verify-with $key.pub --verifications-out ver.txt $key.sec < m.asc > out \
            && cmp -s msg.txt out && [ -s ver.txt ]"
    row "J-07/$key/detached-signature" \
        "bcjava sign $key.sec text.txt j.sig && bcsop verify j.sig $key.pub < text.txt"
done
row "J-06/javap-v6-25519/protected-key" \
    "rm -f out; bcjava encrypt javap-v6-25519.pub msg.txt m.asc \
        && bcsop decrypt --with-key-password pw.txt javap-v6-25519.sec < m.asc > out && cmp -s msg.txt out"
row "J-08/password" \
    "rm -f out; bcjava encrypt-password interop-password msg.txt m.asc \
        && bcsop decrypt --with-password pw.txt < m.asc > out && cmp -s msg.txt out"

# ---------------------------------------------------------------- J-09: Java encrypts to C# keys

for key in bc-rfc4880 bc-rfc9580 bc-rfc9980; do
    row "J-09/$key/java-encrypts" \
        "rm -f out; bcjava encrypt $key.pub big.bin m.asc && bcsop decrypt $key.sec < m.asc > out && cmp -s big.bin out"
    row "J-09/$key/java-signs-and-encrypts" \
        "rm -f out ver.txt; bcjava encrypt $key.pub msg.txt m.asc java-v6-25519.sec \
            && bcsop decrypt --verify-with java-v6-25519.pub --verifications-out ver.txt $key.sec < m.asc > out \
            && cmp -s msg.txt out && [ -s ver.txt ]"
done

{
    echo
    echo "**$pass of $total rows matched their expected outcome.**"
} >> "$REPORT"
log ""
log "$pass of $total rows matched their expected outcome. Report: $REPORT"
[ $fail -eq 0 ]
