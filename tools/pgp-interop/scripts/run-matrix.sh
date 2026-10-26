#!/usr/bin/env bash
#
# RFC 9980 interoperability matrix for version 4 keys with ML-KEM-768+X25519: Bouncy Castle (bcsop) against rsop
# (rPGP) and Sequoia sq.
#
# Requirements: bash, .NET SDK 8+, Docker, perl. Works on Linux and on Windows (Git Bash with Docker Desktop).
# Usage: tools/pgp-interop/scripts/run-matrix.sh [--no-sq]
#
# Every check has an expected outcome: PASS, or the name of a limitation for flows that must fail cleanly.
# The script exits non-zero if any check deviates from its expectation, and writes a Markdown report to
# tools/pgp-interop/results/.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
RUN_SQ=1
[ "${1:-}" = "--no-sq" ] && RUN_SQ=0

RSOP_IMAGE="bc-interop-rsop:0.12.0"
SQ_IMAGE="bc-interop-sq:1.4.1"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$TOOL/results"
WORK="$RESULTS/work-$STAMP"
REPORT="$RESULTS/v4-matrix-$STAMP.md"
mkdir -p "$WORK"

# Docker and dotnet need native paths; on Git Bash convert them and stop MSYS from rewriting arguments
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
build_image "$RSOP_IMAGE" rsop.Dockerfile
[ $RUN_SQ = 1 ] && build_image "$SQ_IMAGE" sq.Dockerfile

bcsop() { dotnet "$BCSOP_DLL" "$@"; }
rsop() { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$RSOP_IMAGE" "$@"; }
sq()   { docker run --rm -i -v "$HOST_WORK:/w" -w /w "$SQ_IMAGE" --home none "$@"; }

# Flip one byte of a file (offset counted from the end if negative)
flip() { perl -e 'local $/; open F, "+<", $ARGV[0] or die; binmode F; my $d = <F>;
    my $o = $ARGV[1] < 0 ? length($d) + $ARGV[1] : $ARGV[1]; substr($d, $o, 1) ^= "\x01";
    seek F, 0, 0; print F $d; close F' "$1" "$2"; }

# ---------------------------------------------------------------- inputs

cd "$WORK" || exit 2
printf 'Hello from the RFC 9980 interop matrix\n' > msg.txt
: > empty.bin
head -c 1048576 /dev/urandom > 1mib.bin
printf 'interop-password' > pw.txt
cp "$ROOT/crypto/test/data/openpgp/rfc9980/a2-secret-key.asc" a2.sec
cp "$ROOT/crypto/test/data/openpgp/rfc9980/a2-public-key.asc" a2.pub

bcsop generate-key "BC PQ <bc@example.org>" > bc.sec
bcsop extract-cert < bc.sec > bc.pub
bcsop generate-key --with-key-password pw.txt "BC protected <bcp@example.org>" > bcp.sec
bcsop extract-cert < bcp.sec > bcp.pub
rsop generate-key --profile rfc9980-v4 "rsop PQ <rsop@example.org>" > rs.sec
rsop extract-cert < rs.sec > rs.pub
rsop generate-key --profile rfc9980-v4 --with-key-password /w/pw.txt "rsop protected <rsp@example.org>" > rsp.sec
rsop extract-cert < rsp.sec > rsp.pub

# ---------------------------------------------------------------- checks

pass=0; fail=0; total=0
{
    echo "# RFC 9980 interop matrix for version 4 keys ($STAMP)"
    echo
    echo "- Bouncy Castle: $(git -C "$(native "$ROOT")" rev-parse --short HEAD) ($(bcsop version))"
    echo "- rsop: $(rsop version --extended 2>/dev/null | head -4 | tr '\n' ' ')"
    [ $RUN_SQ = 1 ] && echo "- sq: $(sq version 2>&1 | head -3 | tr '\n' ' ')"
    echo
    echo "| Check | Expected | Result | Detail |"
    echo "|---|---|---|---|"
} > "$REPORT"

# record NAME EXPECTED OK(0/1) DETAIL
record() {
    local name="$1" expected="$2" ok="$3" detail="${4:-}"
    local result
    if [ "$expected" = "PASS" ]; then
        if [ "$ok" = 0 ]; then result="PASS"; else result="FAIL"; fi
    else
        # Expected limitation: the flow must fail cleanly
        if [ "$ok" = 0 ]; then result="UNEXPECTED-PASS"; else result="$expected"; fi
    fi
    total=$((total + 1))
    if [ "$result" = "$expected" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
    detail="$(printf '%s' "$detail" | tr '\n|' ' /' | cut -c1-200)"
    echo "| $name | $expected | $result | $detail |" >> "$REPORT"
    log "[$result] $name"
}

shape() { bcsop x-packets < "$1" 2>/dev/null | grep -E '^(PKESK|SEIPD)' | tr '\n' ';'; }

for p in msg.txt empty.bin 1mib.bin; do
    # 1. Peer encrypts to the BC certificate, BC decrypts
    for prof in default rfc4880; do
        rm -f out
        rsop encrypt --profile "$prof" /w/bc.pub < "$p" > m.asc && bcsop decrypt bc.sec < m.asc > out && cmp -s "$p" out
        record "1 rsop($prof) -> BC, $p" PASS $? "$(shape m.asc)"
    done
    # 2. BC encrypts to the BC certificate, peer decrypts with the BC secret key
    rm -f out
    bcsop encrypt bc.pub < "$p" > m.asc && rsop decrypt /w/bc.sec < m.asc > out && cmp -s "$p" out
    record "2 BC -> rsop (BC key), $p" PASS $? "$(shape m.asc)"
    # 3. BC encrypts to the peer certificate, peer decrypts
    rm -f out
    bcsop encrypt rs.pub < "$p" > m.asc && rsop decrypt /w/rs.sec < m.asc > out && cmp -s "$p" out
    record "3 BC -> rsop (rsop key), $p" PASS $?
    # 4. Peer encrypts to its own v4 PQ certificate (Features 0x01), BC decrypts with the peer key
    rm -f out
    rsop encrypt /w/rs.pub < "$p" > m.asc && bcsop decrypt rs.sec < m.asc > out && cmp -s "$p" out
    record "4 rsop -> BC (rsop key), $p" PASS $? "$(shape m.asc)"
done

# 5. RFC 9980 A.2 key in both directions; the peer uses a v6 PKESK and a v2 SEIPD (A.2 advertises SEIPDv2)
rm -f out
bcsop encrypt a2.pub < msg.txt > m.asc && rsop decrypt /w/a2.sec < m.asc > out && cmp -s msg.txt out
record "5 BC -> rsop (A.2 key)" PASS $?
rm -f out
rsop encrypt /w/a2.pub < msg.txt > m.asc && bcsop decrypt a2.sec < m.asc > out && cmp -s msg.txt out
record "5b rsop -> BC (A.2 key)" PASS $? "$(shape m.asc)"

# 6. Sign + encrypt in both directions
rm -f out ver.txt
rsop encrypt --sign-with /w/rs.sec /w/bc.pub < msg.txt > m.asc \
    && bcsop decrypt --verify-with rs.pub --verifications-out ver.txt bc.sec < m.asc > out \
    && cmp -s msg.txt out && [ -s ver.txt ]
record "6a rsop sign (Ed25519) + encrypt -> BC decrypt + verify" PASS $? "$(cat ver.txt 2>/dev/null)"
rm -f out ver.txt
bcsop encrypt --sign-with bc.sec rs.pub < msg.txt > m.asc \
    && rsop decrypt --verify-with /w/bc.pub --verifications-out /w/ver.txt /w/rs.sec < m.asc > out \
    && cmp -s msg.txt out && [ -s ver.txt ]
record "6b BC sign (EdDSA) + encrypt -> rsop decrypt + verify" PASS $? "$(cat ver.txt 2>/dev/null)"

# 7. Several recipients (BC and rsop certificates), each decrypts
rm -f out out2
bcsop encrypt bc.pub rs.pub < msg.txt > m.asc && bcsop decrypt bc.sec < m.asc > out && cmp -s msg.txt out \
    && rsop decrypt /w/rs.sec < m.asc > out2 && cmp -s msg.txt out2
record "7 BC -> {BC, rsop} recipients" PASS $? "$(shape m.asc)"

# 8. Passphrase-protected keys in both directions
rm -f out
bcsop encrypt bcp.pub < msg.txt > m.asc && rsop decrypt --with-key-password /w/pw.txt /w/bcp.sec < m.asc > out \
    && cmp -s msg.txt out
record "8a BC-protected key used by rsop" PASS $?
rm -f out
rsop encrypt /w/rsp.pub < msg.txt > m.asc && bcsop decrypt --with-key-password pw.txt rsp.sec < m.asc > out \
    && cmp -s msg.txt out
record "8b rsop-protected key used by BC" PASS $?

# 9. Tampering is rejected and produces no output
bcsop encrypt rs.pub < msg.txt | bcsop dearmor > t.bin
flip t.bin 600
rm -f out; rsop decrypt /w/rs.sec < t.bin > out 2>/dev/null
rc=$?; [ $rc -ne 0 ] && [ ! -s out ]
record "9a tampered ML-KEM ciphertext rejected by rsop" PASS $? "rc=$rc"
rsop encrypt /w/bc.pub < msg.txt | bcsop dearmor > t.bin
flip t.bin -30
rm -f out; bcsop decrypt bc.sec < t.bin > out 2>/dev/null
rc=$?; [ $rc -eq 29 ] && [ ! -s out ]
record "9b tampered SEIPD body rejected by BC (exit 29, no output)" PASS $? "rc=$rc"

# 10. Certificates that are not v4 post-quantum
rsop generate-key --profile rfc9980 "rsop v6 <v6@example.org>" > rs6.sec
rsop extract-cert < rs6.sec > rs6.pub
rm -f out
bcsop encrypt rs6.pub < msg.txt > m.asc && rsop decrypt /w/rs6.sec < m.asc > out && cmp -s msg.txt out
record "10a BC -> rsop v6 PQ certificate" PASS $? "$(shape m.asc)"
rsop generate-key --profile default "rsop classic <classic@example.org>" > rsc.sec
rsop extract-cert < rsc.sec > rsc.pub
rm -f out
bcsop encrypt rsc.pub < msg.txt > m.asc && rsop decrypt /w/rsc.sec < m.asc > out && cmp -s msg.txt out
record "10b BC -> rsop classic v4 certificate" PASS $? "$(shape m.asc)"
rm -f out out2
bcsop encrypt bc.pub rsc.pub < msg.txt > m.asc && bcsop decrypt bc.sec < m.asc > out && cmp -s msg.txt out \
    && rsop decrypt /w/rsc.sec < m.asc > out2 && cmp -s msg.txt out2
record "10c BC -> {BC PQ, rsop classic} recipients" PASS $? "$(shape m.asc)"
rm -f out
rsop encrypt /w/rsc.pub < msg.txt > m.asc && bcsop decrypt rsc.sec < m.asc > out && cmp -s msg.txt out
record "10d rsop -> BC (rsop classic key)" PASS $?

# 11. Text mode and detached signatures
printf 'line one\nline two\n' > lf.txt
printf 'line one\r\nline two\r\n' > crlf.txt
bcsop sign --as text bc.sec < lf.txt > t.sig && rsop verify /w/t.sig /w/bc.pub < crlf.txt > ver.out
record "11a BC text signature -> rsop verify (other line endings)" PASS $? "$(cat ver.out 2>/dev/null)"
rsop sign --as text /w/rs.sec < lf.txt > t.sig && bcsop verify t.sig rs.pub < crlf.txt > ver.out
record "11b rsop text signature (Ed25519) -> BC verify (other line endings)" PASS $? "$(cat ver.out 2>/dev/null)"
rm -f out ver.txt
rsop encrypt --as text --sign-with /w/rs.sec /w/bc.pub < lf.txt > m.asc \
    && bcsop decrypt --verify-with rs.pub --verifications-out ver.txt bc.sec < m.asc > out \
    && cmp -s lf.txt out && grep -q "mode:text" ver.txt
record "11c rsop text sign+encrypt -> BC decrypt + verify" PASS $? "$(cat ver.txt 2>/dev/null)"

if [ $RUN_SQ = 1 ]; then
    for p in msg.txt 1mib.bin; do
        rm -f out m.asc
        sq encrypt --without-signature --for-file /w/bc.pub --output /w/m.asc "/w/$p" 2>/dev/null \
            && bcsop decrypt bc.sec < m.asc > out && cmp -s "$p" out
        record "S1 sq -> BC, $p" PASS $? "$(shape m.asc)"
        rm -f out
        bcsop encrypt bc.pub < "$p" > m.asc \
            && sq decrypt --recipient-file /w/bc.sec --output /w/out /w/m.asc 2>/dev/null && cmp -s "$p" out
        record "S2 BC -> sq (BC key), $p" PASS $?
    done
    rm -f out
    bcsop encrypt rs.pub < msg.txt > m.asc \
        && sq decrypt --recipient-file /w/rs.sec --output /w/out /w/m.asc 2>/dev/null && cmp -s msg.txt out
    record "S3 BC -> sq (rsop v4 PQ key)" PASS $?
    rm -f out
    bcsop encrypt a2.pub < msg.txt > m.asc \
        && sq decrypt --recipient-file /w/a2.sec --output /w/out /w/m.asc 2>/dev/null && cmp -s msg.txt out
    record "S4 BC -> sq (A.2 key)" PASS $?
    rm -f out
    bcsop encrypt --sign-with bc.sec rs.pub < msg.txt > m.asc \
        && sq decrypt --recipient-file /w/rs.sec --signer-file /w/bc.pub --output /w/out /w/m.asc 2>/dev/null \
        && cmp -s msg.txt out
    record "S5 BC sign + encrypt -> sq decrypt + verify" PASS $?
    rm -f out ver.txt m.asc
    sq encrypt --signer-file /w/rs.sec --for-file /w/bc.pub --output /w/m.asc /w/msg.txt 2>/dev/null \
        && bcsop decrypt --verify-with rs.pub --verifications-out ver.txt bc.sec < m.asc > out \
        && cmp -s msg.txt out && [ -s ver.txt ]
    record "S6 sq sign (Ed25519) + encrypt -> BC decrypt + verify" PASS $?
    rm -f out
    bcsop encrypt bcp.pub < msg.txt > m.asc \
        && sq decrypt --recipient-file /w/bcp.sec --password-file /w/pw.txt --output /w/out /w/m.asc 2>/dev/null \
        && cmp -s msg.txt out
    record "S7 BC-protected key used by sq" PASS $?
fi

{
    echo
    echo "**$pass of $total checks matched their expected outcome.**"
} >> "$REPORT"
log ""
log "$pass of $total checks matched their expected outcome. Report: $REPORT"
[ $fail -eq 0 ]
