#!/usr/bin/env bash
#
# End-to-end tests of bcsop on its own (no Docker): SOP behaviour, exit codes and the RFC 9580 and RFC 9980 support as
# seen by a command line user.
#
# Requirements: bash, .NET SDK 8+, perl. Usage: tools/pgp-interop/scripts/run-bcsop-tests.sh [--quick]
#
# --quick skips the SLH-DSA-SHAKE-128s and -256s profiles, whose signatures take several seconds each.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

if command -v cygpath > /dev/null 2>&1; then
    native() { cygpath -m "$1"; }
    export MSYS_NO_PATHCONV=1
else
    native() { echo "$1"; }
fi

dotnet build "$(native "$TOOL/BcSop/BcSop.csproj")" -c Release -v q -nologo > "$WORK/build.log" 2>&1 \
    || { cat "$WORK/build.log"; exit 2; }
BCSOP_DLL="$(native "$TOOL/BcSop/bin/Release/net8.0/bcsop.dll")"
bcsop() { dotnet "$BCSOP_DLL" "$@"; }

flip() { perl -e 'local $/; open F, "+<", $ARGV[0] or die; binmode F; my $d = <F>;
    my $o = $ARGV[1] < 0 ? length($d) + $ARGV[1] : $ARGV[1]; substr($d, $o, 1) ^= "\x01";
    seek F, 0, 0; print F $d; close F' "$1" "$2"; }

pass=0; fail=0
# expect NAME EXPECTED_EXIT_CODE ACTUAL_EXIT_CODE
expect() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1)); echo "[PASS] $1"
    else
        fail=$((fail + 1)); echo "[FAIL] $1 (expected exit $2, got $3)"
    fi
}
# check NAME CONDITION_EXIT_CODE
check() { expect "$1" 0 "$2"; }

cd "$WORK" || exit 2
printf 'Hello\n' > msg.txt
printf 'line one\nline two\n' > lf.txt
printf 'line one\r\nline two\r\n' > crlf.txt
printf 'pw' > pw.txt
printf 'wrong' > wrong.txt

bcsop generate-key "Alice <alice@example.org>" > alice.sec;     check "generate-key" $?
bcsop extract-cert < alice.sec > alice.pub;                     check "extract-cert" $?
bcsop generate-key "Bob <bob@example.org>" > bob.sec
bcsop extract-cert < bob.sec > bob.pub
bcsop generate-key --with-key-password pw.txt "Carol" > carol.sec
bcsop extract-cert < carol.sec > carol.pub
bcsop generate-key > nouid.sec;                                 check "generate-key without user ID" $?
bcsop generate-key --no-armor "Dave" > dave.bin
head -c 5 dave.bin | grep -q "BEGIN"; [ $? -ne 0 ];             check "generate-key --no-armor is binary" $?
bcsop generate-key "Ricarda S. Álvarez" > ricarda.sec
bcsop extract-cert < ricarda.sec > ricarda.pub
bcsop sign ricarda.sec < msg.txt > ricarda.sig
bcsop verify ricarda.sig ricarda.pub < msg.txt > /dev/null;     check "a user ID with other than ASCII characters" $?

# Exit codes for usage errors
bcsop frobnicate > /dev/null 2>&1;                              expect "unsupported subcommand" 69 $?
bcsop encrypt --frob alice.pub < msg.txt > /dev/null 2>&1;      expect "unsupported option" 37 $?
bcsop encrypt < msg.txt > /dev/null 2>&1;                       expect "encrypt without certificates" 19 $?
bcsop encrypt missing.pub < msg.txt > /dev/null 2>&1;           expect "missing input file" 61 $?
bcsop encrypt @ENV:CERT < msg.txt > /dev/null 2>&1;             expect "special prefix" 71 $?
bcsop generate-key --profile nonsense x > /dev/null 2>&1;       expect "unsupported profile" 89 $?
bcsop encrypt --profile nonsense alice.pub < msg.txt > /dev/null 2>&1
expect "unsupported encrypt profile" 89 $?
bcsop encrypt --as mime alice.pub < msg.txt > /dev/null 2>&1;   expect "unsupported --as" 37 $?
bcsop decrypt --session-key-out sk.txt alice.sec < /dev/null > /dev/null 2>&1
expect "decrypt --session-key-out unsupported" 37 $?
bcsop decrypt --with-session-key sk.txt alice.sec < /dev/null > /dev/null 2>&1
expect "decrypt --with-session-key unsupported" 37 $?
bcsop list-profiles generate-key | grep -q "rfc9980-v4";        check "list-profiles generate-key" $?
bcsop list-profiles encrypt | grep -q "seipdv2";                check "list-profiles encrypt" $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-01..08: every key profile, with and without a password: generate, extract, encrypt, decrypt, packet shapes
# ----------------------------------------------------------------------------------------------------------------
# profile  primary version and algorithm  subkey algorithm  password variant
PROFILES="
rfc9980-v4:v4:EdDsa:MLKem768_X25519:1
rfc9580:v6:Ed25519:X25519:1
rfc9980:v6:MLDsa65_Ed25519:MLKem768_X25519:1
rfc9980-high:v6:MLDsa87_Ed448:MLKem1024_X448:1
rfc9980-slh-128f:v6:SlhDsa_Shake128f:MLKem768_X25519:1
rfc9980-slh-128s:v6:SlhDsa_Shake128s:MLKem768_X25519:0
rfc9980-slh-256s:v6:SlhDsa_Shake256s:MLKem1024_X448:0
"
SLOW_PROFILES="rfc9980-slh-128s rfc9980-slh-256s"

for entry in $PROFILES; do
    IFS=: read -r profile ver primary_alg sub_alg with_password <<< "$entry"
    if [ $QUICK = 1 ] && [[ " $SLOW_PROFILES " == *" $profile "* ]]; then continue; fi

    bcsop generate-key --profile "$profile" "P <$profile@example.org>" > "$profile.sec";  check "$profile: generate-key" $?
    bcsop extract-cert < "$profile.sec" > "$profile.pub";                                   check "$profile: extract-cert" $?
    bcsop x-packets < "$profile.pub" | grep -q "^PublicKey ${ver} alg=${primary_alg}\$"
    check "$profile: primary key $ver $primary_alg" $?
    bcsop x-packets < "$profile.pub" | grep -q "^PublicSubkey ${ver} alg=${sub_alg}\$"
    check "$profile: subkey $ver $sub_alg" $?
    bcsop encrypt "$profile.pub" < msg.txt > "$profile.msg"
    bcsop decrypt "$profile.sec" < "$profile.msg" | cmp -s - msg.txt;                      check "$profile: encrypt/decrypt" $?

    if [ "$with_password" = 1 ]; then
        bcsop generate-key --profile "$profile" --with-key-password pw.txt "P" > "$profile.psec"
        bcsop extract-cert < "$profile.psec" > "$profile.ppub"
        bcsop encrypt "$profile.ppub" < msg.txt > "$profile.pmsg"
        bcsop decrypt --with-key-password pw.txt "$profile.psec" < "$profile.pmsg" | cmp -s - msg.txt
        check "$profile: protected key round trip" $?
        bcsop decrypt "$profile.psec" < "$profile.pmsg" > /dev/null 2>&1
        expect "$profile: protected key without password" 67 $?
    fi
done
bcsop generate-key --profile default x | bcsop x-packets | grep -q "^SecretSubkey v4 alg=MLKem768_X25519\$"
check "profile alias default" $?
bcsop generate-key --profile security x | bcsop x-packets | grep -q "^SecretKey v6 alg=MLDsa65_Ed25519\$"
check "profile alias security" $?

# v6 keys carry their preferences in the direct-key signature
bcsop x-packets < rfc9980.pub | grep -q "^Signature v6 type=0x1f .* features=0x09 salt=16\$"
check "v6 direct-key signature advertises SEIPD v1 and v2" $?
printf '\302' | bcsop x-packets > /dev/null 2>&1;               expect "x-packets on a truncated packet" 41 $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-09..12: choice of the message format
# ----------------------------------------------------------------------------------------------------------------
bcsop x-packets < rfc9580.msg | grep -q "^PKESK v6 key=v6 .* alg=X25519\$";                check "v6 recipient: v6 PKESK" $?
bcsop x-packets < rfc9580.msg | grep -q "^SEIPD v2 cipher=Aes256 aead=Ocb chunk=";         check "v6 recipient: SEIPD v2 AES-256 OCB" $?
bcsop encrypt rfc9580.pub rfc9980-v4.pub < msg.txt > mixed.msg
bcsop x-packets < mixed.msg | grep -q "^PKESK v3 ";                                         check "v4 recipient without v2: v3 PKESK" $?
bcsop x-packets < mixed.msg | grep -q "^SEIPD v1\$";                                        check "v4 recipient without v2: SEIPD v1" $?
bcsop decrypt rfc9580.sec < mixed.msg | cmp -s - msg.txt && bcsop decrypt rfc9980-v4.sec < mixed.msg | cmp -s - msg.txt
check "v6 and v4 recipients both decrypt the v1 message" $?
bcsop encrypt --profile seipdv1 rfc9580.pub < msg.txt > v1.msg
bcsop x-packets < v1.msg | grep -q "^PKESK v3 keyid=.* alg=X25519\$" && bcsop x-packets < v1.msg | grep -q "^SEIPD v1\$"
check "--profile seipdv1 for a v6 key" $?
bcsop decrypt rfc9580.sec < v1.msg | cmp -s - msg.txt;                                      check "seipdv1 message decrypts" $?
bcsop encrypt --profile seipdv2 rfc9980-v4.pub < msg.txt > v2.msg
bcsop x-packets < v2.msg | grep -q "^PKESK v6 key=v4 .* alg=MLKem768_X25519\$"
check "--profile seipdv2 for a v4 key: v6 PKESK with a 20-octet fingerprint" $?
bcsop decrypt rfc9980-v4.sec < v2.msg | cmp -s - msg.txt;                                   check "seipdv2 message to a v4 key decrypts" $?
for mode in gcm eax; do
    bcsop encrypt --profile seipdv2-$mode rfc9580.pub < msg.txt > $mode.msg
    bcsop x-packets < $mode.msg | grep -qi "^SEIPD v2 cipher=Aes256 aead=$mode "
    check "--profile seipdv2-$mode: v2 SEIPD with $mode" $?
    bcsop decrypt rfc9580.sec < $mode.msg | cmp -s - msg.txt;  check "seipdv2-$mode message decrypts" $?
done
bcsop generate-key --profile rfc9580-gcm "G <g@example.org>" > gcm.sec
bcsop extract-cert < gcm.sec > gcm.pub
bcsop encrypt gcm.pub < msg.txt > pref.msg
bcsop x-packets < pref.msg | grep -q "^SEIPD v2 cipher=Aes256 aead=Gcm "
check "the AES-256/GCM preference of the recipient is chosen" $?
bcsop decrypt gcm.sec < pref.msg | cmp -s - msg.txt;  check "the GCM message decrypts" $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-13..16: choice of the recipient subkey
# ----------------------------------------------------------------------------------------------------------------
bcsop generate-key --profile rfc9580-mixed "Mixed" > mixed.sec
bcsop extract-cert < mixed.sec > mixed.pub
[ "$(bcsop x-packets < mixed.pub | grep -c '^PublicSubkey')" = 2 ];                         check "mixed cert has two subkeys" $?
bcsop encrypt mixed.pub < msg.txt > mixed1.msg
[ "$(bcsop x-packets < mixed1.msg | grep -c '^PKESK')" = 1 ];                               check "mixed cert: one PKESK" $?
bcsop x-packets < mixed1.msg | grep -q "alg=MLKem768_X25519\$";                             check "mixed cert: the PQ subkey is used" $?
bcsop decrypt mixed.sec < mixed1.msg | cmp -s - msg.txt;                                    check "mixed cert: decrypt" $?
bcsop generate-key --profile rfc9580-sign-only "Signer" > signonly.sec
bcsop extract-cert < signonly.sec > signonly.pub
bcsop encrypt signonly.pub < msg.txt > /dev/null 2>&1;                                      expect "cert without encryption key" 17 $?
bcsop encrypt rfc9580.pub signonly.pub < msg.txt > /dev/null 2>&1
expect "one of two certs cannot encrypt" 17 $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-17..22: signatures for every profile
# ----------------------------------------------------------------------------------------------------------------
for entry in $PROFILES; do
    IFS=: read -r profile ver primary_alg sub_alg with_password <<< "$entry"
    if [ $QUICK = 1 ] && [[ " $SLOW_PROFILES " == *" $profile "* ]]; then continue; fi

    bcsop sign "$profile.sec" < msg.txt > "$profile.sig"
    bcsop verify "$profile.sig" "$profile.pub" < msg.txt | grep -q "mode:binary";            check "$profile: detached signature" $?
    printf 'Hellp\n' | bcsop verify "$profile.sig" "$profile.pub" > /dev/null 2>&1;         expect "$profile: other data" 3 $?
    bcsop inline-sign "$profile.sec" < msg.txt > "$profile.inl"
    bcsop inline-verify "$profile.pub" < "$profile.inl" | cmp -s - msg.txt;                  check "$profile: inline signature" $?
    if [ "$ver" = v6 ]; then
        bcsop x-packets < "$profile.inl" | grep -q "^OPS v6 type=0x00 .* alg=${primary_alg} salt=";  check "$profile: v6 one-pass" $?
    fi
done

# text mode across line endings, for a fast profile of each kind
for profile in rfc9980-v4 rfc9580 rfc9980; do
    bcsop sign --as text "$profile.sec" < lf.txt > t.sig && bcsop verify t.sig "$profile.pub" < crlf.txt | grep -q "mode:text"
    check "$profile: text signature verifies across line endings" $?
done

# cleartext signatures: no Hash header for v6, a header for v4
printf 'first\nsecond  \n- dashed\n' > clear.txt
bcsop inline-sign --as clearsigned rfc9580.sec < clear.txt > clear6.asc
head -3 clear6.asc | grep -q "^Hash:";                                                        [ $? -ne 0 ]; check "v6 cleartext has no Hash header" $?
grep -q "^- - dashed\$" clear6.asc;                                                           check "v6 cleartext escapes dashes" $?
bcsop inline-verify rfc9580.pub < clear6.asc | cmp -s - <(printf 'first\nsecond  \n- dashed\n')
check "v6 cleartext verifies" $?
bcsop inline-sign --as clearsigned rfc9980-v4.sec < clear.txt > clear4.asc
head -3 clear4.asc | grep -q "^Hash: SHA512";                                                 check "v4 cleartext has a Hash header" $?
bcsop inline-verify rfc9980-v4.pub < clear4.asc | cmp -s - <(printf 'first\nsecond  \n- dashed\n')
check "v4 cleartext verifies" $?
bcsop inline-sign --as clearsigned rfc9980.sec < clear.txt | bcsop inline-verify rfc9980.pub | cmp -s - <(printf 'first\nsecond  \n- dashed\n')
check "ML-DSA cleartext verifies" $?
perl -pe 's/^second/secone/' clear6.asc | bcsop inline-verify rfc9580.pub > /dev/null 2>&1;  expect "modified cleartext" 3 $?

# one good and one malformed signature (RFC 9980 3.3)
bcsop sign --no-armor rfc9580.sec < msg.txt > good.sig
cp good.sig bad.sig; flip bad.sig -5
cat bad.sig good.sig > both.sig
bcsop verify both.sig rfc9580.pub < msg.txt > /dev/null;                                      check "verify: one good, one malformed signature" $?
cat bad.sig > onlybad.sig
bcsop verify onlybad.sig rfc9580.pub < msg.txt > /dev/null 2>&1;                              expect "verify: only a malformed signature" 3 $?

# signer selection
bcsop verify good.sig alice.pub < msg.txt > /dev/null 2>&1;                                   expect "verify: other signer" 3 $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-23..25: sign and encrypt, intended recipients
# ----------------------------------------------------------------------------------------------------------------
for profile in rfc9580 rfc9980 rfc9980-v4; do
    bcsop encrypt --sign-with "$profile.sec" rfc9580.pub rfc9980.pub < msg.txt > "se-$profile.msg"
    for recipient in rfc9580 rfc9980; do
        bcsop decrypt --verify-with "$profile.pub" --verifications-out "v-$profile-$recipient.txt" \
            "$recipient.sec" < "se-$profile.msg" | cmp -s - msg.txt
        check "sign with $profile, encrypt to two, $recipient decrypts" $?
        grep -q " mode:binary\$" "v-$profile-$recipient.txt";                                 check "  ... and the signature verifies" $?
    done
done
bcsop decrypt --verify-with rfc9580.pub --verifications-out v-none.txt rfc9580.sec < "se-rfc9980.msg" > /dev/null
[ ! -s v-none.txt ];                                                                          check "signature by another key is not reported" $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-26..28: passwords
# ----------------------------------------------------------------------------------------------------------------
bcsop encrypt --profile seipdv2 --with-password pw.txt < msg.txt > pw2.msg
bcsop x-packets < pw2.msg | grep -q "^SKESK v6 cipher=Aes256 aead=Ocb s2k=4\$";               check "password, v2 mode: v6 SKESK with Argon2" $?
bcsop decrypt --with-password pw.txt < pw2.msg | cmp -s - msg.txt;                            check "password, v2 mode: decrypt" $?
bcsop decrypt --with-password wrong.txt < pw2.msg > /dev/null 2>&1;                           expect "password, v2 mode: wrong password" 29 $?
bcsop encrypt --profile seipdv1 --with-password pw.txt < msg.txt > pw1.msg
bcsop x-packets < pw1.msg | grep -q "^SKESK v4\$";                                            check "password, v1 mode: v4 SKESK" $?
bcsop decrypt --with-password pw.txt < pw1.msg | cmp -s - msg.txt;                            check "password, v1 mode: decrypt" $?
bcsop decrypt --with-password wrong.txt < pw1.msg > /dev/null 2>&1;                           expect "password, v1 mode: wrong password" 29 $?
bcsop encrypt --profile seipdv2 --with-password pw.txt rfc9580.pub < msg.txt > pwk.msg
bcsop decrypt --with-password pw.txt < pwk.msg | cmp -s - msg.txt && bcsop decrypt rfc9580.sec < pwk.msg | cmp -s - msg.txt
check "password and key recipients" $?

# ----------------------------------------------------------------------------------------------------------------
# Round trips of the first profile, passphrase-protected keys, signatures
# ----------------------------------------------------------------------------------------------------------------
bcsop encrypt alice.pub < msg.txt > m.asc && bcsop decrypt alice.sec < m.asc | cmp -s - msg.txt
check "encrypt/decrypt round trip" $?
bcsop x-packets < m.asc | grep -q "PKESK v3 keyid=.* alg=MLKem768_X25519"; check "v4 key: message uses v3 PKESK alg 35" $?
bcsop x-packets < m.asc | grep -q "SEIPD v1";                    check "v4 key: message uses SEIPD v1" $?
bcsop encrypt --no-armor alice.pub < msg.txt > m.bin && bcsop decrypt alice.sec < m.bin | cmp -s - msg.txt
check "binary message round trip" $?
: > empty.txt
bcsop encrypt alice.pub < empty.txt > e.asc && bcsop decrypt alice.sec < e.asc | cmp -s - empty.txt
check "empty message" $?
bcsop encrypt alice.pub bob.pub < msg.txt > two.asc
bcsop decrypt alice.sec < two.asc | cmp -s - msg.txt && bcsop decrypt bob.sec < two.asc | cmp -s - msg.txt
check "two recipients, each decrypts" $?
[ "$(bcsop x-packets < two.asc | grep -c '^PKESK')" = 2 ];      check "one PKESK per recipient" $?
cat bob.sec alice.sec > both.sec
bcsop decrypt both.sec < m.asc | cmp -s - msg.txt;               check "key file with several keys" $?
bcsop decrypt bob.sec < m.asc > out.txt 2>/dev/null;             expect "wrong key" 29 $?
[ ! -s out.txt ];                                                check "wrong key: no output" $?

bcsop encrypt carol.pub < msg.txt > c.asc
bcsop decrypt carol.sec < c.asc > /dev/null 2>&1;                expect "protected key without password" 67 $?
bcsop decrypt --with-key-password wrong.txt carol.sec < c.asc > /dev/null 2>&1
expect "protected key with wrong password" 67 $?
bcsop decrypt --with-key-password pw.txt carol.sec < c.asc | cmp -s - msg.txt
check "protected key with password" $?
bcsop decrypt --with-key-password wrong.txt rfc9980.psec < rfc9980.pmsg > /dev/null 2>&1
expect "v6 AEAD-protected key with the wrong password" 67 $?

bcsop encrypt --sign-with alice.sec bob.pub < msg.txt > s.asc
bcsop decrypt --verify-with alice.pub --verifications-out v.txt bob.sec < s.asc | cmp -s - msg.txt
check "sign+encrypt, decrypt" $?
grep -q " mode:binary" v.txt;                                    check "verification line written" $?
bcsop decrypt --verify-with alice.pub --verifications-out v.txt bob.sec < s.asc > /dev/null 2>&1
expect "verifications-out exists" 59 $?
rm -f v2.txt
bcsop decrypt --verify-with bob.pub --verifications-out v2.txt bob.sec < s.asc > /dev/null
[ ! -s v2.txt ];                                                 check "wrong signer: no verification" $?
bcsop sign alice.sec < msg.txt > d.sig && bcsop verify d.sig alice.pub < msg.txt > /dev/null
check "detached sign/verify" $?
printf 'Hellp\n' | bcsop verify d.sig alice.pub > /dev/null 2>&1; expect "detached verify, other data" 3 $?
bcsop verify d.sig bob.pub < msg.txt > /dev/null 2>&1;           expect "detached verify, other key" 3 $?
bcsop sign --with-key-password pw.txt carol.sec < msg.txt > /dev/null; check "sign with protected key" $?
bcsop sign carol.sec < msg.txt > /dev/null 2>&1;                 expect "sign with locked key" 67 $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-29..30: tampering, no plaintext is released
# ----------------------------------------------------------------------------------------------------------------
bcsop encrypt --no-armor alice.pub < msg.txt > t.bin
flip t.bin 500
bcsop decrypt alice.sec < t.bin > out.txt 2>/dev/null;           expect "tampered ML-KEM ciphertext" 29 $?
[ ! -s out.txt ];                                                check "tampered ML-KEM ciphertext: no output" $?
bcsop encrypt --no-armor alice.pub < msg.txt > t.bin
flip t.bin -25
bcsop decrypt alice.sec < t.bin > out.txt 2>/dev/null;           expect "tampered payload (v1)" 29 $?
[ ! -s out.txt ];                                                check "tampered payload (v1): no output" $?
bcsop encrypt --no-armor rfc9980.pub < msg.txt > t6.bin
flip t6.bin -25
bcsop decrypt rfc9980.sec < t6.bin > out.txt 2>/dev/null;        expect "tampered chunk (v2)" 29 $?
[ ! -s out.txt ];                                                check "tampered chunk (v2): no output" $?
bcsop encrypt --no-armor rfc9980.pub < msg.txt > t6.bin
flip t6.bin -2
bcsop decrypt rfc9980.sec < t6.bin > out.txt 2>/dev/null;        expect "tampered final tag (v2)" 29 $?
[ ! -s out.txt ];                                                check "tampered final tag (v2): no output" $?
bcsop encrypt --no-armor rfc9980.pub < msg.txt > t6.bin
head -c $(( $(wc -c < t6.bin) - 16 )) t6.bin > t6.cut
bcsop decrypt rfc9980.sec < t6.cut > out.txt 2>/dev/null;        expect "truncated final tag (v2)" 29 $?
[ ! -s out.txt ];                                                check "truncated final tag (v2): no output" $?

# ----------------------------------------------------------------------------------------------------------------
# E2E-31..36: inline signing, dates, passwords, session keys
# ----------------------------------------------------------------------------------------------------------------
for profile in rfc9980-v4 rfc9580 rfc9980; do
    for mode in binary text; do
        bcsop inline-sign --as $mode "$profile.sec" < msg.txt | bcsop inline-verify --verifications-out "iv-$profile-$mode.txt" "$profile.pub" | cmp -s - msg.txt
        check "inline-sign --as $mode, $profile" $?
        grep -q " mode:$mode\$" "iv-$profile-$mode.txt";                                      check "  ... verification says mode:$mode" $?
    done
done
bcsop inline-sign rfc9580.sec < msg.txt > win.msg
bcsop inline-verify --not-before 2000-01-01T00:00:00Z --not-after 2100-01-01T00:00:00Z rfc9580.pub < win.msg > /dev/null
check "inline-verify inside the window" $?
bcsop inline-verify --not-before 2100-01-01T00:00:00Z rfc9580.pub < win.msg > /dev/null 2>&1; expect "inline-verify before --not-before" 3 $?
bcsop inline-verify --not-after 2000-01-01T00:00:00Z rfc9580.pub < win.msg > /dev/null 2>&1;  expect "inline-verify after --not-after" 3 $?
bcsop verify --not-before 2100-01-01T00:00:00Z good.sig rfc9580.pub < msg.txt > /dev/null 2>&1
expect "verify before --not-before" 3 $?
bcsop encrypt --sign-with rfc9580.sec rfc9580.pub < msg.txt > swin.msg
bcsop decrypt --verify-with rfc9580.pub --verify-not-before 2100-01-01T00:00:00Z --verifications-out vwin.txt rfc9580.sec \
    < swin.msg | cmp -s - msg.txt && [ ! -s vwin.txt ]
check "decrypt --verify-not-before excludes the signature" $?

# ----------------------------------------------------------------------------------------------------------------
# Armor
# ----------------------------------------------------------------------------------------------------------------
bcsop dearmor < m.asc > m2.bin && bcsop armor < m2.bin > m2.asc && bcsop decrypt alice.sec < m2.asc | cmp -s - msg.txt
check "dearmor/armor round trip" $?
bcsop armor < m.asc | cmp -s - m.asc;                            check "armor is idempotent" $?

# ----------------------------------------------------------------------------------------------------------------
# RFC 9980 test vectors
# ----------------------------------------------------------------------------------------------------------------
V="$ROOT/crypto/test/data/openpgp/rfc9980"
cp "$V/a2-secret-key.asc" a2.sec
cp "$V/a2-public-key.asc" a2.pub
cp "$V/a2-seipdv1-message.asc" a2v1.asc
cp "$V/a2-seipdv2-message.asc" a2v2.asc
bcsop decrypt --verify-with a2.pub --verifications-out a2v.txt a2.sec < a2v1.asc | cmp -s - <(printf 'Testing\n')
check "A.2.3 decrypts" $?
grep -q "342E5DB2DE345215CB2C944F7102FFED3B9CF12D" a2v.txt;      check "A.2.3 signature verifies" $?
rm -f a2v2.txt
bcsop decrypt --verify-with a2.pub --verifications-out a2v2.txt a2.sec < a2v2.asc | cmp -s - <(printf 'Testing\n')
check "A.2.4 (v6 PKESK, v2 SEIPD) decrypts" $?
grep -q "342E5DB2DE345215CB2C944F7102FFED3B9CF12D" a2v2.txt;     check "A.2.4 signature verifies" $?
bcsop encrypt a2.pub < msg.txt > a2m.asc && bcsop decrypt a2.sec < a2m.asc | cmp -s - msg.txt
check "encrypt to the A.2 certificate" $?
bcsop x-packets < a2m.asc | grep -q "^PKESK v6 key=v4 ";        check "A.2 advertises SEIPD v2: v6 PKESK to the v4 key" $?
for n in a1 a3 a4 a5; do
    cp "$V/$n-secret-key.asc" "$n.sec"; cp "$V/$n-public-key.asc" "$n.pub"; cp "$V/$n-message.asc" "$n.asc"
    rm -f "$n.txt"
    bcsop decrypt --verify-with "$n.pub" --verifications-out "$n.txt" "$n.sec" < "$n.asc" | cmp -s - <(printf 'Testing\n')
    check "RFC 9980 $n message decrypts" $?
    [ -s "$n.txt" ];                                             check "RFC 9980 $n message signature verifies" $?
done
for n in a3 a4 a5 a6 a7; do
    cp "$V/$n-public-key.asc" "$n.pub"; cp "$V/$n-signature.asc" "$n.sig"
    bcsop verify "$n.sig" "$n.pub" < <(printf 'Testing\n') > /dev/null
    check "RFC 9980 $n detached signature verifies" $?
done
bcsop encrypt a4.pub < msg.txt | bcsop decrypt a4.sec | cmp -s - msg.txt
check "encrypt to the RFC 9980 A.4 certificate (ML-KEM-1024+X448)" $?

# Certificate validity (RFC 9580 5.2.3.10, 10.1): only self-signatures and binding signatures that verify count, the
# newest valid one wins, and version 6 keys need a valid direct-key signature. The fixtures come from
# fixtures/MakeFixtures, over the message "Hello\n".
FX="$TOOL/fixtures"
fx() { native "$FX/$1"; }
bcsop verify "$(fx primary.sig)" "$(fx granted-flags.pub)" < msg.txt > /dev/null
check "a newer valid self-signature lets the primary key sign" $?
bcsop verify "$(fx primary.sig)" "$(fx forged-flags.pub)" < msg.txt > /dev/null 2>&1
expect "a forged newer self-signature does not let the primary key sign" 3 $?
bcsop verify "$(fx subkey.sig)" "$(fx signing-granted.pub)" < msg.txt > /dev/null
check "the newest valid binding lets a subkey sign" $?
bcsop verify "$(fx subkey.sig)" "$(fx signing-revoked.pub)" < msg.txt > /dev/null 2>&1
expect "the newest valid binding takes the signing flag of a subkey away" 3 $?
bcsop encrypt "$(fx encryption-revoked.pub)" < msg.txt > /dev/null 2>&1
expect "the newest valid binding takes the encryption flags of a subkey away" 17 $?
bcsop verify "$(fx binary.sig)" "$(fx document-signer.pub)" < msg.txt > /dev/null
check "a binary signature is a document signature" $?
bcsop verify "$(fx direct-key-type.sig)" "$(fx document-signer.pub)" < msg.txt > /dev/null 2>&1
expect "a direct-key signature over the message is no document signature" 3 $?
bcsop verify "$(fx malformed-embedded.sig)" "$(fx malformed-embedded.pub)" < msg.txt > /dev/null
check "a malformed embedded signature does not spoil the valid back-signature" $?
bcsop verify "$(fx trailing-back-signature.sig)" "$(fx trailing-back-signature.pub)" < msg.txt > /dev/null 2>&1
expect "a back-signature with an octet after its signature value" 3 $?
bcsop verify "$(fx attribute.sig)" "$(fx attribute-signs.pub)" < msg.txt > /dev/null
check "the self-signature of a user attribute lets the primary key sign" $?
bcsop verify "$(fx attribute.sig)" "$(fx attribute-certify-only.pub)" < msg.txt > /dev/null 2>&1
expect "the self-signature of a user attribute does not let the primary key sign" 3 $?
bcsop verify "$(fx uid.sig)" "$(fx uid-revocable.pub)" < msg.txt > /dev/null
check "a revoked user ID leaves the primary key without self-signature" $?
bcsop verify "$(fx uid.sig)" "$(fx uid-irrevocable.pub)" < msg.txt > /dev/null 2>&1
expect "a non-revocable self-signature ignores the revocation of its user ID" 3 $?
bcsop verify "$(fx uid.sig)" "$(fx uid-superseded.pub)" < msg.txt > /dev/null 2>&1
expect "a non-revocable self-signature does not spare a newer revocable one" 3 $?
bcsop verify "$(fx context.sig)" "$(fx context-signer.pub)" < msg.txt > /dev/null
check "a signature without expiry or intended recipients" $?
bcsop verify "$(fx expired.sig)" "$(fx context-signer.pub)" < msg.txt > /dev/null 2>&1
expect "an expired signature" 3 $?
bcsop verify "$(fx intended-recipient.sig)" "$(fx context-signer.pub)" < msg.txt > /dev/null 2>&1
expect "a signature with an intended recipient outside an encrypted message" 3 $?

# A signature counts if its key signs for the certificate when the signature is made. Times are hours after the
# key is made: the revocations are made at 3, the suspension and the expiring key end at 4, and the signatures are
# made at -1 (early), 2 (before), 3.5 (during) and 5 (after).
timed() {
    bcsop verify "$(fx "timed-$1.sig")" "$(fx "$2.pub")" < msg.txt > /dev/null 2>&1
    local rc=$?
    if [ "$3" = valid ]; then check "$1 signature, $2" $rc; else expect "$1 signature, $2" 3 $rc; fi
}
timed early timed invalid
timed after timed valid
timed before timed-soft-revoked valid
timed during timed-soft-revoked invalid
timed before timed-hard-revoked invalid
timed before timed-suspended valid
timed during timed-suspended invalid
timed after timed-suspended valid
timed during timed-expired valid
timed after timed-expired invalid

# the packets of a binary OpenPGP sequence with new-format headers, one per line as hex
packets() { perl -e 'local $/; binmode STDIN; my $d = <STDIN>; my $p = 0;
    while ($p < length $d) { my $o = ord(substr($d, $p + 1, 1));
        my ($h, $n) = $o < 192 ? (2, $o) : $o < 224 ? (3, (($o - 192) << 8) + ord(substr($d, $p + 2, 1)) + 192)
            : (6, unpack("N", substr($d, $p + 2, 4)));
        print unpack("H*", substr($d, $p, $h + $n)), "\n"; $p += $h + $n; }'; }
unhex() { perl -ne 'chomp; binmode STDOUT; print pack("H*", $_)'; }

# A subkey without a binding signature is not a key of the certificate: Mallory's key, appended to Dave's
# certificate as a subkey, does not sign for Dave (version 6 keys, whose packets have new-format headers)
bcsop generate-key --profile rfc9580 "Dave <dave@example.org>" > dave.sec
bcsop generate-key --profile rfc9580 "Mallory <mallory@example.org>" > mallory.sec
bcsop sign mallory.sec < msg.txt > mallory.sig
bcsop extract-cert --no-armor < dave.sec > dave.bin
bcsop extract-cert --no-armor < mallory.sec | packets | head -n 1 | perl -pe 's/^c6/ce/' | unhex > mallory-subkey.bin
cat dave.bin mallory-subkey.bin > dave-mallory.bin
bcsop verify mallory.sig dave.bin < msg.txt > /dev/null 2>&1
expect "another key does not sign for the certificate" 3 $?
bcsop verify mallory.sig dave-mallory.bin < msg.txt > /dev/null 2>&1
expect "an unbound subkey does not sign for the certificate" 3 $?

# A version 6 certificate without its direct-key signature (the second packet) is not used
packets < dave.bin | perl -ne 'print unless $. == 2' | unhex > dave-nodk.bin
bcsop sign dave.sec < msg.txt > dave.sig
bcsop verify dave.sig dave.bin < msg.txt > /dev/null
check "verify: with the direct-key signature" $?
bcsop encrypt dave-nodk.bin < msg.txt > /dev/null 2>&1
expect "encrypt: no direct-key signature" 17 $?
bcsop verify dave.sig dave-nodk.bin < msg.txt > /dev/null 2>&1
expect "verify: no direct-key signature" 3 $?

# RFC 9580 4.3: an unknown critical packet rejects the detached signatures, an unknown non-critical one is skipped
bcsop sign --no-armor alice.sec < msg.txt > alice-sig.bin
{ printf '\xe7\x01\x01'; cat alice-sig.bin; } > critical.sig
bcsop verify critical.sig alice.pub < msg.txt > /dev/null 2>&1
expect "verify: unknown critical packet" 41 $?
{ printf '\xe8\x01\x01'; cat alice-sig.bin; } > noncritical.sig
bcsop verify noncritical.sig alice.pub < msg.txt > /dev/null
check "verify: unknown non-critical packet" $?

# RFC 9580 7.1: no other armor header than a well-formed Hash header in a cleartext signed message
bcsop inline-sign --as clearsigned alice.sec < msg.txt > clear-alice.asc
bcsop inline-verify alice.pub < clear-alice.asc > /dev/null
check "cleartext without armor headers" $?
perl -pe 's/^(-----BEGIN PGP SIGNED MESSAGE-----\r?\n)/$1Comment: injected\n/' clear-alice.asc > clear-comment.asc
bcsop inline-verify alice.pub < clear-comment.asc > /dev/null 2>&1
expect "cleartext with a Comment armor header" 3 $?

# RFC 9580 7.1, 4.3: a cleartext signature is a text signature, and an unknown critical packet after it rejects
# the message
sed -n '/^-----BEGIN PGP SIGNATURE-----/,$p' clear-alice.asc | bcsop dearmor > clear-alice.sig
sed '/^-----BEGIN PGP SIGNATURE-----/,$d' clear-alice.asc > clear-head.txt
{ cat clear-head.txt; { cat clear-alice.sig; printf '\xe7\x01\x01'; } | bcsop armor; } > clear-critical.asc
bcsop inline-verify alice.pub < clear-critical.asc > /dev/null 2>&1
expect "cleartext with an unknown critical packet after the signature" 41 $?
{ cat clear-head.txt; { cat clear-alice.sig; printf '\xe8\x01\x01'; } | bcsop armor; } > clear-noncritical.asc
bcsop inline-verify alice.pub < clear-noncritical.asc > /dev/null
check "cleartext with an unknown non-critical packet after the signature" $?
{ cat clear-head.txt; printf 'Hello' | bcsop sign --as binary alice.sec; } > clear-binary.asc
bcsop inline-verify alice.pub < clear-binary.asc > /dev/null 2>&1
expect "cleartext with a binary signature" 3 $?

# RFC 9580 5.4: one-pass signatures are bracketed with their signatures, also two by the same key
bcsop inline-sign alice.sec alice.sec < msg.txt > twice.asc
rm -f twice.txt
bcsop inline-verify --verifications-out twice.txt alice.pub < twice.asc > /dev/null
[ "$(wc -l < twice.txt)" -eq 2 ];                               check "two one-pass signatures by one key" $?
bcsop inline-sign --no-armor dave.sec < msg.txt | packets | sed '$d' | unhex > ops-literal.bin
bcsop inline-verify dave.bin < ops-literal.bin > /dev/null 2>&1
expect "a one-pass signature without a signature" 41 $?

# RFC 9580 5.4, 5.2.5: a signature closes the innermost open one-pass signature, and does not verify in the
# wrong place; signatures and one-pass signatures of an unsupported version (23) do not spoil the others
bcsop extract-cert --no-armor < mallory.sec > mallory.bin
bcsop inline-sign --no-armor dave.sec mallory.sec < msg.txt | packets > two.hex
unhex < two.hex > two.bin
perl -pe 's/^(c4..)06/${1}17/ if $. == 1' two.hex | unhex > unsupported-ops.bin
perl -e '@l = <>; @l[3, 4] = @l[4, 3]; print @l' two.hex | unhex > swapped.bin
perl -pe 's/^(c2..)06/${1}17/ if $. == 4' two.hex | unhex > unsupported-inner.bin
for message in two unsupported-ops unsupported-inner; do
    rm -f "$message.txt"
    bcsop inline-verify --verifications-out "$message.txt" dave.bin mallory.bin < "$message.bin" > /dev/null
    check "$message: verifies" $?
done
[ "$(wc -l < two.txt)" -eq 2 ];                                 check "two one-pass signed signatures" $?
[ "$(wc -l < unsupported-ops.txt)" -eq 1 ];                     check "one beside an unsupported one-pass signature" $?
[ "$(wc -l < unsupported-inner.txt)" -eq 1 ];                   check "the outer beside an unsupported inner one" $?
bcsop inline-verify mallory.bin dave.bin < swapped.bin > /dev/null 2>&1
expect "signatures in the wrong order" 3 $?

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
