# OpenPGP RFC 9580 and RFC 9980 interop harness

Tests Bouncy Castle's support for the version 6 formats of RFC 9580 and the post-quantum algorithms of RFC 9980
(ML-DSA+EdDSA, SLH-DSA, ML-KEM+X25519 and ML-KEM+X448) against other OpenPGP implementations, including Bouncy Castle
Java (which has the version 6 formats but not the RFC 9980 algorithms).

This folder is not part of `BouncyCastle.sln` and is not built by CI.

## Contents

| Path | Purpose |
|---|---|
| `BcSop/` | `bcsop`: a subset of the [Stateless OpenPGP CLI](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) over Bouncy Castle |
| `docker/rsop.Dockerfile` | rsop 0.12.0 (rpgpie 0.12.0, rPGP 0.21.0 with post-quantum support) |
| `docker/sq.Dockerfile` | Sequoia sq 1.4.1 (sequoia-openpgp 2.4.1, which has RFC 9980; OpenSSL 3.5 backend) |
| `docker/gosop.Dockerfile` | gosop 1.1.0 (GopenPGP 3.4.1, ProtonMail/go-crypto 529840d2b1bd), pinned commit of the `gosop-gopenpgp-v3-pqc` branch |
| `docker/openpgpjs.Dockerfile` | sop-openpgpjs 2.2.0 on OpenPGP.js 6.3.1 (the `psk` branch with post-quantum algorithms), with an `rfc9980` key profile |
| `docker/pgpainless.Dockerfile` | pgpainless-cli 2.0.4 (PGPainless on Bouncy Castle Java 1.84), the pinned jar from Maven Central |
| `docker/gnupg.Dockerfile` | GnuPG 2.5.24 (RFC 9980 mode `--allow-9980`), the release tarball pinned by SHA-256, on Debian forky (libgcrypt 1.12) |
| `docker/rnp.Dockerfile` | RNP (Thunderbird) at a pinned commit of `main` with `ENABLE_PQC` and `ENABLE_CRYPTO_REFRESH`, on Botan 3.13 |
| `bcjava/` | `BcJavaCheck`: a small command line over the OpenPGP API of Bouncy Castle Java 1.86, and its Dockerfile |
| `scripts/run-bcsop-tests.sh` | End-to-end tests of `bcsop` on its own (no Docker) |
| `fixtures/` | Certificates and signatures for the tests of certificate validity in `run-bcsop-tests.sh`, and `MakeFixtures`, which made them |
| `scripts/run-matrix.sh` | The matrix for version 4 keys with ML-KEM-768+X25519, against rsop and Sequoia |
| `scripts/run-full-matrix.sh` | The full matrix: version 6 keys and all RFC 9980 algorithms against rsop, gosop, sop-openpgpjs, PGPainless and Sequoia |
| `scripts/run-gnupg.sh` | Bouncy Castle against GnuPG 2.5.24 (see below) |
| `scripts/run-rnp.sh` | Bouncy Castle against RNP, with all RFC 9980 algorithms (see below) |
| `scripts/run-bcjava.sh` | Bouncy Castle C# against Bouncy Castle Java 1.86, including byte-for-byte re-encoding (see below) |
| `scripts/run-oits.sh` | Runs the OpenPGP interoperability test suite of the Sequoia project against `bcsop` (see below) |
| `oits/` | Configuration and expectations for that suite |

## Running

You need bash, the .NET SDK 8 or later, Docker and perl. The scripts work on Linux, and on Windows with Git Bash and
Docker Desktop.

```bash
tools/pgp-interop/scripts/run-bcsop-tests.sh            # about 200 checks, a few minutes (--quick skips SLH-DSA-128s/256s)
tools/pgp-interop/scripts/run-full-matrix.sh            # all peers
tools/pgp-interop/scripts/run-full-matrix.sh --no-sq    # without Sequoia
tools/pgp-interop/scripts/run-full-matrix.sh --only rsop --only gosop
tools/pgp-interop/scripts/run-matrix.sh                 # version 4 rows only
tools/pgp-interop/scripts/run-bcjava.sh                 # against Bouncy Castle Java 1.86
tools/pgp-interop/scripts/run-gnupg.sh                  # against GnuPG 2.5.24
tools/pgp-interop/scripts/run-rnp.sh                    # against RNP (main)
```

The first run builds the peer images, which takes a few minutes for rsop, gosop and OpenPGP.js, and longer for
Sequoia. The scripts exit non-zero if any row deviates from its expected outcome, and write a Markdown report to
`results/` (which is not committed).

## bcsop

`bcsop` supports these subcommands:

- `version`
- `list-profiles`
- `generate-key`
- `extract-cert`
- `encrypt`
- `decrypt`
- `sign`
- `verify`
- `inline-sign`
- `inline-verify`
- `armor`
- `dearmor`

It uses the SOP exit codes. `x-packets` is a non-SOP extension that prints the outer packet structure of a message
or key (versions, algorithms, salt sizes, chunk size octets), and `--debug` prints the exception behind a failed
`decrypt`.

- **generate-key** profiles:

  | Profile | Key |
  |---|---|
  | `rfc9980-v4` (alias `default`) | v4: Ed25519 (legacy) primary key, ML-KEM-768+X25519 subkey; advertises v1 SEIPD only |
  | `rfc4880` | v4: Ed25519 (legacy) primary key, Curve25519 ECDH subkey (a classic key, for peers without RFC 9980) |
  | `rfc9580` | v6: Ed25519 primary key, X25519 subkey, SHA-512 |
  | `rfc9980` (alias `security`) | v6: ML-DSA-65+Ed25519 primary key, ML-KEM-768+X25519 subkey, SHA3-256 |
  | `rfc9980-high` | v6: ML-DSA-87+Ed448 primary key, ML-KEM-1024+X448 subkey, SHA3-512 |
  | `rfc9980-slh-128s`, `-128f` | v6: SLH-DSA-SHAKE-128s or -128f primary key, ML-KEM-768+X25519 subkey, SHA3-256 |
  | `rfc9980-slh-256s` | v6: SLH-DSA-SHAKE-256s primary key, ML-KEM-1024+X448 subkey, SHA-512 |
  | `rfc9580-mixed`, `rfc9580-sign-only` | v6 keys for tests of the recipient selection (two encryption subkeys; none) |
  | `rfc9580-gcm` | v6: Ed25519 primary key, X25519 subkey, with AES-256/GCM first in the AEAD preferences (for tests) |

  Version 6 keys have a direct-key signature with the key flags and the preferences of RFC 9980 7.1: Features
  `0x09`, AES-256 before AES-128, AES-256/OCB before AES-128/OCB, and SHA3-512, SHA3-256, SHA-512 and SHA-256.
  `--with-key-password` protects version 6 keys with AES-256, OCB and Argon2id (64 MiB).
- **encrypt** takes the format and the algorithms from the preferences of the recipients (`PgpEncryptionPreferences`):
  v6 PKESK and v2 SEIPD if every recipient supports it, otherwise v3 PKESK and v1 SEIPD. `--profile seipdv1` or
  `--profile seipdv2` forces one of the two; `seipdv2-gcm` and `seipdv2-eax` force v2 SEIPD with GCM or EAX instead
  of OCB. `--with-password` adds a v6 SKESK with Argon2 (v2 mode) or a v4 SKESK.
  - Recipients are valid encryption subkeys that Bouncy Castle can use. If a certificate has an ML-KEM subkey, only
    those subkeys are used.
  - Signatures name the primary keys of the recipients' certificates with Intended Recipient Fingerprint subpackets
    (not marked critical, since OpenPGP.js rejects critical subpackets it does not know), as the RFC test vectors and the
    other implementations do.
- **decrypt** handles v3 and v6 PKESK, v4 and v6 SKESK, v1 and v2 SEIPD, and anonymous PKESKs. It releases plaintext
  only after the integrity check (MDC, or the final authentication tag) succeeded. Any failure exits with 29. A
  signature that names intended recipients only counts if it names a key of the decrypting certificate.
- **sign**, **verify**, **inline-sign** and **inline-verify** make and check version 6 signatures for version 6 keys.
  `verify` succeeds if at least one signature verifies; malformed signatures are ignored (RFC 9980 3.3).
  `inline-sign --as clearsigned` writes the cleartext signature framework, without a `Hash:` header for version 6 keys.
  `--not-before` and `--not-after` limit the signature creation time.
- `--session-key-out` and `--with-session-key` are not supported (exit code 37).

## Expected outcomes

Every row of `run-full-matrix.sh` is named `I-<row>/<peer>/<key>/<payload>` and has an expected outcome: `PASS`,
`UNSUPPORTED-PEER` (the peer cannot do it; the flow must fail cleanly, and an unexpected success is a deviation too) or
`PEER-DEVIATION` (a known deviation of the peer from the RFCs, recorded the same way).

PGPainless has none of the RFC 9980 algorithms, so it is tested with the version 6 (`rfc9580`) and classic version 4
(`rfc4880`) keys of BC where the other peers get the post-quantum ones (signing, mixed recipients and tampering rows).
Its own version 6 keys (`performance`, `rfc9580-curve448`) have no direct-key signature, which RFC 9580 10.1.1
requires, so BC does not use their certificates: the rows in which BC encrypts to them or verifies their signatures
(I-03, I-06, I-07, I-08, I-16) are `PEER-DEVIATION`.

| Row | Check | Expected |
|---|---|---|
| I-01, I-02 | Peer encrypts to a BC key and BC decrypts, and the reverse, for every BC profile (including SLH-DSA-SHAKE-128f and -256s), with unprotected and protected keys, and several payload sizes | PASS; OpenPGP.js has no ML-KEM-1024+X448 and no ML-DSA-87+Ed448; PGPainless has no RFC 9980 algorithm |
| I-03, I-04 | The same with keys made by the peer (rsop, gosop and OpenPGP.js profiles; Sequoia cipher suites) | PASS |
| I-05 | The RFC 9980 A.1 to A.4 keys, in both directions | PASS; OpenPGP.js has no ML-KEM-1024+X448 (A.4); PGPainless has no RFC 9980 algorithm |
| I-06 | Sign and encrypt, both directions | PASS; `PEER-DEVIATION` for PGPainless, which only accepts an Intended Recipient Fingerprint that names the decryption subkey, not the primary key that RFC 9580 5.2.3.36 specifies, and so ignores the signatures of BC |
| I-07 | Detached (binary and text), inline and cleartext signatures, both directions; SLH-DSA-SHAKE-128f and -256s signatures of BC | PASS; OpenPGP.js and PGPainless have no SLH-DSA |
| I-08 | Several recipients: post-quantum and classic, v6 and v4 | PASS |
| I-09 | Password encryption, both directions, v1 and v2 | PASS |
| I-10 | Tampered messages | Rejected by BC (no output) and by the peer (non-zero exit; gosop streams plaintext before it notices a bad final tag) |
| I-11 | Certificates of the peer, exported again by BC | Identical |
| I-15 | OpenPGP.js `rfc9980` keys have no SEIPDv2 feature | BC uses a v3 PKESK and a v1 SEIPD |
| I-16 | Forcing each SEIPD version | PASS |
| I-17 | AEAD modes: BC encrypts 1 MiB with v2 SEIPD and GCM, and with EAX, to its v6 key and the peer decrypts; the peer encrypts to the BC `rfc9580-gcm` key, whose preferences put AES-256/GCM before AES-256/OCB | PASS; Sequoia has no EAX; rsop and Sequoia choose AES-256/OCB, which RFC 9580 5.2.3.15 allows (`UNSUPPORTED-PEER` for the check that GCM is chosen) |

The version 4 rows (`run-matrix.sh`):

| Check | Expected |
|---|---|
| Peer encrypts to a BC key and BC decrypts, or BC encrypts and the peer decrypts (all v4 keys) | PASS |
| Sign + encrypt in both directions; passphrase-protected keys in both directions | PASS |
| Peer encrypts to the RFC 9980 A.2 certificate, BC decrypts | PASS (v6 PKESK and v2 SEIPD to a v4 key) |
| BC encrypts to a v6 post-quantum certificate (rsop profile `rfc9980`) | PASS |
| Classic v4 certificates, and PQ and classic recipients mixed | PASS (the message is then not post-quantum secure) |
| Text-mode signatures, across line endings | PASS |
| Tampered messages | Rejected without output |


## RNP and GnuPG

Neither has a Stateless OpenPGP CLI, so `run-rnp.sh` and `run-gnupg.sh` keep one container for the whole run (the
keyring lives in it) and drive the native tools with `docker exec`. Rows are named `R-<row>/...` and `G-<row>/...`
and have the same outcomes as the matrix.

**RNP** (`main` at 96f35e3, built with `ENABLE_PQC` and `ENABLE_CRYPTO_REFRESH`) has every RFC 9980 algorithm. The
rows cover the RFC 9980 test vectors (messages and detached signatures, A.1 to A.7), encryption in both directions for
every BC profile, SLH-DSA-SHAKE-256s included (RNP with its default format, `--aead=OCB`, `--aead=EAX` and
`--v3-pkesk-only`), keys of every RFC 9980 kind made by RNP (whose certificates BC also exports again byte for byte),
detached, inline and cleartext signatures, sign + encrypt, v4 and v6 password messages, and protected keys in both
directions. RNP pairs its SLH-DSA-SHAKE-256s keys with an ML-KEM-1024+ECDH-NIST-P-521 subkey, a composite of the
drafts that RFC 9980 does not have, so those keys are only used for signatures. RNP has no GCM. Known deviations of RNP
(`PEER-DEVIATION`):

- RNP does not verify version 6 cleartext signatures of other implementations, not even RFC 9580 A.6.
- With `--aead`, RNP writes LibrePGP OCB encrypted data (packet type 20) for v4 recipients, which is not an RFC 9580
  format; BC refuses it.

**GnuPG** 2.5.24 has, with `--allow-9980`, ML-KEM encryption and v6 Ed25519/X25519 keys, but no ML-DSA or SLH-DSA.
It decrypts the RFC 9980 test messages and the ML-KEM messages of BC to v4 and v6 keys, and it verifies the v4
signatures of BC. Its RFC 9580 and RFC 9980 support is otherwise incomplete, and Sequoia agrees with BC on each of these
deviations (`PEER-DEVIATION`):

- It writes a v6 PKESK followed by a v1 SEIPD (RFC 9580 5.1 forbids it), with public key algorithm 0 for v4 keys.
- It fails on v6 PKESKs for X25519 keys ("Checksum error"), also for messages of Sequoia and for RFC 9580 A.8.
- It cannot verify v6 Ed25519 detached and cleartext signatures, also RFC 9580 A.6 and A.7.
- The self-signatures of the v6 keys it makes do not verify, and it writes ML-KEM-768+X25519 subkeys as version 5 key
  packets under v6 primary keys.
- It keeps only a stub of the v4 Curve25519 ECDH secret subkeys of other implementations (PGPainless's too).
- It has no v6 SKESK, and its default LibrePGP Kyber keys (v5, algorithm 8) are not RFC 9980.

Since GnuPG cannot read the v6 PKESKs and SKESKs that a v2 SEIPD needs, the AEAD modes (GCM, EAX) and SLH-DSA are
not tested with it.

## Bouncy Castle Java

Bouncy Castle Java (up to 1.86) supports the version 6 formats of RFC 9580 but not the RFC 9980 algorithms.
`scripts/run-bcjava.sh` builds `bcjava/BcJavaCheck.java` against the 1.86 jars from Maven Central (pinned by SHA-256)
and checks, with `UNSUPPORTED-PEER` for the rows that need an RFC 9980 algorithm on the Java side:

| Row | Check |
|---|---|
| J-01 | Java parses BC keys and certificates (v4 classic, v6, v6 protected) and encodes them again byte for byte; the self-signatures give a signing key, an encryption key and a valid user ID |
| J-02, J-03 | Java re-encodes BC detached signatures (binary and text) byte for byte and verifies them |
| J-04 | Java decrypts BC messages: v1 SEIPD, and v2 SEIPD with OCB, GCM and EAX, small and 70 KB payloads, signed messages, a protected BC key, and password messages |
| J-05 | BC exports the certificates of Java keys again, byte for byte |
| J-06, J-07 | BC decrypts and verifies Java messages and detached signatures (v4 Curve25519, v6 Ed25519/X25519 and Ed448/X448) |
| J-08, J-09 | Java password messages, and Java encrypting (and signing) to BC keys |
| J-10 | Java encrypts to the BC `rfc9580-gcm` key, which prefers AES-256/GCM |

One row is a `PEER-DEVIATION`: Bouncy Castle Java 1.86 appends the 20-octet SHA-1 checksum of S2K usage 254 to the
cleartext of AEAD protected (usage 253) secret keys, where RFC 9580 5.5.3 has only the authentication tag. Bouncy Castle
C# requires the key material of a version 6 key to account for the whole cleartext, so it does not unlock such keys.

## The OpenPGP interoperability test suite

`scripts/run-oits.sh` runs the [OpenPGP interoperability test
suite](https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite) of the Sequoia project against `bcsop`, with
sqop, rsop, gosop, sop-openpgpjs and pgpainless-cli as peers. Nothing from the suite is committed to this repository: it
is licensed under the GPL-3.0, so the script clones it at a pinned commit into `results/oits-src/` (which is not
committed) and builds it in Docker.

`oits/expectations.tsv` is the baseline of what the suite reports for every combination of producer and consumer that
involves `bcsop` (about 2,700 lines, at suite commit a6da06a). `run-oits.sh --check` fails on any difference, and
`--update` rewrites it. `--retain REGEX` runs a subset of the tests.

What the baseline shows:

- All round trips of the post-quantum, version 6 and AEAD groups succeed with every peer that supports the algorithm:
  encryption and decryption, detached, inline and cleartext signatures, and sign + encrypt, for ML-KEM-768+X25519,
  ML-KEM-1024+X448, ML-DSA-65+Ed25519, ML-DSA-87+Ed448, v6 Ed25519/X25519 and the v4 post-quantum keys. The failures are
  peer limitations (OpenPGP.js has no ML-DSA-87+Ed448 or ML-KEM-1024+X448).
- The baseline was recorded when `bcsop` was a thin driver over the library. It now checks certificates as RFC 9580
  5.2.3.10 and 10.1 define them: only self-signatures and binding signatures that verify count, the newest valid one
  wins, version 6 keys need a valid direct-key signature, signing subkeys need a valid primary key binding signature,
  and revoked or expired keys are not used. The baseline therefore still records the suite's tests of certificate
  policy (key flags, expiry, revocations, primary key binding signatures) as failures, and needs `run-oits.sh
  --update`. Its tests of critical unknown subpackets, of the grammar of messages (two literal packets, concatenated
  messages), of partial body lengths and of bare CR characters in cleartext signatures are recorded as failures too;
  none of them is specific to RFC 9980.
- Tests that need session keys, the NIST and Brainpool composite algorithms of the individual draft, and LibrePGP
  formats are unsupported or neutral.
- With PGPainless as the consumer, the failures are the RFC 9980 algorithms (which it does not have; it also rejects
  a whole certificate that has an RFC 9980 subkey, such as the v4 keys of the `default` profile) and its Intended
  Recipient Fingerprint deviation. As the producer, its `rfc9580` profile makes v6 SKESKs with a SHA-1 S2K, which RFC
  9580 9.5 forbids; `bcsop` refuses to decrypt them, as rPGP does.
