# rsop (rPGP SOP) with RFC 9980 support: rsop 0.12.0 -> rpgpie 0.12.0 -> rPGP (pgp) 0.21.0, 'pqc' feature on by
# default. Generate-key profile 'rfc9980-v4' creates v4 keys with an ML-KEM-768+X25519 subkey.
FROM rust:1-bookworm
RUN cargo install rsop --version 0.12.0 --locked
ENTRYPOINT ["rsop"]
