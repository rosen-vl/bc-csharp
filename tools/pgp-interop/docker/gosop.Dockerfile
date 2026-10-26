# gosop (GopenPGP v3 based SOP) with RFC 9980 support: gosop 1.1.0, GopenPGP 3.4.1, ProtonMail/go-crypto 529840d2b1bd.
# Key profiles: performance (v6 Ed25519/X25519), security (v6 Ed448/X448), rfc9980 (ML-DSA-65+Ed25519 and
# ML-KEM-768+X25519), rfc9980-high-security (ML-DSA-87+Ed448 and ML-KEM-1024+X448).
FROM golang:1-bookworm
RUN git clone --branch gosop-gopenpgp-v3-pqc https://github.com/ProtonMail/gosop.git /src/gosop \
    && cd /src/gosop \
    && git checkout 794b9c4e66ea5eacda40b3690ad7784b28f40b13 \
    && go build -o /usr/local/bin/gosop .
ENTRYPOINT ["gosop"]
