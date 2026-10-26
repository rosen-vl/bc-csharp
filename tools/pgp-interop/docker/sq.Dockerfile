# Sequoia sq with RFC 9980 support: sequoia-sq 1.4.1 (sequoia-openpgp 2.4, which has RFC 9980). Post-quantum algorithms
# need the OpenSSL backend with OpenSSL >= 3.5 (Debian trixie ships 3.5.x).
FROM rust:1-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config clang capnproto libsqlite3-dev nettle-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install sequoia-sq --version 1.4.1 --locked --no-default-features --features crypto-openssl
ENTRYPOINT ["sq"]
