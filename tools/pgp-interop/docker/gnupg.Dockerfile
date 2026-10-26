# GnuPG 2.5.24, which supports the ML-KEM encryption of RFC 9980 (and the v6 Ed25519/X25519 keys of RFC 9580) with
# --allow-9980, but no ML-DSA or SLH-DSA signatures. The tarball is pinned by the SHA-256 of the release whose
# signatures (Werner Koch, NIIBE Yutaka) were checked against https://gnupg.org/signature_key.asc; the libraries come
# from Debian (libgcrypt 1.12).
FROM debian:forky-slim AS build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential pkg-config bzip2 \
    libgpg-error-dev libgcrypt20-dev libassuan-dev libksba-dev libnpth0-dev zlib1g-dev libbz2-dev libsqlite3-dev \
    > /dev/null
ADD --checksum=sha256:bf149d01a2b9fcc0e4589b8ae8697d3d5c557ea48ed95a3fa55dd3b1187e6039 \
    https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.5.24.tar.bz2 /src/
RUN cd /src && tar xjf gnupg-2.5.24.tar.bz2 && cd gnupg-2.5.24 \
    && ./configure --prefix=/opt/gnupg --disable-doc --disable-ldap --disable-gnutls --disable-tpm2d \
        --disable-wks-tools --disable-card-support > /dev/null \
    && make -j"$(nproc)" > /dev/null && make install > /dev/null

FROM debian:forky-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libgpg-error0 libgcrypt20 libassuan9 \
    libksba8 libnpth0t64 zlib1g libbz2-1.0 libsqlite3-0 > /dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/gnupg /opt/gnupg
ENV PATH=/opt/gnupg/bin:$PATH
WORKDIR /w
ENTRYPOINT ["gpg"]
