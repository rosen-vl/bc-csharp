# RNP (the OpenPGP library of Thunderbird) at a pinned commit of main, built with its experimental support for the
# version 6 formats of RFC 9580 (ENABLE_CRYPTO_REFRESH) and the algorithms of RFC 9980 (ENABLE_PQC), on Botan 3.13
# from Debian. RNP has no Stateless OpenPGP CLI; scripts/run-rnp.sh drives the rnp and rnpkeys tools.
FROM debian:forky-slim AS build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential cmake pkg-config \
    libbotan-3-dev libjson-c-dev libsexpp-dev zlib1g-dev libbz2-dev > /dev/null
ADD --checksum=sha256:6c331ffe9fd4b951a03e26ec4336bc3b4103ce38e51332c20197696f249971ba \
    https://github.com/rnpgp/rnp/archive/96f35e38d4f8303317392cd213b649f37d753839.tar.gz /src/rnp.tar.gz
RUN cd /src && tar xzf rnp.tar.gz && mv rnp-96f35e38d4f8303317392cd213b649f37d753839 rnp \
    && cmake -S rnp -B build -DCMAKE_BUILD_TYPE=Release -DCRYPTO_BACKEND=botan3 -DENABLE_PQC=ON \
        -DENABLE_CRYPTO_REFRESH=ON -DSYSTEM_LIBSEXPP=ON -DBUILD_TESTING=OFF -DENABLE_DOC=OFF \
        -DCMAKE_INSTALL_PREFIX=/opt/rnp > /dev/null \
    && cmake --build build -j"$(nproc)" > /dev/null && cmake --install build > /dev/null

FROM debian:forky-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libbotan-3-13 libjson-c5 libsexpp0 zlib1g \
    libbz2-1.0 > /dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/rnp /opt/rnp
ENV PATH=/opt/rnp/bin:$PATH LD_LIBRARY_PATH=/opt/rnp/lib
WORKDIR /w
