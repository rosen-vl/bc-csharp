# syntax=docker/dockerfile:1
#
# The OpenPGP interoperability test suite of the Sequoia project (GPL-3.0, cloned by scripts/run-oits.sh into
# results/oits-src, never committed here) with a small set of SOP drivers: bcsop (published self-contained for
# linux-x64 into results/oits-bcsop), Sequoia's sqop with post-quantum support, rsop, gosop, sop-openpgpjs and
# pgpainless-cli (PGPainless on Bouncy Castle Java). The peers come from the images that the interop matrix uses.
#
# Build context: tools/pgp-interop/results, with this file given by -f. See scripts/run-oits.sh.

FROM debian:forky-slim AS base
RUN apt update -y -qq && apt upgrade -y -qq

FROM base AS build-base
RUN apt install -y -qq --no-install-recommends git build-essential pkg-config ca-certificates rustc cargo clang \
    nettle-dev libssl-dev libsqlite3-dev capnproto

## sqop with post-quantum support
FROM build-base AS build-sqop-pqc
RUN cargo install --no-default-features --features=cli,sequoia-openpgp/compression,sequoia-openpgp/crypto-openssl \
    --root=/tmp/root --git https://gitlab.com/sequoia-pgp/sequoia-sop --locked

## the test suite
FROM build-base AS build-suite
WORKDIR /scratch
COPY oits-src/.cargo /scratch/.cargo
COPY oits-src/.git /scratch/.git
COPY oits-src/data /scratch/data
COPY oits-src/src /scratch/src
COPY oits-src/build.rs oits-src/Cargo.toml oits-src/Cargo.lock /scratch/
COPY oits-src/templates /test-suite/templates
RUN cargo build

FROM base
RUN apt install -y -qq --no-install-recommends libnettle8 libssl3 libsqlite3-0 nodejs util-linux libstdc++6 zlib1g \
    ca-certificates

RUN mkdir -p /sops /test-suite/output
COPY --from=build-sqop-pqc /tmp/root/bin/sqop /sops/sqop-pqc
COPY --from=bc-interop-rsop:0.12.0 /usr/local/cargo/bin/rsop /sops/rsop
COPY --from=bc-interop-gosop:1.1.0 /usr/local/bin/gosop /sops/gosop-pqc
COPY --from=bc-interop-ojs:2.2.0 /scratch/sop-openpgpjs /sops/sop-openpgpjs
COPY --from=bc-interop-ojs:2.2.0 /scratch/openpgpjs /sops/openpgpjs-psk
COPY --from=bc-interop-pgpainless:2.0.4 /opt/java/openjdk /opt/java/openjdk
COPY --from=bc-interop-pgpainless:2.0.4 /opt/pgpainless-cli.jar /opt/pgpainless-cli.jar
RUN printf '#!/bin/sh\nexec /opt/java/openjdk/bin/java -jar /opt/pgpainless-cli.jar "$@"\n' > /sops/pgpainless-cli \
    && chmod +x /sops/pgpainless-cli
COPY oits-bcsop /opt/bcsop
RUN printf '#!/bin/sh\nexec /opt/bcsop/bcsop "$@"\n' > /sops/bcsop && chmod +x /sops/bcsop /opt/bcsop/bcsop

# the suite finds the sqop that it builds for its own use through a path in /scratch/target
COPY --from=build-suite /scratch /scratch
RUN ln -s /scratch/target/debug/openpgp-interoperability-test-suite /usr/local/bin/oits
COPY --from=build-suite /test-suite/templates /test-suite/templates
COPY oits-config.json /test-suite/config.json

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENV RUST_MIN_STACK=20971520
WORKDIR /test-suite
ENTRYPOINT ["/usr/local/bin/oits"]
CMD ["--json-out=output/results.json", "--html-out=output/results.html", "--html-out-dir=output"]
