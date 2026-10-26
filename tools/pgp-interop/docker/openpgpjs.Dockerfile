# sop-openpgpjs 2.2.0 on OpenPGP.js 6.3.1 with post-quantum support (the 'psk' branch of twiss/openpgpjs), and a custom
# 'rfc9980' key profile: v6 keys with ML-DSA-65+Ed25519 and ML-KEM-768+X25519. Other profiles: performance, security.
FROM node:22-bookworm
WORKDIR /scratch
RUN git clone https://github.com/openpgpjs/sop-openpgpjs.git \
    && cd sop-openpgpjs \
    && git checkout 34e5c625c57bae37b7b3255742dd4dc402629df4 \
    && npm install
RUN git clone --branch psk https://github.com/twiss/openpgpjs.git \
    && cd openpgpjs \
    && git checkout 42ec54085fb3fbcb417f9b7a4c482ba3ecbf7af8 \
    && sed -i '/@web/d' ./package.json \
    && npm install
ENV OPENPGPJS_PATH=/scratch/openpgpjs
ENV OPENPGPJS_CUSTOM_PROFILES='{ "generate-key": { "rfc9980": { "description": "generate v6 PQC keys using ML-DSA-65+Ed25519/ML-KEM-768+X25519", "options": { "type": "pqc", "config": { "v6Keys": true } } } } }'
ENTRYPOINT ["/scratch/sop-openpgpjs/sopenpgpjs"]
