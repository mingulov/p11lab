# SPDX-License-Identifier: Apache-2.0
# Optional provider-plus-daemon derivative. The basic provider is unchanged.
# Portable offline context contract:
# - proxy-bins/pkcs11-proxy-ng, proxy-bins/pkcs11-proxy-ng-cli,
#   proxy-bins/proxy-entrypoint.sh: exact pinned-build binaries and adapter;
# - proxy-bins.sha256: exact file hashes, sealed by the required build arg;
# - proxy-notices/: pinned-source license texts recorded at build time.
# Acquire these bytes by their recorded origins and verify their seals before
# building; no development workspace path, network resolver or cache export.
# Distribution still requires separate actual-content source/notice admission.
ARG PROVIDER_IMAGE
FROM ${PROVIDER_IMAGE}
ARG PROXY_BINS_MANIFEST_SHA256
ARG PROXY_SOURCE_REVISION
ARG PROXY_CARGO_LOCK_SHA256
COPY proxy-bins/ /tmp/proxy-bins/
COPY proxy-bins.sha256 /tmp/proxy-bins.sha256
COPY proxy-notices/ /usr/share/p11lab/proxy/notices/
RUN test -n "$PROXY_BINS_MANIFEST_SHA256" \
 && test -n "$PROXY_SOURCE_REVISION" \
 && test -n "$PROXY_CARGO_LOCK_SHA256" \
 && echo "$PROXY_BINS_MANIFEST_SHA256  /tmp/proxy-bins.sha256" | sha256sum -c - \
 && cd /tmp/proxy-bins && sha256sum -c /tmp/proxy-bins.sha256 \
 && cp /tmp/proxy-bins/pkcs11-proxy-ng /tmp/proxy-bins/pkcs11-proxy-ng-cli /usr/local/bin/ \
 && cp /tmp/proxy-bins/proxy-entrypoint.sh /usr/local/bin/p11lab-proxy \
 && chmod 755 /usr/local/bin/pkcs11-proxy-ng /usr/local/bin/pkcs11-proxy-ng-cli /usr/local/bin/p11lab-proxy \
 && mkdir -p /usr/share/p11lab/proxy \
 && cp /tmp/proxy-bins.sha256 /usr/share/p11lab/proxy/proxy-bins.sha256 \
 && printf '%s\n' "{\"schema_version\":1,\"source_revision\":\"$PROXY_SOURCE_REVISION\",\"cargo_lock_sha256\":\"$PROXY_CARGO_LOCK_SHA256\",\"binaries\":{\"pkcs11-proxy-ng\":\"$(sha256sum /usr/local/bin/pkcs11-proxy-ng | cut -d' ' -f1)\",\"pkcs11-proxy-ng-cli\":\"$(sha256sum /usr/local/bin/pkcs11-proxy-ng-cli | cut -d' ' -f1)\",\"proxy-entrypoint.sh\":\"$(sha256sum /usr/local/bin/p11lab-proxy | cut -d' ' -f1)\"}}" > /usr/share/p11lab/proxy/build.json \
 && chmod -R a+rX /usr/share/p11lab/proxy \
 && ldd /usr/local/bin/pkcs11-proxy-ng /usr/local/bin/pkcs11-proxy-ng-cli > /usr/share/p11lab/proxy/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/proxy/runtime-linked-dependencies.txt \
 && rm -rf /tmp/proxy-bins /tmp/proxy-bins.sha256
ENTRYPOINT ["/usr/local/bin/p11lab-proxy"]
CMD ["describe"]
