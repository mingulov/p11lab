# SPDX-License-Identifier: Apache-2.0
# Local-only process-local port. corepkcs11_adapter.c is audit input, never built.
ARG BASE_IMAGE=docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c
FROM ${BASE_IMAGE} AS builder
COPY snapshot.sources /etc/apt/sources.list.d/p11lab.sources
COPY builder-requested.txt /tmp/builder-requested.txt
COPY base-packages.tsv builder-packages.tsv /tmp/
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /tmp/actual-base.tsv \
 && diff -u /tmp/base-packages.tsv /tmp/actual-base.tsv \
 && apt-get -o APT::Update::Error-Mode=any update \
 && xargs apt-get install -y --no-install-recommends < /tmp/builder-requested.txt \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /tmp/actual-builder.tsv \
 && diff -u /tmp/builder-packages.tsv /tmp/actual-builder.tsv
COPY source.tar source.sha256 /tmp/
# Shared locked-source acquisition has already applied both ordered patches.
# Every failed patch is fatal there; verify the port/config result here too.
RUN cd /tmp && sha256sum -c source.sha256 \
 && mkdir -p /build/corePKCS11 && tar -xf source.tar -C /build/corePKCS11
COPY corepkcs11_malloc.c corepkcs11_pal_generic.c core_pkcs11_config.h /build/
RUN cmp /build/core_pkcs11_config.h /build/corePKCS11/test/include/core_pkcs11_config.h \
 && grep -Fq '"/build/corepkcs11_pal_generic.c"' /build/corePKCS11/pkcsFilePaths.cmake \
 && grep -Fq '/build/corepkcs11_malloc.c' /build/corePKCS11/CMakeLists.txt
# These are the entire FetchContent input closure, including the Mbed TLS
# framework and generated files in the official release archive. Download and
# hash them before the offline configure/build step; no tag/branch resolution.
RUN curl --fail --location --silent --show-error \
      https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2 -o /tmp/mbedtls.tar.bz2 \
 && echo '4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8  /tmp/mbedtls.tar.bz2' | sha256sum -c - \
 && curl --fail --location --silent --show-error \
      https://codeload.github.com/oasis-tcs/pkcs11/tar.gz/478bfc5077901865993e3a193777c1a9f6516cdf -o /tmp/pkcs11.tar.gz \
 && echo '5d6c66a84c610ff12348f94a96e90a3627b199e97dc92a4646d3786d1caa2423  /tmp/pkcs11.tar.gz' | sha256sum -c - \
 && mkdir -p /build/mbedtls /build/pkcs11 \
 && tar -xf /tmp/mbedtls.tar.bz2 -C /build/mbedtls --strip-components=1 \
 && tar -xf /tmp/pkcs11.tar.gz -C /build/pkcs11 --strip-components=1
RUN --network=none cmake -S /build/corePKCS11 -B /build/corePKCS11-build -GNinja \
      -DSTANDALONE_TEST_BUILD_UNIX=ON -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release \
      -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON \
      -DFETCHCONTENT_SOURCE_DIR_PKCS11=/build/pkcs11 \
      -DFETCHCONTENT_SOURCE_DIR_MBEDTLS=/build/mbedtls \
      -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DGEN_FILES=OFF \
 && cmake --build /build/corePKCS11-build --target core_pkcs -j2
COPY probe.c /tmp/probe.c
RUN --network=none cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -isystem /build/pkcs11/published/2-40-errata-1 /tmp/probe.c -ldl -o /tmp/p11lab-corepkcs11
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/corepkcs11 \
      /runtime/usr/share/licenses/mbedtls /runtime/usr/share/licenses/oasis-pkcs11 \
 && cp /build/corePKCS11-build/libcore_pkcs.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libcore_pkcs.so \
 && cp /tmp/p11lab-corepkcs11 /runtime/usr/local/bin/ \
 && cp /build/corePKCS11/LICENSE /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/corepkcs11/ \
 && cp /build/mbedtls/LICENSE /runtime/usr/share/licenses/mbedtls/ \
 && cp /build/pkcs11/LICENSE.md /build/pkcs11/published/2-40-errata-1/pkcs11*.h /runtime/usr/share/licenses/oasis-pkcs11/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && cmake --version > /runtime/usr/share/p11lab/build/cmake.txt \
 && ninja --version > /runtime/usr/share/p11lab/build/ninja.txt \
 && cp /build/corePKCS11-build/CMakeCache.txt /runtime/usr/share/p11lab/build/ \
 && printf '%s\n' 'corePKCS11 raw function table; generic process-local PAL' \
      'corepkcs11_adapter.c is NOT compiled or installed' \
      'Mbed TLS 3.6.5 static libraries incorporated in libcore_pkcs.so' \
      'cmake --build /build/corePKCS11-build --target core_pkcs -j2' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && ldd /runtime/usr/local/lib/p11lab/libcore_pkcs.so /runtime/usr/local/bin/p11lab-corepkcs11 > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-corepkcs11 /usr/local/lib/p11lab/libcore_pkcs.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libcore_pkcs.so /usr/local/bin/p11lab-corepkcs11 > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
