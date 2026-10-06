# SPDX-License-Identifier: Apache-2.0
# Native certificate/file signer. No test keys, checker, compiler or datasets ship.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/p2c && tar -xf source.tar -C /build/p2c
# Upstream defaults COVERAGE to ON. OFF removes test instrumentation and .gcda
# writes; it does not change the PKCS#11 function table or signing command.
RUN --network=none cmake -S /build/p2c -B /build/p2c/build -DCMAKE_BUILD_TYPE=Release -DCOVERAGE=OFF \
 && cmake --build /build/p2c/build -j2
COPY provision.c /tmp/provision.c
# This helper only checks real native readiness. It has no provisioning/PIN API.
RUN --network=none cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -o /tmp/p11lab-p2c-health
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY sign-command.sh /tmp/sign-command.sh
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/libexec/p11lab /runtime/usr/local/bin /runtime/usr/bin /runtime/etc/ssl /runtime/usr/lib/ssl \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/pkcs11-to-cmd \
 && cp /build/p2c/build/libpkcs11-to-cmd.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/p2c/tests/cmds/sign-cmd-pkeyutl.sh /runtime/usr/local/libexec/p11lab/pkcs11-to-cmd-sign \
 && echo '966f6fba1869f40f9249b5b6ab39bb98a33d9f6d8a97f9faddde8e31a43929eb  /runtime/usr/local/libexec/p11lab/pkcs11-to-cmd-sign' | sha256sum -c - \
 && cp /tmp/sign-command.sh /runtime/usr/local/bin/p11lab-p2c-sign \
 && cp /tmp/p11lab-p2c-health /runtime/usr/local/bin/ \
 && cp /usr/bin/openssl /usr/bin/xxd /runtime/usr/bin/ \
 && cp /etc/ssl/openssl.cnf /runtime/etc/ssl/openssl.cnf \
 && ln -s ../../../etc/ssl/openssl.cnf /runtime/usr/lib/ssl/openssl.cnf \
 && cp /build/p2c/LICENSE /build/p2c/REUSE.toml /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/pkcs11-to-cmd/ \
 && cp /usr/share/doc/openssl/copyright /runtime/usr/share/licenses/pkcs11-to-cmd/openssl-copyright \
 && cp /usr/share/doc/xxd/copyright /runtime/usr/share/licenses/pkcs11-to-cmd/xxd-copyright \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/pkcs11-to-cmd/p11-kit-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/pkcs11-to-cmd/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cp /build/p2c/build/CMakeCache.txt /build/p2c/build/compile_commands.json /runtime/usr/share/p11lab/build/ \
 && { cc --version; c++ --version; cmake --version; make --version; pkg-config --modversion openssl p11-kit-1; } > /runtime/usr/share/p11lab/build/toolchain.txt \
 && dpkg-query -W -f='${Package} ${Version} ${source:Package} ${source:Version}\n' libssl3t64 libssl-dev openssl xxd > /runtime/usr/share/p11lab/build/system-crypto-and-tools.txt \
 && sha256sum /usr/bin/openssl /usr/bin/xxd /etc/ssl/openssl.cnf > /runtime/usr/share/p11lab/build/bundled-tools.sha256 \
 && printf '%s\n' 'cmake -DCMAKE_BUILD_TYPE=Release -DCOVERAGE=OFF; cmake --build -j2' \
      'patches=none' 'auth=none' 'slot_0=RSA-2048; slot_1=empty; slot_2=P-256' \
      'key_generation=runtime-init-only' 'openssl_linkage=system-libcrypto.so.3' \
      'bundled_debian_binaries=openssl,xxd; registered_runtime_packages=base-only' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN find /usr/local /usr/share/p11lab /usr/share/licenses -type d -exec chmod 755 {} + \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-p2c-health /usr/local/bin/p11lab-p2c-sign /usr/local/libexec/p11lab/pkcs11-to-cmd-sign /usr/local/lib/p11lab/libpkcs11-to-cmd.so /usr/bin/openssl /usr/bin/xxd \
 && mkdir -p /var/lib/p11lab /run/p11lab && chmod 700 /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && sha256sum -c /usr/share/p11lab/build/bundled-tools.sha256 \
 && ldd /usr/local/lib/p11lab/libpkcs11-to-cmd.so /usr/local/bin/p11lab-p2c-health /usr/bin/openssl /usr/bin/xxd > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
