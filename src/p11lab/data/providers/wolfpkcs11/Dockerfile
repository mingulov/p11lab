# SPDX-License-Identifier: Apache-2.0
# GPLv3 software-token candidate; no baked token, PINs, PQC, TPM or sanitizers.
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
COPY source.tar source.sha256 dependency-0.tar dependency-0.sha256 /tmp/
# The shared resolver seals wolfPKCS11 and its channel-specific wolfSSL pairing
# separately, checks the source roster, and retains both original archives.
RUN cd /tmp && sha256sum -c source.sha256 dependency-0.sha256 \
 && mkdir -p /build/wolfpkcs11 /build/wolfssl \
 && tar -xf source.tar -C /build/wolfpkcs11 \
 && tar -xf dependency-0.tar -C /build/wolfssl
# Keep every software-token crypto option from the reference. wolfSSL's
# SHA-3 selection can enable ML-KEM by default; explicitly exclude unused PQC.
RUN --network=none cd /build/wolfssl && ./autogen.sh \
 && ./configure --prefix=/opt/wolfssl --enable-shared --disable-static \
      --enable-aescfb --enable-aesccm --enable-aesctr --enable-aescts \
      --enable-aesecb --enable-aeskeywrap --enable-cmac --enable-cryptocb \
      --enable-hkdf --enable-keygen --enable-pwdbased --enable-rsapss \
      --enable-scrypt --enable-sha3 --disable-mldsa --disable-mlkem \
      C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP" \
 && make -j2 && make install
ENV PKG_CONFIG_PATH=/opt/wolfssl/lib/pkgconfig LD_LIBRARY_PATH=/opt/wolfssl/lib
# This upstream Autotools build does not use pkg-config to locate wolfSSL.
# Explicit paths select the same paired library in compile, link and runtime.
RUN --network=none cd /build/wolfpkcs11 && ./autogen.sh \
 && CPPFLAGS=-I/opt/wolfssl/include LDFLAGS=-L/opt/wolfssl/lib \
      ./configure --prefix=/opt/wolfpkcs11 --enable-shared --disable-static \
      --enable-aeskeywrap --enable-aesctr --enable-aesccm --enable-aesecb \
      --enable-aescts --enable-aescmac --enable-pbkdf2 \
      --disable-pkcs11v32 --disable-mldsa --disable-mlkem \
 && make -j2 && make install
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/build/wolfpkcs11 /tmp/provision.c -ldl -o /tmp/p11lab-wolfpkcs11
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/opt/wolfssl/lib /runtime/usr/share/p11lab/build \
      /runtime/usr/share/licenses/wolfpkcs11 /runtime/usr/share/licenses/wolfssl \
 && cp -L /opt/wolfpkcs11/lib/libwolfpkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp -a /opt/wolfssl/lib/libwolfssl.so* /runtime/opt/wolfssl/lib/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libwolfpkcs11.so /runtime/opt/wolfssl/lib/libwolfssl.so.*.*.* \
 && cp /tmp/p11lab-wolfpkcs11 /runtime/usr/local/bin/ \
 && cp /build/wolfpkcs11/LICENSE /build/wolfpkcs11/gpl-3.0.txt /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/wolfpkcs11/ \
 && cp /build/wolfssl/COPYING /build/wolfssl/LICENSING /runtime/usr/share/licenses/wolfssl/ \
 && python3 -c 'from pathlib import Path; import re; roots={"wolfpkcs11":Path("/build/wolfpkcs11"),"wolfssl":Path("/build/wolfssl")}; [(Path("/runtime/usr/share/licenses")/name/"headers"/p.relative_to(root)).with_suffix(p.suffix+".notice").parent.mkdir(parents=True,exist_ok=True) or (Path("/runtime/usr/share/licenses")/name/"headers"/p.relative_to(root)).with_suffix(p.suffix+".notice").write_bytes(b"\n".join(re.findall(rb"/\*.*?\*/",p.read_bytes().split(b"#include",1)[0],re.S))) for name,root in roots.items() for p in sorted(root.rglob("*")) if p.suffix in (".c",".h",".S",".asm") and p.is_file()]' \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && make --version > /runtime/usr/share/p11lab/build/make.txt \
 && autoconf --version > /runtime/usr/share/p11lab/build/autoconf.txt \
 && automake --version > /runtime/usr/share/p11lab/build/automake.txt \
 && cp /build/wolfssl/config.log /runtime/usr/share/p11lab/build/wolfssl-config.log \
 && cp /build/wolfssl/wolfssl/options.h /runtime/usr/share/p11lab/build/wolfssl-options.h \
 && cp /build/wolfpkcs11/config.log /runtime/usr/share/p11lab/build/wolfpkcs11-config.log \
 && cp /build/wolfpkcs11/wolfpkcs11/options.h /runtime/usr/share/p11lab/build/wolfpkcs11-options.h \
 && ldd /runtime/usr/local/lib/p11lab/libwolfpkcs11.so /runtime/usr/local/bin/p11lab-wolfpkcs11 > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN printf '%s\n' '/opt/wolfssl/lib' > /etc/ld.so.conf.d/p11lab-wolfssl.conf \
 && ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-wolfpkcs11 /usr/local/lib/p11lab/libwolfpkcs11.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libwolfpkcs11.so /usr/local/bin/p11lab-wolfpkcs11 > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/opt/wolfssl/lib/libwolfssl.so' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
