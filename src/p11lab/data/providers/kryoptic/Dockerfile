# SPDX-License-Identifier: Apache-2.0
# Non-FIPS, default features plus pqc. All dependency bytes are hash-verified;
# Cargo uses a reconstructed directory source with no index/network resolution.
ARG BASE_IMAGE=docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c
FROM docker.io/library/rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS rust
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
COPY --from=rust /usr/local/rustup/ /usr/local/rustup/
COPY --from=rust /usr/local/cargo/bin/ /usr/local/cargo/bin/
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/build/cargo PATH=/usr/local/cargo/bin:$PATH
RUN rustc -vV > /tmp/rustc.txt && cargo -vV > /tmp/cargo.txt
# The reference tag was verified once before authoring this recipe. Only the
# pinned commit URL and its archive hash are used by the build.
RUN curl --fail --location --silent --show-error \
      https://codeload.github.com/openssl/openssl/tar.gz/f089acdf4bc7ba94a79f4bf6eb7362c3e7d14aa9 -o /tmp/openssl.tar.gz \
 && echo 'fbcf7a1f7b771ec8d4dbb74d9a9e5f727b71195e61fd52b2b879b75d2043687d  /tmp/openssl.tar.gz' | sha256sum -c - \
 && mkdir -p /build/openssl \
 && tar -xf /tmp/openssl.tar.gz -C /build/openssl --strip-components=1 \
 && cd /build/openssl && ./Configure --prefix=/opt/openssl --libdir=lib shared no-docs no-tests \
 && make -j2 && make install_sw
# Dynamic means the libraries selected by pkg-config. Here /opt/openssl is
# selected explicitly, and the same .so closure is shipped in the runtime.
ENV PKG_CONFIG_PATH=/opt/openssl/lib/pkgconfig OSSL_BINDGEN_CLANG_ARGS=-I/opt/openssl/include
COPY source.tar source.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/kryoptic && tar -xf source.tar -C /build/kryoptic
COPY Cargo.lock /build/kryoptic/Cargo.lock
COPY crates.json /tmp/crates.json
COPY freeze-crates.py /tmp/freeze-crates.py
RUN python3 /tmp/freeze-crates.py
RUN --network=none cd /build/kryoptic \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo build --locked --offline --release --features pqc --jobs 2 \
 && test -f target/release/libkryoptic_pkcs11.so
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -isystem /build/kryoptic/src/pkcs11/headers/3.2 /tmp/provision.c -ldl -o /tmp/p11lab-kryoptic
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/kryoptic \
      /runtime/usr/share/licenses/openssl /runtime/opt/openssl/lib \
 && cp /build/kryoptic/target/release/libkryoptic_pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libkryoptic_pkcs11.so \
 && cp /tmp/p11lab-kryoptic /runtime/usr/local/bin/ \
 && cp -a /opt/openssl/lib/libcrypto.so* /runtime/opt/openssl/lib/ \
 && cp /build/openssl/LICENSE.txt /runtime/usr/share/licenses/openssl/ \
 && cp /build/kryoptic/LICENSE.txt /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/kryoptic/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /build/kryoptic/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && LD_LIBRARY_PATH=/opt/openssl/lib /opt/openssl/bin/openssl version -a > /runtime/usr/share/p11lab/build/openssl.txt \
 && printf '%s\n' 'cargo build --locked --offline --release --features pqc --jobs 2' \
      'default_features=true' 'fips=false' 'libcrypto=/opt/openssl/lib/libcrypto.so.4' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && mkdir -p /runtime/usr/share/licenses/kryoptic/crates \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/kryoptic/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && LD_LIBRARY_PATH=/opt/openssl/lib ldd /runtime/usr/local/lib/p11lab/libkryoptic_pkcs11.so /runtime/usr/local/bin/p11lab-kryoptic > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN printf '%s\n' '/opt/openssl/lib' > /etc/ld.so.conf.d/p11lab-openssl.conf \
 && ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-kryoptic /usr/local/lib/p11lab/libkryoptic_pkcs11.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libkryoptic_pkcs11.so /usr/local/bin/p11lab-kryoptic > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/opt/openssl/lib/libcrypto.so.4' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
