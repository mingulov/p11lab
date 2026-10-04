# SPDX-License-Identifier: Apache-2.0
# Siguldry signing stack: module plus bridge/server/signer/client binaries.
# All dependency bytes are hash-verified; Cargo uses a reconstructed directory
# source with no index/network resolution. OpenSSL and SQLite link the frozen
# Debian system libraries that are already present in the base image.
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
COPY source.tar source.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/siguldry && tar -xf source.tar -C /build/siguldry \
 && cp /build/siguldry/.cargo/config.toml /tmp/upstream-cargo-config.toml
COPY Cargo.lock /tmp/channel-Cargo.lock
COPY crates.json /tmp/crates.json
COPY freeze-crates.py /tmp/freeze-crates.py
RUN cmp /tmp/channel-Cargo.lock /build/siguldry/Cargo.lock && python3 /tmp/freeze-crates.py
RUN --network=none cd /build/siguldry \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo tree --locked --offline -e normal,build > /tmp/cargo-tree.txt \
 && cargo build --locked --offline --release --package siguldry --package siguldry-pkcs11 --jobs 2 \
 && test -f target/release/libsiguldry_pkcs11.so \
 && test -f target/release/siguldry-bridge \
 && test -f target/release/siguldry-client \
 && test -f target/release/siguldry-server \
 && test -f target/release/siguldry-signer
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 /tmp/provision.c -lcrypto -ldl -o /tmp/p11lab-siguldry
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/siguldry \
 && cp /build/siguldry/target/release/libsiguldry_pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/siguldry/target/release/siguldry-bridge /build/siguldry/target/release/siguldry-client \
      /build/siguldry/target/release/siguldry-server /build/siguldry/target/release/siguldry-signer \
      /runtime/usr/local/bin/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libsiguldry_pkcs11.so \
      /runtime/usr/local/bin/siguldry-bridge /runtime/usr/local/bin/siguldry-client \
      /runtime/usr/local/bin/siguldry-server /runtime/usr/local/bin/siguldry-signer \
 && cp /tmp/p11lab-siguldry /runtime/usr/local/bin/ \
 && cp /build/siguldry/siguldry/LICENSE /runtime/usr/share/licenses/siguldry/LICENSE.siguldry \
 && cp /build/siguldry/siguldry-pkcs11/LICENSE /runtime/usr/share/licenses/siguldry/LICENSE.siguldry-pkcs11 \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/siguldry/ \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/siguldry/build-only-pkcs11.h \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /tmp/cargo-tree.txt /build/siguldry/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && cp /tmp/upstream-cargo-config.toml /runtime/usr/share/p11lab/build/upstream-cargo-config.toml \
 && ! grep -q 'replace-with' /runtime/usr/share/p11lab/build/upstream-cargo-config.toml \
 && ! grep -q '\[source' /runtime/usr/share/p11lab/build/upstream-cargo-config.toml \
 && cp /build/siguldry/.cargo/config.toml /runtime/usr/share/p11lab/build/effective-cargo-config.toml \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build --locked --offline --release --package siguldry --package siguldry-pkcs11 --jobs 2' \
      'openssl=system-libssl-dev' 'sqlite=system-libsqlite3-dev(sqlx-sqlite-unbundled)' \
      'libcrypto=/lib/x86_64-linux-gnu/libcrypto.so.3' 'libssl=/lib/x86_64-linux-gnu/libssl.so.3' \
      'libsqlite3=/lib/x86_64-linux-gnu/libsqlite3.so.0' 'patches=[]' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && mkdir -p /runtime/usr/share/licenses/siguldry/crates \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/siguldry/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && ldd /runtime/usr/local/lib/p11lab/libsiguldry_pkcs11.so /runtime/usr/local/bin/p11lab-siguldry \
      /runtime/usr/local/bin/siguldry-bridge /runtime/usr/local/bin/siguldry-client \
      /runtime/usr/local/bin/siguldry-server /runtime/usr/local/bin/siguldry-signer > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-siguldry \
      /usr/local/bin/siguldry-bridge /usr/local/bin/siguldry-client \
      /usr/local/bin/siguldry-server /usr/local/bin/siguldry-signer \
      /usr/local/lib/p11lab/libsiguldry_pkcs11.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libsiguldry_pkcs11.so /usr/local/bin/p11lab-siguldry \
      /usr/local/bin/siguldry-bridge /usr/local/bin/siguldry-client \
      /usr/local/bin/siguldry-server /usr/local/bin/siguldry-signer > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libssl.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libsqlite3.so.0' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
