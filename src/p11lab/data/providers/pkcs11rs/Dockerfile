# SPDX-License-Identifier: Apache-2.0
# Software slots only. No upstream manifest changes or default features.
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
# Cargo reads the virtual-core manifests during resolution even with the
# features disabled. Their code is not compiled. No USB/display repo is needed.
COPY source.tar source.sha256 dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 dependency-2.tar dependency-2.sha256 dependency-3.tar dependency-3.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 dependency-0.sha256 dependency-1.sha256 dependency-2.sha256 dependency-3.sha256 \
 && mkdir -p /build/pkcs11rs /build/software-key-core /build/virtual-yubikey /build/virtual-yubihsm /build/signatures \
 && tar -xf source.tar -C /build/pkcs11rs \
 && tar -xf dependency-0.tar -C /build/software-key-core \
 && tar -xf dependency-1.tar -C /build/virtual-yubikey \
 && tar -xf dependency-2.tar -C /build/virtual-yubihsm \
 && tar -xf dependency-3.tar -C /build/signatures
COPY Cargo.lock crates.json freeze-crates.py /tmp/
RUN cmp /tmp/Cargo.lock /build/pkcs11rs/Cargo.lock && python3 /tmp/freeze-crates.py
RUN --network=none cd /build/pkcs11rs \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo tree --locked --offline -p pkcs11rs --no-default-features -e normal,build > /tmp/cargo-tree.txt \
 && ! grep -E 'virtual-yubi|usb-gadget|display-backends|hidapi|pcsc|pkcs11rs-local-hardware' /tmp/cargo-tree.txt \
 && cargo build --locked --offline --release -p pkcs11rs --no-default-features --jobs 2 \
 && test -f target/release/libpkcs11rs.so
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -isystem /build/pkcs11rs /tmp/provision.c -ldl -o /tmp/p11lab-pkcs11rs
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/usr/share/p11lab/build \
      /runtime/usr/share/licenses/pkcs11rs/crates /runtime/usr/share/licenses/pkcs11rs/headers \
 && cp /build/pkcs11rs/target/release/libpkcs11rs.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libpkcs11rs.so \
 && cp /tmp/p11lab-pkcs11rs /runtime/usr/local/bin/ \
 && cp /build/pkcs11rs/pkcs11*.h /runtime/usr/share/licenses/pkcs11rs/headers/ \
 && cp /build/pkcs11rs/LICENSE-* /build/pkcs11rs/THIRD_PARTY_NOTICES.md /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/pkcs11rs/ \
 && for repository in software-key-core virtual-yubikey virtual-yubihsm; do \
      mkdir -p "/runtime/usr/share/licenses/pkcs11rs/$repository"; \
      cp /build/"$repository"/LICENSE-* "/runtime/usr/share/licenses/pkcs11rs/$repository/"; \
      if [ -f /build/"$repository"/THIRD_PARTY_NOTICES.md ]; then cp /build/"$repository"/THIRD_PARTY_NOTICES.md "/runtime/usr/share/licenses/pkcs11rs/$repository/"; fi; \
    done \
 && mkdir -p /runtime/usr/share/licenses/pkcs11rs/signatures/ml-dsa \
 && cp /build/signatures/ml-dsa/LICENSE-* /runtime/usr/share/licenses/pkcs11rs/signatures/ml-dsa/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /tmp/cargo-tree.txt /build/pkcs11rs/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build --locked --offline --release -p pkcs11rs --no-default-features --jobs 2' \
      'default_features=false' 'hardware_discovery=false' 'patches=[]' > /runtime/usr/share/p11lab/build/options.txt \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/pkcs11rs/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && ldd /runtime/usr/local/lib/p11lab/libpkcs11rs.so /runtime/usr/local/bin/p11lab-pkcs11rs > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-pkcs11rs /usr/local/lib/p11lab/libpkcs11rs.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libpkcs11rs.so /usr/local/bin/p11lab-pkcs11rs > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
