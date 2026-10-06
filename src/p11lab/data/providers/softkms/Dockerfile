# SPDX-License-Identifier: Apache-2.0
# softKMS daemon, CLI and PKCS#11 module built from source with a sealed
# Cargo closure (487 registry archives plus one sealed Git checkout as a
# single offline directory source) and a sealed Falcon C checkout. The
# module links the frozen Debian base libssl/libcrypto; the daemon also
# uses base libnettle/libhogweed/libgmp. Six ordered P11Lab patches repair
# the PKCS#11 ABI/finalization/flag defects and add file-based provisioning
# secrets; PKCS#11 semantics are otherwise preserved.
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
RUN rustc -vV > /tmp/rustc.txt && cargo -vV > /tmp/cargo.txt && protoc --version > /tmp/protoc.txt
COPY source.tar source.sha256 dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 dependency-0.sha256 dependency-1.sha256 \
 && mkdir -p /build/softkms /build/xhd/ed25519-bip32 \
 && tar -xf source.tar -C /build/softkms \
 && mkdir -p /build/softkms/libs/falcon && tar -xf dependency-0.tar -C /build/softkms/libs/falcon \
 && tar -xf dependency-1.tar -C /build/xhd/ed25519-bip32
RUN cd /build/softkms \
 && test ! -e .cargo/config.toml \
 && test -f libs/falcon/falcon.c && test -f libs/falcon/falcon.h \
 && grep -q 'LICENSE BEGIN' libs/falcon/falcon.h && grep -q 'LICENSE END' libs/falcon/falcon.h \
 && test -f Cargo.toml && test -f cli/src/main.rs \
 && grep -q 'P11Lab: field order follows the specification' src/pkcs11/mod.rs \
 && grep -q 'CKO_PRIVATE_KEY.to_le_bytes' src/pkcs11/mod.rs \
 && grep -q 'P11Lab: finalization invalidates sessions' src/pkcs11/mod.rs \
 && grep -q 'P11Lab: fill the info struct' src/pkcs11/mod.rs \
 && grep -q 'P11Lab: standard PKCS#11 v2.40 values' src/pkcs11/mod.rs \
 && grep -q 'passphrase_file' cli/src/main.rs \
 && grep -q 'token_file' cli/src/main.rs
COPY Cargo.lock /build/softkms/Cargo.lock
COPY crates.json /tmp/crates.json
COPY freeze-crates.py /tmp/freeze-crates.py
RUN python3 /tmp/freeze-crates.py
RUN --network=none cd /build/softkms \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo build --locked --offline --release --lib --bin softkms-daemon --bin softkms --jobs 2 \
 && test -f target/release/libsoftkms.so \
 && test -f target/release/softkms-daemon \
 && test -f target/release/softkms
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -o /tmp/p11lab-softkms
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/softkms \
 && cp /build/softkms/target/release/libsoftkms.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/softkms/target/release/softkms-daemon /build/softkms/target/release/softkms /runtime/usr/local/bin/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libsoftkms.so \
      /runtime/usr/local/bin/softkms-daemon /runtime/usr/local/bin/softkms \
 && cp /tmp/p11lab-softkms /runtime/usr/local/bin/ \
 && cp /build/softkms/LICENSE /runtime/usr/share/licenses/softkms/LICENSE.softkms-AGPL-3.0 \
 && cp /build/softkms/libs/falcon/falcon.h /runtime/usr/share/licenses/softkms/falcon.h-MIT-license \
 && cp /build/xhd/ed25519-bip32/LICENSE-MIT /build/xhd/ed25519-bip32/LICENSE-APACHE \
      /runtime/usr/share/licenses/softkms/ \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/softkms/ \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/softkms/build-only-pkcs11.h \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /tmp/protoc.txt /runtime/usr/share/p11lab/build/protoc.txt \
 && cp /build/softkms/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build --locked --offline --release --lib --bin softkms-daemon --bin softkms --jobs 2' \
      'patches=[01-function-list-order,02-attribute-encoding,03-finalize-reset,04-info-outputs,05-cli-provisioning-secrets,06-mechanism-flags]' \
      'falcon=ce15e75bceb372867daf6b8e81918ab6978686eb xhd=3cafd074e840971a2de791593918bb1c0707cd04' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && mkdir -p /runtime/usr/share/licenses/softkms/crates \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/softkms/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && ldd /runtime/usr/local/lib/p11lab/libsoftkms.so /runtime/usr/local/bin/softkms-daemon /runtime/usr/local/bin/softkms /runtime/usr/local/bin/p11lab-softkms > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-softkms \
      /usr/local/bin/softkms-daemon /usr/local/bin/softkms \
      /usr/local/lib/p11lab/libsoftkms.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libsoftkms.so /usr/local/bin/softkms-daemon /usr/local/bin/softkms /usr/local/bin/p11lab-softkms > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libssl.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libnettle.so.8' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libc.so.6' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
