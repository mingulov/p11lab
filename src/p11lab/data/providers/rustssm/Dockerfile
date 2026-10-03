# SPDX-License-Identifier: Apache-2.0
# Native SQLite token. Default features, no cli. Shared source acquisition must
# apply the declared discovery patch successfully before producing source.tar.
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
COPY source.tar source.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 \
 && mkdir -p /build/rustssm && tar -xf source.tar -C /build/rustssm \
 && cd /build/rustssm \
 && echo '82ac5c5e4d9fe6d5713a076a0d294b48614031badd228bf1df200a05c995bc35  src/lib.rs' | sha256sum -c - \
 && echo '7d045b4a370f0c13405897d53db0a7fb178e7d4e4db1f85e46d4f26bbdbbc325  tests/pkcs11.rs' | sha256sum -c -
COPY crates.json freeze-crates.py /tmp/
RUN python3 /tmp/freeze-crates.py
RUN --network=none cd /build/rustssm \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo build --locked --offline --release --jobs 2 \
 && test -f target/release/librustssm.so \
 && test ! -e target/release/rustssm-util
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -isystem /build/rustssm /tmp/provision.c -ldl -o /tmp/p11lab-rustssm
COPY patches/ /tmp/patches/
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN cd /tmp/patches \
 && echo 'd7652f66f7c50cf13e925ccac85d02a5146efaf38420618364c53a86d75625b7  0001-implement-mechanism-discovery.patch' | sha256sum -c - \
 && echo '28b6e55a287615b6c47a6df471d321bd735068e6485aa05a4790017b458dbc83  LICENSE-MIT' | sha256sum -c - \
 && mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/rustssm/patches \
 && cp /build/rustssm/target/release/librustssm.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/librustssm.so \
 && cp /tmp/p11lab-rustssm /runtime/usr/local/bin/ \
 && cp /build/rustssm/LICENSE /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/rustssm/ \
 && cp /tmp/patches/* /runtime/usr/share/licenses/rustssm/patches/ \
 && cp /build/rustssm/pkcs11*.h /runtime/usr/share/licenses/rustssm/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /build/rustssm/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build --locked --offline --release --jobs 2' \
      'default_features=true' 'cli=false' 'sqlite=bundled' 'patch=0001-implement-mechanism-discovery.patch' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && mkdir -p /runtime/usr/share/licenses/rustssm/crates \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/rustssm/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && ldd /runtime/usr/local/lib/p11lab/librustssm.so /runtime/usr/local/bin/p11lab-rustssm > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-rustssm /usr/local/lib/p11lab/librustssm.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/librustssm.so /usr/local/bin/p11lab-rustssm > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
