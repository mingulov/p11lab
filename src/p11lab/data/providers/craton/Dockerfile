# SPDX-License-Identifier: Apache-2.0
# Stock Craton embedded provider runtime; no provider patch or insecure RSA feature.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/craton && tar -xf source.tar -C /build/craton
COPY crates.json freeze-crates.py /tmp/
RUN python3 /tmp/freeze-crates.py
ENV RUSTUP_TOOLCHAIN=1.98.1
RUN --network=none cd /build/craton \
 && rustc -vV > /tmp/rustc-build.txt && cargo -vV > /tmp/cargo-build.txt \
 && cargo build -p craton-hsm --locked --offline --release --jobs 2 \
 && sha256sum Cargo.lock > /tmp/cargo-lock-after.txt
COPY provision.c /tmp/provision.c
COPY vendor/pkcs11.h /tmp/pkcs11.h
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I/tmp /tmp/provision.c -ldl -o /tmp/p11lab-craton
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/craton/crates \
 && cp /build/craton/target/release/libcraton_hsm.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libcraton_hsm.so \
 && cp /tmp/p11lab-craton /runtime/usr/local/bin/ \
 && cp /build/craton/LICENSE /build/craton/NOTICE /tmp/FILE-NOTICES.txt /tmp/pkcs11.h /runtime/usr/share/licenses/craton/ \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc-build.txt /runtime/usr/share/p11lab/build/rustc.txt \
 && cp /tmp/cargo-build.txt /runtime/usr/share/p11lab/build/cargo.txt \
 && cp /tmp/cargo-lock-after.txt /runtime/usr/share/p11lab/build/ \
 && cp /build/craton/Cargo.lock /tmp/crates.json /build/crate-file-inventory.json /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build -p craton-hsm --locked --offline --release --jobs 2' \
      'default_features=true' 'insecure-rustcrypto-rsa-private-ops=false' 'fips=false' \
      'provider_patches=none' 'integrity=unsigned-placeholder-key-explicit-dev-bypass-required' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/craton/crates"); [shutil.copytree(p, out/p.name, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]' \
 && ldd /runtime/usr/local/lib/p11lab/libcraton_hsm.so /runtime/usr/local/bin/p11lab-craton > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-craton /usr/local/lib/p11lab/libcraton_hsm.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libcraton_hsm.so /usr/local/bin/p11lab-craton > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
