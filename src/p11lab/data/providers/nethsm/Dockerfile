# SPDX-License-Identifier: Apache-2.0
# Frozen upstream server binaries are observed inputs, not source-built output.
ARG BASE_IMAGE=docker.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
FROM docker.io/library/rust@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS rust-input
FROM docker.io/nitrokey/nethsm@sha256:4c9cf630aab7d4b9a76c7247844635d3dd1b78c34ff4fd473115cc59419f6e9b AS server-input
FROM ${BASE_IMAGE} AS runtime-base
COPY apk-inputs.txt install-apks.sh apk-inventory.sh apk-indexes.txt /tmp/
COPY expected-base.tsv expected-runtime.tsv /tmp/
RUN mkdir -p /usr/share/p11lab/build \
 && sh /tmp/apk-inventory.sh > /usr/share/p11lab/build/actual-base.tsv \
 && diff -u /tmp/expected-base.tsv /usr/share/p11lab/build/actual-base.tsv \
 && sh /tmp/install-apks.sh runtime \
 && sh /tmp/apk-inventory.sh > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /tmp/expected-runtime.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && while read -r sha256 filename url; do \
      wget -q -O "/tmp/$filename" "$url" \
      && printf '%s  %s\n' "$sha256" "/tmp/$filename" | sha256sum -c - \
      && (cd /tmp && sha256sum "$filename") >> /usr/share/p11lab/build/actual-signed-indexes.sha256 \
      || exit 1; \
    done < /tmp/apk-indexes.txt

FROM runtime-base AS module-build
COPY --from=rust-input /usr/local/cargo /usr/local/cargo
COPY --from=rust-input /usr/local/rustup /usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN sh /tmp/install-apks.sh builder
COPY expected-builder.tsv /tmp/
RUN sh /tmp/apk-inventory.sh > /tmp/actual-builder.tsv \
 && diff -u /tmp/expected-builder.tsv /tmp/actual-builder.tsv
COPY source.tar source.sha256 dependency-0.tar dependency-0.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 -c dependency-0.sha256 \
 && mkdir -p /build/nethsm /build/observed-openssl \
 && tar -xf source.tar -C /build/nethsm \
 && tar -xf dependency-0.tar -C /build/observed-openssl
COPY Cargo.lock crates.json freeze-crates.py /tmp/
RUN cmp /tmp/Cargo.lock /build/nethsm/Cargo.lock && python3 /tmp/freeze-crates.py
WORKDIR /build/nethsm
# The default musl static CRT cannot produce a cdylib. Rustls/ring provide the
# module's TLS; no openssl-sys/static OpenSSL linkage is present in either pin.
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN rustc -vV > /tmp/rustc.txt \
 && cargo -vV > /tmp/cargo.txt \
 && cargo tree --locked --offline -e normal,build > /tmp/cargo-tree.txt \
 && cargo build --locked --offline --release --jobs 2 \
 && test -f target/release/libnethsm_pkcs11.so
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -lcurl -o /tmp/p11lab-nethsm
COPY FILE-NOTICES.txt apk-lock.json server-input.json /tmp/
COPY observed-source-notices/ /tmp/observed-source-notices/
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/usr/share/p11lab/build \
      /runtime/usr/share/licenses/nethsm/crates /runtime/usr/share/licenses/nethsm/observed-server-sources \
 && cp target/release/libnethsm_pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp /tmp/p11lab-nethsm /runtime/usr/local/bin/ \
 && cp LICENSE /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/nethsm/ \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/nethsm/build-only-pkcs11.h \
 && cp /tmp/observed-source-notices/* /runtime/usr/share/licenses/nethsm/observed-server-sources/ \
 && cp /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/rustc.txt /tmp/cargo.txt /tmp/cargo-tree.txt Cargo.lock /tmp/crates.json \
      /build/crate-file-inventory.json /tmp/apk-lock.json /tmp/server-input.json /runtime/usr/share/p11lab/build/ \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'cargo build --locked --offline --release --jobs 2' \
      'RUSTFLAGS=-C target-feature=-crt-static' 'module_tls=rustls/ring; no static OpenSSL' \
      'server_input=frozen-binary; server source companion unavailable' 'patches=[]' > /runtime/usr/share/p11lab/build/options.txt \
 && python3 -c 'from pathlib import Path; import shutil; out=Path("/runtime/usr/share/licenses/nethsm/crates"); [shutil.copytree(p,out/p.name,ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright"))]) for p in Path("/build/vendor").iterdir()]'

FROM runtime-base AS runtime
# A clean Alpine parent excludes upstream /start.sh, demo passphrases, tap
# utilities, etcdutl, perf tooling and every upstream image layer containing them.
COPY --from=server-input /keyfender.unix /usr/local/bin/keyfender
COPY --from=server-input /bin/etcd /usr/local/bin/etcd
COPY --from=module-build /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-nethsm \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && chmod 700 /var/lib/p11lab /run/p11lab \
 && /usr/local/bin/etcd --version > /usr/share/p11lab/build/etcd.txt \
 && (/usr/local/bin/keyfender --help > /usr/share/p11lab/build/keyfender.txt 2>&1; test "$?" -eq 63) \
 && sha256sum /usr/local/bin/keyfender /usr/local/bin/etcd /usr/local/bin/p11lab-nethsm /usr/local/lib/p11lab/libnethsm_pkcs11.so > /usr/share/p11lab/build/binaries.sha256 \
 && for binary in /usr/local/bin/keyfender /usr/local/bin/p11lab-nethsm /usr/local/lib/p11lab/libnethsm_pkcs11.so; do \
      printf '\n%s\n' "$binary" >> /usr/share/p11lab/build/runtime-linked-dependencies.txt \
      && ldd "$binary" >> /usr/share/p11lab/build/runtime-linked-dependencies.txt || exit 1; \
    done \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && rm -f /tmp/apk-inputs.txt /tmp/install-apks.sh /tmp/apk-inventory.sh /tmp/apk-indexes.txt \
      /tmp/expected-base.tsv /tmp/expected-runtime.tsv /tmp/*-APKINDEX.tar.gz
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
