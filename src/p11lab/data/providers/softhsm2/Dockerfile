# SPDX-License-Identifier: Apache-2.0
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
COPY source.tar /tmp/source.tar
COPY source.sha256 /tmp/source.sha256
RUN cd /tmp && sha256sum -c source.sha256 && mkdir /build && tar -xf source.tar -C /build
WORKDIR /build
RUN sh autogen.sh \
 && ./configure --prefix=/usr/local --libdir=/usr/local/lib --sysconfdir=/etc \
      --with-crypto-backend=openssl --disable-gost --disable-dependency-tracking \
 && make -j2
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN make DESTDIR=/install install \
 && mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/softhsm2 \
 && cp /install/usr/local/lib/softhsm/libsofthsm2.so /runtime/usr/local/lib/p11lab/libsofthsm2.so \
 && cp /install/usr/local/bin/softhsm2-util /runtime/usr/local/bin/ \
 && cp LICENSE /runtime/usr/share/licenses/softhsm2/LICENSE \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && ldd /runtime/usr/local/lib/p11lab/libsofthsm2.so /runtime/usr/local/bin/softhsm2-util > /runtime/usr/share/p11lab/build/linked-dependencies.txt \
 && gcc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && dpkg-query -W -f='${Package} ${Version} ${source:Package} ${source:Version}\n' libssl3t64 > /runtime/usr/share/p11lab/build/crypto.txt
COPY split-debug.sh /tmp/split-debug.sh
RUN mkdir /debug-original \
 && cp /runtime/usr/local/lib/p11lab/libsofthsm2.so /runtime/usr/local/bin/softhsm2-util /debug-original/ \
 && sh /tmp/split-debug.sh /debug-original /debug-shipped /debug libsofthsm2.so softhsm2-util \
 && cp /debug-shipped/libsofthsm2.so /runtime/usr/local/lib/p11lab/libsofthsm2.so \
 && cp /debug-shipped/softhsm2-util /runtime/usr/local/bin/softhsm2-util \
 && cp /debug/binaries.tsv /debug/binutils.txt /runtime/usr/share/p11lab/build/ \
 && cp LICENSE /debug/LICENSE.softhsm2
FROM scratch AS debug-companion
COPY --from=builder /debug/ /
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider \
 && find /usr/share/p11lab -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libsofthsm2.so /usr/local/bin/softhsm2-util > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
