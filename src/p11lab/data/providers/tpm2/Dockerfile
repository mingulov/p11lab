# SPDX-License-Identifier: Apache-2.0
# tpm2-pkcs11 over swtpm + tpm2-abrmd on a private anonymous D-Bus.
# Native source is unpatched. The module and tpm2_ptool tree are source-built;
# the single Python runtime dependency (tpm2-pytss sdist) installs offline;
# the test-only python-pkcs11 client is not installed (--disable-ptool-checks).
# The daemon closure (swtpm, abrmd, bus, TSS, Python, tpm2-tools picks) ships
# as verified bytes extracted from snapshot .debs, never as dpkg state.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/tpm2-pkcs11 \
 && tar -xf source.tar -C /build/tpm2-pkcs11
COPY dependency-0.tar dependency-0.sha256 /tmp/
RUN cd /tmp && sha256sum -c dependency-0.sha256 && mkdir -p /build/deps \
 && tar -xf dependency-0.tar -C /build/deps \
 && [ -f /build/deps/tpm2-pytss-2.3.0/pyproject.toml ]
COPY build-inputs.json /tmp/build-inputs.json
RUN --network=none pip install --no-build-isolation --no-deps --break-system-packages /build/deps/tpm2-pytss-2.3.0 \
 && PYTHONDONTWRITEBYTECODE=1 python3 -c "from importlib.metadata import version; assert version('tpm2-pytss') == '2.3.0', version('tpm2-pytss')"
WORKDIR /build/tpm2-pkcs11
RUN --network=none UPSTREAM_VERSION=$(grep -o '"upstream_version": "[^"]*"' /tmp/build-inputs.json | cut -d'"' -f4) \
 && [ -n "$UPSTREAM_VERSION" ] \
 && case "$UPSTREAM_VERSION" in *[!A-Za-z0-9._-]*) echo "unsafe upstream version"; exit 1;; esac \
 && git init -q . && git add -A \
 && git -c user.email=p11lab@example.invalid -c user.name=P11Lab commit -qm source \
 && git tag "$UPSTREAM_VERSION" && git describe --tags --always --dirty \
 && sh bootstrap \
 && [ "$(cat VERSION)" = "$UPSTREAM_VERSION" ] \
 && ./configure --prefix=/usr --with-fapi=no --disable-ptool-checks \
 && make -j2 \
 && make install DESTDIR=/staging/tpm2 \
 && (cd tools && pip install --no-build-isolation --no-deps --break-system-packages .) \
 && PYTHONDONTWRITEBYTECODE=1 python3 -c "from importlib.metadata import version; assert version('tpm2-pkcs11-tools') == '1.33.7', version('tpm2-pkcs11-tools')"
COPY provision.c /tmp/provision.c
RUN --network=none cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -o /tmp/p11lab-tpm2
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
COPY runtime-debs.txt /tmp/runtime-debs.txt
RUN mkdir -p /tmp/debs && cd /tmp/debs \
 && while read -r _ file; do name=${file%%_*}; rest=${file#*_}; version=${rest%_*}; apt-get download "$name=$version"; done < /tmp/runtime-debs.txt \
 && sha256sum -c /tmp/runtime-debs.txt \
 && mkdir -p /runtime \
 && for deb in *.deb; do case "$deb" in dbus-bin_*|tpm2-tools_*) continue;; esac; dpkg-deb -x "$deb" /runtime; done \
 && dpkg-deb --fsys-tarfile dbus-bin_*.deb | tar -x -C /runtime ./usr/bin/dbus-send \
 && dpkg-deb --fsys-tarfile tpm2-tools_*.deb | tar -x -C /runtime ./usr/bin/tpm2 ./usr/bin/tpm2_createprimary ./usr/bin/tpm2_create ./usr/bin/tpm2_evictcontrol ./usr/bin/tpm2_readpublic ./usr/bin/tpm2_load ./usr/bin/tpm2_loadexternal ./usr/bin/tpm2_unseal ./usr/bin/tpm2_encryptdecrypt ./usr/bin/tpm2_sign ./usr/bin/tpm2_getcap ./usr/bin/tpm2_import ./usr/bin/tpm2_changeauth \
 && [ -x /runtime/usr/bin/dbus-send ] && [ -x /runtime/usr/bin/tpm2 ] && [ -x /runtime/usr/bin/tpm2_getcap ] \
 && printf '%s\n' './usr/bin/dbus-send' './usr/bin/tpm2' './usr/bin/tpm2_createprimary' './usr/bin/tpm2_create' './usr/bin/tpm2_evictcontrol' './usr/bin/tpm2_readpublic' './usr/bin/tpm2_load' './usr/bin/tpm2_loadexternal' './usr/bin/tpm2_unseal' './usr/bin/tpm2_encryptdecrypt' './usr/bin/tpm2_sign' './usr/bin/tpm2_getcap' './usr/bin/tpm2_import' './usr/bin/tpm2_changeauth' > /tmp/picked-files.txt
COPY p11lab-tpm2-ptool /tmp/p11lab-tpm2-ptool
COPY dbus.conf /tmp/dbus.conf
RUN mkdir -p /runtime/usr/local/bin /runtime/usr/local/lib/python3.13/dist-packages \
      /runtime/usr/lib/x86_64-linux-gnu/pkcs11 /runtime/etc/p11lab/tpm2 \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/tpm2 \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /staging/tpm2/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so* /runtime/usr/lib/x86_64-linux-gnu/pkcs11/ \
 && rm -f /runtime/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.la \
 && [ "$(ls /runtime/usr/lib/x86_64-linux-gnu/pkcs11/ | grep -c .)" = 3 ] \
 && cp -a /usr/local/lib/python3.13/dist-packages/tpm2_pytss /usr/local/lib/python3.13/dist-packages/tpm2_pytss-2.3.0.dist-info /usr/local/lib/python3.13/dist-packages/tpm2_pkcs11 /usr/local/lib/python3.13/dist-packages/tpm2_pkcs11_tools-1.33.7.dist-info /runtime/usr/local/lib/python3.13/dist-packages/ \
 && test -x /usr/local/bin/tpm2_ptool && [ ! -e /runtime/usr/local/bin/tpm2_ptool ] \
 && cp /tmp/p11lab-tpm2 /runtime/usr/local/bin/ \
 && cp /tmp/p11lab-tpm2-ptool /runtime/usr/local/bin/ \
 && cp /tmp/dbus.conf /runtime/etc/p11lab/tpm2/dbus.conf \
 && cp LICENSE /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/tpm2/ \
 && cp /build/deps/tpm2-pytss-2.3.0/LICENSE /runtime/usr/share/licenses/tpm2/tpm2-pytss-LICENSE \
 && cp /usr/share/doc/dbus-bin/copyright /runtime/usr/share/licenses/runtime-closure/dbus-bin-copyright \
 && cp /usr/share/doc/tpm2-tools/copyright /runtime/usr/share/licenses/runtime-closure/tpm2-tools-copyright \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /runtime/usr/share/p11lab/build/ \
 && cp config.log /runtime/usr/share/p11lab/build/tpm2-config.log \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/lib/x86_64-linux-gnu/pkcs11 && sha256sum libtpm2_pkcs11.so*) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && python3 -c "from importlib.metadata import version; print('tpm2-pytss ' + version('tpm2-pytss')); print('tpm2-pkcs11-tools ' + version('tpm2-pkcs11-tools'))" > /runtime/usr/share/p11lab/build/python-trees.txt \
 && printf '%s\n' 'native source unpatched; make -j2' \
      'configure --prefix=/usr --with-fapi=no --disable-ptool-checks (all else upstream defaults)' \
      'VERSION from locked upstream_version via throwaway tag; unmodified bootstrap' \
      'system libcrypto.so.3; no legacy provider; python trees tpm2-pytss + tpm2_pkcs11 only' \
      'console tpm2_ptool excluded: argv-free wrapper is the provider ptool surface' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-tpm2 /usr/local/bin/p11lab-tpm2-ptool \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/p11lab/tpm2/dbus.conf \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so /usr/bin/swtpm /usr/sbin/tpm2-abrmd /usr/bin/dbus-daemon /usr/bin/dbus-send /usr/bin/python3.13 /usr/bin/tpm2 /usr/local/lib/python3.13/dist-packages/tpm2_pytss/_libtpm2_pytss.abi3.so /usr/local/bin/p11lab-tpm2 > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && PYTHONDONTWRITEBYTECODE=1 python3 -c "from tpm2_pkcs11.command import commandlet; from importlib.metadata import version; assert version('tpm2-pytss') == '2.3.0' and version('tpm2-pkcs11-tools') == '1.33.7'" \
 && p11lab-tpm2-ptool 2>&1 | grep -q '^usage: p11lab-tpm2-ptool' \
 && ! test -e /usr/local/bin/tpm2_ptool \
 && ! test -e /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.la \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1 | grep -v -e '^dbus-bin$' -e '^tpm2-tools$'); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
