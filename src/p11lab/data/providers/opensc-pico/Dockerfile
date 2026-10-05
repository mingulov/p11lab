# SPDX-License-Identifier: Apache-2.0
# OpenSC over a pico-hsm SmartCard-HSM emulator served by pcscd
# through the vsmartcard ifd-vpcd handler on fixed loopback 35963.
# The module and sc-hsm-tool are source-built unpatched; the emulator
# is built from the frozen pico-hsm + pico-keys-sdk + mbedTLS v3.6.6
# + framework + mlkem + tinycbor closure with one SDK patch (frozen
# vendored mbedTLS, no configure-time self-update); the IFD handler
# comes from the frozen vsmartcard tree. pcscd, libpcsclite and the
# support libraries ship as verified bytes extracted from snapshot
# .debs, never as dpkg state.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/opensc \
 && tar -xf source.tar -C /build/opensc \
 && [ -f /build/opensc/configure.ac ] && [ -f /build/opensc/COPYING ]
COPY dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 dependency-2.tar dependency-2.sha256 dependency-3.tar dependency-3.sha256 /tmp/
COPY dependency-4.tar dependency-4.sha256 dependency-5.tar dependency-5.sha256 dependency-6.tar dependency-6.sha256 /tmp/
# Locked submodule placement (see lock features.pico_hsm.submodules):
# 0 pico-hsm, 1 pico-keys-sdk, 2 mbedtls, 3 mbedtls-framework,
# 4 mlkem, 5 tinycbor; 6 vsmartcard (standalone tree).
RUN cd /tmp && for n in 0 1 2 3 4 5 6; do sha256sum -c dependency-$n.sha256; done \
 && mkdir -p /build/pico-hsm && tar -xf dependency-0.tar -C /build/pico-hsm \
 && mkdir -p /build/vsmartcard && tar -xf dependency-6.tar -C /build/vsmartcard \
 && for spec in '1:pico-keys-sdk' '2:pico-keys-sdk/mbedtls' '3:pico-keys-sdk/mbedtls/framework' '4:pico-keys-sdk/mlkem' '5:pico-keys-sdk/tinycbor'; do \
      n=${spec%%:*}; dest=/build/pico-hsm/${spec#*:}; mkdir -p "$dest"; \
      [ -z "$(ls -A "$dest")" ] || { echo "submodule placeholder not empty: $dest"; exit 1; }; \
      tar -xf dependency-$n.tar -C "$dest"; \
      [ -n "$(ls -A "$dest")" ] || { echo "submodule empty after extraction: $dest"; exit 1; }; \
    done \
 && [ -f /build/pico-hsm/CMakeLists.txt ] \
 && [ -f /build/pico-hsm/pico-keys-sdk/pico_keys_sdk_import.cmake ] \
 && [ -f /build/pico-hsm/pico-keys-sdk/mbedtls/library/aes.c ] \
 && [ -f /build/pico-hsm/pico-keys-sdk/mbedtls/framework/CMakeLists.txt ] \
 && [ -f /build/pico-hsm/pico-keys-sdk/mlkem/mlkem/mlkem_native.c ] \
 && [ -f /build/pico-hsm/pico-keys-sdk/tinycbor/src/cbor.h ] \
 && grep -q 'P11Lab: using frozen vendored mbedTLS' /build/pico-hsm/pico-keys-sdk/pico_keys_sdk_import.cmake \
 && [ -f /build/vsmartcard/virtualsmartcard/configure.ac ]
WORKDIR /build/opensc
RUN --network=none ./bootstrap \
 && ./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-tests --disable-doc --disable-man \
 && make -j2 \
 && make install DESTDIR=/stage-opensc
RUN test -f /stage-opensc/usr/local/lib/opensc-pkcs11.so \
 && test -n "$(find /stage-opensc -name 'libopensc.so.13*' -print -quit)" \
 && test -x /stage-opensc/usr/local/bin/sc-hsm-tool \
 && test -f /stage-opensc/usr/local/etc/opensc.conf \
 && test -f /stage-opensc/usr/local/share/opensc/pkcs15.profile \
 && test -f /stage-opensc/usr/local/share/opensc/sc-hsm.profile
WORKDIR /build/pico-hsm
RUN --network=none mkdir build && cd build \
 && cmake -DENABLE_EMULATION=1 -D__FOR_CI=1 .. \
 && make -j2 \
 && test -x ./pico_hsm
WORKDIR /build/vsmartcard/virtualsmartcard
RUN --network=none autoreconf -vsi \
 && ./configure \
 && make \
 && make install DESTDIR=/stage-vpcd
RUN test -f /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 \
 && test -f /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'LIBPATH      /usr/lib/pcsc/drivers/serial/libifdvpcd.so' /stage-vpcd/etc/reader.conf.d/vpcd
COPY provision.c /tmp/provision.c
COPY build-inputs.json /tmp/build-inputs.json
# The initialize user-PIN prompt diverges by OpenSC revision: 0.27.1
# prompts unless --pin is given, while the frozen rolling revision only
# prompts with --pin ask: (otherwise it initializes PIN-less). Bake the
# matching argv per frozen revision; any other revision fails the build
# for explicit review rather than silently initializing PIN-less.
RUN --network=none opensc_rev=$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["sources"][0]["revision"])') \
 && case "$opensc_rev" in \
      19868984dc4dc697af6a86d65ab32a1f19a43ea4) ask= ;; \
      4f3ff5111314bde380c3d4e9e25bb1fa0169196d) ask=-DP11LAB_INIT_ASK_PIN ;; \
      *) echo "unknown opensc revision for init style: $opensc_rev"; exit 1 ;; \
    esac \
 && echo "init-style opensc=$opensc_rev ask_pin=${ask:-no}" > /tmp/init-style.txt \
 && cat /tmp/init-style.txt \
 && cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic $ask \
      -I/usr/include/p11-kit-1 -I/usr/include/PCSC /tmp/provision.c -lpcsclite -ldl -o /tmp/p11lab-opensc-pico
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
COPY runtime-debs.txt /tmp/runtime-debs.txt
RUN mkdir -p /tmp/debs && cd /tmp/debs \
 && while read -r _ file; do name=${file%%_*}; rest=${file#*_}; version=${rest%_*}; apt-get download "$name=$version"; done < /tmp/runtime-debs.txt \
 && sha256sum -c /tmp/runtime-debs.txt \
 && mkdir -p /runtime \
 && for deb in *.deb; do dpkg-deb -x "$deb" /runtime; done \
 && printf '%s\n' '(no picked files; every extraction package ships whole)' > /tmp/picked-files.txt
RUN mkdir -p /runtime/usr/local/bin /runtime/usr/local/lib/p11lab /runtime/etc/reader.conf.d \
      /runtime/usr/lib/pcsc/drivers/serial /runtime/usr/local/etc /runtime/usr/local/share/opensc \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/opensc-pico \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /stage-opensc/usr/local/lib/opensc-pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp -P /stage-opensc/usr/local/lib/libopensc.so.13* /runtime/usr/local/lib/ \
 && cp /stage-opensc/usr/local/bin/sc-hsm-tool /runtime/usr/local/bin/ \
 && cp /stage-opensc/usr/local/etc/opensc.conf /runtime/usr/local/etc/ \
 && cp /stage-opensc/usr/local/share/opensc/pkcs15.profile /stage-opensc/usr/local/share/opensc/sc-hsm.profile /runtime/usr/local/share/opensc/ \
 && cp /build/pico-hsm/build/pico_hsm /runtime/usr/local/bin/ \
 && cp -P /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so* /runtime/usr/lib/pcsc/drivers/serial/ \
 && cp /stage-vpcd/etc/reader.conf.d/vpcd /runtime/etc/reader.conf.d/vpcd \
 && cp /tmp/p11lab-opensc-pico /runtime/usr/local/bin/ \
 && cp /build/opensc/COPYING /runtime/usr/share/licenses/opensc-pico/opensc-COPYING \
 && cp /build/pico-hsm/LICENSE /runtime/usr/share/licenses/opensc-pico/pico-hsm-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/LICENSE /runtime/usr/share/licenses/opensc-pico/pico-keys-sdk-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mbedtls/LICENSE /runtime/usr/share/licenses/opensc-pico/mbedtls-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mbedtls/framework/LICENSE /runtime/usr/share/licenses/opensc-pico/mbedtls-framework-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mlkem/LICENSE /runtime/usr/share/licenses/opensc-pico/mlkem-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/tinycbor/LICENSE /runtime/usr/share/licenses/opensc-pico/tinycbor-LICENSE \
 && cp /build/vsmartcard/virtualsmartcard/COPYING /runtime/usr/share/licenses/opensc-pico/vsmartcard-COPYING \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/opensc-pico/ \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /usr/share/doc/libpcsclite-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-pcsclite-header-copyright \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /tmp/init-style.txt /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/local/lib/p11lab && sha256sum opensc-pkcs11.so) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib && sha256sum libopensc.so.13*) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/bin && sha256sum sc-hsm-tool pico_hsm p11lab-opensc-pico) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/lib/pcsc/drivers/serial && sha256sum libifdvpcd.so.0.11) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/etc && sha256sum opensc.conf) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/share/opensc && sha256sum pkcs15.profile sc-hsm.profile) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && printf '%s\n' 'opensc unpatched; ./bootstrap; ./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-tests --disable-doc --disable-man; make -j2' \
      'pico-hsm + pico-keys-sdk + mbedtls v3.6.6 + framework + mlkem + tinycbor reassembled per lock placement; SDK patch 0001 applied by source machinery' \
      'cmake -DENABLE_EMULATION=1 -D__FOR_CI=1; make -j2; mbedTLS backend, no EdDSA, no PQC, no OpenSSL wrapper' \
      'vsmartcard ifd-vpcd unpatched; autoreconf; ./configure; make; only the handler .so and the generated reader.conf ship' \
      'provision.c: cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -lpcsclite -ldl' \
      'system libcrypto.so.3; no legacy provider; no from-source OpenSSL; no openssl CLI in runtime' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-opensc-pico /usr/local/bin/sc-hsm-tool /usr/local/bin/pico_hsm \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/reader.conf.d/vpcd /usr/local/etc/opensc.conf /usr/local/share/opensc/pkcs15.profile /usr/local/share/opensc/sc-hsm.profile \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && test ! -e /run/pcscd && ln -s /run/p11lab/opensc-pico/pcscd /run/pcscd \
 && test "$(readlink /run/pcscd)" = /run/p11lab/opensc-pico/pcscd \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/opensc-pkcs11.so /usr/local/lib/libopensc.so.13 /usr/local/bin/sc-hsm-tool /usr/local/bin/pico_hsm /usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 /usr/sbin/pcscd /usr/local/bin/p11lab-opensc-pico > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libpcsclite.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -f /lib/x86_64-linux-gnu/libpcsclite.so.1 \
 && test -x /usr/sbin/pcscd \
 && ! test -e /usr/bin/pkcs11-tool && ! test -e /usr/bin/opensc-tool && ! test -e /usr/bin/openssl \
 && ! test -e /usr/bin/python3 && ! test -e /usr/bin/gcc && ! test -e /usr/bin/make && ! test -e /usr/bin/cmake \
 && ! test -e /usr/local/bin/vicc && ! test -e /usr/local/bin/vpcd-config \
 && ! test -e /usr/local/lib/p11lab/onepin-opensc-pkcs11.so && ! test -e /usr/local/lib/p11lab/pkcs11-spy.so \
 && ! test -e /usr/local/lib/libopensc.a && ! test -e /usr/local/lib/libopensc.la \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /etc/reader.conf.d/vpcd \
 && test -f /usr/lib/pcsc/drivers/serial/libifdvpcd.so \
 && test -f /usr/local/share/opensc/pkcs15.profile \
 && test -f /usr/local/share/opensc/sc-hsm.profile \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
