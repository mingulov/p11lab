# SPDX-License-Identifier: Apache-2.0
# CardContact libsc-hsm-pkcs11 over a pico-hsm SmartCard-HSM emulator
# served by pcscd through the vsmartcard ifd-vpcd handler on fixed
# loopback 35963. The module is source-built unpatched with explicit
# --enable-libcrypto; the emulator is built from the frozen pico-hsm
# + pico-keys-sdk + mbedTLS v3.6.6 + framework + mlkem + tinycbor
# closure with one SDK patch (frozen vendored mbedTLS, no
# configure-time self-update) and one pico-hsm patch (bare terminal
# CA CVC in EF_TERMCA); the IFD handler comes from the frozen
# vsmartcard tree. pcscd, libpcsclite and the support libraries ship
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/sc-hsm-embedded \
 && tar -xf source.tar -C /build/sc-hsm-embedded \
 && [ -f /build/sc-hsm-embedded/configure.ac ] && [ -f /build/sc-hsm-embedded/COPYING ]
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
 && grep -q 'P11Lab: EF_TERMCA holds the bare terminal CA CVC only' /build/pico-hsm/src/hsm/cmd_initialize.c \
 && [ -f /build/vsmartcard/virtualsmartcard/configure.ac ]
WORKDIR /build/sc-hsm-embedded
RUN --network=none autoreconf -fi \
 && ./configure --prefix=/usr/local --enable-libcrypto > /tmp/schsm-configure.txt 2>&1 \
 && cat /tmp/schsm-configure.txt \
 && grep -q 'libcrypto support: *yes' /tmp/schsm-configure.txt \
 && grep -q 'PC/SC support: *yes' /tmp/schsm-configure.txt \
 && make -j2 \
 && make install DESTDIR=/stage-sc-hsm
RUN test -f /stage-sc-hsm/usr/local/lib/libsc-hsm-pkcs11.so \
 && ldd /stage-sc-hsm/usr/local/lib/libsc-hsm-pkcs11.so | grep -q 'libcrypto.so.3' \
 && ldd /stage-sc-hsm/usr/local/lib/libsc-hsm-pkcs11.so | grep -q 'libpcsclite.so.1' \
 && ! ldd /stage-sc-hsm/usr/local/lib/libsc-hsm-pkcs11.so | grep -q 'libusb'
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
# The advertised mechanism count and the provisioned pre-login
# census total are baked per frozen module revision: both V2.12 and
# the frozen rolling revision advertise 24 mechanisms with
# --enable-libcrypto (rolling carries four extra SHA-384/512 RSA
# entries only in unreachable info-switch code, not in the
# advertised list), but release enumerates the device certificate
# (census 4) while rolling builds without --enable-cvc and skips it
# (census 3). Any other revision fails the build for explicit review
# rather than asserting wrong counts.
RUN --network=none schsm_rev=$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["sources"][0]["revision"])') \
 && case "$schsm_rev" in \
      da7e3623bc3cb8c126eaa5128b2c24501919c728) mechs=24; objects=4 ;; \
      ae01b29dbe1585a174de14c1eabb123dafc96c4a) mechs=24; objects=3 ;; \
      *) echo "unknown sc-hsm revision for baked counts: $schsm_rev"; exit 1 ;; \
    esac \
 && echo "mech-style sc-hsm=$schsm_rev mechanisms=$mechs objects=$objects" > /tmp/mech-style.txt \
 && cat /tmp/mech-style.txt \
 && cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -DP11LAB_MECHANISMS=$mechs -DP11LAB_OBJECTS=$objects \
      -I/usr/include/p11-kit-1 -I/usr/include/PCSC /tmp/provision.c -lpcsclite -ldl -o /tmp/p11lab-sc-hsm
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
      /runtime/usr/lib/pcsc/drivers/serial \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/sc-hsm \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /stage-sc-hsm/usr/local/lib/libsc-hsm-pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/pico-hsm/build/pico_hsm /runtime/usr/local/bin/ \
 && cp -P /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so* /runtime/usr/lib/pcsc/drivers/serial/ \
 && cp /stage-vpcd/etc/reader.conf.d/vpcd /runtime/etc/reader.conf.d/vpcd \
 && cp /tmp/p11lab-sc-hsm /runtime/usr/local/bin/ \
 && cp /tmp/schsm-configure.txt /runtime/usr/share/p11lab/build/ \
 && cp /build/sc-hsm-embedded/COPYING /runtime/usr/share/licenses/sc-hsm/sc-hsm-COPYING \
 && cp /build/pico-hsm/LICENSE /runtime/usr/share/licenses/sc-hsm/pico-hsm-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/LICENSE /runtime/usr/share/licenses/sc-hsm/pico-keys-sdk-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mbedtls/LICENSE /runtime/usr/share/licenses/sc-hsm/mbedtls-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mbedtls/framework/LICENSE /runtime/usr/share/licenses/sc-hsm/mbedtls-framework-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/mlkem/LICENSE /runtime/usr/share/licenses/sc-hsm/mlkem-LICENSE \
 && cp /build/pico-hsm/pico-keys-sdk/tinycbor/LICENSE /runtime/usr/share/licenses/sc-hsm/tinycbor-LICENSE \
 && cp /build/vsmartcard/virtualsmartcard/COPYING /runtime/usr/share/licenses/sc-hsm/vsmartcard-COPYING \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/sc-hsm/ \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /usr/share/doc/libpcsclite-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-pcsclite-header-copyright \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /tmp/mech-style.txt /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/local/lib/p11lab && sha256sum libsc-hsm-pkcs11.so) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/bin && sha256sum pico_hsm p11lab-sc-hsm) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/lib/pcsc/drivers/serial && sha256sum libifdvpcd.so.0.11) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && printf '%s\n' 'sc-hsm-embedded unpatched; autoreconf -fi; ./configure --prefix=/usr/local --enable-libcrypto; make -j2; only libsc-hsm-pkcs11.so ships (no ctccid, no test tools)' \
      'pico-hsm + pico-keys-sdk + mbedtls v3.6.6 + framework + mlkem + tinycbor reassembled per lock placement; SDK patch 0001 and pico-hsm patch 0002 applied by source machinery' \
      'cmake -DENABLE_EMULATION=1 -D__FOR_CI=1; make -j2; mbedTLS backend, no EdDSA, no PQC, no OpenSSL wrapper' \
      'vsmartcard ifd-vpcd unpatched; autoreconf; ./configure; make; only the handler .so and the generated reader.conf ship' \
      'provision.c: cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -DP11LAB_MECHANISMS=<baked> -DP11LAB_OBJECTS=<baked> -lpcsclite -ldl' \
      'system libcrypto.so.3 linked by the module (upstream crypto-libcrypto.c: digests and OAEP padding); no legacy provider; no from-source OpenSSL; no openssl CLI in runtime' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-sc-hsm /usr/local/bin/pico_hsm \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/reader.conf.d/vpcd \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && test ! -e /run/pcscd && ln -s /run/p11lab/sc-hsm/pcscd /run/pcscd \
 && test "$(readlink /run/pcscd)" = /run/p11lab/sc-hsm/pcscd \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libsc-hsm-pkcs11.so /usr/local/bin/pico_hsm /usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 /usr/sbin/pcscd /usr/local/bin/p11lab-sc-hsm > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libpcsclite.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'libusb' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -f /lib/x86_64-linux-gnu/libpcsclite.so.1 \
 && test -x /usr/sbin/pcscd \
 && ! test -e /usr/bin/pkcs11-tool && ! test -e /usr/bin/opensc-tool && ! test -e /usr/bin/openssl \
 && ! test -e /usr/bin/python3 && ! test -e /usr/bin/gcc && ! test -e /usr/bin/make && ! test -e /usr/bin/cmake \
 && ! test -e /usr/local/bin/vicc && ! test -e /usr/local/bin/vpcd-config \
 && ! test -e /usr/local/bin/sc-hsm-tool && ! test -e /usr/local/lib/p11lab/opensc-pkcs11.so \
 && ! test -e /usr/local/lib/p11lab/libsc-hsm-pkcs11.la && ! test -e /usr/local/lib/libctccid.so \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /etc/reader.conf.d/vpcd \
 && test -f /usr/lib/pcsc/drivers/serial/libifdvpcd.so \
 && test -f /usr/share/p11lab/build/mech-style.txt \
 && grep -q 'mech-style sc-hsm=' /usr/share/p11lab/build/mech-style.txt \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
