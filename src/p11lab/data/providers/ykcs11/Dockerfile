# SPDX-License-Identifier: Apache-2.0
# Yubico libykcs11 over a CanoKey-core virtual PIV card served by pcscd.
# The module and yubico-piv-tool are source-built unpatched; the card is
# the CanoKey virt-card IFD handler built from the frozen 8-repository
# closure with two virt-card patches (target without sanitizers; IFD
# entry-trace silenced, warnings kept; upstream ENABLE_TESTS path
# untouched, no PKCS#11 semantic change). pcscd, OpenSSL and the support
# libraries ship as verified
# bytes extracted from snapshot .debs, never as dpkg state.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/ykpiv \
 && tar -xf source.tar -C /build/ykpiv \
 && [ -f /build/ykpiv/CMakeLists.txt ] && [ -f /build/ykpiv/COPYING ]
COPY dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 dependency-2.tar dependency-2.sha256 dependency-3.tar dependency-3.sha256 /tmp/
COPY dependency-4.tar dependency-4.sha256 dependency-5.tar dependency-5.sha256 dependency-6.tar dependency-6.sha256 dependency-7.tar dependency-7.sha256 /tmp/
# Locked submodule placement (see lock features.canokey_core.submodules):
# 0 canokey-core, 1 canokey-crypto, 2 littlefs, 3 tinycbor,
# 4 tf-psa-crypto, 5 mlkem-native, 6 mldsa-native, 7 mbedtls-framework.
RUN cd /tmp && for n in 0 1 2 3 4 5 6 7; do sha256sum -c dependency-$n.sha256; done \
 && mkdir -p /build/canokey && tar -xf dependency-0.tar -C /build/canokey \
 && for spec in '1:canokey-crypto' '2:littlefs' '3:tinycbor' '4:canokey-crypto/tf-psa-crypto' '5:canokey-crypto/third_party/mlkem-native' '6:canokey-crypto/tf-psa-crypto/drivers/pqcp/mldsa-native' '7:canokey-crypto/tf-psa-crypto/framework'; do \
      n=${spec%%:*}; dest=/build/canokey/${spec#*:}; mkdir -p "$dest"; \
      [ -z "$(ls -A "$dest")" ] || { echo "submodule placeholder not empty: $dest"; exit 1; }; \
      tar -xf dependency-$n.tar -C "$dest"; \
      [ -n "$(ls -A "$dest")" ] || { echo "submodule empty after extraction: $dest"; exit 1; }; \
    done \
 && [ -f /build/canokey/CMakeLists.txt ] \
 && [ -f /build/canokey/canokey-crypto/tf-psa-crypto-ed25519.patch ] \
 && [ -f /build/canokey/canokey-crypto/tf-psa-crypto/scripts/generate_driver_wrappers.py ]
WORKDIR /build/canokey
RUN --network=none cmake -S . -B build -DVIRTCARD=ON -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DENABLE_DEBUG_OUTPUT=OFF \
 && cmake --build build --target u2f-virt-card -j2 \
 && find build -name 'libu2f-virt-card.so' -exec cp {} /build/libu2f-virt-card.so \; \
 && test -f /build/libu2f-virt-card.so \
 && nm -D /build/libu2f-virt-card.so | grep -q 'IFDHCreateChannel' \
 && (ldd /build/libu2f-virt-card.so | grep -qE 'libasan|libubsan' && { echo 'libu2f-virt-card.so is sanitizer-instrumented; pcscd cannot dlopen it'; exit 1; } || true)
WORKDIR /build/ykpiv
RUN --network=none cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGENERATE_MAN_PAGES=OFF \
 && cmake --build build -j2 \
 && make -C build install DESTDIR=/stage-ykpiv
RUN test -n "$(find /stage-ykpiv -name 'libykcs11.so.2*' -print -quit)" \
 && test -n "$(find /stage-ykpiv -name 'libykpiv.so.2*' -print -quit)" \
 && test -x /stage-ykpiv/usr/local/bin/yubico-piv-tool
COPY provision.c /tmp/provision.c
RUN --network=none cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 -I/usr/include/PCSC /tmp/provision.c -lpcsclite -ldl -o /tmp/p11lab-ykcs11
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY canokey-reader.conf /tmp/canokey-reader.conf
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
COPY runtime-debs.txt /tmp/runtime-debs.txt
RUN mkdir -p /tmp/debs && cd /tmp/debs \
 && while read -r _ file; do name=${file%%_*}; rest=${file#*_}; version=${rest%_*}; apt-get download "$name=$version"; done < /tmp/runtime-debs.txt \
 && sha256sum -c /tmp/runtime-debs.txt \
 && mkdir -p /runtime \
 && for deb in *.deb; do dpkg-deb -x "$deb" /runtime; done \
 && printf '%s\n' '(no picked files; every extraction package ships whole)' > /tmp/picked-files.txt
COPY build-inputs.json /tmp/build-inputs.json
RUN mkdir -p /runtime/usr/local/bin /runtime/usr/local/lib /runtime/etc/reader.conf.d \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/ykcs11 \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /stage-ykpiv/usr/local/bin/yubico-piv-tool /runtime/usr/local/bin/ \
 && cp -P /stage-ykpiv/usr/local/lib/libykcs11.so* /runtime/usr/local/lib/ \
 && cp -P /stage-ykpiv/usr/local/lib/libykpiv.so* /runtime/usr/local/lib/ \
 && rm -f /runtime/usr/local/lib/libykcs11.a /runtime/usr/local/lib/libykpiv.a \
 && cp /build/libu2f-virt-card.so /runtime/usr/local/lib/ \
 && cp /tmp/canokey-reader.conf /runtime/etc/reader.conf.d/canokey \
 && cp /tmp/p11lab-ykcs11 /runtime/usr/local/bin/ \
 && cp /build/ykpiv/COPYING /runtime/usr/share/licenses/ykcs11/yubico-piv-tool-COPYING \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/ykcs11/ \
 && for spec in 'canokey-core/LICENSE:canokey-core-LICENSE' 'canokey-crypto/LICENSE:canokey-crypto-LICENSE' 'littlefs/LICENSE.md:littlefs-LICENSE.md' 'tinycbor/LICENSE:tinycbor-LICENSE' 'canokey-crypto/tf-psa-crypto/LICENSE:tf-psa-crypto-LICENSE' 'canokey-crypto/third_party/mlkem-native/LICENSE:mlkem-native-LICENSE' 'canokey-crypto/tf-psa-crypto/drivers/pqcp/mldsa-native/LICENSE:mldsa-native-LICENSE' 'canokey-crypto/tf-psa-crypto/framework/LICENSE:mbedtls-framework-LICENSE'; do \
      src=/build/canokey/${spec%%:*}; dst=/runtime/usr/share/licenses/ykcs11/${spec#*:}; \
      cp "$src" "$dst"; \
    done \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /usr/share/doc/libpcsclite-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-pcsclite-header-copyright \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/local/lib && sha256sum libykcs11.so* libykpiv.so* libu2f-virt-card.so) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && printf '%s\n' 'yubico-piv-tool unpatched; cmake Release GENERATE_MAN_PAGES=OFF; make -j2' \
      'canokey-core + 7 pinned submodules reassembled per lock placement; virt-card patches 0001+0002 applied by source machinery' \
      'cmake -DVIRTCARD=ON Release CMAKE_POSITION_INDEPENDENT_CODE=ON ENABLE_DEBUG_OUTPUT=OFF; target u2f-virt-card; make-equivalent cmake --build -j2' \
      'provision.c: cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -lpcsclite -ldl' \
      'system libcrypto.so.3 and libpcsclite.so.1; no legacy provider; no from-source OpenSSL' \
      'management key stays the public factory default (tool default; never passed on argv/stdin)' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-ykcs11 /usr/local/bin/yubico-piv-tool \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/reader.conf.d/canokey \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && test ! -e /run/pcscd && ln -s /run/p11lab/ykcs11/pcscd /run/pcscd \
 && test "$(readlink /run/pcscd)" = /run/p11lab/ykcs11/pcscd \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/libykcs11.so.2 /usr/local/lib/libykpiv.so.2 /usr/local/lib/libu2f-virt-card.so /usr/sbin/pcscd /usr/local/bin/yubico-piv-tool /usr/bin/openssl /usr/local/bin/p11lab-ykcs11 > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libpcsclite.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -qE 'libasan|libubsan' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -x /usr/sbin/pcscd && test -x /usr/bin/openssl \
 && ! test -e /usr/local/lib/libykcs11.a && ! test -e /usr/local/lib/libykpiv.a \
 && ! test -e /usr/bin/pkcs11-tool && ! test -e /usr/bin/opensc-tool \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
