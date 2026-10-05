# SPDX-License-Identifier: Apache-2.0
# OpenSC over a PivApplet card on the jcardsim VSmartCard emulator,
# served by pcscd through the vsmartcard ifd-vpcd handler on fixed
# loopback 35963. The module is source-built unpatched; PivApplet is
# compiled from frozen source against the pinned Maven Central
# jcardsim jar (source-building jcardsim needs the proprietary
# Oracle JavaCard SDK, so the jar is the frozen input); the IFD
# handler comes from the frozen vsmartcard tree. The yubico-piv-tool
# provisioning CLI is source-built from the frozen tag with the
# frozen host-transport chunk patch applied. pcscd, libpcsclite,
# the JRE and the support libraries ship as verified bytes extracted
# from snapshot .debs, never as dpkg state.
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
# Locked standalone trees (see lock features): 0 pivapplet (compiled
# against the sealed jar), 1 yubico-piv-tool (patched; provisioning
# CLI), 2 vsmartcard (ifd-vpcd handler), 3 jcardsim sources (license
# evidence only: the tree needs the proprietary Oracle JavaCard SDK
# to build, so it is never compiled).
RUN cd /tmp && for n in 0 1 2 3; do sha256sum -c dependency-$n.sha256; done \
 && mkdir -p /build/pivapplet && tar -xf dependency-0.tar -C /build/pivapplet \
 && mkdir -p /build/pivtool && tar -xf dependency-1.tar -C /build/pivtool \
 && mkdir -p /build/vsmartcard && tar -xf dependency-2.tar -C /build/vsmartcard \
 && mkdir -p /build/jcardsim-src && tar -xf dependency-3.tar -C /build/jcardsim-src \
 && [ -f /build/pivapplet/src/net/cooperi/pivapplet/PivApplet.java ] \
 && grep -q 'Mozilla Public' /build/pivapplet/src/net/cooperi/pivapplet/PivApplet.java \
 && [ -f /build/pivtool/tool/yubico-piv-tool.c ] \
 && [ -f /build/pivtool/COPYING ] \
 && grep -q 'Redistribution and use in source and binary forms' /build/pivtool/COPYING \
 && [ -f /build/vsmartcard/virtualsmartcard/configure.ac ] \
 && [ -f /build/jcardsim-src/NOTICE ] && [ -f /build/jcardsim-src/pom.xml ] \
 && grep -q 'JC_CLASSIC_HOME' /build/jcardsim-src/pom.xml
COPY maven.json fetch-jar.py /tmp/
RUN python3 /tmp/fetch-jar.py \
 && test -f /build/maven/jcardsim-3.0.6.0.jar \
 && sha256sum /build/maven/jcardsim-3.0.6.0.jar
WORKDIR /build/opensc
RUN --network=none ./bootstrap \
 && ./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-tests --disable-doc --disable-man \
 && make -j2 \
 && make install DESTDIR=/stage-opensc
RUN test -f /stage-opensc/usr/local/lib/opensc-pkcs11.so \
 && test -n "$(find /stage-opensc -name 'libopensc.so.13*' -print -quit)" \
 && test -f /stage-opensc/usr/local/etc/opensc.conf
# The frozen yubico-piv-tool chunk patch (host-transport
# compatibility for the emulator's 255-byte send boundary; see
# FILE-NOTICES) is applied by the source machinery before the
# build context is assembled; a failed declared patch fails
# acquisition. The post-image is asserted here as a receipt.
WORKDIR /build/pivtool
RUN --network=none grep -q 'templ\[3\], 0xfe}' lib/ykpiv.c \
 && grep -q 'never exceed 260 bytes' lib/ykpiv.c \
 && ! grep -q 'templ\[3\], 0xff}' lib/ykpiv.c \
 && mkdir -p /build/pivtool-build && cd /build/pivtool-build \
 && cmake -DCMAKE_BUILD_TYPE=Release /build/pivtool \
 && make -j2 \
 && make install DESTDIR=/stage-pivtool
RUN test -x /stage-pivtool/usr/local/bin/yubico-piv-tool \
 && test -n "$(find /stage-pivtool -name 'libykpiv.so.2*' -print -quit)"
WORKDIR /build/vsmartcard/virtualsmartcard
RUN --network=none autoreconf -vsi \
 && ./configure \
 && make \
 && make install DESTDIR=/stage-vpcd
RUN test -f /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 \
 && test -f /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'LIBPATH      /usr/lib/pcsc/drivers/serial/libifdvpcd.so' /stage-vpcd/etc/reader.conf.d/vpcd
COPY PivAppletCard.java /tmp/PivAppletCard.java
# PivApplet preprocesses with the repo-bundled JPP jar through the
# frozen ant at the build.xml defaults (RSA plus EC families, P-384
# signer, AES plus 3DES management key, non-strict contactless,
# attestation on, extended length on), then compiles against the
# sealed jar (sorted source order; no Oracle SDK needed since the
# jar bundles the javacard classes). A second compile must be
# byte-identical: javac output determinism is asserted, not assumed.
RUN --network=none sha256sum /build/pivapplet/ext/jpp-1.0.3.jar | tee /tmp/jpp.txt \
 && grep -q '^0cf0ba9b691ba29d6787a5e3d1d78d74c266c50146aa1f4a4136936976c8fea8 ' /tmp/jpp.txt \
 && cd /build/pivapplet && ant preprocess \
 && find src-gen -name '*.java' | sort | xargs javac -cp /build/maven/jcardsim-3.0.6.0.jar -d /opt/pivapplet-classes \
 && find src-gen -name '*.java' | sort | xargs javac -cp /build/maven/jcardsim-3.0.6.0.jar -d /opt/pivapplet-classes-check \
 && diff -r /opt/pivapplet-classes /opt/pivapplet-classes-check \
 && mkdir -p /opt/pivapplet-wrapper \
 && javac -cp /build/maven/jcardsim-3.0.6.0.jar /tmp/PivAppletCard.java -d /opt/pivapplet-wrapper \
 && test -f /opt/pivapplet-classes/net/cooperi/pivapplet/PivApplet.class \
 && test -f /opt/pivapplet-wrapper/PivAppletCard.class \
 && javac -version 2>&1 | tee /tmp/javac.txt \
 && java -version 2>&1 | tee /tmp/java.txt
COPY provision.c /tmp/provision.c
COPY build-inputs.json /tmp/build-inputs.json
# The yubico-piv-tool argv shapes plus the exact success markers
# (change-pin/change-puk/generate/verify-pin/selfsign/import, with
# --stdin-input and -i/-o file IO) were proven natively for exactly
# this frozen tool tag. Any other revision fails the build for
# explicit argv-plus-marker review rather than risking mis-parsed
# provisioning traffic.
RUN --network=none pivtool_rev=$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["dependencies"][1]["revision"])') \
 && pivtool_patch=$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["patches"][0]["sha256"])') \
 && [ "$pivtool_rev" = ed1cd7862d39a92502c0476f53dfcf93f195007a ] \
 && [ "$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["patches"][0]["path"])')" = patches/0001-ykpiv-short-apdu-chunks.patch ] \
 && echo "prompt-matrix pivtool=$pivtool_rev patch=$pivtool_patch ykpiv-change+generate(9c-pin-once)+selfsign+import stdin+fileio ATR-pinned" | tee /tmp/prompt-matrix.txt \
 && cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 -I/usr/include/PCSC /tmp/provision.c -lpcsclite -ldl -o /tmp/p11lab-opensc-pivapplet
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
      /runtime/usr/lib/pcsc/drivers/serial /runtime/usr/local/etc \
      /runtime/usr/local/lib/p11lab/pivapplet/wrapper /runtime/usr/local/lib/p11lab/pivapplet/classes \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/opensc-pivapplet \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /stage-opensc/usr/local/lib/opensc-pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp -P /stage-opensc/usr/local/lib/libopensc.so.13* /runtime/usr/local/lib/ \
 && cp /stage-opensc/usr/local/etc/opensc.conf /runtime/usr/local/etc/ \
 && cp -P /stage-pivtool/usr/local/bin/yubico-piv-tool /runtime/usr/local/bin/ \
 && cp -P /stage-pivtool/usr/local/lib/libykpiv.so.2* /runtime/usr/local/lib/ \
 && cp -P /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so* /runtime/usr/lib/pcsc/drivers/serial/ \
 && cp /stage-vpcd/etc/reader.conf.d/vpcd /runtime/etc/reader.conf.d/vpcd \
 && cp /build/maven/jcardsim-3.0.6.0.jar /runtime/usr/local/lib/p11lab/pivapplet/jcardsim.jar \
 && cp -r /opt/pivapplet-classes/. /runtime/usr/local/lib/p11lab/pivapplet/classes/ \
 && cp /opt/pivapplet-wrapper/PivAppletCard.class /runtime/usr/local/lib/p11lab/pivapplet/wrapper/ \
 && cp /tmp/p11lab-opensc-pivapplet /runtime/usr/local/bin/ \
 && cp /build/opensc/COPYING /runtime/usr/share/licenses/opensc-pivapplet/opensc-COPYING \
 && cp /build/pivapplet/README.adoc /runtime/usr/share/licenses/opensc-pivapplet/pivapplet-README.adoc \
 && cp /build/pivapplet/src/net/cooperi/pivapplet/PivApplet.java /runtime/usr/share/licenses/opensc-pivapplet/pivapplet-license-header.java \
 && cp /build/pivtool/COPYING /runtime/usr/share/licenses/opensc-pivapplet/pivtool-COPYING \
 && cp /build/pivtool/lib/ykpiv.c /runtime/usr/share/licenses/opensc-pivapplet/pivtool-ykpiv-patched.c \
 && cp /build/jcardsim-src/NOTICE /runtime/usr/share/licenses/opensc-pivapplet/jcardsim-NOTICE \
 && cp /build/jcardsim-src/pom.xml /runtime/usr/share/licenses/opensc-pivapplet/jcardsim-pom.xml \
 && cp /tmp/maven.json /runtime/usr/share/licenses/opensc-pivapplet/sealed-maven.json \
 && cp /build/vsmartcard/virtualsmartcard/COPYING /runtime/usr/share/licenses/opensc-pivapplet/vsmartcard-COPYING \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/opensc-pivapplet/ \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /usr/share/doc/libpcsclite-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-pcsclite-header-copyright \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /tmp/prompt-matrix.txt /tmp/javac.txt /tmp/java.txt /tmp/jpp.txt /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/local/lib/p11lab && sha256sum opensc-pkcs11.so) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib && sha256sum libopensc.so.13*) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/bin && sha256sum yubico-piv-tool p11lab-opensc-pivapplet) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib && sha256sum libykpiv.so.2*) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/lib/pcsc/drivers/serial && sha256sum libifdvpcd.so.0.11) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/etc && sha256sum opensc.conf) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib/p11lab/pivapplet && sha256sum jcardsim.jar && find classes wrapper -type f | sort | xargs sha256sum) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && printf '%s\n' 'opensc unpatched; ./bootstrap; ./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-tests --disable-doc --disable-man; make -j2' \
      'pivapplet compiled from frozen 5cb14a9 source (build.xml defaults) with frozen ant+JPP plus frozen javac against the sealed jcardsim 3.0.6.0 jar (sorted sources; double-compile byte-identical)' \
      'jcardsim jar from Maven Central by sealed sha256 (source build needs the proprietary Oracle JavaCard SDK); wrapper is P11Lab-authored' \
      'yubico-piv-tool 2.7.3 with the frozen 0001-ykpiv-short-apdu-chunks host-transport patch; cmake Release; make -j2; only the CLI plus libykpiv ship' \
      'vsmartcard ifd-vpcd unpatched; autoreconf; ./configure; make; only the handler .so and the generated reader.conf ship' \
      'provision.c: cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -lpcsclite -ldl' \
      'system libcrypto.so.3; no legacy provider; no from-source OpenSSL; no openssl CLI in runtime' \
      'JRE is whole-package openjdk-21-jre-headless; liblcms2/libjpeg/libnss/libnspr/ca-certificates/java-common/openssl excluded by removal proof' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-opensc-pivapplet /usr/local/bin/yubico-piv-tool \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/reader.conf.d/vpcd /usr/local/etc/opensc.conf \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && test ! -e /run/pcscd && ln -s /run/p11lab/opensc-pivapplet/pcscd /run/pcscd \
 && test "$(readlink /run/pcscd)" = /run/p11lab/opensc-pivapplet/pcscd \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/opensc-pkcs11.so /usr/local/lib/libopensc.so.13 /usr/local/bin/yubico-piv-tool /usr/local/lib/libykpiv.so.2 /usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 /usr/sbin/pcscd /usr/local/bin/p11lab-opensc-pivapplet /usr/lib/jvm/java-21-openjdk-amd64/bin/java /usr/lib/jvm/java-21-openjdk-amd64/lib/server/libjvm.so > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libpcsclite.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -f /lib/x86_64-linux-gnu/libpcsclite.so.1 \
 && test -x /usr/sbin/pcscd \
 && ! test -e /usr/bin/pkcs11-tool && ! test -e /usr/bin/opensc-tool && ! test -e /usr/bin/openssl \
 && ! test -e /usr/bin/python3 && ! test -e /usr/bin/gcc && ! test -e /usr/bin/make \
 && ! test -e /usr/bin/javac && ! test -e /usr/bin/java \
 && ! test -e /usr/local/bin/vicc && ! test -e /usr/local/bin/vpcd-config \
 && ! test -e /usr/local/bin/sc-hsm-tool && ! test -e /usr/local/bin/pkcs15-init \
 && ! test -e /usr/local/lib/p11lab/onepin-opensc-pkcs11.so && ! test -e /usr/local/lib/p11lab/pkcs11-spy.so \
 && ! test -e /usr/local/lib/libopensc.a && ! test -e /usr/local/lib/libopensc.la \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /etc/reader.conf.d/vpcd \
 && test -f /usr/lib/pcsc/drivers/serial/libifdvpcd.so \
 && test -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java \
 && test -f /usr/local/lib/p11lab/pivapplet/jcardsim.jar \
 && test -f /usr/local/lib/p11lab/pivapplet/classes/net/cooperi/pivapplet/PivApplet.class \
 && test -f /usr/local/lib/p11lab/pivapplet/wrapper/PivAppletCard.class \
 && test -x /usr/local/bin/yubico-piv-tool \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
