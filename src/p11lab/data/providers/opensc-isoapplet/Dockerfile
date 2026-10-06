# SPDX-License-Identifier: Apache-2.0
# OpenSC over an IsoApplet card on the jcardsim VSmartCard emulator,
# served by pcscd through the vsmartcard ifd-vpcd handler on fixed
# port 35963 (the JVM dials 127.0.0.1; the frozen handler listens
# wildcard, disclosed in the recipe docs). The module and
# pkcs15-init are source-built
# unpatched; IsoApplet is compiled from frozen source against the
# pinned Maven Central jcardsim jar (source-building jcardsim needs
# the proprietary Oracle JavaCard SDK, so the jar is the frozen
# input); the IFD handler comes from the frozen vsmartcard tree.
# pcscd, libpcsclite, the JRE and the support libraries ship as
# verified bytes extracted from snapshot .debs, never as dpkg state.
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
COPY dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 dependency-2.tar dependency-2.sha256 /tmp/
# Locked standalone trees (see lock features): 0 isoapplet (compiled
# against the sealed jar), 1 vsmartcard (ifd-vpcd handler), 2
# jcardsim sources (license evidence only: the tree needs the
# proprietary Oracle JavaCard SDK to build, so it is never compiled).
RUN cd /tmp && for n in 0 1 2; do sha256sum -c dependency-$n.sha256; done \
 && mkdir -p /build/isoapplet && tar -xf dependency-0.tar -C /build/isoapplet \
 && mkdir -p /build/vsmartcard && tar -xf dependency-1.tar -C /build/vsmartcard \
 && mkdir -p /build/jcardsim-src && tar -xf dependency-2.tar -C /build/jcardsim-src \
 && [ -f /build/isoapplet/src/net/pwendland/javacard/pki/isoapplet/IsoApplet.java ] \
 && [ -f /build/isoapplet/LICENSE ] \
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
 && test -x /stage-opensc/usr/local/bin/pkcs15-init \
 && test -f /stage-opensc/usr/local/etc/opensc.conf \
 && test -f /stage-opensc/usr/local/share/opensc/pkcs15.profile \
 && test -f /stage-opensc/usr/local/share/opensc/isoApplet.profile
WORKDIR /build/vsmartcard/virtualsmartcard
RUN --network=none autoreconf -vsi \
 && ./configure \
 && make \
 && make install DESTDIR=/stage-vpcd
RUN test -f /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 \
 && test -f /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /stage-vpcd/etc/reader.conf.d/vpcd \
 && grep -q 'LIBPATH      /usr/lib/pcsc/drivers/serial/libifdvpcd.so' /stage-vpcd/etc/reader.conf.d/vpcd
COPY IsoAppletCard.java /tmp/IsoAppletCard.java
# Compile IsoApplet plus the P11Lab wrapper against the sealed jar
# (sorted source order; no Oracle SDK needed since the jar bundles
# the javacard classes). A second compile must be byte-identical:
# javac output determinism is asserted, not assumed.
RUN --network=none mkdir -p /opt/isoapplet-classes /opt/isoapplet-classes-check /opt/isoapplet-wrapper \
 && find /build/isoapplet/src -name '*.java' | sort | xargs javac -cp /build/maven/jcardsim-3.0.6.0.jar -d /opt/isoapplet-classes \
 && find /build/isoapplet/src -name '*.java' | sort | xargs javac -cp /build/maven/jcardsim-3.0.6.0.jar -d /opt/isoapplet-classes-check \
 && diff -r /opt/isoapplet-classes /opt/isoapplet-classes-check \
 && javac -cp /build/maven/jcardsim-3.0.6.0.jar /tmp/IsoAppletCard.java -d /opt/isoapplet-wrapper \
 && test -f /opt/isoapplet-classes/net/pwendland/javacard/pki/isoapplet/IsoApplet.class \
 && test -f /opt/isoapplet-wrapper/IsoAppletCard.class \
 && javac -version 2>&1 | tee /tmp/javac.txt \
 && java -version 2>&1 | tee /tmp/java.txt
COPY provision.c /tmp/provision.c
COPY build-inputs.json /tmp/build-inputs.json
# The pkcs15-init prompt matrix (PIN, PIN retype, PUK, PUK retype, in
# that order, with ATR-pinned reader selection) was proven natively
# for exactly these two frozen OpenSC revisions. Any other revision
# fails the build for explicit prompt-matrix review rather than
# risking mis-answered secrets.
RUN --network=none opensc_rev=$(python3 -c 'import json;print(json.load(open("/tmp/build-inputs.json"))["inputs"]["sources"][0]["revision"])') \
 && case "$opensc_rev" in \
      19868984dc4dc697af6a86d65ab32a1f19a43ea4|4f3ff5111314bde380c3d4e9e25bb1fa0169196d) ;; \
      *) echo "unknown opensc revision for prompt matrix: $opensc_rev"; exit 1 ;; \
    esac \
 && echo "prompt-matrix opensc=$opensc_rev pkcs15+onepin 4-prompt ATR-pinned" > /tmp/prompt-matrix.txt \
 && cat /tmp/prompt-matrix.txt \
 && cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 -I/usr/include/PCSC /tmp/provision.c -lpcsclite -ldl -o /tmp/p11lab-opensc-isoapplet
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
      /runtime/usr/local/lib/p11lab/isoapplet/wrapper /runtime/usr/local/lib/p11lab/isoapplet/classes \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/opensc-isoapplet \
      /runtime/usr/share/licenses/runtime-closure \
 && cp /stage-opensc/usr/local/lib/opensc-pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && cp -P /stage-opensc/usr/local/lib/libopensc.so.13* /runtime/usr/local/lib/ \
 && cp /stage-opensc/usr/local/bin/pkcs15-init /runtime/usr/local/bin/ \
 && cp /stage-opensc/usr/local/etc/opensc.conf /runtime/usr/local/etc/ \
 && cp /stage-opensc/usr/local/share/opensc/pkcs15.profile /stage-opensc/usr/local/share/opensc/isoApplet.profile /runtime/usr/local/share/opensc/ \
 && cp -P /stage-vpcd/usr/lib/pcsc/drivers/serial/libifdvpcd.so* /runtime/usr/lib/pcsc/drivers/serial/ \
 && cp /stage-vpcd/etc/reader.conf.d/vpcd /runtime/etc/reader.conf.d/vpcd \
 && cp /build/maven/jcardsim-3.0.6.0.jar /runtime/usr/local/lib/p11lab/isoapplet/jcardsim.jar \
 && cp -r /opt/isoapplet-classes/. /runtime/usr/local/lib/p11lab/isoapplet/classes/ \
 && cp /opt/isoapplet-wrapper/IsoAppletCard.class /runtime/usr/local/lib/p11lab/isoapplet/wrapper/ \
 && cp /tmp/p11lab-opensc-isoapplet /runtime/usr/local/bin/ \
 && cp /build/opensc/COPYING /runtime/usr/share/licenses/opensc-isoapplet/opensc-COPYING \
 && cp /build/isoapplet/LICENSE /runtime/usr/share/licenses/opensc-isoapplet/isoapplet-LICENSE \
 && cp /build/jcardsim-src/NOTICE /runtime/usr/share/licenses/opensc-isoapplet/jcardsim-NOTICE \
 && cp /build/jcardsim-src/pom.xml /runtime/usr/share/licenses/opensc-isoapplet/jcardsim-pom.xml \
 && cp /tmp/maven.json /runtime/usr/share/licenses/opensc-isoapplet/sealed-maven.json \
 && cp /build/vsmartcard/virtualsmartcard/COPYING /runtime/usr/share/licenses/opensc-isoapplet/vsmartcard-COPYING \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/opensc-isoapplet/ \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /usr/share/doc/libpcsclite-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-pcsclite-header-copyright \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /tmp/runtime-debs.txt /tmp/picked-files.txt /tmp/prompt-matrix.txt /tmp/javac.txt /tmp/java.txt /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && (cd /runtime/usr/local/lib/p11lab && sha256sum opensc-pkcs11.so) > /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib && sha256sum libopensc.so.13*) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/bin && sha256sum pkcs15-init p11lab-opensc-isoapplet) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/lib/pcsc/drivers/serial && sha256sum libifdvpcd.so.0.11) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/etc && sha256sum opensc.conf) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/share/opensc && sha256sum pkcs15.profile isoApplet.profile) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && (cd /runtime/usr/local/lib/p11lab/isoapplet && sha256sum jcardsim.jar && find classes wrapper -type f | sort | xargs sha256sum) >> /runtime/usr/share/p11lab/build/module-hashes.sha256 \
 && printf '%s\n' 'opensc unpatched; ./bootstrap; ./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-tests --disable-doc --disable-man; make -j2' \
      'isoapplet compiled from frozen v0.6.1 source with frozen javac against the sealed jcardsim 3.0.6.0 jar (sorted sources; double-compile byte-identical)' \
      'jcardsim jar from Maven Central by sealed sha256 (source build needs the proprietary Oracle JavaCard SDK); wrapper is P11Lab-authored' \
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
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-opensc-isoapplet /usr/local/bin/pkcs15-init \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/reader.conf.d/vpcd /usr/local/etc/opensc.conf /usr/local/share/opensc/pkcs15.profile /usr/local/share/opensc/isoApplet.profile \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && test ! -e /run/pcscd && ln -s /run/p11lab/opensc-isoapplet/pcscd /run/pcscd \
 && test "$(readlink /run/pcscd)" = /run/p11lab/opensc-isoapplet/pcscd \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/opensc-pkcs11.so /usr/local/lib/libopensc.so.13 /usr/local/bin/pkcs15-init /usr/lib/pcsc/drivers/serial/libifdvpcd.so.0.11 /usr/sbin/pcscd /usr/local/bin/p11lab-opensc-isoapplet /usr/lib/jvm/java-21-openjdk-amd64/bin/java /usr/lib/jvm/java-21-openjdk-amd64/lib/server/libjvm.so > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libpcsclite.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -f /lib/x86_64-linux-gnu/libpcsclite.so.1 \
 && test -x /usr/sbin/pcscd \
 && ! test -e /usr/bin/pkcs11-tool && ! test -e /usr/bin/opensc-tool && ! test -e /usr/bin/openssl \
 && ! test -e /usr/bin/python3 && ! test -e /usr/bin/gcc && ! test -e /usr/bin/make \
 && ! test -e /usr/bin/javac && ! test -e /usr/bin/java \
 && ! test -e /usr/local/bin/vicc && ! test -e /usr/local/bin/vpcd-config \
 && ! test -e /usr/local/bin/sc-hsm-tool \
 && ! test -e /usr/local/lib/p11lab/onepin-opensc-pkcs11.so && ! test -e /usr/local/lib/p11lab/pkcs11-spy.so \
 && ! test -e /usr/local/lib/libopensc.a && ! test -e /usr/local/lib/libopensc.la \
 && grep -q 'FRIENDLYNAME "Virtual PCD"' /etc/reader.conf.d/vpcd \
 && test -f /usr/lib/pcsc/drivers/serial/libifdvpcd.so \
 && test -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java \
 && test -f /usr/local/lib/p11lab/isoapplet/jcardsim.jar \
 && test -f /usr/local/lib/p11lab/isoapplet/classes/net/pwendland/javacard/pki/isoapplet/IsoApplet.class \
 && test -f /usr/local/lib/p11lab/isoapplet/wrapper/IsoAppletCard.class \
 && test -f /usr/local/share/opensc/pkcs15.profile \
 && test -f /usr/local/share/opensc/isoApplet.profile \
 && for name in $(cut -d' ' -f2 /usr/share/p11lab/build/runtime-debs.txt | cut -d_ -f1); do test -f "/usr/share/doc/$name/copyright" || { echo "missing notice: $name"; exit 1; }; done
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
