# SPDX-License-Identifier: Apache-2.0
# LOCAL-ONLY: fixed-credential, file/NOR simulation; migrated grants unresolved.
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
COPY source.tar source.sha256 dependency-0.tar dependency-0.sha256 dependency-1.tar dependency-1.sha256 dependency-2.tar dependency-2.sha256 /tmp/
# The shared source resolver applies the ordered patches to the named libhal
# dependency. No patched prepared checkout or development mount is a build input.
RUN cd /tmp && sha256sum -c source.sha256 dependency-0.sha256 dependency-1.sha256 dependency-2.sha256 \
 && mkdir -p /build/sw/pkcs11 /build/sw/libhal /build/sw/thirdparty/libtfm/tomsfastmath \
 && tar -xf source.tar -C /build/sw/pkcs11 \
 && tar -xf dependency-0.tar -C /build/sw/libhal \
 && tar -xf dependency-1.tar -C /build/sw/thirdparty/libtfm \
 && tar -xf dependency-2.tar -C /build/sw/thirdparty/libtfm/tomsfastmath
COPY stubs/stm-keystore.h /build/sw/libhal/stm-keystore.h
# The stock WHEEL bootstrap generator uses random salt. Consequently byte-for-
# byte module/keystore reproducibility is NOT asserted, despite fixed user/SO PINs.
RUN --network=none cd /build/sw/libhal \
 && python3 -c 'import Cryptodome, runpy, sys; sys.modules["Crypto"] = Cryptodome; runpy.run_path("utils/last_gasp_default_pin", run_name="__main__")' > last_gasp_pin_internal.h \
 && make -j2 -C /build/sw/thirdparty/libtfm \
 && make -j2 IO_BUS=none RPC_MODE=server RPC_TRANSPORT=loopback libhal.a \
 && make -j2 -C /build/sw/pkcs11 \
      LIBHAL_BLD=/build/sw/libhal LIBTFM_BLD=/build/sw/thirdparty/libtfm \
      -o /build/sw/libhal/libhal.a -o /build/sw/thirdparty/libtfm/libtfm.a libcryptech-pkcs11.so
# GNU make's documented -o preserves prebuilt archives. The reference wrapper
# neutralization patch is rejected; neither upstream wrapper Makefile is edited.
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I/build/sw/pkcs11 /tmp/provision.c -ldl -o /tmp/p11lab-cryptech
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/cryptech/libhal \
      /runtime/usr/share/licenses/cryptech/pkcs11 /runtime/usr/share/licenses/cryptech/libtfm \
 && cp /build/sw/pkcs11/libcryptech-pkcs11.so /runtime/usr/local/lib/p11lab/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libcryptech-pkcs11.so \
 && cp /tmp/p11lab-cryptech /runtime/usr/local/bin/ \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/cryptech/ \
 && cp /build/sw/pkcs11/pkcs11*.h /runtime/usr/share/licenses/cryptech/pkcs11/ \
 && cp /build/sw/thirdparty/libtfm/Makefile /build/sw/thirdparty/libtfm/tomsfastmath/LICENSE /runtime/usr/share/licenses/cryptech/libtfm/ \
 && cp /build/sw/libhal/last_gasp_pin_internal.h /runtime/usr/share/p11lab/build/ \
 && python3 -c 'from pathlib import Path; import re; roots={"pkcs11":Path("/build/sw/pkcs11"),"libhal":Path("/build/sw/libhal")}; [(Path("/runtime/usr/share/licenses/cryptech")/name/(p.name+".notice")).write_bytes(m.group(0)) for name,root in roots.items() for p in root.iterdir() if p.suffix in (".c",".h") and (m:=re.match(rb"\s*/\*.*?\*/",p.read_bytes(),re.S))]' \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && make --version > /runtime/usr/share/p11lab/build/make.txt \
 && printf '%s\n' 'IO_BUS=none RPC_MODE=server RPC_TRANSPORT=loopback RPC_CLIENT_LOCAL' \
      'make -j2; statically linked libhal.a + libtfm.a' \
      'loopback UDP port 17425 is unused on the LOCAL path' \
      'fixed user/SO PIN; test-only NOR file, no FPGA, no RNG fallback, no PIN-delay enforcement' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && ldd /runtime/usr/local/lib/p11lab/libcryptech-pkcs11.so /runtime/usr/local/bin/p11lab-cryptech > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-cryptech /usr/local/lib/p11lab/libcryptech-pkcs11.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libcryptech-pkcs11.so /usr/local/bin/p11lab-cryptech > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
