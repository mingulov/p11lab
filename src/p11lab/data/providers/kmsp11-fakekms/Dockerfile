# SPDX-License-Identifier: Apache-2.0
# Google kmsp11 client built from source with a sealed Bazel closure, plus a
# co-located fakekms mock and provisioning helper built from a sealed Go
# module closure. All dependency bytes are hash-verified; both compilers run
# with no network resolution. The C++ module links only the frozen Debian
# base libm/libc/libstdc++/libgcc; the Go binaries are static.
ARG BASE_IMAGE=docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c
ARG GOLANG_IMAGE=docker.io/library/golang@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
FROM ${GOLANG_IMAGE} AS golang
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
COPY --from=golang /usr/local/go/ /usr/local/go/
ENV GOROOT=/usr/local/go PATH=/usr/local/go/bin:$PATH P11LAB_GO=/usr/local/go/bin/go
ENV HOME=/build/home GOCACHE=/build/go-cache GOMODCACHE=/build/go-modcache
RUN mkdir -p /build/home /build/go-cache /build/go-modcache \
 && go version > /tmp/go-version.txt && cat /tmp/go-version.txt
COPY source.tar source.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/kms && tar -xf source.tar -C /build/kms
RUN cd /build/kms \
 && test -f WORKSPACE && test -f go.mod && test -f go.sum \
 && grep -q 'go_download_sdk' WORKSPACE \
 && grep -q 'cloud.google.com/go/kms v1.25.0' go.mod \
 && test -f fakekms/fault/faultpb/fault.pb.go \
 && test -f fakekms/fault/faultpb/fault_grpc.pb.go \
 && test -f p11lab-bootstrap/main.go
COPY bazel-deps.json /tmp/bazel-deps.json
COPY go-modules.json /tmp/go-modules.json
COPY freeze-bazel.py freeze-gomod.py /tmp/
RUN python3 /tmp/freeze-bazel.py \
 && /build/bazel-bin/bazel --output_base=/build/bazel-probe version > /tmp/bazel-version.txt \
 && cat /tmp/bazel-version.txt
RUN P11LAB_GO=/usr/local/go/bin/go python3 /tmp/freeze-gomod.py
RUN --network=none cd /build/kms \
 && HOME=/build/home GOPROXY=file:///build/goproxy GOSUMDB=off GOFLAGS=-mod=mod \
      /build/bazel-bin/bazel --output_base=/build/bazel-out build --jobs=2 -c opt \
      --copt=-Wno-error=discarded-qualifiers \
      --distdir=/build/bazel-distdir --repository_cache=/build/bazel-repocache \
      --experimental_repository_disable_download \
      //kmsp11/main:libkmsp11.so \
 && test -f /build/bazel-out/execroot/com_google_kmstools/bazel-out/k8-opt/bin/kmsp11/main/libkmsp11.so
RUN --network=none cd /build/kms \
 && GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=0 \
      go build -trimpath -o /build/fakekms ./fakekms/main \
 && GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=0 \
      go build -trimpath -o /build/p11lab-kmsp11-bootstrap ./p11lab-bootstrap \
 && test -f /build/fakekms && test -f /build/p11lab-kmsp11-bootstrap
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -o /tmp/p11lab-kmsp11
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/kmsp11-fakekms \
 && cp /build/bazel-out/execroot/com_google_kmstools/bazel-out/k8-opt/bin/kmsp11/main/libkmsp11.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/fakekms /build/p11lab-kmsp11-bootstrap /runtime/usr/local/bin/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libkmsp11.so \
      /runtime/usr/local/bin/fakekms /runtime/usr/local/bin/p11lab-kmsp11-bootstrap \
 && cp /tmp/p11lab-kmsp11 /runtime/usr/local/bin/ \
 && cp /build/kms/LICENSE /runtime/usr/share/licenses/kmsp11-fakekms/LICENSE.kms-integrations \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/kmsp11-fakekms/ \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/kmsp11-fakekms/build-only-pkcs11.h \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp /tmp/go-version.txt /tmp/bazel-version.txt /runtime/usr/share/p11lab/build/ \
 && cp /tmp/bazel-deps.json /tmp/go-modules.json /build/bazel-fetch-inventory.json \
      /build/gomod-inventory.json /runtime/usr/share/p11lab/build/ \
 && cp /build/kms/go.mod /build/kms/go.sum /build/kms/WORKSPACE /runtime/usr/share/p11lab/build/ \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && printf '%s\n' 'bazel build --jobs=2 -c opt --copt=-Wno-error=discarded-qualifiers --distdir --repository_cache --experimental_repository_disable_download //kmsp11/main:libkmsp11.so' \
      'GOPROXY=off go build -trimpath CGO_ENABLED=0 ./fakekms/main ./p11lab-bootstrap' \
      'patches=[01-workspace-sdk-pin,02-faultpb-generated,03-kms-bump-v1.25.0,04-p11lab-bootstrap]' \
      > /runtime/usr/share/p11lab/build/options.txt \
 && mkdir -p /runtime/usr/share/licenses/kmsp11-fakekms/bazel-deps \
 && python3 -c 'import json,shutil; from pathlib import Path; deps=json.loads(Path("/tmp/bazel-deps.json").read_text()); [shutil.copytree(Path("/build/bazel-out/external")/a["repo"], Path("/runtime/usr/share/licenses/kmsp11-fakekms/bazel-deps")/a["repo"], ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright","authors","patents"))]) for a in deps["archives"]]' \
 && mkdir -p /runtime/usr/share/licenses/kmsp11-fakekms/go-modules \
 && python3 -c 'import shutil; from pathlib import Path; cache=Path("/build/go-modcache"); out=Path("/runtime/usr/share/licenses/kmsp11-fakekms/go-modules"); [shutil.copytree(p, out/(str(p.relative_to(cache)).replace("/","+").replace("@","_at_")), ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright","authors","patents"))]) for p in sorted(cache.rglob("*@*")) if p.is_dir()]' \
 && python3 -c 'import shutil; from pathlib import Path; [shutil.copytree(Path("/build/bazel-out/external")/r, Path("/runtime/usr/share/licenses/kmsp11-fakekms/bazel-deps")/r, ignore=lambda d,n: [x for x in n if not Path(d,x).is_dir() and not any(w in x.lower() for w in ("license","licence","copying","notice","copyright","authors","patents"))]) for r in ("com_github_golang_protobuf","org_golang_google_protobuf")]' \
 && ldd /runtime/usr/local/lib/p11lab/libkmsp11.so /runtime/usr/local/bin/p11lab-kmsp11 > /runtime/usr/share/p11lab/build/linked-dependencies.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-kmsp11 \
      /usr/local/bin/fakekms /usr/local/bin/p11lab-kmsp11-bootstrap \
      /usr/local/lib/p11lab/libkmsp11.so \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libkmsp11.so /usr/local/bin/p11lab-kmsp11 > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libstdc++.so.6' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libgcc_s.so.1' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q '/lib/x86_64-linux-gnu/libc.so.6' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
