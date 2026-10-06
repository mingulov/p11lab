# SPDX-License-Identifier: Apache-2.0
ARG PROVIDER_IMAGE
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
COPY consumer/ /consumer/
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic /consumer/smoke.c /consumer/p256.c -ldl -o /p11lab-smoke \
 && cc --version > /consumer/compiler.txt \
 && ldd /p11lab-smoke > /consumer/linked-dependencies.txt
FROM ${PROVIDER_IMAGE}
COPY --from=builder /p11lab-smoke /usr/local/bin/p11lab-smoke
COPY --from=builder /consumer/ /usr/share/p11lab-consumer/
LABEL org.p11lab.consumer="independent-c-smoke-v1" org.p11lab.admission="unreviewed-test-only"
