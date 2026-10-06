# SPDX-License-Identifier: Apache-2.0
# Optional source-only OCI wrapper. No runtime, binary debug or base image.
FROM scratch
COPY files/ /source/
