This runtime contains Debian components, SoftHSM and P11Lab material under their
own grants. THIRD-PARTY-NOTICES.txt preserves the applicable original notices,
including sqv's statically incorporated libraries and Rust attribution candidates.

A P11Lab distributor must provide the digest-matched source-only companion and
catalogue receipt alongside access to this binary. The receipt identifies exact
binary, source archive/OCI, platform and SPDX hashes. Source must be anonymously
retrievable by immutable identity before the binary becomes publicly accessible.
An unreviewed local image or private source upload does not satisfy this gate.

The source companion contains complete retained Debian source families, SoftHSM
sources, P11Lab sources, ordered patches, licenses and portable BUILD.md directions.
Use its SHA256SUMS and inventory.json to verify the extracted files. Complete
sources and the packaged rebuild/recombine instructions support modifying sqv's
LGPL libraries. Compatible replacements of its native LGPL shared libraries are
permitted. P11Lab imposes no restriction on modification or debugging modifications.

Distributors must keep matching sources accessible while corresponding binaries
remain available and for any additional applicable license duty. CI artifact
expiry and candidate cleanup must not remove required source or notice material.
The SPDX document supplements these materials and does not replace them.
