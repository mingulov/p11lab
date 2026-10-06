# Consumer source and license provenance

`smoke.c`, `p256.c`, `p256.h`, `verify.py`, `README.md`, this document, and the test
assets are original P11Lab material under Apache-2.0. The complete license is in
[LICENSE](LICENSE). They contain no migrated provider recipe or upstream patch.
The P256 OID, group order, SPKI structure and test generator coordinates implement
published mathematical/ASN.1 conventions; they are not an imported toolkit.

`vendor/pkcs11.h` is copied verbatim from the p11-kit project:

- Repository: <https://github.com/p11-glue/p11-kit>
- Revision: `5a2749ed7b7dda5e9af7f3c29e52ca39532930cb`
- Upstream path: `common/pkcs11.h`
- Immutable source:
  <https://raw.githubusercontent.com/p11-glue/p11-kit/5a2749ed7b7dda5e9af7f3c29e52ca39532930cb/common/pkcs11.h>
- SHA256: `9b396c5b61c52d108740357fb944445a22d8ca370d8b636368b6dfa7cee66bc4`
- Modifications: none.
- Copyright notices: g10 Code GmbH (2006, 2007), Andreas Jellinghaus (2006),
  Red Hat, Inc. (2017, 2021-2025).
- License evidence: the header's retained opening notice grants unlimited
  permission to copy/distribute, with or without modifications, as long as that
  notice is preserved. It includes the original warranty disclaimer. The actual license text
  retained in the file is authoritative. This header is not relicensed under
  P11Lab's Apache-2.0 license.
- Distribution obligation: preserve the complete original notice. No additional
  source-distribution obligation is stated in that file's grant. Distribute the
  vendored header and this provenance with the consumer sources.

The application builds against this header only; it neither links p11-kit nor
requires its runtime. Dynamically loaded providers and optional OpenSSL/Python
installations remain separately supplied dependencies with their own licensing.
Their runtime distribution and image-content eligibility are reviewed by the
owning packaging recipes. This source-level provenance is not a blanket grant to
publish arbitrary providers or runtime images.
