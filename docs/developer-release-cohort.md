# Developer release cohort

## M6: Cryptech rolling simulator

| Channel | Recipe | Local usability | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | Permanently unavailable: no Cryptech release tags | Unavailable | Unavailable | Blocked |
| rolling | Four frozen repository inputs, ordered libhal patches, file NOR stub | Persistent initialization and SO/user login; SHA-256 checked separately | `general-token` falsified by native RNG/key-generation failures; key operations unqualified | Local research only; migrated grants are `NOASSERTION` |

Build the local candidate with
`p11lab build cryptech --channel rolling --output-dir NEW_DIRECTORY`.
The output directory retains resolved sources,
patches, package/index readbacks and an exact local Docker engine image ID. This
operation builds locally and does not authorize distribution. No release build
is supported. Optional consumers need their own compatible application code;
the basic runtime contains no checker, compiler, tracing tools or datasets.

## Appendix: Cryptech

The module is `/usr/local/lib/p11lab/libcryptech-pkcs11.so` on Linux amd64 with
Debian 13 glibc 2.41. It statically links `libhal.a` and `libtfm.a` into one
module. Direct applications load it in their own process. Remote applications
need a compatible proxy daemon and client module; no remote/proxy lane is
qualified by this recipe. A Docker network cannot make a native module remote.

The three non-GitHub Cryptech repositories and their exact inputs are:

| Source | Revision | Observed grant |
| --- | --- | --- |
| [sw/pkcs11](https://git.cryptech.is/sw/pkcs11) | `a0a7d907c4ea47e3a3a963bb765a81b41294dd0d` | BSD-3-Clause source headers; RSA Cryptoki header terms retained |
| [sw/libhal](https://git.cryptech.is/sw/libhal) | `6f0d8236b8622a68f42284ed1314d8acd86c89ed` | BSD-3-Clause source headers |
| [sw/thirdparty/libtfm](https://git.cryptech.is/sw/thirdparty/libtfm) | `3189a37313b19c994482e78589072519ce6b9ac9` | BSD-2-Clause wrapper |
| [TomsFastMath gitlink](https://github.com/libtom/tomsfastmath/tree/09c7b2dce03356bcc8a70d51e4b125c35fe36496) | `09c7b2dce03356bcc8a70d51e4b125c35fe36496` | Public-domain dedication or WTFPL-2.0; this recipe selects WTFPL-2.0 |

The rolling lock retains original archive hashes, per-repository license
evidence, the complete Debian package/source closure, signed snapshot indexes,
recipe hashes and ordered patch hashes. Source resolution applies all four
patches to the named `libhal` dependency and fails on any patch error. Each
dependency is a distinct hash-checked build archive. Compilation runs without
network access and uses `make -j2`. GNU make `-o` selects prebuilt archives
without replacing the upstream PKCS#11 wrapper Makefiles. The stock WHEEL
bootstrap generator uses random salt, so frozen inputs do not imply a
byte-for-byte identical module or keystore on rebuilding.

**Both SO and user PINs are fixed to `fnord`. This is a credential backdoor for
local testing. It is not a general credential store.** Patch 0001 seeds fresh
PIN blocks with PBKDF2-HMAC-SHA256, 2000 iterations, a 64-byte output and an
all-zero 16-byte salt. Existing PIN blocks override those seeds. Stock
`C_InitToken`, `C_InitPIN` and `C_SetPIN` return
`CKR_FUNCTION_NOT_SUPPORTED` (`0x54`); P11Lab adds no PKCS#11 provisioning
implementation. Libhal's lower-level WHEEL/bootstrap setters are outside this
module's PKCS#11 provisioning API and are not used to set caller-selected PINs.

`P11LAB_PIN_FILE`/`P11LAB_SO_PIN_FILE` and their scalar equivalents are optional
assertions of that fixed credential. If supplied, they must equal `fnord`;
unequal inputs fail before token state is created or opened. Omitted inputs
use the known fixed PIN. Empty/malformed inputs and scalar/file conflicts fail.
Lifecycle logs and markers contain neither caller PIN bytes nor their hashes.
Applications still supply the actual fixed PIN when logging in. The native
token has slot ID `0`, token-present index `0` and the immutable label
`Cryptech Token`; a conflicting `P11LAB_LABEL` fails.

The exact migrated `stm-keystore.h` stub backs storage with
`keystore.bin`, 64 subsectors of 8192 bytes (512 KiB). Writes emulate NOR by
clearing bits with bitwise AND; erase restores `0xff`. The raw module defaults
to `/var/lib/cryptech`; `CRYPTECH_KEYSTORE_DIR` overrides the directory. The
managed entrypoint sets `/var/lib/p11lab/cryptech` and rejects conflicting
overrides so readiness checks and application state refer to the same store.
Use the supported state mount or `p11lab run --state-dir EXISTING_DIRECTORY`
for persistent state. Independent shards and clients need independent
processes and directories. The stub has no storage locking or crash-atomicity
guarantee; simultaneous consumers of one directory are unqualified.

`init` requires an empty caller-owned state root, lets module-native
`C_Initialize` create the keystore, proves both logins in a fresh process and
then writes a non-secret completion marker. Repeated initialization validates
existing state. Owned directories use mode `0700`, files `0600`.
`health` validates ownership, the exact file roster, marker, size and
read-only block/CRC structure before loading HAL and checking both logins.
It checks lifecycle/login readiness, not cryptographic qualification.
`exec -- ARGV...` performs the same readiness checks and executes arbitrary
application argv, preserving its exit status. Partial, corrupt, linked,
foreign-owned, busy or mismatched state fails and is retained. Stop all
consumers and explicitly remove the entire owned directory/volume to reset;
P11Lab never silently resets persistent state. No separate service is started.

The build uses `IO_BUS=none RPC_MODE=server RPC_TRANSPORT=loopback` with
`RPC_CLIENT_LOCAL`. UDP loopback port `17425` exists in upstream transport
code but is unused on this path. No FPGA, HSM hardware or network peer is
required for initialization/login. Patch 0004 supplies LOCAL keystore
startup because the PKCS#11 consumer never calls `hal_rpc_server_init`.

The stub is a simulation of the missing STM32 platform. It also replaces
platform allocation with `malloc/free`, disables bad-PIN sleep throttling and
returns `HAL_ERROR_CORE_NOT_FOUND` for FPGA I/O. These are disclosed changes
to platform/storage/authentication behavior, not hardware assurance. Patches
0002 and 0003 address build/link failures; patch 0004 changes LOCAL lifecycle.
All four patches and the stub have individual authorship, provenance, hashes
and changed-behavior records in
[FILE-NOTICES.txt](../src/p11lab/data/providers/cryptech/FILE-NOTICES.txt).
Their authorship does not supply a grant: all remain `NOASSERTION`, local-only.

The reference stub supplies no RNG or master-key core fallback.
`C_GenerateRandom` advertises RNG through native token metadata but returns
`CKR_FUNCTION_FAILED` (`0x06`). The general-token consumer reaches
`C_GenerateKeyPair` first, which also fails with `0x06`; P11Lab preserves both
errors. A passing SHA-256 oracle covers that digest
only. Key generation, import, signing, persistent private-key reopen, RSA,
ECDSA, AES, HMAC, certificates, hardware RNG and master-key protection remain
unqualified; unsupported mechanisms are not silently counted as passes.
Neither the simulator's narrow observations nor lifecycle tests qualify
Cryptech hardware or certify PKCS#11 behavior. Actual runtime/layer rights,
source delivery, optional derivatives and public distribution have separate
unmet gates.

## M6: wolfPKCS11 release and rolling software tokens

| Channel | Recipe | Local usability | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | wolfPKCS11 `v2.1.0-stable` plus wolfSSL `v5.9.2-stable`, exact revisions below | Native caller-PIN initialization, persistent file store, arbitrary application argv | Bounded P-256, persistent reopen, installed checker smoke and preferred proxy application lanes | Unreviewed; source-companion and actual-content admission required |
| rolling | Frozen wolfPKCS11 master plus its separately frozen wolfSSL master pairing | Same persistent runtime contract, independently built image | Same bounded lanes against this exact pair | Unreviewed; GPLv3 grants exist, distribution admission is separate |

Build either local candidate with
`p11lab build wolfpkcs11 --channel release --output-dir NEW_DIRECTORY` or
`p11lab build wolfpkcs11 --channel rolling --output-dir NEW_DIRECTORY`.
Each output retains both original source archives, resolved source/license
evidence, the sealed build context, package/index readbacks, local Docker engine
image identity and measured size. Compilation uses `make -j2` without network
access. Builds and local tests do not authorize publishing these images.

## Appendix: wolfPKCS11

The module is `/usr/local/lib/p11lab/libwolfpkcs11.so` on Linux amd64 with
Debian 13 glibc 2.41. It dynamically links the matching wolfSSL library shipped
at `/opt/wolfssl/lib`; installed `ldd` records identify the actual SONAME and
remaining libc/libm closure. The basic runtime contains the module, its library
closure, a small libc/dl lifecycle helper and notices. It contains no checker,
Python, compiler, OpenSC/pkcs11-tool, tracing, upstream examples or datasets.
Optional consumer, installed checker and provider-plus-proxy derivatives are
separate artifacts. Direct applications load the native module in their own
process. Remote applications require the compatible `pkcs11-proxy-ng` daemon and
`libpkcs11_proxy_ng_shim.so` client; a shared network alone is insufficient.

| Channel | [wolfPKCS11](https://github.com/wolfSSL/wolfPKCS11) | [wolfSSL](https://github.com/wolfSSL/wolfssl) | Pairing basis |
| --- | --- | --- | --- |
| release | `caeaaa5693ad7b4253d6bc585e642381033a6a87` (`v2.1.0-stable`) | `ac01707f552c611fbd135cc723b2682b3e7f80f2` (`v5.9.2-stable`) | Reference software-token stable pairing, verified and built |
| rolling | `15691bd6accf45cad54b44eb07839e08c11b50fc` | `2411aae3f74d0fc6ccb09d3d6dfdc69e7b32c632` | Upstream default-branch CI pairing, frozen on acquisition and tested with the pinned module |

Branch and tag names explain acquisition; full revisions and archive SHA-256
values in the channel locks control subsequent builds. No provider patches are
applied. Both locks use the shared multi-source resolver: wolfPKCS11 is the
primary source, wolfSSL is a named dependency, each has its own sealed archive,
and the resolved roster must match the locked roster. Debian base image,
packages, source-package archives, signed snapshot indexes, toolchain and recipe
assets are also pinned. Frozen inputs do not assert byte-identical rebuilds;
token seeds and generated keys are intentionally random.

Every reference software-token crypto flag is kept on both channels:

| Component | Flags | Verdict and reason |
| --- | --- | --- |
| wolfSSL | `--enable-shared --disable-static` | Keep a dynamic, replaceable runtime closure; omit static archives from runtime |
| wolfSSL | `--enable-aescfb` | Keep the reference's AES-CFB support; no broad CFB qualification claim |
| wolfSSL | `--enable-aesccm --enable-aesctr --enable-aescts --enable-aesecb --enable-aeskeywrap` | Keep backing implementations for the corresponding module mechanisms |
| wolfSSL | `--enable-cmac --enable-cryptocb` | Keep AES-CMAC and upstream crypto-callback support |
| wolfSSL | `--enable-hkdf --enable-keygen` | Keep derivation and RSA/EC key generation coverage |
| wolfSSL | `--enable-pwdbased --enable-scrypt` | Keep password/PIN derivation and reference prerequisites |
| wolfSSL | `--enable-rsapss --enable-sha3` | Keep RSA-PSS and SHA-3 coverage |
| wolfSSL | `-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT` in `C_EXTRA_FLAGS` | Keep public multiprecision and direct RSA interfaces used by the module |
| wolfSSL | `-DHAVE_AES_ECB -DHAVE_AES_KEYWRAP` in `C_EXTRA_FLAGS` | Keep the reference's explicit compatibility defines along with configure selections |
| wolfPKCS11 | `--enable-aeskeywrap --enable-aesctr --enable-aesccm --enable-aesecb --enable-aescts` | Keep advertised wrap, CTR, CCM, ECB and CTS module paths |
| wolfPKCS11 | `--enable-aescmac --enable-pbkdf2` | Keep AES-CMAC and PBKDF2 module paths |

Only installation prefixes change: wolfSSL uses `/opt/wolfssl`, wolfPKCS11 uses
`/opt/wolfpkcs11` in the builder. `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH` select
that wolfSSL installation; this module's Autotools build additionally needs
`CPPFLAGS=-I/opt/wolfssl/include` and `LDFLAGS=-L/opt/wolfssl/lib`. The module
recipe explicitly selects shared libraries and excludes static ones. The
non-PQC selection adds `--disable-mldsa --disable-mlkem` to wolfSSL because its
SHA-3 configuration can enable ML-KEM by default, and adds
`--disable-pkcs11v32 --disable-mldsa --disable-mlkem` to wolfPKCS11. The optional
reference PQC enable flags are excluded; no advertised non-PQC mechanism is
removed to obtain a passing report.

Caller-selected SO and user PINs are supported through native `C_InitToken`,
`C_Login(CKU_SO)` and `C_InitPIN`. The helper also proves user login during
initialization. Token state is created at runtime with caller PINs and a
selectable label. First `init` requires `P11LAB_PIN_FILE` and `P11LAB_SO_PIN_FILE`, or the shared
scalar equivalents. Use private files where possible. Each PIN is 4–32 bytes
after the common single-line parser removes one optional trailing LF; empty,
multiline, NUL, oversized and conflicting scalar/file inputs fail before owned
state is created. Scalars are unexported before child commands; provisioning
receives PINs through inherited anonymous pipes. Logs, receipts and completion
markers contain no PIN bytes or their hashes. Caller-selected credentials
reopen on both channels; the reference's default PINs fail with native
`CKR_PIN_INCORRECT` (`0xA0`). Native slot ID is `1`, token-present index is `0`.
`P11LAB_LABEL` defaults to `P11Lab` and permits 1–32 ASCII letters, digits,
spaces, dot, underscore or hyphen.

The managed state mount is `/var/lib/p11lab`; the adapter sets
`WOLFPKCS11_TOKEN_PATH=/var/lib/p11lab/wolfpkcs11` and rejects conflicting
overrides. Raw native consumers must set their own independent directory;
without the override, upstream falls back to `$HOME/.wolfPKCS11` on this
platform. The store contains `wp11_token_0000000000000001` and native
`wp11_obj`, symmetric/RSA/EC/DH key, certificate/trust/data companion files
with the same slot suffix and 16-hex object index. Fresh metadata is 204 bytes;
object type entries extend it by eight bytes each. Upstream uses temporary
`wp11_tmp_*` files and replacement for individual file writes. This does not
qualify cross-file transactions, concurrent processes or crash durability.

`init` requires an empty caller-owned directory, takes `.init-lock`, provisions
the token through the module and writes an exact non-secret completion marker
only after success. Compatible repeated initialization validates existing state
and preserves its PINs even if supplied PIN files change. `health` first
checks ownership, private file modes, links, allowed filenames, exact marker
bytes and bounded native metadata framing, then opens/finalizes the real module
and checks token flags, label and PIN limits. It checks lifecycle and metadata
readiness; application login and cryptographic verification are separate.
`exec -- ARGV...` performs readiness and preserves arbitrary argv and exit status.
Partial, corrupt, linked, foreign-owned, occupied or mismatched state is retained
and refused. Direct calls to the provisioning helper refuse an initialized token.

Directories use `0700` and files `0600`. Serialize all consumers of one store,
including readiness opens; independent shards and clients need independent
directories/processes. Applications should close sessions, finalize the module
and stop all processes before reset. Reset is explicit caller removal/replacement
of the entire owned state directory/volume. There is no silent reset or service
to supervise and no provider `server`/`server-ready` operation.

Both repositories are GPLv3-or-commercial. P11Lab relies on the GPLv3 grant
and holds no commercial license. Their source/header notices also preserve
GPLv3-or-later wording. The wolfSSL `LICENSING` listed-software GPLv2 alternative
is not used. The original Apache-2.0 provisioning source does not relicense the
upstream GPL header or combined executable. Matching Corresponding Source,
used headers, generated configuration, build/install instructions and notices
are required for applicable GPL distribution. Bundled LibTomMath/TomsFastMath,
ChaCha and Poly1305 attributions, architecture assembly notices, conservative
source comment notices and complete GPL texts are retained. Source archives
also contain test/certificate/key bundles with separate review needs; those
tools/data are excluded from the runtime payload. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/wolfpkcs11/FILE-NOTICES.txt).
The actual image layers, Debian/compiler runtime content, source-companion
admission and digest-bound source delivery remain distinct unfinished gates.

The reference also has TPM/fwTPM and ASAN/UBSAN Dockerfiles. Those are excluded,
as are PQC/PKCS#11 v3.2, FIPS and hardware assurance. Local qualification is
bounded to lifecycle, caller-PIN behavior, P-256 generation/signing and persistent
key reopen with an independent positive/altered-message oracle, installed
23-node checker smoke and a compatible preferred-proxy application lane.
Mechanism-list checks establish presence only. Remaining RSA/AES/HMAC/KDF/digest
mechanisms, key import variants, multiple simultaneous clients, crashes, wider
checker matrices, proxy-host checker, other architectures/libcs and hardware
remain unqualified. Each installed checker smoke completed 23 observations:
20 passed, two v3.2 checks skipped, and empty-input SHA-256 was classified as an
expected failure after native `CKR_ARGUMENTS_BAD`. This finding is retained
without changing provider behavior. None of these checks supplies provider-wide
certification or public-distribution approval.
