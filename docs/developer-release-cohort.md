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

## M6: pkcs11rs rolling software token

| Channel | Recipe | Local usability | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | Unavailable; upstream has no release tags | No release artifact | No release qualification | Unavailable |
| rolling | Original catalogue revision plus four separately frozen supporting repositories | Native caller-PIN initialization, persistent encrypted file store, arbitrary application argv | Bounded P-256, persistent reopen, installed checker smoke and preferred proxy application lanes | Unreviewed; actual-content and source-companion admission required |

Build the local candidate with
`p11lab build pkcs11rs --channel rolling --output-dir NEW_DIRECTORY`.
The public build acquires and verifies all five source archives, freezes the
recipe and crate closure, compiles without network access and retains package,
signed-index, runtime image-identity and measured-size receipts. No initialized
token or credentials are baked into the image. Local builds and tests do not
authorize publication.

## Appendix: pkcs11rs

The module is `/usr/local/lib/p11lab/libpkcs11rs.so` for Linux amd64, Debian 13
glibc 2.41. Its dynamic closure is libc, libm, libgcc_s and the system loader.
The basic runtime contains the module, a libc/dl provisioning helper, lifecycle
adapter and notices; Rust, Python, compilers, checker dependencies, OpenSC,
tracing, test datasets and virtual-device executables are excluded. Compatible direct
applications load the module in their own process. Remote applications require
the matching `pkcs11-proxy-ng` daemon and `libpkcs11_proxy_ng_shim.so`; a shared
container network alone does not expose a native module.

| Repository | Frozen revision | Build role |
| --- | --- | --- |
| [pkcs11rs](https://github.com/qpernil/pkcs11rs) | `646736043d1ce4949d812ed9e161949e635121c4` | Original catalogue stub, verified upstream; module and internal platform-credential/yubihsm-auth-client crates |
| [software-key-core](https://github.com/qpernil/software-key-core) | `903e7fe3b94b37d96b2d6cd42593dba821f62383` | Mandatory software cryptography and `x509-validation` feature |
| [virtual-yubikey](https://github.com/qpernil/virtual-yubikey) | `dc2941a8ac2e5af51fabad6434e6c1488b130da7` | Required optional-dependency manifest only; device code is not compiled |
| [virtual-yubihsm](https://github.com/qpernil/virtual-yubihsm) | `d71705ca4b298c1945fe05bd9aec824ec1e7b4ad` | Required optional/test/workspace-dependency manifest only; device code is not compiled |
| [signatures](https://github.com/qpernil/signatures) | `e06d2e28699428fbcc135c388516883bbb71f170` | Exact Cargo.lock Git source; only `ml-dsa` compiles |

The reference's older software-key-core revision lacks the required
`x509-validation` feature. The supporting software/virtual revisions above were
resolved once at or immediately before the unchanged module revision's commit
time, matching its upstream CI sibling layout and frozen lock. The five
repositories are the minimum inputs for the unmodified Cargo manifests: even
disabled path dependencies must be present for resolution. USB gadget and
display repositories belong to the virtual-device executable workspaces;
those workspaces are not selected by this package build. Neither repository
is acquired or consumed. No provider patches, manifest pruning, synthetic
dependency packages or default features are used.

The shared multi-source resolver seals each repository independently and checks
the exact resolved roster. Rust 1.98.1 is pinned by the same platform-specific
OCI digest used by the other Rust recipes; the upstream minimum is 1.94.
The exact upstream `Cargo.lock`, 290 hash-verified registry archives and one
separately sealed Git source form the full resolution closure. The
`freeze-crates.py` builder helper constructs directory sources, preserves the
upstream Cargo alias configuration and inherited Git-workspace lint settings,
and inventories every file. Compilation is
`cargo build --locked --offline --release -p pkcs11rs --no-default-features --jobs 2`.
The retained normal/build dependency tree excludes virtual devices, native
hardware, HIDAPI, PC/SC, USB gadget and display code. The closure also includes
uncompiled workspace/target/test packages; their notices do not imply runtime
inclusion. Input identity is deterministic; bit-identical binary rebuilds are
not asserted and token master keys/nonces are intentionally random.

The adapter enforces `PKCS11RS_HARDWARE_DISCOVERY=0`,
`PKCS11RS_SOFTWARE_SLOTS=p11lab` and
`PKCS11RS_TOKEN_STORAGE=/var/lib/p11lab/pkcs11rs`. Conflicting overrides and
remote `PKCS11RS_YUBIHSM_URLS` controls are refused. The fixed software name
provides stable storage identity; `P11LAB_LABEL` controls the initialized token
label and defaults to `P11Lab`. Labels permit 1–32 ASCII letters, digits,
spaces, dot, underscore or hyphen. Native slot ID is `0`, token-present index
is `0`; no hardware slot is advertised by this recipe.

First `init` requires caller-selected SO and user PINs, through
`P11LAB_SO_PIN_FILE` and `P11LAB_PIN_FILE` or their shared scalar equivalents.
The common parser removes one optional trailing LF and refuses empty,
multiline, NUL, oversized and conflicting inputs. Native PINs are 8–1024 UTF-8
bytes. Scalars are unexported before child commands; inherited pipes pass
credentials to `C_InitToken`, SO login and `C_InitPIN`, followed by a user-login
proof. Native errors remain visible. Invalid UTF-8 can fail natively, retaining
partial state. Caller credentials reopen successfully; both roles reject the
reference's fixed PIN with native `CKR_PIN_INCORRECT` (`0xA0`). PINs and their
hashes are absent from adapter logs, receipts and completion markers.

Bind a caller-owned state directory at `/var/lib/p11lab`. The token lives below
`pkcs11rs/tokens-v1/software-name-7031316c6162` (hexadecimal `p11lab`). Native
`private-keys-v1/header-<20-digit-generation>.cbor` files hold encrypted,
role-specific master-key wrappers; initialization ends at generation 2.
Public encrypted objects are under `public-objects-v1/objects`, and private
encrypted objects under `private-keys-v1/records/objects`, with immutable
`sha3-256-<64-hex-digest>.cbor` names. Public and private master keys are
separate; the SO role cannot unlock private records. The recipe creates the
complete new directory roster with `0700`, including on default-ACL/setgid
mounts; files use `0600`. It never repairs permissions on occupied state.
Native storage requires hard-link-capable local filesystems. Concurrent/crash
durability and PIN rotation remain unqualified here.

`init` requires empty owned state, takes `.init-lock` and writes an exact
non-secret `complete` marker only after native provisioning succeeds. Compatible
repeated initialization checks readiness and preserves existing credentials,
including when supplied PIN files change. `health` validates the entire static
directory/file roster, ownership, modes, links, file bounds and exact marker
before initializing the real module and checking token flags, label and PIN
limits. Header decoding and authentication remain native operations; malformed
headers retain `CKR_DATA_INVALID`. This is metadata/lifecycle readiness;
applications authenticate and verify cryptography separately. `exec -- ARGV...`
checks readiness and preserves argv and exit status. Partial, linked, foreign,
occupied, busy or conflicting state is retained and refused. The helper refuses
to reset an initialized token. There is no provider service or
`server`/`server-ready` operation.

Allocate independent state directories/processes per shard and client, and
serialize access to a store, including readiness checks. Applications should
close sessions, finalize the module and stop every consumer before an explicit
reset by replacing/removing the entire owned directory or volume. The proxy's
documented isolation limits still apply.

P11Lab selects Apache-2.0 for the five repositories' dual-licensed selected
artifacts, including RustCrypto's `signatures/ml-dsa`; their original MIT and
Apache texts and contributor notices remain intact. OASIS PKCS#11 3.2 headers
and generated bindings retain their own IPR-policy notices. Vendored HIDAPI
and Wycheproof vectors are source-only, uncompiled/excluded runtime inputs.
`crates.json` records every crate's declared expression, selected branch and
license/notice hashes; conjunctive ring/Unicode obligations and CDLA data terms
remain applicable, including the compiled public CA-root dependency. No LGPL
alternative is selected. Eleven resolution-only
crate archives carry manifest license declarations without packaged grant
texts, and require further source-delivery review; none compiles into this
Linux runtime. Runtime/source/whole-layer rights, base-package notices and
source-companion admission remain separate unfinished gates. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/pkcs11rs/FILE-NOTICES.txt).

Qualification is bounded to lifecycle, caller PINs, P-256 generation/signing,
persistent key reopen with independent original/altered-message verification,
installed 23-node checker smoke and a preferred-proxy application lane.
Mechanism enumeration is presence evidence only. Other RSA/AES/HMAC/KDF/PQC
mechanisms, export/import variants, discovery PINs, PIN changes, concurrency,
crashes, hardware/virtual devices, broader checker matrices, proxy-host checker,
other platforms and public distribution remain unqualified. These observations
do not certify the provider.

## M6: pkcs11-to-cmd release and rolling file signers

| Channel | Recipe | Local usability | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | Verified upstream `v1.0.0`, frozen revision below | Runtime-generated private file keys, persistent certificates, native readiness, arbitrary application argv | Narrow explicit-mechanism RSA/P-256 signing and independent verification; common `signing` baseline falsified | Unreviewed; actual-content and source-delivery admission required |
| rolling | Verified `main`, currently the same upstream revision | Same contract, separate selector/build identity and local image | Same bounded native observations; discovery and token-label defects retained | Unreviewed; no public qualification claim |

Build either local candidate with
`p11lab build pkcs11-to-cmd --channel release --output-dir NEW_DIRECTORY` or
`p11lab build pkcs11-to-cmd --channel rolling --output-dir NEW_DIRECTORY`.
Each output retains original Git archives, source/license evidence, the sealed
context, actual package/index inventories, an exact local Docker engine image ID
and measured size. Builds are local and do not authorize distribution. The
[upstream release](https://github.com/siemens/pkcs11-to-cmd/releases/tag/v1.0.0)
was published on 18 March 2026; older reference material saying there are no
releases is stale. Both its tag and the acquired default branch resolve to
`8fddf3b4cec6bf5d4287f71f5c3c4a7cfc9c7aa3`. Their equality is verified,
while tag and branch selector identities remain distinct.

## Appendix: pkcs11-to-cmd

The Linux amd64/glibc 2.41 module is
`/usr/local/lib/p11lab/libpkcs11-to-cmd.so`. It dynamically links the pinned
Debian system OpenSSL `libcrypto.so.3` and the base's C++/libc closure. The
runtime additionally bundles the hash-frozen Debian OpenSSL CLI, its default
configuration and `xxd`, needed by the signing command. Build readbacks identify
those files and their dependencies separately from the 78 registered base
packages. The basic image contains no checker, Python, datasets, OpenSC tool,
tracing, compiler or build system. Compilation uses C++17, CMake Release,
`COVERAGE=OFF` and `cmake --build -j2` without network access. Upstream's default
coverage instrumentation is disabled to keep test instrumentation and writes out
of the runtime; no provider patches change its native API behavior.

**This provider has no authentication. Possession of the private key files and
permission to execute the command confer signing authority.** Token metadata
omits `CKF_LOGIN_REQUIRED`, and minimum/maximum PIN lengths are both zero.
Native `C_Login` and `C_Logout` return success unconditionally, including calls
with absent/arbitrary PINs and invalid session handles or roles. They do not
check credentials. `C_InitToken`, `C_InitPIN` and `C_SetPIN` return
`CKR_FUNCTION_NOT_SUPPORTED` (`0x54`). The descriptor declares no PIN inputs;
the adapter rejects supplied PIN controls instead of suggesting they protect
keys. There is no PIN parser or native credential-provisioning path.

The managed sparse layout has RSA-2048 in slot ID `0`, an empty slot `1`, and
P-256 in slot ID `2`. The native labels are immutable `pkcs11-to-cmd-0` and
`pkcs11-to-cmd-2`. Upstream fills their unused bytes with NULs, contrary to the
standard space-filled label representation. Its `C_GetSlotList(CK_TRUE)` also
returns the empty slot, so token-present indices are not assumed to equal a
filtered roster. P11Lab preserves both observations and supports one native
session per process. It does not provide a general token.

First `init` requires an empty caller-owned writable `/var/lib/p11lab`, takes
`.init-lock`, and generates fresh RSA-2048/P-256 keys and self-signed certificates
at runtime. The image ships no generated key or upstream test key fixture.
Runtime generation is the managed provisioning mode; arbitrary caller-supplied
keys are not admitted by this recipe. The owned `pkcs11-to-cmd` directory is
`0700`; `rsa.key`, `rsa.pem`, `ec.key`, `ec.pem`, `wiring.env` and `complete` are
`0600`. Key files are sealed before OpenSSL writes private material, including
under inherited filesystem ACLs. The completion marker binds the artifact and
exact non-secret layout/wiring. Repeated compatible initialization validates and
preserves all key material. No silent reset occurs.

`health` validates the exact state roster, ownership, modes, link counts, size
bounds, marker and wiring before parsing the key/certificate pairs and opening
the real module. It checks key/certificate equality, RSA size, P-256 curve and
native key types/slot readiness. The small helper named `provision.c` is used
only for actual native readiness; it has no login or token-initialization calls.
Readiness is distinct from a successful signing operation or certificate trust.
`exec -- ARGV...` applies the same readiness and preserves application argv,
working directory and exit status. Partial, corrupt, linked, foreign-owned,
occupied or mismatched state is refused and retained. There is no card or daemon
to supervise and no provider `server`/`server-ready` operation.

`P2C_SLOT_CERT_0` and `P2C_SLOT_CERT_2` name the managed certificate files.
`P2C_CMD=/usr/local/bin/p11lab-p2c-sign` selects the signing-directory wrapper;
`P2C_DEBUG=0` is fixed. Equal wiring overrides are accepted; unequal controls,
extra slot certificates or supplied data/signature paths fail before opening
persistent state. Native `P2C_CERT` and `P2C_MECHANISM` are outputs selected by
the module. Each invocation reserves a distinct private directory under
`/run/p11lab`, with its own `P2C_DATA` and `P2C_SIG`. Use private writable tmpfs
there, independent of persistent keys. The wrapper runs upstream's unchanged
[sign-cmd-pkeyutl.sh](https://github.com/siemens/pkcs11-to-cmd/blob/8fddf3b4cec6bf5d4287f71f5c3c4a7cfc9c7aa3/tests/cmds/sign-cmd-pkeyutl.sh)
in that directory because its EC conversion additionally uses relative
`r.bin`/`s.bin`. All DigestInfo and ASN.1 conversion bytes remain upstream MIT
bytes, installed at `/usr/local/libexec/p11lab/pkcs11-to-cmd-sign`, SHA-256
`966f6fba1869f40f9249b5b6ab39bb98a33d9f6d8a97f9faddde8e31a43929eb`.
The command, key-file permissions and private data/signature paths are the trust
boundary. Trusted applications can still choose native controls themselves;
this is not an authentication service or key-access policy enforcement layer.

Serialize consumers of each key store and use separate state, processes and
control tmpfs for independent shards/clients. Close sessions, finalize the
module and stop all consumers before explicitly removing/replacing the entire
owned state to reset. Temporary signing files are scoped to the invocation and
cleared with its container/tmpfs; long-lived application processes must manage
their temporary-file lifetime. Concurrent consumers, crash durability and
hostile applications with key-file access remain unqualified.

The declared PKCS#11 2.40 function list returns `0x54` for mechanism discovery,
encryption, decryption, digesting, object creation/destruction, key generation,
wrapping/unwrapping, derivation, verification and RNG. These are adversarial
capability-honesty observations, preserved with the native errors and checker
classification. A low pass count or completed negative observation does not
become a runtime initialization failure; missing evidence is never a pass.

The common `signing` baseline requires mechanism discovery, native token/session
use and independently verified crypto. It is falsified here: the ordinary
P11Lab consumer cannot select the NUL-filled token label, and direct mechanism
discovery independently returns `0x54`. The provider-local
`pkcs11-to-cmd-signing` profile note records this supported-operation exception:
explicit native P-256 raw-digest signing works without login and passes an
independent OpenSSL original/altered-message oracle. RSA observations preserve
the upstream raw-digest `pkeyutl` behavior; standard DigestInfo/`dgst` RSA
compatibility is unqualified. These narrow observations do not qualify the
common consumer, fix discovery or normalize provider behavior.

Optional installed checker and preferred `pkcs11-proxy-ng` derivatives/client
bundles are separate artifacts. The shared `run_checker` launcher assumes a
selectable label and two PINs, and cannot launch this no-auth provider through
that path; its failed attempt and incomplete observation receipt remain explicit.
The explicit-index installed checker attempt freezes the 23-node smoke selection
but aborts in preflight on C_GetMechanismList returning 0x54: zero completed test
observations, exit 2, and evidence marked incomplete. This is a precise blocker
for the checker component, with no provider-local fallback or fabricated pass. Remote
applications need the compatible daemon and client shim; a Docker network alone
cannot make the native module loadable remotely. Proxy observations inherit the
selected version's isolation limits; wider transport/provider qualification is
not claimed.

The selected proxy successfully carries explicit P-256 signing and preserves
mechanism-discovery `0x54`, but it changes native NUL-filled token-label tails
to spaces. This metadata difference belongs to the proxy component and limits
direct/proxy equivalence. P11Lab does not use the proxy to qualify the common
label-selection baseline or repair the native labels. Returned proxy slot
handles are opaque and need not equal native numeric slot IDs.

The module and unchanged signing script are upstream MIT, Copyright 2025
Siemens; their license text, script headers and REUSE evidence are retained.
Original P11Lab wiring remains Apache-2.0. The ABI header, OpenSSL/`xxd` package
copyrights and all base package notices retain their own terms. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/pkcs11-to-cmd/FILE-NOTICES.txt).
The locks identify exact Debian binary/source archives and signed indexes;
actual layers, compiler runtime/header content and corresponding-source delivery
still require admission. Other curves/mechanisms, broad PKCS#11 compliance,
certificate trust/expiry, full checker matrices, other architecture/libc,
concurrency/crash behavior and public qualification remain unqualified.

## M6: OpenCryptoki release and rolling SWToken

OpenCryptoki has locked `release` and `rolling` runtimes using only its software
SWToken backend. Build through the installed package with
`p11lab build opencryptoki --channel release --output-dir NEW_DIRECTORY` or the
same operation with `--channel rolling`. Release `v3.27.0` is frozen at
`583d0128bb5ebfac263496bc8fe32d4aef440178`; the rolling `master` snapshot is
`b0769d6332d4d82b33991b89f2d2dc9d64142cbe`. Builds acquire these commits, verify
Git archive hashes, check the frozen Debian package/index inventories, and
compile with `make -j2`. They do not resolve a new branch tip or release tag.

Both channels use Debian OpenSSL 3.5.7 and its packaged legacy provider. Native
initialization and legacy DES encryption work with that pairing; hiding the
legacy module makes native initialization return `CKR_FUNCTION_FAILED`.
A separate source-built OpenSSL is unnecessary for these two frozen builds.
Neither channel includes a FIPS claim. The `general-token` profile is retained
on the bounded P-256 application evidence; this is not provider-wide qualification.

Local runtime, application, checker and proxy evidence has separate identities.
Every artifact remains unreviewed for distribution; these build operations do
not publish images or satisfy corresponding-source delivery requirements.

The current shared checker launcher drops the trusted NSS/preload environment
needed by the native provider: token preflight succeeds, but the checker child
returns native initialization error `0x6` with zero completed smoke observations.
The preferred proxy application signs and passes independent verification, but
the shared runner starts post-run health against the state before stopping its
live daemon; the required volume lease refuses that second operation. Overall
proxy lifecycle acceptance is blocked. Both issues belong to their shared
launchers and require separate fixes; the recipe preserves native errors and
state isolation. Its acceptance tests mark these two integration lanes as
expected failures while retaining their receipts and successful crypto evidence.

## Appendix: OpenCryptoki

The local module is `/usr/local/lib/p11lab/libopencryptoki.so` on Linux amd64,
glibc 2.41. Its SWToken module is `/usr/local/lib/p11lab/libpkcs11_sw.so`. Native
`pkcsslotd` is `/usr/local/sbin/pkcsslotd`; the P11Lab provisioning/supervision
adapter is `/usr/local/bin/p11lab-opencryptoki`. The runtime keeps Debian's
`libcrypto.so.3`, its exact legacy module and base library closure. It adds
hash-verified Debian `liblber.so.2` and `libnss_wrapper.so` bytes, with their
copyright records. It contains no compiler, checker, Python, datasets, tracing
requirement, OpenSC, `pkcs11-tool`, `pkcsconf` or `p11sak` consumer dependency.

**Execution identity.** Use a non-root UID and primary **GID 1001**. OpenCryptoki
requires its strength configuration to be root-owned, group-owned by its native
PKCS#11 group, and mode `0640`; the image retains this check with immutable
`/usr/share/p11lab/opencryptoki/strength.conf`, owned `0:1001`. NSS wrapper maps
the actual non-root caller UID to the native `p11lab` daemon account, using
private ephemeral passwd/group files. It does not alter native policy checks,
PIN checks or return values. The installed P11Lab runner uses the host UID/GID,
so its current supported host primary GID for this recipe is 1001. Other primary
groups require a separately reviewed variant or an owning-runner enhancement;
this recipe does not claim their acceptance. For direct Docker use, select the
required container group explicitly and make the bound state writable by the
selected UID. Root execution is refused to avoid the native daemon's root
privilege-drop/re-exec path.

**Daemon requirement and supervision.** Both frozen native SWToken builds fail
`C_Initialize` with `CKR_FUNCTION_FAILED` before daemon startup and again after
daemon shutdown. With the daemon, they enumerate slot 0, initialize and
authenticate the token, exercise native legacy DES encryption, and sign P-256
messages that an independent OpenSSL verifier accepts while rejecting altered
messages. The daemon manages native SysV shared memory, slots, locking and event
notifications, even for the software token.

`init`, `health` and `exec -- ARGV...` each launch the native daemon for their own
operation. The Linux supervisor becomes a child subreaper, waits for the native
launcher, adopts and verifies the daemon's native fork, gates on its socket and
a real module/token open, then monitors the provisioning/readiness child or
application. Native startup and library errors stay visible. Applications retain
separate argv elements and their exit status. A required daemon exit fails the
operation and stops its application; it is never silently restarted. Signals
stop the application process group before the daemon, with bounded terminate,
kill and reap handling. A persistent volume lease and an ephemeral service lease
prevent conflicting operations. Native daemon logs stay under ephemeral owned
state, with a 64 KiB bound; an exceeded bound fails the operation. Shutdown
removes owned sockets/pid state and native IPC after children stop. There is no
long-lived `server`/`server-ready` operation: the preferred proxy daemon is an
application launched through this same supervised `exec` operation.

**Slots, authentication and provisioning.** The generated configuration selects
exactly one SWToken in native slot ID `0`, token-present index `0`, with native
token-data version `3.12`. `P11LAB_LABEL` defaults to `P11Lab` and accepts 1–32
ASCII letters, digits, spaces, dot, underscore or hyphen. First `init` requires
caller-selected `P11LAB_PIN_FILE` and `P11LAB_SO_PIN_FILE`, or the corresponding
scalar environment inputs, with 4–8 bytes per PIN. Empty, conflicting,
multiline, NUL-containing and out-of-bound inputs are refused before state is
created; a file may have one trailing LF. Caller credential files remain outside
the persistent state. Prefer files to keep values out of Docker argv.

A fresh native SWToken authenticates `C_InitToken` against its upstream factory
SO credential. Passing the selected SO PIN directly to that fresh operation
returns `CKR_PIN_INCORRECT`; attempting `C_InitPIN` without SO login returns
`CKR_USER_NOT_LOGGED_IN`. The adapter uses the native factory authentication
once, logs in as SO, calls `C_SetPIN` to replace it with the caller's SO PIN,
then calls `C_InitPIN` for the caller's user PIN, logs out, closes and finalizes.
Selecting the factory SO value is refused. The old factory PIN and wrong user
PIN fail native login after provisioning. No initialized token or caller PIN is
baked into the image. The factory value remains an upstream bootstrap property,
not a caller default. Credentials reach provisioning over a bounded private
stdin pipe, are erased before application launch, and never enter native argv,
completion markers or durable logs.

**State and readiness.** Bind writable `/var/lib/p11lab` and provide private
writable ephemeral `/run/p11lab` plus `/tmp`, with a read-only image filesystem.
The persistent owned root is `/var/lib/p11lab/opencryptoki`. It contains
`opencryptoki.conf`, `complete`, the private `lease` file and the sole declared
symlink `strength.conf`, pointing to the immutable protected image file.
Upstream's configured local-state layout places token data in
`lib/opencryptoki/swtok/`: `NVTOK.DAT` (592 bytes for these builds), `MK_SO` and
`MK_USER` (40 bytes each), and the `TOK_OBJ/` object store/index. The sibling
`lib/opencryptoki/HSM_MK_CHANGE/` directory remains empty for SWToken. These are
provider-native encrypted/token metadata formats, not P11Lab credential receipts.
Sockets, locks, identity files and bounded daemon logs are under
`/run/p11lab/opencryptoki`. No state uses the system `/etc/opencryptoki` or
`/var/lib/opencryptoki` defaults.

Use separate volumes, containers, private PID/IPC namespaces and daemon control
state for independent shards/clients. Do not use host/shared IPC. Serialize all
operations against one state; a second container cannot acquire its volume
lease. Native process/session state is ephemeral, while token objects and
selected credentials survive restart. Arbitrary compatible applications load
the module within the supervised application lifetime and must close/finalize
their sessions normally. Applications that detach children into new sessions,
unbounded native stalls and power-loss recovery are unqualified surfaces.

Compatible repeated initialization ignores changed PIN files and preserves the
existing token. Before launching a daemon or loading a module, the adapter
refuses missing or incorrect-sized token files, changed configuration/marker
bytes, unexpected or hidden entries, unsafe links/hardlinks, changed protected
policy wiring and a busy `.init-lock`. Native readiness checks the exact slot,
label, initialized/user-PIN/login-required flags and completed PIN replacement.
It does not log in or validate an application's supplied PIN. A native failure
retains partial state; there is no automatic reset, credential replacement or
state-changing retry. Reset means explicitly stopping every operation and
removing/replacing the caller's disposable volume.

Native state/configuration redirects, OpenSSL provider/configuration overrides,
preload/identity overrides and tracing controls are rejected as recipe inputs.
The fixed system pairing and per-shard wiring are applied by the adapter.
Remote use requires the compatible pinned `pkcs11-proxy-ng` daemon/client shim;
a shared Docker network alone does not make a native module loadable remotely.
The proxy's documented isolation limitations still apply. Optional checker,
consumer and proxy derivatives keep their own source/package/content identities
and do not enlarge the basic runtime.

**Exclusions and licensing.** `icatok`, `ccatok`, `ep11tok`, `tpmtok`, `icsftok`
and `p11sak` are disabled in both builds; unused administration/KMIP utilities
are also disabled. ASan and s390x reference variants were not built. Wider
mechanisms, multiple concurrent clients, power-loss/crash recovery, other
architectures/libcs/groups, tracing, FIPS, provider-wide matrices and public
release delivery are not qualified by this bounded acceptance.

OpenCryptoki retains CPL-1.0 and its per-file terms, including the Apache-2.0
OpenSSL-derived `constant_time.h`. Excluded AIX BSD code and s390x Apache code
retain their source notices. P11Lab's original adapter remains Apache-2.0;
there are no upstream semantic or provisioning patches. CPL distributor source
access, source licensing, notices, object-code terms and applicable patent and
commercial-distribution provisions still require review and implementation.
The exact Git sources, generated build inputs, Debian package sources, copied
library notices and actual layers must be preserved and assessed for each
artifact. See [FILE-NOTICES.txt](../src/p11lab/data/providers/opencryptoki/FILE-NOTICES.txt).
Admission stays blocked pending whole-content review and digest-bound source
companions/distributor delivery; an SBOM or smoke success does not complete it.

## M6: NetHSM release and rolling module with frozen local server

| Channel | Frozen module source | Runtime contract | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | `v3.0.0`, `fb3f448df6033a6406c9dc034ea729e930fc5fdc` | Co-located supervised keyfender/etcd, persistent state, amd64/musl | `general-token` falsified by native public-handle cleanup; persistent P-256 assessed separately | BLOCKED: frozen server bytes have no verified source companion or complete notices |
| rolling | `main`, `49d0a21a83c031ad35f127f21db34de5116d5040` | Same frozen server and musl platform; distinct module source/artifact | Same native profile limitation, without error normalization | Same independent binary/source/license blocks |

The release selector is an annotated tag: tag object
`a59ef5ef3e8356fb06cbef5e8dd9b01c38abe0c3` peels to the recorded release commit.
Both module sources retain Apache-2.0. There are no upstream patches. The
server input and module channel are separate identities: neither module
channel promises a released, source-built or hardware-qualified server.

The existing shared build gate expects the base package roster to equal the
runtime roster. This recipe records the actual 16-package Alpine base,
27-package runtime and 69-package builder separately; the gate cannot issue a
successful artifact receipt for that difference. Its Debian/glibc installed
checker recipe and pinned wheel set also require a compatible musl counterpart.
These limitations belong to the shared components. Do not replace actual
inventories, relabel glibc bytes or interpret a missing lane as qualification.

The separate preferred-proxy derivative uses a musl daemon built from the
frozen shared proxy revision and crate lock. A static musl CLI supplies the
same verified bytes to the Alpine daemon image and the glibc client bundle;
the loadable client shim retains its frozen glibc build. Each build's source,
toolchain and binary identity is recorded separately. This composition keeps
the shared component-identity checks and lets a compatible glibc application
use the co-located musl provider remotely. It does not qualify additional
architectures, proxy versions or clients.

### Appendix: NetHSM input, platform, credential and lifecycle boundary

**Frozen binary server input.** The input is
`nitrokey/nethsm@sha256:4c9cf630aab7d4b9a76c7247844635d3dd1b78c34ff4fd473115cc59419f6e9b`.
Observed banners identify keyfender/NetHSM 5.0 (`fc28f32`) and etcd 3.6.13
(`b0f9ef1`, built with Go 1.25.11). Its matching-name source is observed at
NetHSM `fc28f323319e34edc680197da1991b477fe199ab` and etcd
`b0f9ef190952e6e66a778513097a02ee41220727`; version/digest agreement does not
verify a complete source/build attestation. No upstream signing attestation
was observed in this acquisition. All 11 upstream image layers were inventoried;
none contains a license or notice file. Observed source EUPL-1.2, etcd
Apache-2.0 and Go BSD-style notices are supplied separately and explicitly
remain an incomplete binary notice/source closure.

Only unchanged `keyfender.unix` and `etcd` bytes are copied into a clean,
digest-pinned Alpine parent. No upstream image layer, `/start.sh`, shell
provisioning default, TAP/debug/performance utility, initialized token or caller
credential is inherited. Observed certificate files are the public CA bundle
and its aliases; the NetHSM TLS identity is created at runtime. The binary's
compiled dummy platform device-key and failed-unlock fallbacks remain. They
prevent a complete no-embedded-credential or production-security claim and are
an additional distribution-review block. The software platform is declared
simulated; this does not qualify Nitrokey hardware or HSM security.

**Musl platform exception.** Direct applications load
`/usr/local/lib/p11lab/libnethsm_pkcs11.so` on Linux amd64/musl with loader
`/lib/ld-musl-x86_64.so.1`. The clean parent is Alpine 3.24.1, with BusyBox and
APK tooling rather than Debian/glibc tools. A glibc application/daemon/extension
cannot be copied into this runtime as if its dependency closure were compatible.
Separate proxy clients can use their own declared platform.

The musl Rust 1.98.1 toolchain is digest-pinned. Both upstream Cargo locks are
byte-identical; all 215 registry archives are pinned by their original lock
checksums and independently verified. The build reconstructs a sealed directory
source, then runs `cargo build --locked --offline --release --jobs 2` with
`RUSTFLAGS=-C target-feature=-crt-static`. Default features are retained and no
extra Cargo features are enabled. The module links musl libc only and uses
rustls/ring; the reference's `OPENSSL_STATIC` setting does not link OpenSSL in
these revisions. The separate HTTPS API helper uses dynamic libcurl and its
pinned Alpine OpenSSL 3.5.9 dependency. Its observed source revision and
archive hash are retained without claiming an equivalent Alpine rebuild.

**Credentials and native behavior.** First initialization requires the caller's
operator PIN and administrator SO input. Both use 10..200 printable ASCII
characters; input files follow the shared single-line secret contract. Native
API validation proves those passphrase bounds. `C_InitToken` and `C_InitPIN`
return native `0x54`, so provisioning explicitly calls `/provision` and creates
the Operator through `/users/operator`. Secrets travel through private stdin
pipes and in-memory HTTPS requests, never service argv or completion markers.
The unlock passphrase is independently generated at runtime. Loopback HTTPS
skips TLS peer verification on both the module (`danger_insecure_cert`) and the
supervisor; the 127.0.0.1-only binding is the transport boundary, not
certificate authentication.

`nethsm/admin`, `nethsm/unlock` and `nethsm/p11nethsm.conf` are private mode-0600
state. The module config includes operator username but no operator password;
the application's `C_Login` supplies the PIN. It includes the administrator
password because native key generation automatically uses administrator access.
Removing that access yields native `C_GenerateKeyPair=0x06`. Applications able
to read this config have administrator authority, including native import,
deletion and administrative operations; an operator login does not isolate them
from that configured authority. A wrong operator PIN returns native `0x103`.
Failed authentication can cause native rate limiting. The adapter adds no retry,
PIN replacement, error translation or provider semantic patch.

**Readiness, supervision and reset.** Supply caller-owned mode-0700 writable
`/var/lib/p11lab` and a private mode-0700 `/run/p11lab`. Each shard/client owns
its own volume, container, PID namespace and network namespace. No host/shared
networking or TAP capability is needed. Both keyfender listeners (8080/8443)
and both etcd listeners (2379/2380) bind to `127.0.0.1`; the module talks HTTPS
to `127.0.0.1:8443/api/v1`. No external server endpoint is part of this contract.

`init`, `health` and `exec -- ARGV...` use the same C supervisor. It holds the
volume lease and private service-control lock, starts direct native children,
waits for actual API state, and checks native slot 0/token-present index 0,
initialized flags and exact token label before executing an application.
Startup is bounded; each service log sink stores at most 64 KiB and drains
excess without changing native service state. Required-service death fails the
operation and terminates the application. Signal forwarding, bounded TERM/KILL
escalation and subreaper adoption/reaping clean up owned child processes.
The preferred proxy daemon uses the same supervised `exec` lifetime, so a
separate permanent `server`/`server-ready` API is unnecessary.

Repeated compatible init preserves existing PINs and keys and ignores changed
input credential files. Static checks reject a busy `.init-lock`, incompatible
exact-byte marker/config, foreign or hidden entries, unsafe links/hardlinks,
changed ownership/modes and missing/invalid etcd data before a native launch.
Clean restart unlocks an existing Locked server with its stored generated
passphrase; an Unprovisioned server behind a completion marker is refused.
Failed initialization retains partial state. Reset requires stopping all users
and explicitly replacing/removing disposable caller state; no automatic reset
or state-changing retry occurs.

An etcd `SIGKILL` can leave its native `0.tmp` WAL preallocation. Static
validation refuses that partial state without changing it. The service-death
check proves failure propagation and process cleanup, not crash recovery.
Clean shutdown/restart is the supported persistence path.

**Qualification limits.** The unchanged generated-key smoke preserves
`C_DestroyObject(public cleanup)=0x60` after private-key deletion invalidates the
public alias; `general-token` is falsified. Restricted persistent P-256
generation/signing is checked separately with original-message verification and
altered-message rejection. Those narrower observations do not qualify session
object semantics, wider mechanisms, concurrent clients, crash/power-loss
recovery, other architectures/libcs or hardware/security properties. Optional
checker/consumer/proxy artifacts have separate provenance and admission. The
basic runtime contains none of their Python, checker, dataset, compiler or
tracing dependencies.

Server bytes have no verified complete source companion. Alpine packages,
Rust incorporated runtime, OCaml/Go/server closure, embedded data, per-file
notices, corresponding-source/relinking obligations and anonymous source-first
delivery still require review. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/nethsm/FILE-NOTICES.txt).
Distribution remains blocked independently of local runtime or crypto results.

## M6: Siguldry release and rolling signing services with PKCS#11 module

| Channel | Frozen source | Runtime contract | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | tag `siguldry-pkcs11-2.2.0`, `43a7acf3fa898e22ffd935c0a641bbae68e98363` | Co-located supervised bridge/signer/server/client-proxy, persistent state, amd64/glibc | `signing` holds narrowly: single P-256 key, caller-PIN unlock, ECDSA sign-only with independent oracles; `general-token` falsified natively | BLOCKED: linked LGPL crates have no source companion, notice or relinking delivery |
| rolling | `main` tip `8f22c77b26bf5bbdf81049fb100c05e2395d1c64` | Same supervised stack and platform; distinct source/artifact | Same narrow observation, without error normalization | Same independent source/license blocks |

The release selector is an annotated tag: tag object
`673d6ac6fb7d99eddbf1e8633508a93188766cb6` peels to the recorded release commit.
The rolling pin is the tip of upstream `main` at acquisition. The reference
workspace pins `d0f8cccf37257842cc3f43a16a1b8e9059ef9a4d`, which matches neither
channel and was not adopted. Both channels retain MIT workspace/crate manifests
and ship both crate LICENSE texts. There are no upstream patches and no
simulation.

The module authenticates with the caller key-access password (the PKCS#11 PIN).
There is no security-officer role: native `C_Login(CKU_SO)` is
`CKR_USER_TYPE_INVALID`, and `C_InitToken`/`C_InitPIN`/`C_GenerateKeyPair` are
native `0x54`, so SO credential inputs are refused and `general-token` is
falsified. The installed checker lane builds but its shared runner requires an
SO credential unconditionally; the proxy lane serves and transports the native
observation faithfully while the shared post-health check holds the known
live-daemon volume-lease ordering limit. Those runner limits stay separate from
the completed provider observations.

### Appendix: Siguldry source, platform, credential and lifecycle boundary

**Frozen source and build.** The workspace builds
`cargo build --locked --offline --release --package siguldry --package
siguldry-pkcs11 --jobs 2` with the digest-pinned Rust 1.98.1 toolchain. Both
channels keep an upstream `Cargo.lock`, verified byte-equal before the freeze;
479 registry archives per channel are hash-verified and reconstructed into a
sealed directory source with no build-time resolution. Binaries
`siguldry-bridge`, `siguldry-client`, `siguldry-server`, `siguldry-signer` and
module `/usr/local/lib/p11lab/libsiguldry_pkcs11.so` run on Linux amd64/glibc
from the digest-pinned Debian base. OpenSSL and SQLite link the frozen system
libraries (`libcrypto.so.3`, `libssl.so.3` at OpenSSL 3.5.7,
`libsqlite3.so.0` at SQLite 3.46.1 via the sqlx `sqlite-unbundled` feature);
no source-built crypto, openssl CLI, compiler, Cargo, checker, Python, dataset
or tracing ships in the basic runtime.

**Service topology and mTLS.** The four services run as direct supervisor
children for the operation/application lifetime: bridge, signer, server and
client proxy in bind mode. The bridge listens on `127.0.0.1:44333` (servers)
and `127.0.0.1:44334` (clients); the signer and proxy use private sockets
under `/run/p11lab/siguldry`. A P11Lab-owned libcrypto helper in the supervisor
bootstraps mTLS at runtime (RSA-2048, SHA-256, 3650-day validity, SAN+EKU leaf
extensions, `v3_ca` CA), mirroring the vetted upstream devel script semantics
without shipping that script. Fixed internal identities are server
`siguldry-server`, bridge `localhost` and user `siguldry-client` (the client
certificate CN must equal the username). No baked credentials or initialized
state ship, and the CA private key is never written.

**PIN, label and database.** First init requires caller key-password input of
32..200 printable ASCII characters via `P11LAB_PIN_FILE` or `P11LAB_PIN`; the
32-character lower bound is native (`user_password_length=32`), while the token
64..128 PIN-length display is informational and unenforced. The password travels
by anonymous pipe and a private unlinked control file, never argv, logs or
markers. `P11LAB_LABEL` (1..32 ASCII letters/digits/spaces/dot/underscore/
hyphen) names the single server-side P-256 signing key and therefore the single
token at slot 0, token-present index 0. Exactly one key exists. Server state is
SQLite at `state/siguldry.sqlite` (the native stack sets mode 0640 explicitly;
0600/0640 are accepted for that file only behind the 0700 directory boundary).
A wrong PIN returns native `0xA0`. A failed unlock, or a sign without login
(`C_SignInit` OK then `C_Sign` `0x06`), breaks that process proxy connection
natively; fresh processes are unaffected and there is no server lockout. No
retry, PIN replacement, error translation or semantic patch is added.

**Readiness, supervision and reset.** Supply caller-owned mode-0700 writable
`/var/lib/p11lab` and a private mode-0700 `/run/p11lab`. Each shard/client owns
its own volume, container, PID namespace and network namespace; no host/shared
networking is used, and a second stack cannot share the loopback ports (native
bind refusal). `init`, `health` and `exec -- ARGV...` use the same C
supervisor: exclusive volume lease and private control lock, static ownership/
mode/link/roster/SQLite-magic checks and exact-byte marker/config validation
before any native launch, then real readiness gating on owned PIDs, both unix
sockets, both TCP ports, a bounded native `whoami` and a native slot/label/
flags/ECDSA check that never logs in. Startup is bounded, each service log sink
stores at most 64 KiB, required-service death fails the operation, and signal
forwarding with TERM/KILL escalation plus subreaper adoption/reaping cleans up
owned processes. The preferred proxy daemon uses the same supervised `exec`
lifetime, so no permanent `server`/`server-ready` operation exists. Repeated
compatible init preserves credentials and keys and ignores changed input files.
Reset is explicit caller removal/replacement of disposable state after all
operations stop; crash/power-loss recovery is unqualified.

**Qualification limits.** `signing` means exactly the proven narrow
observation: pre-provisioned single P-256 key, caller-PIN unlock, ECDSA
sign-only, with independent oracle verification of original signatures and
rejection of altered messages plus restart/isolation evidence. The unchanged
stock consumer cannot parse the native double-wrapped `CKA_EC_POINT`; that
interop observation is retained, never normalized, and the signing oracle below
it is the qualified crypto evidence. Wider mechanisms, key types, session
objects, concurrent clients, other architectures/libcs, hardware security and
production mTLS practices (systemd credentials, rotation/revocation) are
unqualified. Optional checker/consumer/proxy artifacts have separate provenance
and admission.

Twelve locked crates declare a license only in their manifest, and linked
LGPL-2.0-or-later code (`sequoia-openpgp`, `buffered-reader`) has no completed
corresponding-source, notice or relinking delivery. Base-package source
obligations, Rust standard-library reachability, generated layers and
digest-bound source delivery remain incomplete. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/siguldry/FILE-NOTICES.txt).
Distribution remains blocked independently of local runtime or crypto results.

## M6: kmsp11 release and rolling clients with co-located fakekms

| Channel | Frozen source | Runtime contract | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | tag `pkcs11-v1.9`, `e01c9b66a4b1db63e42de956ae6b2cefde2fea67` | Source-built `libkmsp11.so` plus supervised in-memory fakekms, per-launch provisioning, amd64/glibc | `kms-vendor-crypto` holds narrowly: six pre-provisioned keys, vendor-template keygen, RSA/EC/HMAC lanes with independent oracles; `general-token` falsified natively | BLOCKED: linked BoringSSL/gRPC/Abseil/protobuf families and 86 Go modules have no completed source companion, notice or relinking delivery |
| rolling | `master` tip `de849afa57f6e46c1268fbced15c161c532bff8b` | Same supervised stack and platform; distinct source/artifact | Same narrow observation, without error normalization | Same independent source/license blocks |

The release selector is an annotated tag: tag object
`0ac563ef4d337a0b91a8861b176c41e87eac6198` peels to the recorded release
commit. The rolling pin is the tip of upstream `master` at acquisition. No
prebuilt upstream bytes are used: both channels compile the client from source
with the pinned Bazel 6.4.0 toolchain over 35 sealed archives (plus a pinned
Go 1.22.0 SDK and two sealed Go zips for the host code generator) with
downloads disabled, and build fakekms plus the provisioning helper with Go
1.27.1 from 86 sealed modules with `GOPROXY=off`. Four ordered P11Lab patches
apply before sealing: a build-only Go SDK hash freeze, generated protobuf
bindings for the Bazel-only fault service, a build-only `kms` v1.25.0
dependency floor (the minimum carrying `HSM_SINGLE_TENANT`, proven by version
bisection), and a P11Lab-original readiness/provisioning helper. The patches
are provisioning extensions; no PKCS#11 semantic or simulation change is
added, and a declared patch that fails to apply fails the build.

The caller PIN is accepted for contract compatibility but ignored natively:
`C_Login(CKU_USER)` succeeds with any value, even empty (empty is still
refused at the adapter as malformed). There is no security-officer role:
native `C_Login(CKU_SO)` is `CKR_PIN_LOCKED` (`0xA4`), and
`C_InitToken`/`C_InitPIN`/`C_SetPIN`/`C_CreateObject` are native `0x54`, so SO
credential inputs are refused. `C_GenerateKeyPair` without the
`CKA_KMS_ALGORITHM` vendor template fails natively (empty template `0xD0`,
public-key attributes `0xD1`); only the vendor template succeeds, so
`general-token` is falsified. Upstream fakekms semantics are mixed: RSA keys
are fixed pregenerated test vectors while EC and HMAC keys draw fresh
`crypto/rand` material per launch. The installed checker lane builds but its
shared runner requires an SO credential unconditionally; the proxy lane serves
and transports the native observation faithfully while the shared post-health
check holds the known live-daemon volume-lease ordering limit. Those runner
limits stay separate from the completed provider observations.

### Appendix: kmsp11-fakekms source, platform, credential and lifecycle boundary

**Frozen source and build.** The builder compiles
`bazel build --jobs=2 -c opt --copt=-Wno-error=discarded-qualifiers
--distdir --repository_cache --experimental_repository_disable_download
//kmsp11/main:libkmsp11.so` (the copt relieves a `-Werror` failure that modern
GCC raises on vendored BoringSSL; the flag is recorded, not a source edit)
and `GOPROXY=off go build -trimpath CGO_ENABLED=0 ./fakekms/main
./p11lab-bootstrap` with `GOMAXPROCS=2`. Gazelle's `fetch_repo` bypasses the
Bazel downloader, so the two verified Go zips are additionally laid out as a
sealed `file://` module proxy (zip bytes plus the `.mod` extracted from each
zip) that the offline compile consumes via `GOPROXY`. The module
`/usr/local/lib/p11lab/libkmsp11.so` links only the frozen Debian base
`libm`/`libc`/`libstdc++`/`libgcc` (GCC 14.2); the Go binaries are static and
the C supervisor uses only libc/dl. No source-built system crypto, openssl
CLI, Java/Maven, compiler, Bazel, Go toolchain, checker, Python, datasets or
tracing ships in the basic runtime.

**Service topology and provisioning.** One memory-only fakekms runs as a
direct supervisor child for the operation/application lifetime. It takes no
arguments and prints an OS-ephemeral `127.0.0.1` port to stdout; the
supervisor parses that strictly, then gates readiness on a real gRPC
round-trip plus provisioning, never the printed address alone. Every
`init`/`health`/`exec` starts from zero keyrings and provisions keyring
`projects/p/locations/global/keyRings/p11lab` plus six SOFTWARE keys (RSA
PKCS#1/PSS sign, EC P-256/P-384 sign, RSA OAEP decrypt, HMAC-SHA256), waiting
for ENABLED versions. Each shard/client owns its own volume, container, PID
namespace and network namespace; no host/shared networking is used. No baked
keys, credentials or initialized state ship.

**PIN, label and token.** `P11LAB_LABEL` (1..32 ASCII letters/digits/spaces/
dot/underscore/hyphen, default `P11Lab`) names the single token at slot 0,
token-present index 0, via the generated mode-0600 libkmsp11 config under the
private control directory. A caller PIN is optional; when present its shape
(nonempty single line, 4096-byte bound, no NUL) is validated before any
native launch, but no PIN ever reaches the supervisor and readiness never
logs in. Native token flags are exactly `0x400409`, the mechanism roster is
exactly 46 entries (24 zeros: 23 from an upstream `vector(size)+push_back`
mistake plus genuine `CKM_RSA_PKCS_KEY_PAIR_GEN`), and the object roster is
exactly 11 objects under the six key labels. No retry, error translation or
semantic patch is added.

**Readiness, supervision and reset.** Supply caller-owned mode-0700 writable
`/var/lib/p11lab` and a private mode-0700 `/run/p11lab`. `init`, `health` and
`exec -- ARGV...` use the same C supervisor: exclusive volume lease and
private control lock, static ownership/mode/link/roster checks and exact-byte
marker validation before any native launch, then real readiness gating on the
owned fakekms PID, strict loopback port parse, TCP accept, a bounded gRPC
provisioning round-trip and a native slot/label/flags/mechanism/object check.
Startup is bounded, the log sink stores at most 64 KiB, required-service
death fails the operation, and signal forwarding with TERM/KILL escalation
plus subreaper adoption/reaping cleans up owned processes. The preferred
proxy daemon uses the same supervised `exec` lifetime, so no permanent
`server`/`server-ready` operation exists. Repeated compatible init preserves
the marker and ignores changed credential inputs. Reset is explicit caller
removal/replacement of disposable state after all operations stop;
crash/power-loss recovery is unqualified.

**Qualification limits.** `kms-vendor-crypto` means exactly the proven
narrow observation: six pre-provisioned keys, vendor-template key generation,
RSA PKCS#1/PSS and ECDSA P-256/P-384 signing, RSA-OAEP decrypt, HMAC-SHA256
and random generation, each with independent oracles (raw RSA exponentiation,
curve arithmetic over P-256/P-384 with subgroup checks, OAEP round-trip,
HMAC determinism), plus restart/isolation evidence. The image qualifies the
CLIENT against an explicitly fake in-memory backend; it never qualifies
Cloud KMS. Wider mechanisms, key types, session objects, concurrent clients,
other architectures/libcs and real Cloud KMS behavior are unqualified.
Optional checker/consumer/proxy artifacts have separate provenance and
admission.

Linked BoringSSL dual/MIT-fiat code, gRPC/Abseil/protobuf families and 86 Go
modules have no completed corresponding-source, notice or relinking delivery;
one fetched-only archive carries no in-archive license text. Base-package
source obligations, toolchain reachability, generated layers and digest-bound
source delivery remain incomplete. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/kmsp11-fakekms/FILE-NOTICES.txt).
Distribution remains blocked independently of local runtime or crypto
results.

## M6: softkms rolling local daemon with PKCS#11 module

| Channel | Frozen source | Runtime contract | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| rolling | `master` tip `f6235a4b8aee9394b1c03ce76cafb5b7652442e5`, falcon `ce15e75bceb372867daf6b8e81918ab6978686eb`, ed25519-bip32 `3cafd074e840971a2de791593918bb1c0707cd04` | Source-built `libsoftkms.so` plus supervised persistent daemon, per-state provisioning, amd64/glibc | `softkms-local-token` holds narrowly: fixed-label token, exact 10-mechanism roster, identity-token login, ECDSA-P256/Ed25519 lanes with independent oracles; `general-token` falsified natively | BLOCKED: AGPL-3.0 network copyleft plus LGPL/GPL closure code with no completed corresponding-source, notice or relinking delivery |
| release | No source (upstream publishes no tags or release refs) | Unavailable | Unqualified | Unqualified |

The rolling pin is the tip of upstream `master` at acquisition, and the
falcon submodule and ed25519-bip32 dependency pins were re-verified at the
frozen revision before sealing. No prebuilt upstream bytes are used: the
channel compiles the module, daemon and CLI from source with `cargo build
--locked --offline --release --lib --bin softkms-daemon --bin softkms --jobs
2` over 487 sealed crates.io archives plus the sealed ed25519-bip32 checkout
consumed as a directory source and the sealed Falcon C checkout, with
downloads disabled. Six ordered P11Lab patches apply before sealing:
function-table slot order, attribute-value encoding, post-finalize session
invalidation, deterministic info outputs, file-based CLI provisioning
secrets, and mechanism/token flag constants repaired to standard PKCS#11
v2.40 values (token flags are now `0x404`). The first five are ABI repairs
and provisioning extensions; the flag repair is a declared semantic repair
of wrong constants, and a declared patch that fails to apply fails the
build. ECDSA-always-SHA-256, the fixed label and permissive SO behavior are
preserved, not silently changed.

The caller passphrase (32..200 printable ASCII) provisions the daemon admin
secret and never reaches PKCS#11; the server-issued 192-character identity
token IS the PKCS#11 PIN for both `CKU_USER` and `CKU_SO` (no distinct SO
role: SO login succeeds exactly like USER, so SO inputs are shape-checked
and ignored). `C_InitToken` is native `0x00` while
`C_InitPIN`/`C_SetPIN`/`C_CreateObject` are native `0x54`.
`C_GenerateKeyPair` succeeds for P-256 and Ed25519 labels (RSA is `0x70`,
repeat labels are `0x30`), but generated objects expose no `CKA_ID`,
private keys expose no `EC_POINT`/`EC_PARAMS`, `C_DestroyObject` is `0x54`,
and find ignores templates, so `general-token` is falsified. The installed
checker lane runs to completed evidence (23 nodes: 5 passed, 15 setup
errors on `CKR_PIN_INCORRECT` for the caller credential, 3 skipped); the
proxy lane serves and transports the native login rejection faithfully
while the shared post-health check holds the known live-daemon
volume-lease ordering limit. Those runner outcomes stay separate from the
completed provider observations.

### Appendix: softkms source, platform, credential and lifecycle boundary

**Frozen source and build.** The builder runs `cargo build --locked
--offline --release --lib --bin softkms-daemon --bin softkms --jobs 2`
(Rust 1.98.1, protoc 3.21.12) against the P11Lab-frozen `Cargo.lock` with
the sealed archives reconstructed as a directory source and `--locked
--offline`, so no build-time resolution can occur. The module
`/usr/local/lib/p11lab/libsoftkms.so` dynamically uses the frozen Debian
base `libssl`/`libcrypto`/`libc`; the daemon additionally uses base
`libnettle`/`libhogweed`/`libgmp` via sequoia-openpgp; the CLI is
libc-only and the C supervisor is libc/dl-only. No source-built system
crypto, openssl CLI, Python, Rust toolchain, checker, datasets or tracing
ships in the basic runtime. `ldd` receipts identify actual usage, and the
sealed `Cargo.lock` plus crate manifest ship in-image for byte comparison.

**Service topology and provisioning.** One keykeeper daemon runs as a
direct supervisor child for the operation/application lifetime and
self-forks its key-free REST frontend child (reparented to the supervisor
as subreaper); both exit with the operation. The keykeeper listens on
fixed `127.0.0.1:50051` (gRPC) and the frontend on `127.0.0.1:8080`
(REST); fixed ports fail closed when occupied. The supervisor gates
readiness on TCP accept plus exact health JSON
(`healthy`/`initialized`/`unlocked`) plus a native login-bearing check,
never ports alone. First-time `init` provisions the keystore with the
caller passphrase as the admin secret plus exactly one `pkcs11` identity;
`health`/`exec` unlock the existing keystore with the persisted secret.
Each shard/client owns its own volume, container, PID namespace and
network namespace; no host/shared networking is used. No baked keys,
credentials or initialized state ship.

**PIN, label and token.** `P11LAB_LABEL` is fixed to `softKMS` (any other
value is refused) and names the single token at slot 0, token-present
index 0. The caller passphrase arrives via file or scalar and is piped to
the supervisor, never argv/logs; the 192-character server-generated
identity token persists mode-0600 in owned state for the state owner and
is the only PKCS#11 PIN. Native token flags are exactly `0x404`
(`TOKEN_INITIALIZED`|`LOGIN_REQUIRED`, standard bits via the repaired
constants) and the mechanism roster is exactly 10 entries in native order
(`0x1001`, `0x1041`, `0x1042`, `0x1043`, `0x1044`, `0x1040`, `0x1050`,
`0x1057`, `0x1080`, `0x1087`). Library/slot/token info outputs are fully
deterministic (version 2.40, zeroed serial/utcTime, pin 4..256).

**Readiness, supervision and reset.** Supply caller-owned mode-0700
writable `/var/lib/p11lab` and a private mode-0700 `/run/p11lab`. `init`,
`health` and `exec -- ARGV...` use the same C supervisor: exclusive
volume lease and private control lock, static ownership/mode/link/roster
checks and exact-byte marker validation before any native launch, then
real readiness gating on the owned keykeeper PID, TCP accept on both
fixed ports, exact health JSON and a native
slot/label/flags/mechanism/login/object check that also proves
post-finalize sessions invalidate. Startup is bounded, the log sink
stores at most 64 KiB, required-service death fails the operation, and
signal forwarding with TERM/KILL escalation plus subreaper/adopted-child
cleanup reaps owned processes. The preferred proxy daemon uses the same
supervised `exec` lifetime, so no permanent `server`/`server-ready`
operation exists. Repeated compatible init preserves native credentials
and objects and ignores changed credential inputs. Reset is explicit
caller removal/replacement of disposable state after all operations stop;
persistent tokens are never silently reset. Crash/power-loss recovery is
unqualified.

**Qualification limits.** `softkms-local-token` means exactly the proven
narrow observation: one fixed-label token with the exact 10-mechanism
roster, identity-token login for USER and SO, ECDSA P-256 (always
SHA-256, verified over the digest) and Ed25519 signing each with an
independent oracle (pure-Python curve arithmetic with subgroup checks;
the Ed25519 oracle is pinned to an OpenSSL-produced anchor vector), exact
public-key sourcing from the daemon's own persisted sidecars because
PKCS#11 exposes no public key material, exact-byte info outputs, and
restart/isolation evidence. RSA and ECDSA-secp256k1 are advertised in CLI
help but unimplemented natively and in the daemon. Wider mechanisms, key
types, session objects, concurrent clients, other architectures/libcs and
multi-tenant behavior are unqualified. Optional checker/consumer/proxy
artifacts have separate provenance and admission.

softKMS is AGPL-3.0 with network copyleft and the sealed dependency
closure adds LGPL/GPL code (nettle, sequoia-openpgp) plus 480+
permissive/dual crates without completed corresponding-source, notice or
relinking delivery; base-package source obligations, toolchain
reachability and actual-layer review remain pending. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/softkms/FILE-NOTICES.txt).
Distribution remains blocked independently of local runtime or crypto
results.

## M6: tpm2 release and rolling emulated-TPM tokens

| Channel | Frozen source | Runtime contract | Application qualification | Distribution |
| --- | --- | --- | --- | --- |
| release | Tag `1.10.1`, revision `9a3bfbd6b9e20513cbf5413b395ba1fe8b23ef0c` | Source-built unpatched `libtpm2_pkcs11.so` over supervised swtpm plus tpm2-abrmd on a private anonymous D-Bus, persistent emulator state and sqlite store, amd64/glibc | `general-token` retained: slot 1 token with native flags `0x40d`, P-256 sign/verify with independent OpenSSL oracle and altered-message rejection, persistence and isolation across resumes | BLOCKED: closure flags (GPL-3 packaging stanzas, LGPL glib, CPL swtpm sources, IBM-Custom libtpms) with no completed corresponding-source, notice or actual-layer review |
| rolling | `master` revision `d8375fa68e4ce8a477f7f5953511711e500e4143` (`1.10.1-21-gd8375fa`) | Same contract, same Debian trixie platform and frozen package roster | Same `general-token` evidence, same checker outcome | Same blockers |

Both channels source-build the unpatched module with
`--prefix=/usr --with-fapi=no --disable-ptool-checks` and `make -j2`
against Debian system OpenSSL 3.5.7 (`libcrypto.so.3`, no legacy
provider, no from-source OpenSSL). The single Python runtime dependency
is the frozen tpm2-pytss 2.3.0 sdist installed offline; the test-only
python-pkcs11 client is not installed and the argv-taking `tpm2_ptool`
console script is excluded from the runtime. Provisioning calls the
frozen `tpm2_ptool` commandlets as a library through an argv-free driver
(`tpm2_ptool init` plus `addtoken --pid=1`, persistent primary
`0x81000001`) with secrets on a bounded private stdin pipe, then sets
the emulator dictionary-attack parameters (max 64 tries; recovery and
lockout-recovery at the observed swtpm defaults). No P11Lab patches
exist and none are needed: native behavior, native errors and the
first-authentication TPM_RC_RETRY drawn after each daemon bring-up are
preserved, and the DA budget that retry spend requires is explicit
provisioning, not a workaround.

The caller user/SO PINs (each non-empty through 4096 bytes,
single-line) provision exactly one token at slot 1, token-present
index 0; `P11LAB_LABEL` (1..32 ASCII letters/digits/spaces/dot/
underscore/hyphen) names it. Generated-mode keygen stays native
`0x13`, wrong PINs stay native `0xa0`, and hammering the 64-try budget
locks the token with native `0xa4`, after which the correct PIN is
also rejected. The installed checker lane completes with full
observations in both channels (smoke-v1, 23 nodes: 13 passed, 5
skipped, 5 xfailed, 0 failed); the proxy lane serves remote P-256
crypto verified by the independent oracle while the shared post-health
check holds the known live-daemon volume-lease ordering limit. Those
runner outcomes stay separate from the completed provider
observations. Acceptance is 78 passed with the 2 documented proxy
lifecycle xfails.

### Appendix: tpm2 source, platform, credential and lifecycle boundary

**Frozen source and build.** The builder compiles the module from the
pinned git archive with the pinned arguments above; the daemon closure
(swtpm 0.7.1-1.5, tpm2-abrmd 3.0.0-1.2, tpm2-tools 5.7-1, libtss2
4.1.3-1.2, python3, D-Bus) comes from the frozen Debian trixie roster
(base `debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c`,
snapshot `20260918T000000Z`). The basic runtime ships the module, the
tpm2_pytss/tpm2_pkcs11 Python trees, the argv-free wrapper, the daemons,
the private bus, the tpm2 multicall with its invoked symlinks,
dbus-send, base libraries and the exact extracted closure (60 whole
packages plus picks, audited with `ldd` receipts); no build tools,
checker, datasets or tracing ship. Runtime images measure about 206 MB
(release) and 209 MB (rolling).

**Service topology and provisioning.** swtpm, a private anonymous
dbus-daemon and tpm2-abrmd run as supervised children for the
operation/application lifetime only; each shard/client owns a separate
volume, container, daemon set and private network namespace. The
supervisor gates readiness on TCP accept plus bus-name ownership plus
a native pre-login token round-trip, never ports alone. Daemons, bus
socket, logs and pid files live under ephemeral `/run/p11lab/tpm2`;
the emulator state (`tpm2-00.permall` plus the swtpm lock), the sqlite
store, the lease and the marker persist under `/var/lib/p11lab/tpm2`
and resume across operations. The canonical bus address is guidless
and static because the daemon config pins the socket path; the
per-boot guid is discarded after readiness, and the provider
descriptor declares the same store path, TCTI and bus address for
checker grandchildren, which otherwise run scrubbed. Resource-manager
capacities are the re-derived native bounds: 100 transient objects
and 4 sessions. No baked credentials or initialized state ship.

**PIN, label, token and DA budget.** First init requires both caller
PINs and provisions the store, token and DA parameters; compatible
repeated init preserves state and ignores changed credential files.
The token reports native flags `0x40d` with pin lengths 0..128 and a
34-mechanism roster. Every operation that performs PKCS#11
authentication draws one counted TPM_RC_RETRY (silently resubmitted
by libtss2, accounted by swtpm at emulator save), and every wrong-PIN
attempt burns one try natively, so the 64-try budget covers the
acceptance suite about tenfold while keeping lockout reachable and
observable. No silent reset or retry of native state-changing calls
exists.

**Readiness, supervision and reset.** Supply caller-owned mode-0700
writable `/var/lib/p11lab` and a private mode-0700 `/run/p11lab`;
the caller UID may be root or non-root with any primary group.
`init`, `health` and `exec -- ARGV...` share the entrypoint plus C
supervisor: exclusive volume lease and private control lock, static
ownership/mode/link/roster checks (non-empty store, exact tpmstate
roster, exact-byte marker) before any daemon starts, then real
readiness gating, daemon-death detection, signal forwarding with
TERM/KILL escalation, bounded logs and subreaper cleanup. The
preferred proxy daemon uses the same supervised `exec` lifetime, so
no permanent `server`/`server-ready` operation exists. swtpm rewrites
`tpm2-00.permall` on every operation (TPM clock and NV counters
advance even for read-only probes), so lanes where daemons
legitimately run compare all other state bytes exactly and assert
the blob is still a regular file; refusal lanes assert exact bytes
including the blob. Reset is explicit caller
removal/replacement of disposable state after all operations stop;
persistent tokens are never silently reset. Crash/power-loss recovery
is unqualified.

**Qualification limits.** `general-token` means exactly the proven
observation: one labeled token at slot 1 with the native roster,
P-256 sign/verify with the independent oracle, persistence and
isolation across resumes, native generated-mode/wrong-PIN/lockout
errors, the DA hammer observation, and the completed checker
profile. The module natively exposes two token-present slots for the
one provisioned token; wider mechanisms, multi-client concurrency,
other TCTIs/backends, hardware TPMs, FIPS claims and provider-wide
qualification are not asserted. Optional checker/consumer/proxy
artifacts have separate provenance and admission.

The module source is BSD-2-Clause, but the image closure carries
blocking flags: GPL-3 packaging stanzas, LGPL glib, CPL swtpm
sources and IBM-Custom libtpms, with base-package source
obligations, notice delivery and actual-layer review pending. See
[FILE-NOTICES.txt](../src/p11lab/data/providers/tpm2/FILE-NOTICES.txt).
Distribution remains blocked independently of local runtime or crypto
results.
