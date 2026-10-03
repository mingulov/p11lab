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
