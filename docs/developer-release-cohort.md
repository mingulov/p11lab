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
