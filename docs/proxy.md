# Remote SoftHSM over pinned mTLS proxy

P11Lab runs external applications and the installed checker against SoftHSM
through `pkcs11-proxy-ng` over mutually authenticated TLS. The daemon loads
the provider locally in its own container; the consumer loads only a
compatible client shim. A shared Docker network never makes the provider
module remotely loadable. This path needs Linux amd64 throughout; native
Windows proxy and cross-OS topologies are unqualified follow-ups.

## Pinned components

The daemon, administration CLI and shim are built from public source
`a348a5f59b535b1ca309ea9f0a722e3bec692f72` (0.2.0) with the frozen
`Cargo.lock`, `--locked --offline`, Rust 1.98.1 and protoc 36.1. All three
are dynamically linked against glibc with a measured GLIBC 2.34 floor plus
`libgcc_s`, and need no OpenSSL at runtime. They load on Debian 13
(glibc 2.41) and newer glibc hosts; musl is a separate unbuilt target.

The provider-plus-daemon image derives from the exact accepted runtime and
adds only the daemon, CLI, lifecycle entrypoint and pinned-source notices.
It reports its component identities through `proxy-build`. The native-client
bundle carries the shim and CLI with the same recorded proxy identities.
A proxy component change invalidates both identities: a run refuses a daemon
derivative or client bundle that does not match the pinned source, lock and
CLI bytes. Distribution admission is separate for every artifact.

## Selecting a proxy run

Proxy runs use the library API or the CLI: `prepare_proxy(spec)` validates
selection without creating resources, and `run_application` routes
`mode='proxy'`. `p11lab run --mode proxy` takes the daemon image as
`--artifact`, the caller image as `--consumer-image` for `proxy/container`,
and the native-client bundle as `--client-artifact` plus its
`--client-sha256`; `prepare_proxy` still requires the `bundle` kind with a
full SHA-256 on `linux/amd64`, and a reused client installation
(`installed_prefix` for `proxy/host`) stays library-only.

`proxy/container` needs an exact daemon image, an explicit exact caller image
and an exact native-client bundle. The consumer container runs precisely the
caller argv with `argv[0]` as entrypoint, so provider-derived consumers cannot
reinterpret the command. The shim is mounted read-only with client TLS files,
and the consumer receives `P11LAB_MODULE` pointing at the shim plus the exact
`PKCS11_PROXY_ENDPOINT`/`PKCS11_PROXY_TLS_*` transport variables. The
consumer mounts no token state: the token is reachable only through the shim.

`proxy/host` needs an exact daemon image and an exact client bundle. The
application runs on the host with the shim from a verified installation
(`installed_prefix`) or a verified temporary prefix, whose path is exported
as `P11LAB_SHIM` and `P11LAB_MODULE`. It inherits the caller environment
minus `P11LAB_*`, `SOFTHSM*`, `LD_*` and `PKCS11_PROXY_*` names, plus the
declared inputs and the shim/transport variables. The daemon publishes its
port on the loopback interface only; anything else fails the run before
the application.

## TLS and daemon contract

Every run generates a fresh evaluation CA with server and client leaves
(OpenSSL Ed25519) and verifies chain, SAN and EKU before use. The server leaf
covers `provider-daemon`, `localhost` and `127.0.0.1` with serverAuth; the
client leaf carries a nonempty subject with clientAuth. Only server
leaf/key+CA reach the daemon and only client leaf/key+CA reach the consumer;
the CA private key never enters a mount. Partial TLS triples, wrong owners,
group/other-readable keys and world-writable certificates fail before any
container starts. The daemon additionally refuses a group/world-writable
config file.

The daemon takes a positional TOML file with the provider module path,
`max_contexts = 1`, transparent mechanism discovery, an IP:port mTLS
listener and `allow_all_authenticated` for the dedicated evaluation
instance. `lease_seconds = 1` reclaims contexts orphaned by short-lived
helpers that exit without `C_Finalize` (observed in checker preflight);
reaping still needs an expired lease plus a new admission, so a second live
context is refused exactly as with the default lease. The context-free CLI
health probe must report SERVING before the application runs; it checks
transport and backend gating, never application behavior. In the pinned
CLI, exit 0 holds exactly when SERVING is reported (exit 1 is
NOT_SERVING, 2 is probe failure), so the runner's exit-code check is
equivalent to asserting the SERVING line. The daemon configuration fixes
`request_timeout_secs = 60` and `startup_timeout_secs = 30`; the runner's
health gate gets a 30-second window with at most 10 seconds per probe and
one second between attempts.

## Isolation and failures

One logical client uses one dedicated daemon, token state and TLS set.
Restart the daemon between independent clients and use separate tokens for
shards. After a restart all handles are invalid; reopen sessions instead of
replaying operations. Unauthorized clients, wrong-CA consumers and daemon
loss fail closed without retries: the CLI reports transport failure and the
application observes native errors such as `CKR_GENERAL_ERROR` on connect
or `CKR_HOST_MEMORY` at the context limit. Direct/provider and transport
outcomes are recorded separately and never merged.

Residual bridge exposure (STRIDE S2/D4): the daemon and a
`proxy/container` consumer share one owned bridge network, so daemon-side
listeners that cannot bind loopback stay reachable from the consumer. The
frozen vpcd handler in the isoapplet/pivapplet providers listens wildcard
on 35963/35964, so a malicious or buggy consumer can dial the card channel
directly, bypassing mTLS proxy auth, or disrupt card state. The tpm2 swtpm
listeners bind `127.0.0.1` explicitly. Direct mode is unaffected
(`--network none`). Bridge segmentation (a daemon-only network plus a
published loopback proxy port) stays a future option, not implemented.

The installed checker runs in its declared consumer through the same
contract. Its driver preserves the controlled container environment for the
shim and finalizes helper contexts deterministically at process exit; result
evidence is validated with the frozen checker validator, and interface
observations (for example v2-only negotiation skips) are transport facts,
not provider findings.

## Native-client bundle

The `native-client` role packages the shim (`lib/...` module) and CLI with
proxy license notices. Installation verifies the archive, manifest and every
payload file, checks the Linux x86_64 host, resolves the shim closure with
the system loader and launches the CLI before publishing the prefix. It
installs no prerequisites and changes no loader settings. Archive hash and
installed placement stay separate identities with their own receipts.
