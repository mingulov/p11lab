# SoftHSM over a p11-kit server/client Unix-socket route

One working demonstration: a `p11-kit server` exposes the initialized
SoftHSM token of the accepted P11Lab native runtime on an owned Unix
socket, and an independent application crypto operation (on-token RSA-2048
key generation plus SHA256-RSA-PKCS signing) runs through
`p11-kit-client.so` with an OpenSSL oracle check. The demo reuses the
reviewed native runtime; it rebuilds no provider.

`pkcs11-proxy-ng` remains the primary P11Lab remote route
(see [proxy.md](../../docs/proxy.md)). This p11-kit route is an optional
demonstration of a compatible alternative, not a replacement.

## Aggregation versus remote use

p11-kit has two distinct roles; do not confuse them:

- **Aggregation (local).** The `p11-kit-proxy.so` module merges locally
  registered provider modules (`.module` files) into one client-visible
  module inside the application's own process. There is no server, no
  socket, and no transport. Trust and policy modules compose here.
  This demo does not exercise aggregation.
- **Remote (server/client).** `p11-kit server` exposes named tokens of one
  module on a Unix socket; a client process loads `p11-kit-client.so` with
  `P11_KIT_SERVER_ADDRESS` pointing at that socket and issues PKCS#11
  calls across the transport. This demo exercises exactly this route.

## Prerequisites

- An x86-64 host with Docker (the vessel runs `linux/amd64`), and
  network access for the one-time vessel build (Debian base pull plus
  `apt-get install`).
- Run from inside a P11Lab source checkout: `run.sh` bind-mounts its
  `src/` directory into the vessel (only `src/`; no `.local/` content,
  no reference workspace, and no prebuilt provider image is needed).
- A reviewed SoftHSM native archive for the release channel plus its
  SHA256, from your own reviewed build receipt
  (see [native.md](../../docs/native.md)). The demo verifies the archive
  through `p11lab install` and never rebuilds the provider.
- Private user and SO PIN files with at most one final newline
  (framing, not part of the PIN; `printf 'secret' > pin; chmod 600 pin`).

## Run

```sh
./run.sh --archive ./softhsm2-native.tar.gz --sha256 "$archive_sha256" \
  --pin-file ./pin --so-pin-file ./so-pin --output-dir ./p11kit-demo-out
```

The vessel build needs the network; the demo run itself uses
`docker run --network none` with the caller as container user, so the
route carries no hidden fetches and all outputs stay caller-owned.
A successful run prints `P11KIT_DEMO_OK` and leaves evidence under the
output directory: vessel image identity, package versions, install/init
receipts, local and remote slot listings, the server address with socket
ownership records, keygen/sign transcripts, the OpenSSL oracle verdicts
(original accepted, altered message rejected), and the shutdown proof
(socket gone). The output directory must be fresh: `run.sh` refuses a
path that already exists. Reset is deleting the output directory; PIN
files stay outside it.

## What is proven, and the boundary

Observed 2026-10-05 on `debian:13.6-slim` pinned by index digest
`sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132`:
p11-kit `0.25.5-3`, OpenSC `0.26.1-2` (`pkcs11-tool`), OpenSSL
`3.5.7-1~deb13u3`, against native SoftHSM release module
(`Hardware version: 2.7`, token label `P11Lab`).

- The server socket lives at `$XDG_RUNTIME_DIR/p11-kit/pkcs11-<pid>` in a
  fresh caller-owned `0700` directory; the demo refuses a non-empty,
  foreign-owned, or wrong-mode directory, refuses a non-absolute server
  address, and requires the address to be the single socket under that
  directory, owned by the caller. No attachment to another user's
  service is possible: the directory is created empty by the run.
- Compatible client actually proven: OpenSC `pkcs11-tool` loading the
  matching `p11-kit-client.so`. GnuTLS `p11tool`, other PKCS#11
  consumers, concurrent clients, multi-token exposure, TCP/TLS
  transports, and token URIs beyond `pkcs11:token=<label>` are untested
  here.
- The crypto operation is independent of the health check: the key is
  generated on the token through the route, the signature is produced
  through the route, and a separate OpenSSL process accepts the original
  message and rejects an altered one.
- Shutdown is explicit: the server receives SIGTERM and the demo asserts
  the socket path is gone before reporting success.

Residual limits: the user PIN appears transiently in the `pkcs11-tool`
argv inside the disposable vessel (`pkcs11-tool` takes no PIN file);
retained logs are verified to contain no PIN. With `-n <bare-name>` the
server printed a relative `unix:path=<name>` address instead of placing
the socket under `XDG_RUNTIME_DIR`, so the demo uses the default socket
name and parses the printed address. Debian package versions float at
vessel build time; the run records the actual versions.

## Distribution note

This example distributes no binaries: the vessel image is built locally
and never pushed, the native archive is supplied by the operator from a
reviewed receipt, and Debian packages are fetched by the operator's own
`apt-get` from Debian. No new source/notice duties attach to P11Lab from
this example beyond the records the run itself retains.
