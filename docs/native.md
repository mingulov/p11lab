# Native SoftHSM on Debian 13 amd64

P11Lab packages frozen SoftHSM release and rolling sources as separate native
archives for **Debian 13 amd64 (`debian13-amd64`, `linux/amd64`)**. Windows,
Ubuntu, other Debian versions, musl, macOS and other architectures are not
qualified targets. A Debian container can supply the test OS; this is native
module loading inside Debian, without a Docker daemon on the consumer.

The bundle contains the provider module, `softhsm2-util`, a shell lifecycle
adapter and original license notices. It contains no Python, checker, compiler,
initialized token, PIN, private key, glibc, loader or private OpenSSL. The host
must supply `libc6`, `libstdc++6`, `libgcc-s1`, `libssl3t64`, `zlib1g`, `libzstd1`,
`dash`, `coreutils`, `findutils` and `mawk`. Both binaries need GLIBC 2.38 or
later; the utility needs GLIBCXX 3.4.32. Rolling additionally requires
OPENSSL 3.4.0 and CXXABI 1.3.15. These symbol floors do not widen OS support.
The installer checks Debian identity, the actual system-loader closure and
utility launch; it never installs prerequisites or changes library search paths.

## Install a local candidate

Install the P11Lab command separately from the provider. Obtain the candidate
archive and its SHA256 from the same reviewed build receipt; local installation
does not grant public distribution admission.

```sh
p11lab install softhsm2 --channel release --platform linux/amd64 \
  --artifact ./softhsm2-native.tar.gz --sha256 "$archive_sha256" \
  --prefix "$HOME/providers/SoftHSM release"
```

The command prints the absolute prefix, module and installation receipt paths.
Installation verifies the archive and every file, checks target prerequisites
before publishing the requested prefix, and initializes no tokens. Matching
verified installations can be reused. Unrelated or damaged prefixes fail without
replacement. An explicit verified reinstall at a second prefix creates a new
placement receipt; copying the installed directory leaves an invalid receipt.

The module is `PREFIX/payload/lib/libsofthsm2.so`. The configuration is
`CONTROL/softhsm2.conf`, created by initialization. Keep state, control and output
outside the prefix, including resolved symlinks and either direction of nesting.
State and control must also be separate from each other. Paths with internal
spaces work; newlines, carriage returns and `#` cannot be represented safely in
SoftHSM configuration. Credentials belong in private files, with no final newline.

## Run your application

```sh
mkdir -m 700 "$HOME/test token state"
p11lab run softhsm2 --channel release --mode native --where host \
  --installed-prefix "$HOME/providers/SoftHSM release" \
  --state-dir "$HOME/test token state" --control-dir "$HOME/test token control" \
  --input P11LAB_PIN_FILE="$HOME/secrets/user-pin" \
  --input P11LAB_SO_PIN_FILE="$HOME/secrets/so-pin" \
  --cwd "$PWD" --output-dir "$PWD/run result" --timeout 60 \
  -- /path/to/application 'literal argument with spaces'
```

The runner passes `P11LAB_MODULE`, `SOFTHSM2_CONF` and `P11LAB_OUTPUT_DIR` as
absolute paths. Your application loads the supplied module using its normal
PKCS#11 interface. `--installed-prefix` uses the original ArtifactRef in the
fully verified installation receipt; the downloaded archive may be deleted.
It is mutually exclusive with `--artifact`. Archive-based execution instead
requires `--artifact PATH --sha256 SHA256` and prepares a temporary verified
installation. Native mode rejects container/client options.

The runner checks init, readiness, application status and post-run health,
retains bounded redacted logs, and records the installation and resolved runtime
identities. A completed application's nonzero status survives later lifecycle
errors. Timeout and interruption are explicit receipt facts. Caller state and
control are retained. Without explicit directories, state/control live in the
new run output directory. Independent shards/clients need independent state.

## Manual use without Python or checker

See [the shell example](../examples/native-softhsm/run.sh). With a verified
installation, the adapter can initialize and check state directly:

```sh
prefix="$HOME/providers/SoftHSM release"
state="$HOME/test token state"
control="$HOME/test token control"
export P11LAB_PIN_FILE="$HOME/secrets/user-pin"
export P11LAB_SO_PIN_FILE="$HOME/secrets/so-pin"
"$prefix/payload/bin/p11lab-provider" --prefix "$prefix" --state "$state" --control "$control" init
"$prefix/payload/bin/p11lab-provider" --prefix "$prefix" --state "$state" --control "$control" health
export P11LAB_MODULE="$prefix/payload/lib/libsofthsm2.so"
export SOFTHSM2_CONF="$control/softhsm2.conf"
"$prefix/payload/bin/softhsm2-util" --module "$P11LAB_MODULE" --show-slots
/path/to/application --module "$P11LAB_MODULE"
```

The adapter uses only the installed utility and module, never a system SoftHSM
fallback. Compatible initialization preserves existing tokens and does not need
credentials again. Incompatible markers, lost token contents or partial state
fail; they are never repaired or reset automatically. A token label identifies
the token; SoftHSM assigns its native slot ID. A consumer's token-present slot
**index** is a different value and must be translated by that consumer.

The adapter uses private permissions (`umask 077`). State is a local file store;
ordinary process exit/finalization is shutdown. There is no background service.
Remove an owned installation prefix explicitly after applications exit, retaining
external token state. Reset only an explicitly disposable state directory after
applications exit. This release provides no upgrade or garbage collection service.

## Optional qualification and build

`p11lab build softhsm2 --channel release --role native --output-dir NEW_DIR`
packages exact sealed binaries from the target lock's immutable build parent.
Building uses Docker to acquire those bytes; native consumers do not. Rolling
uses its own lock and archive. Source companion references, ordered patches,
compilation inputs, packaging assets and original notices are retained. Native
actual-content admission is separate from container admission and publication.

The independent C consumer under `src/p11lab/data/consumer/` supports P-256
session-key signing and existing token-key signing. Verify exported signatures
with an independent OpenSSL process, including altered-message rejection.
A separately installed checker can call `execute_checker` with `smoke-v1`'s
frozen nodes and Task5 completion validation. It is optional and stays outside
the provider bundle. Host checker execution has a bounded 900-second run limit,
plus bounded collection and termination.

Acceptance concerns exact installed bytes, persistence, independent instances,
reinstall, native error preservation and the declared system OpenSSL. It does
not qualify every application's preloaded-library combination, every algorithm,
provider-wide behavior or certification. Raw package versions and resolved runtime
hashes belong in the run receipt; a successful install alone is not a provider test.
