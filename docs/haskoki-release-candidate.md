# Haskoki v0.5.0.0 candidate

The `release` channel is an **unvalidated, local-only candidate**, not a
published or runtime-qualified release. The `rolling` source remains
`e442a38dbbe12b1024c7852b0f0709130f92a112`; its prior results do not qualify the
new release. No native bundle or additional platform is introduced.

## Locked inputs and retained gates

The release tag `v0.5.0.0` is locked to
`091a2223e6dc559af72913c7f5a061ca22af34dc`, with Git archive SHA-256
`be8bb8363ec624c05db9ab1c7132dab14348512cf10023b1dcc8c91882b1ec97`.
The source is unpatched. Release-specific recipe, adapter and notice assets
use the existing sealed build-context contract. The runtime tool must report
exactly `haskoki-ctl 0.5.0.0`, not an arbitrary accepted version.

The recipe retains the prior strict checks for 24 bundled GHC libraries,
GLIBC_2.38, exactly two byte-pinned Hackage source archives, static OpenSSL,
allowed host dependencies, package inventories and signed index inputs.
These are **required candidate gates, not measured release results**.
The new private `haskoki-core` component and complete build-tool/runtime
closure need an actual cold build. A changed count, floor or dependency set
must stop the build for review; it is not silently accepted. In that case no
runtime artifact exists and dependent runtime tests cannot establish results.

Source resolution can be inspected independently of a provider build:

```sh
p11lab resolve haskoki --channel release --output-dir NEW_DIRECTORY
```

Provider builds and acceptance tests require a suitable Docker-capable Linux
amd64 environment. Ordinary consumers still do not need Python, checker,
tracing or reference-workspace mounts in the basic provider runtime.

## State and credential policy

P11Lab initially provisions slot 0 with label `haskoki-demo`, user PIN `1234`
and SO PIN `5678`. This is explicit **adapter demo-initialization policy**,
not a claim that release v0.5 lacks native PIN management. The release
implements durable `C_InitToken`, `C_InitPIN` and `C_SetPIN`; application-led
PIN changes must survive fresh processes. Completed-state `init` remains
validate-only and must not restore demo PINs. Arbitrary initial PINs or labels
are not added by this version change. Config, markers and receipts must not
contain caller PIN bytes.

Release serving state uses SQLite schema 3. Earlier schema versions require
explicit upstream migration; P11Lab neither migrates nor resets persistent
state automatically. Markers remain bound to the exact artifact, so this
candidate does not promise cross-artifact token reuse.

There is an unresolved readiness issue: upstream `haskoki-ctl store inspect`
counts tables but does not validate the schema-version marker. Its schema-aware
`store check` refuses a live owner, so it cannot replace lock-safe health.
The candidate leaves this upstream behavior unpatched, records the gap, and
keeps schema-refusal tests as ordinary acceptance assertions. Failure is a
reported finding, not an expected-failure waiver or a reason to weaken health.
A live-safe schema-validating upstream mode or a reviewed, explicitly
provenanced packaging patch remains a separate decision.

## Acceptance and evidence boundaries

The existing Haskoki standalone, credential-failure, direct generated and
persistent-key crypto, independent OpenSSL oracle, installed checker and
preferred-proxy host/container lanes cover both channels. Release-only cases
add:

- A real module process owning both database and sidecar kernel locks,
  independent `flock` confirmation, second-open refusal, parallel health,
  graceful termination and killed-owner recovery.
- Stale sidecar takeover while its recorded PID belongs to a live unrelated
  process, without disturbing that process.
- User and SO PIN-change persistence, explicit native token/PIN initialization,
  old-PIN refusal, validate-only re-init and secret-free metadata/receipts.
- Fresh schema 3, missing/corrupt/incompatible-store nonmutation and refusal
  before application execution, plus independent native schema refusal.
- Two independent frozen checker shards, exact installed checker/source
  identity, native merge and missing-shard rejection.

`P11LAB_TEST_HASKOKI_CHANNELS=release` selects the release-only test roster.
The image maps documented in
[`tests/integration/test_haskoki.py`](../tests/integration/test_haskoki.py)
require exact caller-supplied runtime, consumer/checker/proxy derivative and
client-bundle identities. Missing derivative inputs remain explicit skips,
not complete-workflow success. The native lifecycle helper is test-only and
is not included in the provider runtime.

Local source contracts, shell regressions, helper compilation, source
resolution and installed-wheel tests are not substitutes for module, SQLite
or cryptographic observations. Runtime evidence must identify the actual
artifact and distinguish provider findings, infrastructure failures and
missing evidence. Public distribution remains unreviewed: full source/license
closure, notices for retained GHC/OpenSSL/direct-sqlite/hsc2hs/libffi materials,
actual image contents and digest-bound source delivery admission are pending.
