# Installed consumer tool inputs

P11Lab can acquire a fixed public input roster for its planned Debian 13 amd64
consumer image, without a provider checkout or private artifact cache:

```sh
p11lab tools resolve consumer --target debian13-amd64 --output-dir ./consumer-inputs
```

The output directory must not exist. A successful command writes
`resolved-inputs.json` after every input has been checked against the installed
package's curated lock. It retains opaque `.deb` files, complete corresponding
source sets, original signed-snapshot metadata, and copies of the installed
consumer source/notice resources. Nothing is extracted, installed or executed.
There is no `tools build` command in this increment. `checker` and `proxy` input
acquisition remain unsupported, with explicit errors rather than placeholder
success. Existing provider build/run commands and publication gates are unchanged.

## Exact supported inputs

The roster uses snapshot `20260918T000000Z` and the pinned Debian base
`docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c`.
It binds a complete 78-package parent inventory, shared by the current SoftHSM
release and the separately prepared Haskoki release candidate. The package set is
provider-neutral; its inventory does not by itself identify a provider image.
A later builder must verify both the selected provider and the actual parent.

- Compiler: `gcc=4:14.2.0-1`, `libc6-dev=2.41-12+deb13u4`, and their fixed dependency
  additions, for 114 total installed packages in the planned compiler stage.
- OpenSC: `opensc=0.26.1-2` and seven additions, for 86 total packages in the
  planned consumer image. Recommends/Suggests, including `pcscd`, are excluded.
- Unique acquired binaries: 43 files, 60,235,540 bytes.
- Corresponding sources: 16 source sets, 48 files, 317,014,868 bytes.
- Signed-snapshot metadata: nine files, 20,947,810 bytes.
- Network total: 100 files, 398,198,218 bytes; owned resources add 190,630 bytes.

These are declared sizes, not measured download time or peak resource use.
Allow additional space for metadata/receipts and partial failed attempts. No
shared cache, automatic retry, live package solver, or mutable package selection
is used. The per-file bound is 256 MiB and aggregate bound is 512 MiB. Requests
have a 60-second I/O timeout, a 900-second monotonic payload deadline and a
3600-second monotonic attempt deadline. Redirects are limited to five and must
stay on the approved HTTPS snapshot origin; they are checked before following.
Deadline checks cover address attempts, TLS/request transitions, HTTP headers and
chunk framing, not just payload reads.
These request/stream budgets cannot preempt arbitrary stuck operating-system
DNS or filesystem calls; they are not process-isolation guarantees.

The installed provenance binds the original published InRelease and compressed
and uncompressed Packages/Sources hashes, signature verification records, exact
binary/source selectors and curated dependency witnesses. Resolve verifies
content hashes against those installed pins; it does not run a fresh PGP verifier
or decide Debian dependency versions. Full indexes are acquired as evidence, not
bundled into the P11Lab wheel. An edited receipt cannot authorize different hashes,
URLs, source identities or rosters.

## Rechecking retained inputs

The Python API reselects installed authority and rejects altered receipts,
missing/extra files, unsafe paths and changed contents:

```python
from pathlib import Path
from p11lab.tool_inputs import resolve_tool_inputs, verify_resolved_tool_inputs

result = verify_resolved_tool_inputs(
    "consumer", target="debian13-amd64",
    receipt_path=Path("consumer-inputs/resolved-inputs.json"),
)
```

Reverification is a Python API, not an additional CLI command. It requires the
same exact installed lock bytes, not merely the same toolset name. Keep successful
inputs and their receipt together. The receipt records relative paths and does
not constitute an artifact reference, image identity or origin attestation.

## Failure and evidence limits

On failure, the attempt is retained for diagnosis and must not be reused. Retry
with a different fresh output directory. A checksum/size failure, interruption or
receipt-write error is not successful resolution. The resolver removes a receipt
if its write fails after replacement; if the filesystem also refuses that
cleanup, the original error is preserved with a cleanup diagnostic. Do not treat
a receipt from an operation that reported failure as success. These guarantees
assume an ordinary functioning local filesystem, not an adversarial concurrent
writer or a host capable of changing the installed authority.

All license and publication admission remains unreviewed. Source references and
expected copyright paths are not inspection of actual embedded notices. The
parent's `sqv` incorporated-source obligations remain inherited, not silently
covered by this tool acquisition. No redistribution permission is granted.

Metadata closure is not proof that package maintainer scripts install cleanly,
that the compiler works, that ELF/loader dependencies are correct, or that a
provider passes any test. The planned consumer builder and its four direct
crypto/persistence cases require separate implementation and real bounded
execution evidence. Editing the existing consumer recipe also triggers the
currently configured Windows workflow, so that later PR needs a separate CI-cost
decision. This command neither changes that workflow nor consumes its budget.
