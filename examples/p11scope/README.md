# Observing a PKCS#11 workload with p11scope

An optional demonstration of [mingulov/p11scope](https://github.com/mingulov/p11scope):
a non-interposing PKCS#11 workload profiler built on eBPF uprobes. The
demo pins one release, records preflight (`doctor`) unprivileged, and —
only with explicit opt-in — captures a small own-process workload
(`p11scope run` over a PKCS#11 slot/mechanism listing) in a disposable
privileged vessel.

Identity: this is the Rust observability project by `mingulov`
(GPL-3.0-or-later), verified via the GitHub API on 2026-10-05. It is
NOT the unrelated OpenCryptoki command of a similar name.

Tracing is optional: ordinary consumers of P11Lab provider images never
need p11scope, privileges, or this demo. Phase 1 (preflight evidence)
is already a complete observation on hosts without capture privileges.

## Frozen selection

v0.2.0, the newest tagged release at freeze time and equal to the
default branch head, so tag and branch agree on one revision. Frozen
deliberately in [pins.env](pins.env); do not refresh without review.

- Tag `v0.2.0`: annotated tag object
  `abef0d6a1f60e9c8c7347ab7828cb4084e46d0c1`, peeling to commit
  `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4`.
- Observer bundle
  `p11scope-0.2.0-x86_64-linux-musl.tar.gz`, SHA256
  `c2713194d39ab9538042db73cbc3246cbdce4e82cbcb09485ef7b685aa9f7f2f`.
  The demo downloads it over HTTPS and refuses any byte mismatch.

## Observation point

p11scope discovers the provider's actual function table in the observed
process (by file offset, including stripped providers) and attaches
eBPF uprobes to those offsets. It never replaces the application's
module or changes its configuration: observation is passive call
counting with return values and latency, plus an explicit pause control
(SIGSTOP) of its own child while it observes loading. The observed
profile (`observed-profile.json`, schema
`p11scope/observed-profile/v3`) carries an `evidence` block with a
completeness verdict, loss counters, and gap classes — every number in
this README comes from that block, not from the live display.

## Privilege and kernel requirements

Per the upstream operator guide (`docs/usage.md` of the pinned
release) and confirmed by `doctor` on the demo host:

- Kernel floor 5.15; the demo host runs `7.0.0-34-generic`.
- Attaching needs BPF privileges. At
  `kernel.perf_event_paranoid >= 3` (the Debian/Ubuntu level; the demo
  host reads 4), capture needs `CAP_SYS_ADMIN` — root in practice —
  because the uretprobe self-probe and live-discovery probes use
  `perf_event_open`. Memory-scan discovery of a same-UID non-descendant
  additionally needs `CAP_SYS_PTRACE`.
- `run` requires the observer in the initial PID namespace with its own
  `/proc`; a nested namespace is refused (`pid-namespace-mismatch`), so
  the privileged vessel runs with the host PID namespace.
- `run` as root drops its child to the non-root account named by
  `SUDO_UID`/`SUDO_GID` (here the vessel's `obs-child`, uid 10001);
  root without that explicit target is refused. The child keeps no
  capabilities and receives only a sanitized environment.

## Run

Prerequisites: an x86-64 host with `curl`, `sha256sum`, and `tar`,
plus — for the live-capture phase only — Docker with `linux/amd64`
support. The pinned observer bundle is an `x86_64-linux-musl` binary
that phase 1 executes directly on the host, so other architectures
cannot run it. No checkout mounts, no `.local/` content, and no
provider image are needed. The output directory must be fresh:
`run.sh` refuses a path that already exists.

```sh
./run.sh --output-dir ./p11scope-demo-out            # preflight only
./run.sh --privileged --output-dir ./p11scope-demo-out  # + live capture
```

Phase 1 validates the preflight outputs before reporting success: it
refuses (keeping the evidence) unless `--version` prints the pinned
release and both `doctor` runs complete with a capability-tier
verdict.

`--privileged` runs one disposable container with `--privileged`, the
host PID namespace, root inside, debugfs/bpffs mounted inside that
container, and no network; outputs are chowned back to the caller. The
vessel image is built locally and never pushed.

## What was observed on the demo host (2026-10-05)

Unprivileged phase: `p11scope 0.2.0`, tier `T0 offline`, `doctor` exit
1 with concrete FAIL rows (`BPF map create`, `uprobe attach (self)`,
`host program preflight`, all `Operation not permitted`), and
`doctor --extra-strict` exit 1 with a 10-violation refusal line. That
is the expected honest outcome without privileges — evidence, not
failure.

Privileged phase (Debian 13 vessel: `softhsm2 2.6.1-3`, OpenSC
`0.26.1-2`, kernel `7.0.0-34-generic`): preflight tier `T1 host
attach`, exit 0; the capture of an initialized-token slot/mechanism
listing attached 136/136 probes (backends `uprobe-multi` and
`per-offset`), counted 82 calls across 8 functions, and reported
`completeness: PARTIAL`, `verdict_detail: concrete_gap`,
`event_loss: 0`. The partial verdict has two concrete causes, both
disclosed in the evidence block: observation `lossy` (1 skipped
`discovery subject`) and attribution `withheld` (68
semantics-unverified, count-only slots — no `--manifest` attestation
was supplied, so function semantics stay unverified by design).

Dropped/partial data, as observed: no ring loss (`event_loss: 0`,
`drain_proven: true`, stop quiescence `proven`); the loss is
coverage/attribution, not counts. Mechanism parameters and templates
are policy-omitted upstream (`params: null`, empty
`templates.operations`) and must not be read as "the application used
none".

Instrumentation effects: the observer adds per-call trap cost. Upstream
measured the worst case (unobserved SoftHSM2 `C_GenerateRandom`
hammered back to back, v0.1.0 release candidate): +4.1 µs/call in
`metrics` mode, +5.5–6.8 µs/call in `profile`/`trace`, i.e. 6–10x wall
clock on microsecond-scale calls and negligible relative cost against
millisecond-scale HSM calls. The demo's own workload is one short
listing; its observed latencies are log2-bucket approximations in the
profile, not a benchmark. Two run quirks were observed: `run` refuses
`-o` under a directory owned by another uid (the demo writes to a
root-owned path and copies out), and `run` reports stay `PARTIAL` by
construction (the initial-set capture limit).

## Distribution note

This example distributes no p11scope binary: the operator's demo run
downloads the pinned bundle and verifies its hash before executing
anything. P11Lab ships only the pin (URL plus SHA256), the scripts,
and these instructions. The bundle itself carries its license notices
(GPL-3.0-or-later, plus bundled-crate notices and `RELEASE.json`);
operators keep their own GPL compliance for any redistribution they do
with the fetched bundle. No new P11Lab source/notice duties arise from
this example.
