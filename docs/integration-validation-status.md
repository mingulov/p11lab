# Integration validation status

Status: **2026-10-20**. Baseline:
[`main` at 3dead295](https://github.com/mingulov/p11lab/commit/3dead295e586927168b6586c2f3e09fddaa51ef2).
The catalogue contains 24 locked provider candidates. Current integration work
focuses on SoftHSM2 and Haskoki, not catalogue expansion.

This is a contributor evidence snapshot and roadmap, not provider certification.
The proposals below are **open and unmerged** at this date. Their tests do not
establish that the changes are present on `main` or that provider artifacts are
eligible for distribution.

## What the evidence establishes

- **Source/package checks:** orchestration, installed-package and packaged-adapter
  contracts. Adapter fixtures substitute native tools where stated; they do not
  prove the provider's cryptographic or database behavior.
- **Runtime observations:** require the exact built provider, real tools and
  transports, expected lane inputs and complete run receipts. A missing input or
  skipped test is missing evidence, not a pass.
- **Distribution admission:** separately requires reviewed redistribution rights,
  complete source obligations, evidence of actual artifact contents and immutable
  public source readback bound to the binary. Tests cannot grant those rights.

## Open review proposals

Each linked PR records commands, exact reviewed trees, red/green regressions,
independent review and limitations. The revisions here fix this snapshot; later
updates need their own evidence.

- [#1: Haskoki lifecycle failures](https://github.com/mingulov/p11lab/pull/1)
  ([1cd5e3a4](https://github.com/mingulov/p11lab/commit/1cd5e3a4e0d49b4d7ca7818787204ee810752e0f)):
  preserve native failures and harden signal, identity, state-inventory and owned
  cleanup boundaries. Actual adapter tests run under dash and bash.
- [#2: Proxy shutdown receipt expectation](https://github.com/mingulov/p11lab/pull/2)
  ([9011658f](https://github.com/mingulov/p11lab/commit/9011658fa2ace20dee70be6d0ef1896edbe9eaa9)):
  correct a stale assertion while retaining strict daemon-stop-before-post-health
  ordering. Production lifecycle behavior is unchanged.
- [#3: Action isolation and receipt safety](https://github.com/mingulov/p11lab/pull/3)
  ([bdbc43ae](https://github.com/mingulov/p11lab/commit/bdbc43ae810b7f97764dd693dc726b2120e22180)):
  isolate repeated invocations and advertise only safe, complete receipts matching
  the invocation, artifact and CLI status. This is not authenticity proof against
  caller-controlled host processes; Windows behavior remains simulated.
- [#4: Bounded Linux source/package CI](https://github.com/mingulov/p11lab/pull/4)
  ([569f05d3](https://github.com/mingulov/p11lab/commit/569f05d38b053771d20f19166f551b71e8e30344)),
  stacked on #2: one read-only, 10-minute job with pinned Python dependencies and
  checker source. The [hosted run](https://github.com/mingulov/p11lab/actions/runs/39454787936)
  recorded **1001 passed, 1000 skipped in 58.06 seconds**. It built no provider.
- [#5: Manual Haskoki release validation](https://github.com/mingulov/p11lab/pull/5)
  ([fca1b148](https://github.com/mingulov/p11lab/commit/fca1b148f074bc0f3fd527bc02fe7920f33fa4cd)),
  stacked on the [release candidate at 4f753f3f](https://github.com/mingulov/p11lab/commit/4f753f3f0a54ca8ae1131b3d0657494022b2c086):
  a no-publication pipeline with a separate manual runtime job. The
  [corrected hosted static run](https://github.com/mingulov/p11lab/actions/runs/39463132399)
  recorded **203 passed in 3.42 seconds** on its PR merge; runtime was skipped.
- [#6: SoftHSM2 initialization outcomes](https://github.com/mingulov/p11lab/pull/6)
  ([c1fbe90d](https://github.com/mingulov/p11lab/commit/c1fbe90df29d4a68f582b7c84e2f854a4bac47d4)):
  preserve native/signal failures and cleanup ownership in container and native
  adapters. Identity/marker bytes are addressed separately by #8.
- [#8: SoftHSM2 identity and marker bytes](https://github.com/mingulov/p11lab/pull/8)
  ([e3b6dcc2](https://github.com/mingulov/p11lab/commit/e3b6dcc252468a9d6f533038b03a763b5a37fb2f)),
  stacked on unmerged #6: enforce existing byte-exact identity and completion
  marker contracts in both adapters. Its full local run recorded **2016 passed,
  1000 skipped, 3 known failures**; independent review repeated all **1028 adapter
  cases** plus 64 boundary probes. These tests substitute native tools; runtime
  remains unqualified.

The local unfiltered suites for #1, #3, #6 and #8 report the same three failures:
the stale proxy expectation addressed separately by #2 and two local sandbox
AF_UNIX restrictions. Both socket cases pass in #4's hosted run. That hosted
result does not cover the other open branches. Existing opt-in runtime skips
remain intact; no local Docker/provider execution is claimed.

## Haskoki runtime evidence still pending

The v0.5.0.0 candidate uses unpatched upstream
`091a2223e6dc559af72913c7f5a061ca22af34dc`. Its exact 24-Haskell-library,
GLIBC_2.38 and two-Hackage recipe gates remain unchanged and unmeasured for the
candidate build. Source inspection and pipeline preparation do not verify that
runtime closure.

No manual Haskoki runtime attempt has started as of this snapshot. The one-run
plan has a hard 240-minute ceiling, no matrix, no publication and no automatic
rerun; it awaits maintainer dispatch. Its 49 selected acceptance cases comprise
39 runtime cases, two static cases and eight derivative-dependent cases whose
inputs are missing. Missing derivative evidence must produce an incomplete,
nonzero outcome. The schema-readiness gap is covered by ordinary acceptance
assertions; any observed failure must not be xfailed or waived, and preparation
is not qualification.

## Remaining work

1. Establish scoped runtime evidence for pinned Haskoki and SoftHSM2 builds:
   fresh/repeated initialization, health, native errors, direct consumers,
   checker, proxy and failure isolation. Keep provider findings, infrastructure
   failures and evidence completeness separate.
2. Design reusable public acquisition/build operations for pinned OpenSC,
   checker/Python and proxy/native-client derivatives. Current packaged
   Dockerfiles accept preacquired sealed inputs; they are not those public APIs.
3. Address remaining SoftHSM2 traversal/type boundaries without assuming a fixed
   layout for opaque provider state. Foreground-child cancellation remains a
   separate design question; neither is covered by #6 or #8.
4. Review source redistribution eligibility **before upload**, complete companion
   identity and actual-content admission. Repository naming by artifact role and
   a versioned handoff contract also remain design decisions, not approved
   implementation requirements.
5. Maintain the provider/version and platform gap survey as research. Discovery
   alone does not add providers, change locks or expand the supported matrix.

The existing [delivery workflows](delivery.md) contain source and binary
publication steps and are not test-only entry points. At this baseline, their
admission calls omit actual-content evidence, so binary admission stays blocked.
Archive sealing alone does not establish source redistribution eligibility.
Preserve fail-closed gates while reviewing that design; do not use delivery as a
runtime-validation shortcut. See [source and licensing evidence](licensing.md)
for the separate obligations.
