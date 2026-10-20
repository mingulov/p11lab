# One main-launched frozen Haskoki opportunity

This manual controller schedules **frozen candidate evidence launched from main**.
It does not integrate or qualify the candidate on main. Registration, a skipped
job, successful admission or a green summary is not acceptance success.

The only candidate is commit `fca1b148f074bc0f3fd527bc02fe7920f33fa4cd`, tree
`08f74d03f9d6acfa2a461c48aa9088b05c317693`. Its source, locks, requirements,
driver and all 49 acceptance cases remain unchanged. The eight missing
derivative-dependent cases and genuine provider failures cannot become green.
Runtime evidence does not establish distribution rights.

## Before the one click

1. Independently review the final cumulative main tree and controller diff,
   including cheap test and actionlint evidence. Do not merge the candidate
   wholesale or substitute current-main package code for the frozen payload.
2. Read back the actual remote main commit and workflow bytes. Confirm the
   default branch is main, the existing workflow ID is `390791808`, and the
   [manual workflow UI](https://github.com/mingulov/p11lab/actions/workflows/haskoki-release-validation.yml)
   offers **Run workflow**. Registration must not be tested by dispatching.
3. Recheck complete public history. Only runs `39461303417` (number 1, static
   failure) and `39463132399` (number 2, static success) may precede the launch.
   Both must remain first-attempt completed PR runs with their runtime jobs
   skipped and no runtime steps. Unknown/deleted history or changed identity
   requires reconciliation, not a guessed replacement slot.
4. Supply the exact reviewed current main SHA to the authenticated `mingulov`
   owner account (actor ID `1794540`), not another repository writer. In that UI select **main**, enter it as `reviewed_controller_sha`,
   and submit **once**. Do not dispatch candidate/PR/historical refs or use rerun
   controls. No extra token or permission grant is needed.

Main may keep advancing before dispatch. Refresh the cumulative review, remote
readback, history and supplied SHA after an advance; this does not consume an
opportunity. Never silently accept a new unreviewed main SHA merely because the
launcher itself did not change. Coordinate fresh readback immediately before
the click; there is no technical main lock or full-runtime branch freeze.

Once GitHub accepts the dispatch, run **3 / attempt 1** is consumed even if
checkout, admission or setup fails before Docker starts. A main advance during
queue/startup/setup refuses that opportunity. A timeout, cancellation, failed
build, incomplete evidence or uncertain submission does not authorize a retry.
Reconcile uncertainty by reads and request a separate rearming decision before
any replacement. Follow the one accepted run to its terminal outcome.

## What the controller enforces

- One dispatch-only, main-only Ubuntu 24.04 job, **240 minutes inclusive**.
  Build and test stage maxima are 220 and 16 minutes; their sum plus setup may
  exceed the job ceiling and leave incomplete evidence. There is no matrix,
  automatic rerun, fail-fast, acceptance suppression or budget extension.
- Exact repository/owner IDs, genuine dispatch context, reviewed controller
  checkout and live main SHA, workflow identity, run number 3 and attempt 1.
  Both direct current-run reads and complete history must show the same active
  `in_progress` current run with no conclusion.
- Two independently complete bounded public observations: before setup and
  immediately before the sole build. Each permits at most five 100-run history
  pages, 12 GETs, 4 MiB per response, 24 MiB total and 60 seconds overall, with
  a 10-second per-GET watchdog. All exhaustion or uncertainty refuses; no token,
  proxy credentials, redirect, arbitrary pagination URL, backoff or retry.
- Exact ID/path/name collision checking before history selection, repeated
  first-page comparison, and both historical job lists using `filter=all`.
  New unrelated Linux CI between observations is allowed. Historical PR-head
  references and profile descriptions are mutable metadata, not run identities.
- Separate `controller/` and `payload/` checkouts, no persisted credentials,
  and venv/wheels/private evidence outside both. Before payload execution and
  again before build, all 441 frozen files must match raw blob bytes, exact
  modes, regular-file types and single link counts. Extra ignored files,
  bytecode, symlinks, submodules and extra directories refuse the run.
- Unmodified genuine init, pinned Python 3.12.14 and no-deps requirements,
  installed-wheel provenance, strict preflight, one build, full acceptance and
  always-run safe summary. The frozen summary itself requires a fresh complete
  payload proof; a later integrity failure cannot reuse an earlier success.

## Limits and evidence

This is **at most one admitted opportunity through the reviewed main route**,
not global exactly-once or a durable lock. It may produce zero builds. Bounded
pagination and repeated reads cannot exclude transient insertion/deletion,
unchanged-count changes outside the repeated page, consistently stale API data,
post-check cancellation, a later main move or an old-ref launch immediately
after the final read. Raw-file verification likewise trusts the hosted runner
against changes after observation. Administrators and historical workflows can
bypass this controller. Operators must not launch those routes in parallel.

Constant concurrency with `cancel-in-progress: false` serializes this route,
but default pending-run replacement still applies; dispatch order and run 3's
survival are not guaranteed. No queue mechanism rescues accidental submissions.

Only allowlisted identities, fixed failure classifications and the unchanged
frozen driver's sanitized outcomes enter summaries. Raw API/event/environment
values, assertions, logs, PINs, stores, keys and TLS private keys are not exposed
or uploaded. There are no source/image/cache/artifact/release uploads, registry
logins, registry package publication or related-repository changes. Cancellation or the job
ceiling may prevent a final summary: absent evidence is never a pass.

The main launcher is scheduling infrastructure, not proof that registration,
the authenticated click, a Docker build or acceptance has occurred. Those are
separate observable gates; local tests do not consume or establish runtime
success.
