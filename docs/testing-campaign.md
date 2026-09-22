# The physical-device test campaign

Everything `bussard` knows about programming devices was proven against KNX
Virtual, the independent `knx-sim`, and fifteen real ETS captures. It has never
written to a physical device. [Issue #89](https://github.com/tmbo/bussard/issues/89)
is the campaign that changes that, and
[issue #90](https://github.com/tmbo/bussard/issues/90) is the KNX Secure half.

This page is the runbook: which script runs which phase, where the data lands,
how to compare a `bussard` download against ETS's, and what must never be
committed.

Read [SAFETY.md](SAFETY.md) first. Nothing here replaces it.

## Before anything

Issue #89's first ground rule, and the reason the preflight script refuses
without `--i-have-an-ets-backup`:

1. Take a full ETS project backup.
2. Do an ETS full download of one device and confirm it works.

ETS is the only recovery path for a device this campaign reprograms. Prove the
recovery path before you need it.

## The scripts

All four live in `scripts/campaign/`. They share three habits:

- **They print the plan and stop.** Nothing runs until you add `--go`, so the
  gateway, the model and the device list are read before anything happens, not
  after.
- **They name the gateway.** Every plan prints the resolved `host:port` and says
  whether it is loopback or a real bus.
- **The two that can write refuse a real bus without the opt-in.** Exactly the
  rule `bussard` applies to itself: `--allow-remote-gateway`, or
  `BUSSARD_ALLOW_REAL_GATEWAY=1` for the session.

Common flags: `--dir <model>`, `--gateway <host[:port]>`, `--date <YYYY-MM-DD>`,
`--iface <if>`, `--dry-run`, `--fast`, `--go`, `--allow-remote-gateway`.

### `00-preflight.sh`: arm the recorders

```
scripts/campaign/00-preflight.sh --i-have-an-ets-backup --go \
    --allow-remote-gateway --iface en0
```

Confirms the ETS backup, checks the binary and validates the model, starts
`tcpdump` and `bussard capture` into the campaign directory, and writes
`session.env` for the later scripts. It touches no device.

`tcpdump` normally needs `sudo`. Without it the script warns and carries on: a
per-step window file records the time range instead, so a capture taken elsewhere
can still be sliced. Stop the recorders with `00-preflight.sh --stop`.

### `10-baseline.sh`: Phase 0, read-only

```
scripts/campaign/10-baseline.sh --go --line 1.1
```

Three `scan --json` runs ten minutes apart with `-vv` (the per-address timing
[#45](https://github.com/tmbo/bussard/issues/45) wants), then `describe --json`
and `reconstruct` for every device in the model, then `findings.md`. Read-only,
so it is not gated on the opt-in. It still prints the gateway.

`--gap <seconds>` shortens the wait between scans; `--fast` sets a short sweep
and a two-second gap, for a dry run.

### `20-per-device.sh`: one step, wrapped in evidence

```
scripts/campaign/20-per-device.sh <IA> <PHASE> --go [--allow-remote-gateway] [-- <bussard args>]
```

`PHASE` is `plan`, `apply`, `assign`, `describe`, or `flash` / `flash-force` /
`custom`, which need the command spelled out after `--`:

```
scripts/campaign/20-per-device.sh 1.1.5 flash --go --allow-remote-gateway \
    -- flash 1.1.5 --product products/foo.knxprod --yes
```

Around the step it records `describe --json` and `reconstruct` before and after,
runs the step with `-vv` and `BUSSARD_WIRE_TRACE=1`, takes a per-step pcap (or
writes the window to slice one), splits the wire trace into `wire.log`, and
appends a row to the baseline `findings.md`. It exits with the step's own exit
code, so a phase loop stops where the device did.

### `90-reconcile.sh`: Phase 6

```
scripts/campaign/90-reconcile.sh --go --line 1.1
```

Re-runs the Phase 0 reads and diffs every artefact against the baseline into
`reconcile/diff.md`. Read-only. A device that reads back differently is not
automatically a problem, because the campaign reprograms devices on purpose, but
every difference belongs in the findings log with a classification.

## Phases to scripts

| Issue #89 phase | What to run |
| --- | --- |
| Ground rules | `00-preflight.sh --i-have-an-ets-backup` |
| Phase 0, baseline | `10-baseline.sh` |
| Phase 1, links on System B | `20-per-device.sh <ia> plan`, then `<ia> apply` |
| Phase 2, flash System B | `20-per-device.sh <ia> flash -- flash <ia> --product ...` |
| Phase 3, flash System 7 | the same, per device class |
| Phase 4, assign and adopt | `20-per-device.sh <ia> assign`; `adopt` via `-- adopt ...` |
| Phase 5, reliability | `20-per-device.sh <ia> flash ...` in a loop; the unplug and power-cycle tests are manual |
| Phase 6, reconciliation | `90-reconcile.sh` |

Issue #90's Secure steps use the same wrapper. Add `--keyring <file>` to the
command after `--`, and keep `BUSSARD_KEYRING_PASSWORD` out of shell history
(there is deliberately no flag for it). Store Secure data under
`captures/secure/`.

## Where the data lands

```
captures/campaign/<date>/
  session.env                     written by the preflight, read by the rest
  preflight/
    campaign-<ts>.pcap            the campaign-wide tcpdump
    bus.db                        bussard capture
    validate.txt  devices.txt
  baseline/
    scan-1.json  scan-1.log       ... x3; the .log holds the -vv timing
    devices/<ia>/describe.json    describe.log  describe.rc
    devices/<ia>/reconstruct.log  reconstruct.rc
    findings.md                   the findings log for the whole campaign
  devices/<ia>/<phase>-<ts>/
    before-describe.json  before-reconstruct.log
    step.log  wire.log  step.pcap  window.txt
    after-describe.json   after-reconstruct.log
  reconcile/
    scan.json  devices/<ia>/...   diff.md
```

`captures/` is gitignored and the pre-commit hook refuses anything under it. One
findings log, `baseline/findings.md`, carries the whole campaign: the baseline
table, the classification legend, and one appended row per step.

Classifications: `match`, `benign`, `bug`, `corpus gap`, `cal confirmed`,
`refusal ok`, `refusal wrong`. A refusal that should not have happened is a
finding, and so is a write that should have been refused. Record the message
verbatim either way.

## Comparing a download against ETS

This is the campaign's central measurement, and what
[`tools/knxtrace`](../tools/knxtrace/README.md) exists for. Capture ETS doing a
download of a device, capture `bussard` doing the same, and diff them:

```
uv run tools/knxtrace/knxtrace.py devices ets.pcapng
uv run tools/knxtrace/knxtrace.py diff ets.pcapng bussard.pcapng --device 1.1.5
```

The differ normalizes both captures into an operation sequence per device,
dropping tunnel counters, L4 acknowledgements, `L_Data.con` echoes, repeats and
timing, then classifies each remaining difference:

| Verdict | Reasons |
| --- | --- |
| `IDENTICAL` | The sequences match byte for byte. |
| `BENIGN` | `ordering`, `cycling`, `chunking`, `retry`. |
| `DIFFERENT` | `payload`, `missing`, `extra`, `coverage`, `content`. |

`chunking` matters most: ETS and `bussard` pick different APDU sizes, so the
write records disagree while the resulting image is identical. The differ
compares the coalesced memory image separately, which reports a genuine
divergence as exact address ranges however the writes lined up. It exits `1` on
`DIFFERENT`, so a loop over devices can gate on it.

To read one capture rather than compare two:

```
uv run tools/knxtrace/knxtrace.py trace bussard.pcapng --device 1.1.5   # chronological
uv run tools/knxtrace/knxtrace.py ops   bussard.pcapng --device 1.1.5   # normalized
```

When `tcpdump` could not run per step, `window.txt` names the `editcap` command
that slices the step out of the campaign-wide capture.

## Private data

The repository must never describe a real installation. See
[SAFETY.md](SAFETY.md#private-data-the-maintainers-installation-and-yours) for
the full rule; for this campaign specifically:

- Everything the scripts write goes under `captures/`, which is gitignored.
- `.pcap`, `.pcapng`, `.knxproj`, `.knxkeys` and `captures/` are gitignored;
  check a diff for the LAN address and for room or device names before
  committing anything derived from a campaign.
- `knxtrace` never prints key material: `A_Authorize` keys are hashed,
  `A_SecureData` payloads are a length and a hash, and KNXnet/IP Secure frames
  are named but never decrypted.
- When a finding becomes an issue, paste the decoded `knxtrace` excerpt, not the
  raw capture, and replace addresses with TEST-NET ones.

## Rehearsing on the simulator

Every script has a loopback dry-run mode, so the runbook can be rehearsed
without a bus. Build both binaries, start `knx-sim`, and point the scripts at it:

```
cargo build --bin bussard
cargo build --manifest-path knx-sim/Cargo.toml --bin serve
knx-sim/target/debug/serve knx-sim/examples/small-installation/sim.yaml &

M=knx-sim/examples/small-installation/knx
scripts/campaign/00-preflight.sh  --dir $M --dry-run --i-have-an-ets-backup --go
scripts/campaign/10-baseline.sh   --dir $M --dry-run --fast --line 1.0 --go
scripts/campaign/20-per-device.sh 1.0.2 plan --dir $M --dry-run --go
scripts/campaign/90-reconcile.sh  --dir $M --dry-run --fast --line 1.0 --go
scripts/campaign/00-preflight.sh  --stop
```

`--dry-run` refuses a non-loopback gateway, so a rehearsal cannot become a live
run by a stale flag. The example needs four vendor `.knxprod` files, which are
copyrighted and gitignored; `knx-sim/examples/small-installation/run.sh` explains
where to put them.

## See also

- [SAFETY.md](SAFETY.md): the write path and its rails.
- [`tools/knxtrace/README.md`](../tools/knxtrace/README.md): decoder coverage
  and the diff rules in detail.
- [`docs/flash-op-coverage.md`](flash-op-coverage.md): which load operations
  `bussard` can execute.
- [`docs/knx-secure-spec.md`](knx-secure-spec.md): the `SEC-CAL` markers issue
  #90 settles.
