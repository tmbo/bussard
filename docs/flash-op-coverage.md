# `bussard flash` LoadProcedure op coverage

A data-driven gap analysis of the `LdCtrl*` LoadProcedure interpreter in
`crates/bussard-download/src/flash.rs`. It answers: across real KNX product
files, which LoadProcedure ops appear, how often, and which ones `bussard flash`
does not yet execute — so we know what to implement next and in what order.

## Corpus

80 application programs extracted from 36 vendor `.knxprod` files (the full
`data/product-index.json`), spanning 7 manufacturers: MDT, Zennio, Theben,
Lingg & Janke, Elsner Elektronik, Steinel, EAE Technology.

The `.knxprod` files and the extracted model YAMLs are copyrighted vendor data
and are gitignored (`tests-support/product-corpus/cache/`). Regenerate with
`tests-support/product-corpus/fetch.sh`, then re-run the tally:

```
tests-support/product-corpus/analyze-load-ops.py
```

Ops are classified against bussard's supported set by reading each model's
rendered `load_procedure:` block. Unknown `LdCtrl*` ops render as
`raw LdCtrl<Name>` and are counted by their verbatim name.

## The decisive split: mask family, not op richness

> **Update: System 7 is supported.** This analysis predates System 7 flash
> support. `bussard flash` now also targets the System 7 masks `0705`, `0701`
> and `0700` through a separate absolute-addressed lowering (`LdCtrlAbsSegment`,
> `LdCtrlTaskSegment`, `LdCtrlTaskCtrl1`, `LdCtrlCompareMem`, the obj0/PID78
> compare); see [system7-spec.md](system7-spec.md). The per-mask support table
> lives in [SAFETY.md](SAFETY.md#supported-device-masks). The tallies below are
> the original System-B-only snapshot and have not been re-run against the
> System 7 lowering.

When this analysis was taken, `bussard flash` targeted **System B (mask 07B0)
only**: `plan_flash` refused any other device at the `NotSystemB` gate *before*
it inspected a single op. The corpus splits cleanly along that line:

| mask | family | apps | flashable today |
|------|--------|-----:|-----------------|
| 07B0 | System B | 24 | **all 24** |
| 0705 | BCU2 | 44 | none (gated: not System B) |
| 0701 | BCU1 | 5 | none (gated: not System B) |
| 0021 | System 2 / Secure | 5 | none (gated: not System B) |
| 091A, 0012 | other | 2 | 2 (no refused ops present) |

**Every System B app in the corpus is fully executable by bussard today.** Not
one 07B0 app uses a refused op. All the refused ops below belong to the
non-System-B families that `flash` does not target yet.

26 of 80 apps (24 × 07B0 + 2 outliers) are fully executable end to end.

## Support matrix

| op | status | occurrences | apps | mfrs |
|----|--------|-----------:|-----:|-----:|
| `abs_segment` | **REFUSED** | 326 | 54 | 7 |
| `load` | supported | 163 | 54 | 7 |
| `unload` | supported | 162 | 54 | 7 |
| `task_segment` | **REFUSED** | 162 | 52 | 6 |
| `load_completed` | supported | 162 | 54 | 7 |
| `load_image_prop` | supported | 66 | 24 | 2 |
| `connect` | supported | 54 | 54 | 7 |
| `disconnect` | supported | 54 | 54 | 7 |
| `compare_prop` | supported | 50 | 47 | 2 |
| `restart` | supported | 47 | 47 | 5 |
| `rel_segment` | supported | 46 | 24 | 2 |
| `write_rel_mem` | supported | 24 | 24 | 2 |
| `task_ctrl1` | **REFUSED** | 8 | 8 | 4 |
| `write_prop` | supported | 5 | 5 | 2 |
| `LdCtrlTaskPtr` | **REFUSED** (raw) | 5 | 5 | 2 |
| `LdCtrlTaskCtrl2` | **REFUSED** (raw) | 5 | 5 | 2 |
| `write_mem` | supported | 3 | 1 | 1 |
| `LdCtrlCompareMem` | **REFUSED** (raw) | 1 | 1 | 1 |

Supported set (verified in `flash.rs`): `connect`, `disconnect`, `unload`,
`load`, `load_completed`, `rel_segment`, `write_rel_mem`, `write_mem`,
`write_prop`, `compare_prop`, `load_image_prop`, `restart`.

## Ranked unimplemented ops

Ranked by number of distinct apps. "Blocked only by this op" = apps whose every
*other* op is already supported.

| rank | op | apps | mfrs | example vendors | blocked only by this | mask family |
|-----:|----|-----:|-----:|-----------------|:--------------------:|-------------|
| 1 | `abs_segment` | 54 | 7 | all 7 | 1 | 0705/0701/0021 |
| 2 | `task_segment` | 52 | 6 | MDT, Theben, L&J, Elsner, Steinel, EAE | 0 | 0705/0701/0021 |
| 3 | `task_ctrl1` | 8 | 4 | Theben, L&J, Elsner, Steinel | 0 | 0705/0021 |
| 4 | `LdCtrlTaskPtr` (raw) | 5 | 2 | Theben, L&J | 0 | 0705/0021 |
| 5 | `LdCtrlTaskCtrl2` (raw) | 5 | 2 | Theben, L&J | 0 | 0705/0021 |
| 6 | `LdCtrlCompareMem` (raw) | 1 | 1 | Zennio | 0 | 0701 |

What each would take to implement:

- `abs_segment` — absolute-segment allocate (`LdCtrlAbsSegment`) plus absolute
  `A_Memory` placement. `bussard-mgmt`'s allocate is a stub today.
- `task_segment` / `task_ctrl1` / `LdCtrlTaskPtr` / `LdCtrlTaskCtrl2` — the
  BCU1/BCU2 task-and-segment descriptor programming set. These co-occur:
  **52 of the 54 `abs_segment` apps also use `task_segment`**, and the task-ptr
  / task-ctrl2 ops only ever appear alongside them. They are the classic
  absolute-download machinery of the pre-System-B mask families, not independent
  features.
- `LdCtrlCompareMem` — read absolute memory (`A_Memory_Read`) and byte-compare;
  one Zennio 0701 app.
- `LdCtrlCompareRelMem` (issue #51) — **does not appear in any file in the
  corpus.**

## Master reset

**No real vendor device uses `LdCtrlMasterReset`.** It appears in zero of the 80
apps across all 7 manufacturers. Its only known user is KNX Virtual's own apps,
which are not vendor product files. bussard would currently refuse it (it parses
as a `raw` op and `plan_flash` returns `UnsupportedOp`), and that gap is real —
but it is a KNX-Virtual-interop gap, not a real-device gap.

## Recommendation

**The System B interpreter is complete for the products we can reach.** All 24
System B apps flash end to end; no 07B0 app needs anything unimplemented. There
is no highest-value single op to add for real System B hardware — that surface is
done.

The ranked table is dominated by `abs_segment` + `task_segment`, but those
numbers are misleading in isolation: every one of those apps is a non-System-B
device (0705/0701/0021) that `plan_flash` already refuses at the mask gate.
Implementing `abs_segment` alone unlocks nothing — 52 of its 54 apps also need
the full task-segment set, and all of them need a BCU1/BCU2 absolute-download
device layer bussard does not have.

Priority order:

1. **`LdCtrlMasterReset`** — smallest change, clears the known KNX-Virtual
   interop blocker that motivated this analysis. It is one `A_Restart` variant
   (master-reset erase code), not a new device family. Do this first even though
   it has zero real-vendor frequency: it is cheap and it is the actual bug.
2. **Absolute-download family as one unit** (`abs_segment` + `task_segment` +
   `task_ctrl1` + `LdCtrlTaskPtr` + `LdCtrlTaskCtrl2`) — only worth starting once
   bussard decides to support BCU2 (0705) devices, which is 44 apps / the single
   largest family in the field. This is a device-support project (a new mask
   family behind the `NotSystemB` gate), not an isolated op. Treat the five ops
   as one milestone; they never appear apart.
3. **`LdCtrlCompareMem` / `LdCtrlCompareRelMem`** — lowest priority.
   `CompareMem` is one app; `CompareRelMem` (issue #51) appears in no file at
   all. Both are read-and-verify precondition checks, not writers, so their
   absence never leaves a device half-flashed — they can stay refused safely.
