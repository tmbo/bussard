- Internal: the device file is read and written through one serde shape, the
  model analysis behind `bussard audit` and the viz problems panel is built
  from the `validate` diagnostics, the device view, `bussard doc` and the
  lock's parameter index share one parameter row, and the DPT validity checks
  run inside the decoder (#907).
- `bussard validate` reports the one-sided links `bussard audit` lists as
  findings: I048 (a group address with a sender but no listener) and I049 (a
  listener but no sender), both info (#907).
- `bussard audit` and the viz count as unlinked com objects the ones I009
  reports (a T or W object in no link); objects without either flag are no
  longer counted (#907).
- `bussard doc --json` lists each device's parameters as the rows
  `bussard device --json` shows, plus `label`: `key` is the device file's key,
  `value` the stored value and `computed` what a download writes for a
  calculation output (#907).
