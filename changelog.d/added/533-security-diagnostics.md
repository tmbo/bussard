- `bussard secure diag <ia> [--clear]` reads a Data Secure device's security
  failures log (PID 55: sequence, cryptographic and access counts, the latest
  failure), its security report (PID 57) and report control (PID 58) with the
  tool key; `--clear` resets them and reads them back. `status <ia>` and
  `knx_describe_device` show the same for a Secure device, the note of a
  secured write without admission evidence points at it, `monitor` names a
  device's broadcast security report, and knx-sim counts the failures as the
  standard says (#533).
