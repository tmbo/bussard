# ETS golden images (issue #123)

Memory images ETS 6 wrote during full downloads, composed from bus captures
(`knxtrace trace`, the `A_Memory(Extended)_Write` telegrams between an object's
`PID_TABLE_REFERENCE` read and its load completion). Hex, 32 octets per line.
They contain no group addresses.

| file | device | application | what |
| --- | --- | --- | --- |
| `f50-obj3.hex` | Jung 52921ST (F50 push-button module 2-gang) | `M-0004_A-D142-21-8848-O000A` | group-object table, 2668 octets (count 1333) |
| `f50-obj4.hex` | same | same | parameter segment, 6152 octets: zero fill plus the 276 octets ETS wrote |
| `a3030-obj3.hex` | Jung 390041SR (LED universal dimmer 4-gang) | `M-0004_A-3030-23-F0EA-O000A` | group-object table, 942 octets (count 470) |
| `a0ed-obj3.hex` | ABB BE/S16.230.3.2 (binary input 16-gang) | `M-0002_A-A0ED-10-9B4E` | group-object table, 466 octets (count 232) |
| `helios-obj3.hex` | Helios KWL KNX connect | `M-0112_A-0003-10-*-O0115` | group-object table, 130 octets (count 64) |
| `helios-obj4.hex` | same | same | parameter segment, 32 octets |

The F50 capture is the ETS 6 download of 2026-09-16. `tests/ets_golden.rs`
rebuilds each image from the vendor product (corpus cache, not committed), the
device's linked object numbers with their per-object flags and com-object refs,
and its non-default parameters (ref ids and values only).
