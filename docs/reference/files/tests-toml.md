# tests.toml

`tests.toml` holds the acceptance tests `bussard test` and the `knx_run_tests` MCP tool run against the bus. You write it; it is optional, and parsed as strictly as the rest of the project.

## Example

```toml
allow_protected = false      # opt-in for tests that write protected group addresses (also needs --force)

[[tests]]
name = "Kitchen ceiling light switches and reports"
write = { ga = "1/0/10", value = "on" }
expect = { ga = "1/0/12", value = "on", within = "2s" }

[[tests]]
name = "Wind alarm raises the blinds"
manual = "Trigger the wind alarm on the weather station"
expect = { ga = "3/1/0", value = "up", within = "5s" }
```

## Keys

| Key | Type | Meaning |
|---|---|---|
| `allow_protected` | bool, default `false` | Half of the opt-in for writing a `protected = true` group address. The CLI also needs `--force`; the MCP tool ignores this flag and always refuses. |
| `tests[].name` | string | Reported name, and the key for `--only`. |
| `tests[].write` | `{ga, value, dpt?}` | The stimulus: a group write. `value` is human-typed and encoded against the group address's DPT, or against `dpt` when given. |
| `tests[].manual` | string | The stimulus instead of a write: an instruction for a human. Exactly one of `write` or `manual`. |
| `tests[].expect.ga` | group address | The address the proof must appear on. |
| `tests[].expect.value` | scalar, optional | The value it must carry, encoded against the address's DPT and compared byte for byte. Omit it to accept any value. On an address without a DPT, give the payload as hex (`"0x01"`). |
| `tests[].expect.within` | duration, default `3s` | How long to wait: `"2s"`, `"500ms"`, `"1m"`, or a bare number of seconds. |

## Notes

- Tests run in file order. A test has a stimulus and usually an `expect`; a manual test must have one.
- The runner ignores the gateway's echo of its own write and anything sent from its own address, so a test may write and expect the same group address.

!!! warning
    A `write` test transmits on the bus. `bussard test` asks before it runs.

## Related

- [Bus commands](../commands/bus.md): `bussard test` and its flags.
- [Commission a line](../../how-to/commission-a-line.md): the acceptance test in practice.
- [groups.toml](groups-toml.md): the DPTs the values are encoded against, and `protected`.
