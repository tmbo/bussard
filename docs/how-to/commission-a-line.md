# Commission a line

Take a new installation from an empty plan to a tested, documented line: reserve the group addresses, give every device its address, prove it works, and print the handover folder. For owners building or extending a house, and for integrators on the bench.

## Reserve the group addresses room by room

A group address (`1/1/0`) is the topic a button sends on and an actuator listens to. Let bussard number them:

```console
$ bussard groups reserve "EG Küche" light light-dim blind heating
reserved 20 group address(es) for EG Küche in knx/groups.toml (floor-trade-block scheme):
  1/1/0     1.001    EG Küche Light Switch
  1/1/3     1.001    EG Küche Light Switch status
  1/1/5     1.001    EG Küche Dimmer Switch
  ...
wrote the floor-trade-block scheme to the [lint] table of knx/bussard.toml; `bussard validate` now checks the convention.
validation: 0 error(s), 0 warning(s).
$ bussard groups reserve "EG Wohnen" light-dim blind heating socket
$ bussard groups reserve "OG Schlafen" light blind heating
```

The room is one argument, floor first. The functions are `light`, `light-dim`, `blind`, `heating` and `socket`. Each gets a fixed block (five addresses for a light, ten for a blind or heating zone), so a plain light can later become a dimmer without renumbering. The second column is the DPT, the data type that tells bussard how to decode the value.

- The default scheme puts the floor on the main group and the trade on the middle group. For trade first, pass `--scheme function-floor` on the first reservation. A scheme that contradicts `bussard.toml` is refused.
- Running it again for a room adds nothing. Existing addresses and names are never renumbered or renamed.
- From now on `bussard validate` warns about an address outside its block, a switch with no status address, or a DPT that contradicts its role.

An assistant can do the same with `knx_reserve_groups` (one room) or `knx_scaffold_groups` (a list of rooms). Confirm the floors, rooms and functions before it writes.

## Commission the devices on the bench

Put the model's devices for the line on the bench, factory-fresh. Each needs its individual address (`1.1.7`, area.line.device), the address bussard and ETS use to program it.

!!! warning
    `commission` writes individual addresses, and with `--flash` and `--apply` it programs each device. Against a real gateway it also needs `--allow-remote-gateway`.

```console
$ bussard commission --line 1.1 --labels labels.csv
commission 2 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
  press the programming button on Blind actuator (JAL-0810.03)
  assigned 15.15.255 → 1.1.7
1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room
```

bussard first checks which devices already answer at their address. Those are reported as `present` and left alone. For each of the others it asks you to press the programming button, then:

1. Reads the pressed device's order number and compares it with the model. A mismatch stops that device with nothing written, and the run moves on.
2. Writes the address, verifies it, and clears programming mode.
3. Prints a label line and appends `address;name;order_number;floor;room` to `labels.csv`.

Add `--flash` to download each device's application program (the vendor firmware configuration) and `--apply` to write its links in the same pass. With `--flash`, every device's product file is resolved before the run starts; a missing one refuses the whole run before any bus access. The summary lists each device as `commissioned`, `present` or `failed: <reason>`, and the exit code is non-zero if any failed.

## Write the links of an addressed line

When the devices already have their addresses, preview the line with `bussard plan --line 1.1`: one table with each device's status (`changes: 2`, `unchanged`, or `skipped` for a device bussard cannot program).

!!! warning
    `apply --line` writes every device on the line that has changes.

```console
$ bussard apply --line 1.1
apply the model's links to 3 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
```

It asks once for the whole line, then backs up, writes and verifies each device, and keeps going when one fails. If the tunnel drops or you stop the run, re-run with `--resume`: it skips the devices already done and retries the failed ones.

## Write an acceptance test

Put a `tests.toml` next to `groups.toml`. Each test is a stimulus and the telegram that proves the installation reacted:

```toml
[[tests]]
name = "Kitchen ceiling light switches and reports"
write = { ga = "1/0/10", value = "on" }
expect = { ga = "1/0/12", value = "on", within = "2s" }

[[tests]]
name = "Wind alarm raises the blinds"
manual = "Press the test button on the weather station"
expect = { ga = "3/1/0", value = "up", within = "5s" }
```

Each test has exactly one of `write` or `manual`. `within` defaults to `3s`; leave out `value` to accept any value. An assistant can draft the file from the model: switches with a status address are the obvious first tests.

## Run the acceptance test

!!! warning
    `bussard test` writes group values, so lights switch and blinds move. It asks for confirmation naming the gateway.

```console
$ bussard test --gateway 192.0.2.10
PASS Kitchen ceiling light switches and reports
     1/0/12 arrived = on within 2s
FAIL Wind alarm raises the blinds
     expected 3/1/0 = up within 5s after the manual step "Press the test button on the weather station", but it did not arrive

2 test(s): 1 passed, 1 failed, 0 skipped, 0 refused
```

The report has no timestamps, so a rerun at the three-month visit gives a protocol you can compare line by line. The run exits non-zero on any failure. A test that writes a protected group address needs `allow_protected = true` in the file and `--force`; the MCP tool `knx_run_tests` never runs it. `--skip-manual` skips the manual tests, `--only <NAME>` runs one.

## Generate the handover documentation

```console
$ bussard doc
$ bussard doc --format html --out handover/
```

`doc` reads only the model and writes the folder the KNX guidelines ask for, by default to `docs/installation`: a device list, a group-address list with senders and listeners, one sheet per room in plain language, the connection details (never credentials) and a change log from git. Devices without a `location:` get no room sheet. Two runs on the same model write identical files, so commit the folder and regenerate it after every change.

## Next steps

- [Work with an integrator](work-with-an-integrator.md): send the result as a bundle.
- [Programming commands](../reference/commands/programming.md): every `commission` and `apply --line` flag.
- [tests.toml](../reference/files/tests-toml.md): every field of the test file.
