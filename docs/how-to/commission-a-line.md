# Commission a line

Take a new installation from an empty plan to a tested, documented line: reserve the group addresses, give every device its address, prove it works, and print the handover folder. For owners building or extending a house, and for integrators on the bench.

## Reserve the group addresses room by room

A group address (`1/1/0`) is the topic a button sends on and an actuator listens to. Let bussard number them.

=== "In chat"

    ```text
    You:        The kitchen on the ground floor gets a light, a dimmer,
                a blind and heating.
    Assistant:  EG Küche: light, light-dim, blind, heating. Reserve them?
    You:        Yes.
    Assistant:  (calls knx_reserve_groups)
                Reserved 20 group addresses for EG Küche, starting at
                1/1/0 EG Küche Light Switch. The project validates clean.
    ```

    `knx_reserve_groups` reserves one room; `knx_scaffold_groups` takes a list of rooms at once. The assistant confirms the floors, rooms and functions before it writes.

=== "At the terminal"

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

    The room is one argument, floor first. For trade first, pass `--scheme function-floor` on the first reservation.

The room names the floor first. The functions are `light`, `light-dim`, `blind`, `heating` and `socket`. Each gets a fixed block (five addresses for a light, ten for a blind or heating zone), so a plain light can later become a dimmer without renumbering. The second column is the DPT, the data type that tells bussard how to decode the value.

- The default scheme puts the floor on the main group and the trade on the middle group. A scheme that contradicts `bussard.toml` is refused.
- Reserving a room again adds nothing. Existing addresses and names are never renumbered or renamed.
- From now on validation warns about an address outside its block, a switch with no status address, or a DPT that contradicts its role.

## Commission the devices on the bench

Put your project's devices for the line on the bench, factory-fresh. Each needs its address (`1.1.7`, area.line.device), the one bussard and ETS use to program it.

!!! warning
    Commissioning writes device addresses. Against a real gateway it also needs `--allow-remote-gateway`.

=== "In chat"

    An illustrative exchange:

    ```text
    You:        Commission line 1.1.
    Assistant:  (calls knx_commission_line)
                Your project has 2 devices on line 1.1: Blind actuator in the
                living room and Switch actuator in the kitchen. Start?
    You:        Yes.
    Assistant:  (calls knx_commission_line with yes, then knx_job_status)
                Press the programming button on Blind actuator
                (JAL-0810.03), Ground floor, Living room.
    You:        Done.
    Assistant:  (calls knx_job_status)
                Blind actuator is 1.1.7, read back and verified. Press the
                programming button on Switch actuator (AKK-0216.03).
    ```

    `knx_commission_line` needs a server started with `--allow-programming`. Your one yes covers every device whose order number matches your project. When the pressed device is another product, or nothing answers, the job waits for your word: retry, skip or stop. At the end the assistant reads out the label lines.

=== "At the terminal"

    ```console
    $ bussard commission --line 1.1 --labels labels.csv
    commission 2 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
      press the programming button on Blind actuator (JAL-0810.03)
      assigned 15.15.255 → 1.1.7
    1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room
    ```

    A mismatch stops that device with nothing written, and the run moves on. Each label line is appended to `labels.csv` as `address;name;order_number;floor;room`.

bussard first checks which devices already answer at their address. Those are reported as `present` and left alone. For each of the others it asks you to press the programming button, then:

1. Reads the pressed device's order number and compares it with your project.
2. Writes the address, verifies it, and clears programming mode.
3. Gives you a label line.

In chat only addresses are written; links, parameters and the application follow per device with the plan and the write, or for the line as below. At the terminal, add `--flash` to download each device's application program (the vendor firmware configuration) and `--apply` to write its links in the same pass. With `--flash`, every device's product file is resolved before the run starts; a missing one refuses the whole run before any bus access. The summary lists each device as `commissioned`, `present` or `failed: <reason>`, and the exit code is non-zero if any failed.

## Write the links of an addressed line

!!! warning
    A line write changes every device on the line that has changes.

=== "In chat"

    ```text
    You:        Write the links of line 1.1.
    Assistant:  (calls knx_plan_device with line)
                2 devices have changes, 1 is unchanged. Write them?
    You:        Yes.
    Assistant:  (calls knx_apply_device with line, then knx_job_status)
                Both devices written and verified.
    ```

    The line form writes links only, never parameters.

=== "At the terminal"

    Preview the line with `bussard plan --line 1.1`: one table with each device's status (`changes: 2`, `unchanged`, or `skipped` for a device bussard cannot program).

    ```console
    $ bussard apply --line 1.1
    apply the model's links to 3 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
    ```

    If the tunnel drops or you stop the run, re-run with `--resume`: it skips the devices already done and retries the failed ones.

The line write asks once for the whole line, then backs up, writes and verifies each device in address order, and keeps going when one fails.

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

Each test has exactly one of `write` or `manual`. `within` defaults to `3s`; leave out `value` to accept any value. An assistant can draft the file from your project: switches with a status address are the obvious first tests.

## Run the acceptance test

!!! warning
    The test writes group values, so lights switch and blinds move.

=== "In chat"

    ```text
    You:        Run the acceptance test.
    Assistant:  (calls knx_run_tests)
                Kitchen ceiling light switches and reports: passed.
                Wind alarm raises the blinds is a manual test, so I
                skipped it; run it at the terminal.
    ```

    `knx_run_tests` needs a server started with `--allow-writes`. It skips manual tests and refuses a test that writes a protected group address, whatever the file says.

=== "At the terminal"

    It asks for confirmation naming the gateway.

    ```console
    $ bussard test --gateway 192.0.2.10
    PASS Kitchen ceiling light switches and reports
         1/0/12 arrived = on within 2s
    FAIL Wind alarm raises the blinds
         expected 3/1/0 = up within 5s after the manual step "Press the test button on the weather station", but it did not arrive

    2 test(s): 1 passed, 1 failed, 0 skipped, 0 refused
    ```

    The run exits non-zero on any failure. A test that writes a protected group address needs `allow_protected = true` in the file and `--force`. `--skip-manual` skips the manual tests, `--only <NAME>` runs one.

The report has no timestamps, so a rerun at the three-month visit gives a protocol you can compare line by line.

## Generate the handover documentation

=== "In chat"

    ```text
    You:        Write the handover documentation.
    Assistant:  (calls knx_export with what: doc)
                Written to docs/installation.
    ```

=== "At the terminal"

    ```console
    $ bussard doc
    $ bussard doc --out handover/
    ```

The documentation reads only your project and writes the folder the KNX guidelines ask for as Markdown, by default to `docs/installation`: a device list, a group-address list with senders and listeners, one sheet per room in plain language, the connection details (never credentials) and a change log from git. Devices without a `location:` get no room sheet. Two runs on the same project write identical files, so commit the folder and regenerate it after every change.

## Next steps

- [Work with an integrator](work-with-an-integrator.md): send the result as a bundle.
- [Programming commands](../reference/commands/programming.md): every `commission` and `apply --line` flag.
- [tests.toml](../reference/files/tests-toml.md): every field of the test file.
