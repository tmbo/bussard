# Add a device

Bring a new device into the model and onto the bus, label devices on the bench, and start a model when there is no ETS project at all. Every device needs its vendor's product data (a `.knxprod` file); bussard downloads it from the vendor and never ships it.

## Get the product data

=== "In chat"

    ```text
    You:        Get the product data for the MDT AKK-0216.03.
    Assistant:  (calls knx_import_file)
                The vendor index has MDT Switch Actuator AKK (compact,
                REG). May I download it from the vendor?
    You:        Yes.
    Assistant:  (calls knx_import_file with download: true)
                Downloaded, verified and stored in products/.
    ```

    `knx_import_file` with an order number fetches from the product index. Downloading needs your separate consent; without it nothing is downloaded and the assistant says what would be. With a `.knxprod` you already have, give the assistant its path.

=== "At the terminal"

    Shortened output:

    ```console
    $ bussard import-product --order-number "AKK-0216.03"
    Found in the product-data index:
      MDT — MDT Switch Actuator AKK (compact, REG)
      ...
    Download this file? [y/N] y
    Downloaded and verified 334088 bytes.
    Stored vendor file (downloaded): knx/products/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
    ```

    With a file you already have, run `bussard import-product <file.knxprod>`.

The order number is printed on the device and shown by a scan. bussard checks the download's size and checksum before it keeps it. Adding the device, below, fetches the file on its own when this step is skipped.

## Adopt the device

!!! warning
    Adopting writes an individual address (the device's own bus address, such as `1.1.5`) to whichever device is in programming mode.

=== "In chat"

    An illustrative exchange:

    ```text
    You:        I mounted a new switch actuator. Add it.
    Assistant:  (calls knx_add_device)
                Press the programming button on the new device, then
                say done.
    You:        Done.
    Assistant:  (calls knx_job_status)
                It is an MDT AKK-0216.03 at 15.15.255. I would give it
                1.1.5. Its product data is not here yet: I would download
                it from the vendor index. Assign 1.1.5 and download?
    You:        Yes, download it.
    Assistant:  (calls knx_add_device with yes and download)
                1.1.5 is assigned and verified. Its device file is
                written; channel A has a status object to wire.
    ```

    `knx_add_device` needs a server started with `--allow-programming`. It waits 30 seconds for the button. Your yes to the address does not answer the download question: the assistant asks for that separately.

=== "At the terminal"

    Shortened output:

    ```console
    $ bussard adopt
    bussard adopt guides a new device into your project
    Step 1 of 5 product data
    Step 2 of 5 assign an address
    device in programming mode: 15.15.255 (its current address)
    adopt 15.15.255 → 1.1.5? [y/N] y
    wrote 1.1.5; verifying…
    Step 3 of 5 write the device file
      wrote knx/devices/1.1.5.toml
    Step 4 of 5 wire the group objects
      ready-to-paste snippets (edit the group address to a free one):
        # ---8<--- groups.toml (inside `groups = [ … ]`)
        { address = "0/0/1", name = "Status channel A", dpt = "1.001" },
        # ---8<--- devices/1.1.5.toml
        [channel.a]
        status.send = "0/0/1"     # or `status.listen = ["0/0/1"]` for a receiving object
    Step 5 of 5 summary

    adopted 15.15.255 → 1.1.5
      device file   knx/devices/1.1.5.toml

    Next steps
      > edit knx/devices/1.1.5.toml
        set the device's name and room, and wire its group objects (snippet above)
      > bussard plan 1.1.5
        shows what writing the tables would change
      > bussard apply 1.1.5
        writes them to the device
    ```

    Press the device's programming button when `adopt` asks. It prints snippets to paste. Without a terminal it needs `--yes`. `--no-download` adopts without product data.

bussard picks the next free address on your main line, or the one you name (`bussard adopt 1.1.47` at the terminal), then writes it and reads the device back at the new address. It checks the device's order number against the product data, then writes the device file. A Data Secure device listed in your keyring keeps its address and is only read, never written.

What remains: wire the device's objects (see [Change what a button does](change-a-link.md)), then plan and write the device. A factory-fresh device needs its application program loaded before its links work.

## Flash a factory-fresh device

!!! warning
    The flash downloads the application program (the vendor software that decides what the device does). It assumes the device is factory-fresh.

=== "In chat"

    ```text
    You:        Program the new actuator.
    Assistant:  (calls knx_plan_device)
                1.1.5 must have its application program loaded: MDT
                Switch Actuator AKK. Then its parameters and links are
                written. Load it?
    You:        Yes.
    Assistant:  (calls knx_apply_device, then knx_job_status until done)
                Loaded and verified: 1.1.5 holds the model.
    ```

    When a device does not run the application the lock pins, the plan loads it, and one yes covers the load, the parameters and the links. The parameter memory is backed up first.

=== "At the terminal"

    ```console
    $ bussard flash 1.1.5 --product MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
    Flash plan for 1.1.5
      application : M-0083_A-000D-23-5BFD MDT Switch Actuator AKK
      mask        : app 07B0 vs device 07B0 — compatible
      writes      : 512 byte(s) across 8 step(s), est. 2.4s on TP1
    flash M-0083_A-000D-23-5BFD (2 memory write(s)) to 1.1.5? [y/N] y
    ...
    flash verified: application program M-0083_A-000D-23-5BFD is Loaded on 1.1.5, and its parameters match the model
    ```

    `flash` takes no backup. A device with a BCU access key needs `--bcu-key <HEX>`. `--dry-run` prints the plan without a gateway.

The flash refuses before writing when the mask (the device's system generation) is not System B or System 7, the application's mask does not match the device, the vendor's load procedure has a step bussard cannot run, or (on System B) the device reports another manufacturer than the application's. It also refuses a device that already carries a different application, an unknown one, or a load state it cannot read. At the terminal `--force` overrides that and destroys what is there; in chat there is no override. The same application again needs no flag.

If a flash fails midway, run it again: it rewrites the application whole.

## Label devices on the bench

!!! warning
    Commissioning writes the address of each device you press. At the terminal, `--flash` and `--apply` program it too.

=== "In chat"

    ```text
    You:        Commission line 1.1 on the bench.
    Assistant:  (calls knx_commission_line)
                2 devices on line 1.1 need an address. Start?
    You:        Yes.
    Assistant:  (calls knx_commission_line with yes, then knx_job_status)
                Press the programming button on Blind actuator
                (JAL-0810.03), Ground floor, Living room.
    ```

    `knx_commission_line` needs a server started with `--allow-programming`. At the end the assistant reads out the label lines. It writes addresses only.

=== "At the terminal"

    ```console
    $ bussard commission --line 1.1 --labels labels.csv
    commission 2 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
      press the programming button on Blind actuator (JAL-0810.03)
      assigned 15.15.255 → 1.1.7
    1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room
    ```

    Each commissioned device appends `address;name;order_number;floor;room` to the CSV for a label printer.

Devices that already answer at their address are left alone. For each other model device, bussard asks for its programming button and checks the pressed device's order number against the model before it writes. The wrong module stops that device with both order numbers named. [Commission a line](commission-a-line.md) has the whole flow.

## Start without an ETS project

=== "In chat"

    Register the server on an empty folder ([Connect an assistant](../getting-started/assistant.md)), then:

    ```text
    You:        Set up my house. There is no ETS project.
    Assistant:  (calls knx_setup)
                Found the KNX IP Interface at 192.0.2.10 and created an
                empty model.
    You:        Read what the devices on line 1.1 carry into a new model.
    Assistant:  (calls knx_reconstruct_device with line, then knx_job_status)
                Synthesized 9 group addresses and 5 links into a new
                directory under captures/reconstructed/.
    ```

    `knx_setup` runs what `bussard init` runs. The line sweep takes about 3 seconds per address and runs as a job. It writes a fresh directory; the model the server serves is never changed.

=== "At the terminal"

    ```console
    $ mkdir knx && cd knx
    $ bussard init
    Searching for KNXnet/IP gateways on the local network...
    Found gateway: KNX IP Interface (192.0.2.10:3671, IA 1.1.250)
    ```

    `init` writes an empty model in the current directory. Then build a model from what the devices carry (shortened output):

    ```console
    $ bussard reconstruct --line 1.1 --out fresh
    sweeping line 1.1.0–255 sequentially — estimated up to 13m38s on TP1
    synthesized 9 group address(es) and 5 link(s)
    ```

    `--out` must be a new or empty directory.

Discovery does not cross subnets; if it finds nothing, name the gateway (`--gateway <ip>`, or tell the assistant). The read of the line only reads. The result is a scaffold: names and types are placeholders, every link is recorded as `listen`, and devices it cannot read become stubs.

## Name the group addresses

=== "In chat"

    Start the assistant's server with `--passive`, since nothing here transmits, and say "help me name the group addresses". It asks you to press a button, waits for the telegram with `knx_wait_for_telegram`, and proposes a type and a name such as "Kitchen ceiling light, switch" with `knx_infer_group`. You confirm or correct it, and only then does it write the model.

=== "At the terminal"

    `bussard learn` runs the same loop: press a button, accept or edit the proposed type and name.

[Watch the bus](watch-the-bus.md) shows the loop in both forms.

## Next steps

- [Change what a button does](change-a-link.md): wire the new device's objects.
- [Commission a line](commission-a-line.md): plan group addresses and program a whole line.
- [Device commands reference](../reference/commands/devices.md): every flag of `adopt` and `import-product`.
