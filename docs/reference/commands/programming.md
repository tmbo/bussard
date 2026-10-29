# Programming commands

The commands that write devices: `plan`, `apply`, `flash`, `commission`, `backup`, `restore` and `replace`, with their flags, refusals and verification steps.

Every device write follows the same order: read the live state, show the plan, ask once, back up, write, verify by reading back. A refusal exits non-zero before anything is written. The confirmation rules, the real-gateway gate and the exit codes are on [Global options](../global-options.md); why the rails exist is in [What each write command does](../../explanation/write-commands.md).

!!! warning
    Every command on this page except `plan` and `backup` writes to a device. Check which gateway you are pointed at before you confirm: the prompt names it.

## `bussard plan <ADDRESS>`

Show what `apply` would write, without writing anything. `plan` reads the device's tables and, when product data is at hand, its parameter memory, and compares both with the model.

```console
$ bussard plan 1.1.47
1.1.47 Jalousieaktor Kind 2
  channel a-1 (Fenster Süd)
    + langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)
    ~ status-position sends 0/1/4, was 0/1/9
    ~ betriebsart = Jalousie, was Rollladen
  unchanged: 3 objects, 41 parameters
  writes: address table (4 entries), association table (5 entries), 1 parameter octet
  backup: knx/captures/backups (tables) and knx/captures/backups/parameters (parameter memory)
```

The plan speaks the device file's words, grouped by channel. `+` is a link the device gains (`now listens on`, or `now sends` for the object's sending address). `~` is a sending address or a parameter that takes another value. `-` is an address only the device has (`no longer uses`). A device that already matches prints `<ia> matches the model; nothing to write`.

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to plan for, e.g. `1.1.4`. Omit with `--line`. |
| `--line <LINE>` | | Plan every model device on this line, e.g. `1.1`, in address order (see [whole-line runs](#whole-line-runs)). |
| `--product <FILE>` | pinned archive | The product data to compare the parameter memory with (see [parameter read-back](#parameter-read-back)). Without it, the archive `bussard.lock` pins for the device in `<dir>/products/` is used. A pinned archive that is missing or changed prints a warning, and the parameters are not read. |
| `--application <REF>` | the lock's program | The application program id to decode with. |
| `--keyring <FILE>` | the key store | The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key, as for `reconstruct`. With `--line`, each device's key is looked up in it. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--json` | off | Emit the plan as JSON, with `state_hash`. |
| `-v` | off | Add the table-level detail: every object and address, the load operations, the full parameter read-back. |

Behaviour:

- Read-only on the bus.
- Refuses to compute an empty table set for a device with no links in the model, because applying it would wipe the device. A KNX IP interface is the exception (see [KNX IP interfaces](#knx-ip-interfaces)).
- Supports System B (`x7B0`) and System 7 (`0705`, `0701`). On other masks it refuses.
- Parameters are compared only when product data is at hand; without it a `note:` line says so.
- Prints the device's [identity verdict](#one-identity-verdict) against `bussard.lock` as part of the report.
- Uses a `--product` or `--application` that contradicts the lock, with a warning.
- Authorizes with the free-access key only, so a device with a BCU key set denies it.

`--json` prints the same plan as data: `address`, `name`, `gateway`, `changes` (`mark`, `subject`, `channel`, `key`, `object`, `sentence`), `unchanged_objects`, `unchanged_parameters`, `writes` (`address_table`, `association_table`, `parameter_octets`), `backup_dir`, `notes`, `question` and `state_hash`. The table detail (`additions`, `removals`, `unchanged`, the table counts, `load_steps`, `noop`) and the parameter read-back (`parameters`) are there too. `state_hash` is the SHA-256 of the device state read: the raw tables, plus the parameter memory when it was read. `apply --plan <hash>` refuses when the device no longer hashes to it.

### Admitting the tunnel addresses

With `admit_tunnel_senders = true` under `[connection]` in `bussard.toml`, `plan` and `apply` on a KNX Data Secure System B device also read its security individual address table (PID 54), the list of senders the device accepts secured telegrams from. Every tunnelling address of the key store that the table does not list becomes one change:

```text
+ the security individual address table (PID 54) admits the tunnelling addresses 1.1.22, 1.1.23 as secure senders (sequence 0, admit_tunnel_senders)
```

In `--json` it has `subject` `security` and `writes.security_object` `true`; the state hash covers the table read. Applying it rewrites the tables and the security object. With the option on, every secured `apply`, `apply --line` and `flash` keeps those addresses in PID 54. Off (the default), nothing is read and the security object is written as ETS writes it. This matches what ETS does when group addresses are assigned to the interface's tunnelling addresses.

Every verified secured write of the security object records the PID 54 table it wrote as the device's `secure_senders` in `bussard.lock`, so the next secured group write is checked against it.

### A group address that leaves or joins Data Secure

On a KNX Data Secure System B device read with a tool key, `plan` and `apply` also read the group-object security flags (PID 61) and compare them with what the model and the key store ask for. A difference is one change with `subject` `security`:

```text
- security object: Data Secure off for 1/0/4 (Licht Küche): its group key leaves the group key table (PID 53) and object 12 loses its security flag (PID 61 0x03 to 0x00)
```

or `+ … Data Secure on for …`, with `writes.security_object` `true`. Applying it rewrites the tables and the whole security object, as a full ETS download does, and records the flags in the lock. A device that refuses or does not answer the PID 61 read shows no such change; the write still programs the whole object. `bussard flash` prints the same line from its pre-flight. See [`groups secure`](secure.md).

### KNX IP interfaces

A device whose file has a `[knxnet]` table and no links is planned as its KNXnet/IP parameter object instead of its tables. `plan` reads the object and lists each difference from the table as a change with `subject` `interface`:

```text
~ friendly name = "Bocklisch Beta", was "Bocklisch Alpha"
+ tunnel address 1.1.30 added
- tunnel address 1.1.29 removed
~ static address = 192.168.1.80, was 0.0.0.0
~ assignment = static, was dhcp
```

`writes` names the properties (`writes.interface_properties` in `--json`, with the writes on the wire in `interface_writes`; `-v` prints them).

- A field absent from the table, and an empty `tunnels`, leaves the device's value alone.
- A property the device does not serve refuses the plan.
- A different number of tunnel addresses needs a device description that calls PID 53 writable with room for them. Otherwise the plan refuses and asks for exactly as many addresses as the device holds.
- `apply` refuses to change the IP assignment or static address set of the interface the command tunnels through, and any write of its tunnel addresses, unless `--allow-self-reconfigure`. The tunnel drops once the interface applies an IP change, the interface may drop its open tunnels on a tunnel-address write, and the read-back may not reach it. The MCP tools refuse both outright.
- After the writes, every written property is read back and the whole object read again. `apply verified` means both match the model.
- The values before the write go to `<dir>/captures/backups/<ia>-knxnet-<unix seconds>.toml` as a pasteable `[knxnet]` table.
- No KNXnet/IP Secure property is read or written; use [`interface secure`](secure.md) for that.

??? note "Details"
    `apply` writes the properties by object type (KNXnet/IP parameter object, type 11) with `A_PropertyExtValue_WriteCon`, falling back to the object's index on a device that refuses the extended services. The order: the friendly name (PID 76, 30 octets of ISO 8859-1 padded with NUL), the tunnel addresses (PID 53, one array write; a different count first writes element 0), the static address set (PIDs 60 to 62), the assignment method (PID 55, manual `0x01` or DHCP `0x04`) last. `plan` also reads the device's description of PID 53 (writable, maximum element count).

## `bussard apply <ADDRESS>`

Write the model to one device: its link tables and the parameter octets that differ. `apply` is the one verb for everyday changes, links and parameters alike.

```console
$ bussard apply 1.1.47
1.1.47 Jalousieaktor Kind 2
  ...
apply these 3 changes to 1.1.47 through 192.168.1.74:3671? [y/N]
```

The output above is illustrative: the plan is the one [`plan`](#bussard-plan-address) prints. The steps:

1. Validate the model. An error stops here with the diagnostics and nothing is written; warnings do not block. A group address the device files use but `groups.toml` does not define is declared there first.
2. Read the device's live tables and, when product data is at hand, its parameter memory, over one management session.
3. Print the plan and ask once. An empty plan prints `1.1.47 matches the model; nothing to write` and asks nothing.
4. Back up the pre-state tables to `<dir>/captures/backups/<ia>-<timestamp>.json` (the format `backup` and `restore` share) and, when parameters change, the parameter memory to `<dir>/captures/backups/parameters/`.
5. Write the minimum: the tables when a link changes, and only the parameter octets that differ where a parameter is placed under the configuration (the [parameter-only download](#parameter-only-download)). Each write is verified by reading it back.

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.1.4`. Omit with `--line`. |
| `--line <LINE>` | | Apply to every model device on this line, e.g. `1.1`, in address order (see [whole-line runs](#whole-line-runs)). |
| `--resume` | off | Line mode only: continue the run recorded in `<dir>/captures/apply-line-<line>.json`, skipping the devices it finished. |
| `--json` | off | Line mode only: emit the summary as JSON. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--plan <HASH>` | | Single-device mode: refuse unless the device state still hashes to this `state_hash` from `bussard plan --json`. |
| `--force` | off | Single-device mode: use a `--product` or `--application` that contradicts `bussard.lock` (another archive hash, another application). The archive is then pinned for the device. Without it such an override is refused before any bus access. |
| `--product <FILE>` | pinned archive | Single-device mode: the product data to compare and write the parameter memory with. Default: the archive `bussard.lock` pins for the device in `<dir>/products/`. |
| `--application <REF>` | the lock's program | Single-device mode: the application program id to decode the parameters with. |
| `--keyring <FILE>` | the key store | KNX Data Secure tool keys and group keys. A device the keyring lists is written over Data Secure and its security object is rewritten with the tables. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--secure-sender <IA>` | off | Single-device mode, Data Secure: add this address (bussard's tunnel address) with sequence 0 to the security individual address table (PID 54), as for `flash`. Conflicts with `--line`. |
| `--allow-self-reconfigure` | off | A KNX IP interface (see [KNX IP interfaces](#knx-ip-interfaces)): write a change of its IP assignment, static address set or tunnel addresses although bussard tunnels through that interface. The tunnel drops (or, for tunnel addresses, may drop) when the interface applies it. Conflicts with `--line`. |

Behaviour:

- Refuses on a model validation error, before the bus is touched.
- Refuses before any bus access when the pinned archive is missing or changed, naming the recovery step, and when a `--product` or `--application` contradicts the lock without `--force`.
- Refuses a device whose application id or mask [drifted](#one-identity-verdict) from `bussard.lock`, before any write, naming the `bussard flash` it needs.
- Refuses without a terminal unless `--yes`. `--yes` never lifts the real-gateway gate.
- With `--plan <hash>`, refuses before the question when the device no longer hashes to it.
- Refuses if a backup cannot be written: no backup, no write.
- A parameter change that shows or hides a com-object changes the group-object table, which a parameter download does not rewrite. `apply` refuses that device and names the full [`bussard flash <ia>`](#bussard-flash-address) it needs. Enable flags and data-length choices are often such parameters. Over MCP with `--allow-programming`, `knx_plan_device` plans such a change as `method: flash` and `knx_apply_device` runs that flash.
- A device that runs another application than the product data describes gets its links written and its parameters left alone, with a note that a full `flash` changes the application.
- An octet the configuration places no parameter in is left as the device holds it, as ETS's download does (see [the write set](#parameter-only-download)).
- A group address the model marks `secure` without a key in the keyring refuses the plan.
- Tables are rewritten wholesale, so re-running `apply` is idempotent.
- Prints a hint while no installation-wide `backup` run exists.
- Authorizes with the free-access key only, so a device with a BCU key set denies it.
- To go back: re-apply from the model, or `bussard restore <dir>/captures/backups <ADDRESS>`. `restore --parameters` puts backed-up parameter memory back.

??? note "Details"
    System B (`x7B0`): each table is written into a segment the device allocates for it: StartLoading, `LdCtrlRelSegment`, read the placement from `PID_TABLE_REFERENCE`, memory-write the count word plus the elements, LoadCompleted. The `PID_TABLE` property array is never written, because real devices refuse it. With product data, a group-object table that differs from the one a full flash writes (a newly linked object whose communication flag is off) is reloaded first the same way, from the full flash's image, and read back. A parameter change then runs the parameter-only download: the standard's partial download of the parameter object (unload, load, a Mode 0 re-allocation that keeps the memory, the differing octets), then the load completes and the device restarts.

    System 7 (`0705`, `0701`): a link change follows ETS 6.4.1's table-only download: Unload LSM 1 and 2, then each table loaded to completion in turn (StartLoading, allocate, 12-octet writes with read-back verify, TaskSegment, LoadCompleted), then a basic restart. Parameters and the application are not rewritten. `apply` waits for the device to answer again after the restart and reads the tables back from the restarted device. The address table is written alone, bounded by its segment; when its end is unknown (no product data, and no association table the device reports), the table is not grown. With product data, the communication flag of each object that gains its first link is switched on, and of each object that loses its last link switched off: the group-object table the product declares is rewritten whole with those octets changed, inside a StartLoading/LoadCompleted bracket on LSM 3, and read back. A device ignores an object whose flag is off, so without product data `plan` names the newly linked objects whose flag it could not check.

    With `--keyring`, `apply` rewrites the security object next to the tables, because the group key table indexes the address table.

### Whole-line runs

`plan --line` and `apply --line` visit the model's devices on one line in address order and end with one summary table: address, name, mask and status.

| Status | Meaning |
|---|---|
| `changes: N` | `plan`: N changes would be written. |
| `applied: N` | `apply`: N changes were written and verified. |
| `unchanged` | The device already matches the model. |
| `skipped: <reason>` | An unsupported mask, or no links in the model. |
| `failed: <reason>` | The device could not be read or written. |

- Neither a skip nor a failure stops the run. The exit code is non-zero if any device failed.
- `apply --line` asks one confirmation for the whole run, naming the resolved gateway and the device count. Each device then gets what `apply <ADDRESS>` does: plan, back up, write, verify.
- Each outcome is written to `<dir>/captures/apply-line-<line>.json` as it happens. After a tunnel drop, a killed process or Ctrl-C, `--resume` reads that file and skips the finished devices without any bus traffic; failed devices are retried. A run with no failures deletes the file.
- `--json` prints `{line, mode, gateway, devices: [{address, name, mask, system_type, status, changes, detail}], total, changed, unchanged, skipped, failed, state_file}`; `state_file` is set when the run left one behind.

## `bussard flash <ADDRESS>`

Download the full application program from vendor product data into a device: for a fresh device, or one whose application changes. Everyday changes to links and parameters go through [`apply`](#bussard-apply-address), which writes only what differs.

```console
$ bussard flash 1.0.10 --dry-run
```

`--dry-run` prints the pre-flight plan without opening a connection. Without it, `flash` runs the pre-flight against the device, prints the plan and asks `flash <app> to <target> via <host:port>?`. Before it writes, it states that no backup exists:

```text
NOTE: a first flash assumes the device is factory-fresh; no backup is
possible (there is no prior application to save). Recovery from a failed
flash is re-running `bussard flash`.
```

The pre-flight report leads with one line per parameter the flash changes, named with the vendor's parameter text, with old value, new value and unit (`Night setback: 18 °C to 17 °C`). Enumerations show the vendor's member text. On a factory-fresh device, or when a segment cannot be read, the line reads `unknown current value, will be <new>`.

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.0.10`. |
| `--product <FILE>` | pinned archive | The vendor `.knxprod` containing the application program. Default: the archive `bussard.lock` pins for the device in `<dir>/products/`. One that contradicts the lock needs `--force`, which also pins it. |
| `--application <REF>` | the lock's program | The application program id (default: the program the lock pins, else the order number's, else the sole one). Not needed for an ETS export when the lock pins the program. One other than the lock's needs `--force`. Mutually exclusive with `--order-number`. |
| `--order-number <ORDER>` | | Select the application by hardware order number (e.g. `AKK-0216.03`), resolved through the product's hardware catalogue. Exactly one match is required. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--force` | off | Flash a device that is **not** factory-fresh: it carries a different or unidentifiable application, or its load state could not be read. Destructive: the resident application, its parameters and its links are overwritten with no backup. Not needed to re-flash the same application. Also accepts a `--product` or `--application` that contradicts the lock. |
| `--full` | off | Skip nothing: re-stream every object. By default, when the device already carries the same application (or none), an object whose resident image matches and which reports `Loaded` is skipped, and the output lists each skipped step. A parameter-only change then re-downloads the parameter segment but not the code segment. |
| `--parameters-only` | off | Rewrite only the parameter memory of a device that already runs this application (see [parameter-only download](#parameter-only-download)). Conflicts with `--full`, `--force` and `--no-factory-reset`. With `--dry-run` it prints the op sequence offline. |
| `--no-factory-reset` | off | Leave out the factory reset (secure-capable System B applications). Use this only when you know the device holds no stale image, for example a device fresh from the box. |
| `--bcu-key <HEX>` | free access | The device's BCU access key, in hex (`FFFFFFFF` or `0x11223344`). Unset presents the free-access key `FFFFFFFF`, correct for an unkeyed device; a keyed device needs its project key here or it denies access. |
| `--keyring <FILE>` | the key store | KNX Data Secure: the tool key and group keys. With it, `flash` also programs the device's security object. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`; unsuitable for a real key, because process arguments are visible. Carries no group keys, so it only suits a device without secured group addresses. |
| `--secure-sender <IA>` | off | Data Secure: also list this address (bussard's tunnel address) with sequence 0 in the security individual address table (PID 54), so the device accepts `write --keyring` from bussard. Without it the table holds only the devices that send on a secured group address the device listens to, as ETS writes it, and the device drops bussard's secured group telegrams. The next ETS download removes it again. |
| `--json` | off | Print the pre-flight plan as JSON: a `parameters` array (`key`, `name`, `old`, `new`, `unit`; `old` is `null` when unreadable), the application identity, the write summary and the step trace. The confirmation and the flash are unchanged. |
| `--dry-run` | off | Build and print the pre-flight plan against the application's own mask, then stop. No gateway is resolved and no connection is opened, so it works with no gateway configured. |
| `--dump-images <DIR>` | | With `--dry-run`: write `plan.json` and the exact memory images the flash would stream (one `.bin` each, plus the table images) into `DIR`, for offline comparison with an ETS download of the same device. |
| `-v` | off | Show the memory-level plan (the step trace) and the raw override keys, and end with the wall-clock time per phase (pre-flight, download, restart and verification) plus the reboot readiness per restart. |

Behaviour:

- Product data: the archive `bussard.lock` pins, verified by its SHA-256. A pinned archive that is missing or changed refuses the flash before any bus access, naming the recovery step (see [product data](../product-data.md)).
- Supports System B (`07B0` and the `57B0`, `27B0` variants) and System 7 (`0705`, `0701`, `0700`). Refuses before any write on an unsupported mask family, a mask mismatch, or an unsupported load-procedure operation. A procedure with an unrecognized op is refused whole.
- Prints the device's [identity verdict](#one-identity-verdict) but does not refuse on drift: a flash is how drift is fixed. The factory-freshness check decides instead.
- The parameter memory image is the vendor defaults plus the parameter values in the device file, so a flash also carries parameter changes.
- No backup exists for a flash. Recovery from a failed or interrupted flash is re-running the same `flash`; if that does not recover the device, download it with ETS. Do not assume a device works until a flash reports the application `Loaded` and verified.
- A group address the model marks `secure` without a key in the keyring refuses the plan before anything is written.
- Verifies after writing: the application reads back as `Loaded`, and written segments are spot-checked byte for byte.
- Only `flash` takes `--bcu-key`; `plan`, `apply` and `reconstruct` always present the free-access key.
- Activating Data Secure on a device (turning it on, writing the tool key) is ETS's job. bussard programs devices ETS has activated.

### The factory-freshness check

Because there is no backup, `flash` checks in its read-only pre-flight that the device is factory-fresh. It reads the load states that decide and, on System B, the resident application id.

| What the device reports | What `flash` does |
|---|---|
| No application loaded | Proceeds: the device is factory-fresh. |
| An object left `Loading` or in `Error` by an interrupted flash | Proceeds: re-flashing is the recovery path. |
| The **same** application already loaded | Proceeds without `--force`, with a notice. |
| A **different** application loaded | **Refuses**; `--force` overrides. |
| An application loaded that it cannot identify | **Refuses**; `--force` overrides. |
| A load state it cannot read at all | **Refuses** as unknown; `--force` overrides. |

- A refusal names the device, the resident application and the two ways forward: capture what is on the device first (`reconstruct` reads its links into the model, `apply` backs up the tables), or re-run with `--force`.
- `--force` prints one loud line naming the device, the gateway and what is destroyed, and the confirmation prompt repeats it.
- Unreadable is not fresh: a device that refuses the state reads is refused.
- Re-flashing the same application is still a full rewrite: the parameters are reset to the vendor defaults plus the device file's values, and the tables are rewritten from the model's links.
- System 7 has no application-id property, so a loaded System 7 device is never recognised as "the same application" and always needs `--force`.

### The factory reset (System B)

Many System B applications allocate their segment with a fill byte, and bussard, like ETS, writes only the octets that differ from it. The fill does not erase anything, so a re-flash would keep the previous image's octets wherever the new one writes nothing. So `flash` starts such a download of a secure-capable application (one whose product data declares `IsSecureEnabled`) the way ETS unloads one, with a factory reset that keeps the individual address. ETS never sends a master reset to an application that is not secure-capable, so neither does `flash`: such a download starts with its load procedure's own unloads.

- The device erases its application, its parameters and its group addresses and links, keeps its individual address, and reboots. `flash` waits the time the device reports (at most 60 s), reconnects and continues.
- The reset is added, for a secure-capable application, when the download writes filled segments sparsely, and when `--force` replaces an application `flash` did not recognise or could not read.
- The plan shows it as the first step, and every object is then streamed in full: nothing is skipped.
- A device that refuses the reset, or does not answer it, fails the flash before anything is written.
- `--no-factory-reset` leaves it out. System 7 downloads write every region in full and never reset.
- If the flash stops right after the reset, the device is left unloaded: re-run the same `flash`.

??? note "Details"
    The reset is `A_Restart` master reset with erase code 7 and channel 0, sent numbered (`4f 81 07 00`), answered by `A_Restart_Response` with an error code and a process time in seconds (`4f a1 00 00 08`). It sits before the first `Unload`, after any read-only `CompareProp` or `CompareRelMem` preconditions. Every download of a secure-capable System B application ends like ETS's: the terminal `LdCtrlRestart` goes out as a confirmed master reset with erase code 1, and bussard waits its process time before verifying. Every other application keeps the bare `A_Restart` ETS sends it, and an `LdCtrlMasterReset` op in a load procedure is sent as a bare `A_Restart`.

    If the gateway link drops while the reset is pending, it is sent again once the tunnel is back; a link loss during the reconnect after it is ridden out.

### Data Secure devices

With `--keyring` (or `--tool-key`), `flash` programs the device's security object the way an ETS secured download does. The object holds the group keys and the per-object security flags, not the link tables.

- The dry run lists each security step; key bytes are never printed.
- The security individual address table (PID 54) gets one entry per device that sends on a secured group address this device listens to, plus `--secure-sender` or the `admit_tunnel_senders` addresses, plus the `secure_senders` the lock recorded from an earlier read, so a download does not drop a sender the model does not describe.
- The factory reset stays in secured downloads; the device keeps its tool key across it.

??? note "Details"
    The security object is unloaded right after the other objects. After the tables and parameters it is reloaded with the security individual address table (cleared, then one `[IA][sequence]` entry per sender, with the sender's keyring `SequenceNumber` when the model marks it `activated`, else 0), the group key table (one entry per keyed group address the device links) and the group-object security flags, then completed.

    After any restart `flash` triggers on a Data Secure device, the device can answer at the transport layer before its security layer is ready and drop the first `S-A_Sync_Req`. `flash` probes the rebooted device with a plain `A_DeviceDescriptor_Read` every 500 ms for up to 30 s, keeps that connection and sends the sync request on it. A sync request the device acknowledges but does not answer is repeated: up to five attempts with a 1, 2, 4, 8 s backoff after a restart, three attempts (1, 2 s) on any other secured connection. Then the flash stops with "did not answer the Data Secure sync request".

### Verification and restarts

??? note "Details"
    After the terminal restart, `flash` reads the application object's type and load state, plus a sample of each segment whose MCB check did not pass before the restart. An application that is not `Loaded` gets every object's state and every sample read. Each load-state change (unload, open, segment allocation, completion) is confirmed by the state the device returns in its answer; when that answer carries no state octet or not the expected one, `flash` reads the state back.

    On System B the pre-flight reads the load state and the resident application id (`PID_PROGRAM_VERSION`) of the application objects (interface-object types 3 and 4); the other objects are read only when no application object answers. System 7 reads every load-state machine.

    Supported load-procedure operations on System B: `Unload`, `Load`, `LoadCompleted`, `RelSegment`, `WriteRelMem`, `WriteMem`, `WriteProp`, `CompareProp`, `LoadImageProp`, `Restart`. On System 7: `Unload`, `Load`, `AbsSegment` (allocate and stream), `TaskSegment`, `TaskCtrl1`, `LoadCompleted`, the obj0/PID78 `CompareProp`, `CompareMem`, `LoadImageProp` and `Restart`. Unrecognized ops (e.g. `LdCtrlCompareRelMem`) refuse the procedure.

    On a System 7 mask whose product data declares no `VerifyMode` (Theben `0700`, `0701`), `flash` reads every chunk first, writes only the chunks that differ from the image and reads written chunks back, so a re-flash of an unchanged device writes nothing but the load-state records. The plan shows these segments as `stream segment (read-compare, N octets)`, and `plan.json` from `--dump-images` marks them `"write_mode": "read-compare"` (a `VerifyMode` mask such as Jung `0705` stays `"blind"`).

    Waits after a restart: after a restart the device confirmed, `flash` waits the process time it reported and probes from 0.5 s after that; after a bare `A_Restart` it stays quiet for 1.5 s first. A probe waits 500 ms for the acknowledgement and up to 2 s for the answer. A probe the interface confirms negatively counts as "not up yet", never as absent. After the factory reset, `flash` also probes from +3 s to measure readiness; `-v` prints it, for example `; readiness M-0004_A-20D6-26-FAEB-O000A: factory reset 8.5 s (process time 8 s), restart 2.1 s (process time 0 s)`.

    The pre-flight and the write share one tunnel. With `--yes` they also share the device connection. Without `--yes` the prompt sits between the phases, the device closes a connection silent for 6 s, and the write reconnects and reuses what the pre-flight learned. A connection idle for more than 3 s, or closed by the device, is replaced; `BUSSARD_FLASH_NO_HANDOVER=1` always reconnects.

    Resume on connection loss: when the device drops its connection, `flash` reconnects, re-authorizes and resumes the current step; a chunked memory write continues from the last confirmed chunk. When the gateway tunnel drops, bussard re-establishes it within `BUSSARD_TUNNEL_RECONNECT_SECS` (60 s by default), re-sends the pending frame and resumes. The retries stop 90 s after the first failure. A gateway that stays unreachable longer leaves the device partially written; re-run the same `flash`.

### One identity verdict

Every management command that reads a device compares what it reports with what `bussard.lock` pins for that address, and prints the same line on stderr (on stdout in `describe`, `plan` and `reconstruct`, whose report it belongs to):

```text
identity of 1.1.4: matches bussard.lock (application id 0004D14122, mask 07B0)
identity of 1.1.4: drift from bussard.lock: the device reports application id 0004D14123 but the lock pins 0004D14122 (M-0004_A-D141-22-151B)
identity of 1.1.9: not pinned in bussard.lock
```

- The application id comes from the device facts (System B) or the pre-flight; outside System B the mask alone is compared.
- A hidden mask (`FFFF`, a Data Secure device read in the clear) and an unread application id compare as unknown, never as drift.
- In JSON the verdict is an `identity` object (`lock`, `device`, `verdict` of `match`, `drift` or `unmodelled`, `differences`): in `describe`, `plan`, `reconstruct`, the rows of `scan` and `audit --live`, and each device of the `backup` manifest.

What the verdict does:

| Command | On drift |
|---|---|
| `describe`, `plan`, `reconstruct`, `scan`, `assign`, `backup`, `restore`, `audit` | Report it. |
| `apply`, and `commission --apply` and `replace` through it | Refuse before any write, naming the `bussard flash` the device needs. |
| `replace --no-flash` | Refuses a replacement that runs another application. |
| `flash` | Reports it and does not refuse; the factory-freshness check applies. |

**Product overrides.** Every command that needs product data takes it from the lock and the product store; `--product` and `--application` override it. An override that contradicts the lock (another SHA-256, another application) is refused by `flash`, `apply` and `replace` unless `--force`, which uses it and pins the archive for the device. `plan` and `reconstruct` use it with a warning, and `flash --dry-run` only warns. An ETS export given as `--product` is compared by application only, and `flash --product <export>.knxproj` needs no `--application` when the lock pins the device's program.

### Parameter-only download

`flash --parameters-only <ADDRESS>` rewrites only the parameter memory of a device that already runs the application. `apply` runs the same download for the parameters that differ, after the tables.

It works like `apply`: it reads the parameter memory, shows the parameters that change (`Threshold: 7 to 12`), the memory regions and how many of their octets change, asks once, backs up, writes only the octets that differ, completes the load, restarts the device and verifies by reading back. When nothing differs it prints `nothing to do` and exits 0 without touching a load state. On System B the download is the standard's partial download, as ETS runs it: unload the parameter object, open it, re-allocate its segment in Mode 0 (the device keeps the memory and the base), write, complete. On System 7 it opens and completes the load-state machine without an allocation. It never factory-resets and never touches the link tables.

It refuses before any write when:

| What the device reports | Why, and what to do |
|---|---|
| Another application | Its memory has another layout. Use a full `flash`. |
| No loaded application, or the load state cannot be read | There is nothing to patch, or its state is unknown. Use a full `flash`. |
| A parameter segment that cannot be read back | Its base address or current content is unknown. |
| New values that show or hide a com-object, or change an object's size or flags | The group-object table would change, and only a full `flash` rewrites it. The refusal names the objects. |
| On System 7, links that differ from the device's tables | The table load-state machines are not reloaded. Run `apply` first. |

- The confirmation, `--yes` and the gateway gate are the same as for `apply`.
- The parameter memory is backed up to `<dir>/captures/backups/parameters/<ia>-<unix time>.json` before the first write, apart from the table backups, so `restore <BACKUP_DIR>` never picks it up.
- After the restart, the memory is read back and every changed octet compared. A mismatch exits 1 with the backup path and the recovery: re-run the download while the application still reads `Loaded`, otherwise a full `flash --force`.
- Segments the application rewrites at run time are written but not compared.
- `--json` prints the plan as JSON (`parameters`, `regions`, `procedure`).

**The write set.** Only the octets a parameter is placed in under the current configuration are compared and written: a parameter the Dynamic section reaches, a hidden parameter the application downloads at its default, and the device-managed octets alongside another write. Every other octet keeps the device's value, because ETS's download does not write it either. When such an octet differs from the model's image, the plan lists it as not written (`unwritten` in `--json`, `written: false` in `octet_ranges`) and does not count it. The same rule holds for `apply`, `restore --parameters` and the MCP `knx_apply_device`. A full `flash` still writes the whole image, as an ETS full download does, so a device that needs those octets cleared gets a full flash.

??? note "Details"
    System B (Configuration Procedures 03_05_03 §3.5.3, as ETS runs the product's `par` procedure, issue #543): a check that the object holding the parameter segment is `Loaded`, `Unload` and `StartLoading` on it, its segment re-allocated in Mode 0 with no fill (the device keeps the memory and the base), the procedure's property writes on that object (the `PID_MCB_TABLE` seed and `PID_PROGRAM_VERSION`), the differing parameter octets at the base the object reports through `PID_TABLE_REFERENCE` after the allocation (the whole image if the device moved the segment, nothing if the reference reads zero), `LoadCompleted`, the procedure's MCB checks on that object, and the terminal restart. No factory reset, no table object.

    System 7: `StartLoading` on the load-state machine that holds the parameter segments (LSM 3), the differing octets written in place into each parameter segment, `LoadCompleted`, the procedure's MCB reads of objects 1 to 3, and the restart. No `AbsSegment` record, no task segment, no task control: re-sending the allocation put a device into load state Error. The executor reads LSM 3 first and writes nothing unless it is `Loaded`. LSM 1 and 2 (the tables) are not touched.

    "Another application": on System B, `PID_PROGRAM_VERSION` differs from the product's or cannot be read. System 7 has no readable application id, so every load-state machine must be `Loaded` and the first octets of each application code segment must read back as the product's bytes. A code segment is one streamed verbatim from the product, never a link table, the group-object descriptor table or parameter memory. A product with no code segment is judged by the load-state machines alone.

    "Placed under the configuration" covers applications without `DownloadInvisibleParameters` and without `PreferPartialDownloadIfApplicationLoaded`, where a hidden parameter is downloaded at its default. Segments not compared after the restart: System 7 `checksum_ctrl` 0, and the Jung `0x4916` region.

### Parameter read-back

`plan <ADDRESS>` and `reconstruct <ADDRESS>` read the parameter memory too when they have the device's product data (`--product`, or the archive `bussard.lock` pins in `products/`). Both stay read-only.

- The memory is decoded as the exact inverse of the image `flash` writes, so a device holding the model's image reports no difference.
- Only the parameters the configuration shows are decoded; a hidden parameter downloaded at its default is never reported.
- The report lists the parameters whose value differs from the vendor default and those that differ from the device file (`Threshold: device 9, model 12`), keyed like the model (`P-5_R-5`, `MD-1_M-2_MI-1_P-2_R-5` for a module instance). `--json` adds a `parameters` object with `non_default` and `differences`.
- Parameters the application owns at runtime (`Access="None"`, such as a download flag) are listed separately as device-managed, with no verdict (`device_managed` in `--json`).
- Internal ETS values whose octets differ from the model's image are listed with both values and, for a selector, what the difference means (`internal` in `--json`).
- The memory is decoded only when the device runs the product's program, by the rule `flash --parameters-only` applies: on System B the same manufacturer, application number and version; on System 7 every loaded load-state machine `Loaded` and the code segments matching. Otherwise the section carries a note instead of values.

??? note "Details"
    The memory is located through the application's load procedure: on System B, `PID_TABLE_REFERENCE` of the object plus the write offset; on System 7, the `AbsSegment` addresses. The decode uses the same offsets, union members, module instances and parameter refs as the image. A product build with another hash counts as the same program.

### Octet attribution roles

A plan that writes parameter octets names the parameters behind each run of written octets: `octet_ranges` in `knx_plan_device`, the plan's notes, and `internal` in the read-back. Each run carries `written`: `true` for an octet the plan writes, `false` for one that differs from the model's image where no parameter the configuration reaches is placed. Unwritten runs are never counted in `parameter_octets`.

| Role | Meaning |
|---|---|
| `changed` | A shown parameter whose value changes; it is in the changed list. |
| `same_value` | A shown parameter that decodes to the model's value although bits of its field differ. |
| `hidden` | A parameter the configuration hides, or one an `<Assign>` sets. The image holds its default, or the segment's vendor data when the application does not download hidden parameters. |
| `internal` | An `Access="None"` parameter the configuration does not reach: a value ETS keeps for itself, never shown and never in the model, such as a push-button's function-block selectors. An enumeration is named an internal ETS selector. |
| `device_managed` | An `Access="None"` parameter the configuration reaches, owned by the application at runtime, such as a download flag the application resets after the restart. |

- Octets owned only by `device_managed` parameters do not count as a difference. A plan whose only differing octets are device-managed writes nothing: `plan` prints `<ia> matches the model; nothing to write` with a note naming the octets, `apply` exits without touching the device, and `knx_plan_device` reports `noop: true` with no digest.
- When a link or another parameter changes, device-managed octets are written along with it at the model's value, as ETS does.
- A plan whose only differing octets are unwritten ones writes nothing either.
- When an internal selector the download writes differs, the plan adds one note: the device's function assignment differs from the project, and writing makes the device match the model.

??? note "Details"
    Each parameter in a run carries `device` and `model`, the values the device's octets and the model's image hold, as the enumeration member's text where the value is one, else the number, with the unit. A written run reads `1 octet at offset 165 of segment RS-04-00000: _AppInstanz 51 (internal ETS selector, P-643), device 3, model no application`.

    An unwritten run reads `1 octet at offset 165 of segment RS-04-00000, not written (ETS does not write this octet in a download): _AppInstanz 51 (internal ETS selector, P-643), device AP_RGBWLED, model no application`, and its `explanation` says `ETS does not write this octet in a download; a full download leaves the segment fill (0x00) there; the device holds <value> from an earlier state`. One plan note lists the unwritten runs. Module parameters are attributed where the configuration places them; an octet no parameter covers names none.

## `bussard commission --line <LINE>`

Bench mode: commission the devices the model has on a line, one programming button at a time.

```console
$ bussard commission --line 1.1 --flash --apply --labels labels.csv
```

The command first checks which model devices already answer at their address; those are reported as `present` and left alone. After one confirmation naming the gateway, it walks the rest in address order:

1. Prompts `press the programming button on <name> (<order number>)` and waits for exactly one device in programming mode, as `assign` does.
2. Reads that device's order number and compares it with the model's `product.order_number`, ignoring case and surrounding space.
3. Writes the address, verifies it with a descriptor read, and clears programming mode.
4. With `--flash`, runs `flash` on the new address, selecting the application by the model's order number. With `--apply`, runs `apply`.
5. Prints a label line, e.g. `1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room`, and with `--labels` appends a row to the CSV.

The summary table lists each device as `commissioned`, `present` or `failed: <reason>`.

| Flag | Default | Meaning |
|---|---|---|
| `--line <LINE>` | | The line to commission, e.g. `1.1`. |
| `--flash` | off | Also flash each device's application program. |
| `--apply` | off | Also apply the model's link tables. |
| `--labels <FILE>` | | Append one row per commissioned device, columns `address;name;order_number;floor;room` (header written when the file is new). |
| `--product <FILE>` | pinned archive | The `.knxprod` to flash from (with `--flash`). Default: the archive `bussard.lock` pins for each device. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--json` | off | Emit the summary as JSON; label lines then go to stderr and into each device's `label` field. |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool key for `--flash` and `--apply`. |

Behaviour:

- Acts on whatever device is in programming mode, so without a terminal and without `--yes` it refuses before loading the model or opening a connection.
- An order-number mismatch, or an unreadable order number while the model names one, is a hard stop for that device: nothing is written and the run moves on. A model device without an order number is assigned with a warning.
- With `--flash`, every device's archive is resolved before the run starts: a missing or changed one refuses the whole run before any bus access.
- `--apply` goes through `apply`, so a drifted device is refused there.
- One confirmation covers the run; each device still gets the full single-device rails of `flash` and `apply`.
- The exit code is non-zero if any device failed.

## `bussard backup [ADDRESS...]`

Snapshot the installation before you change it. `backup` reads every model device's address and association tables, and its parameters where it can, into one JSON file per device plus a `manifest.json`.

```console
$ bussard backup
$ bussard backup --line 1.1 --out ~/knx-backup
```

| Flag | Default | Meaning |
|---|---|---|
| `[ADDRESS...]` | every model device | Back up only these devices. |
| `--line <LINE>` | | Back up only the model devices on this line, e.g. `1.1`. |
| `--out <DIR>` | `<dir>/captures/backups/<UTC timestamp>/` | Where to write the snapshot. |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool keys, as for `apply`. |

`manifest.json` lists every device the run considered, with its mask, system type, resident application id, order number, read time, parameter status, [identity verdict](#one-identity-verdict) and one of four statuses:

| Status | Meaning |
|---|---|
| `backed_up` | Tables (and, where possible, parameters) were written to a file. |
| `skipped` | The mask is outside System B and System 7; the reason is in `detail`. |
| `unreachable` | Nothing answered at the address. |
| `failed` | The device answered, but a read failed; the reason is in `detail`. |

Behaviour:

- Read-only on the bus: it sends only descriptor, authorize, property-read and memory-read requests, so it is safe on a live installation.
- The files use the same format `apply` writes before each write, so `restore` reads either.
- On System B the snapshot includes the application segment, where the parameters live, and needs no product data. System 7 reports no length for its parameter image, so its parameters are marked as not captured.
- Uses one bus connection, leased per device.
- Exit code 0 when no device failed, 1 otherwise.
- `apply` prints a hint while no such snapshot exists.

??? note "Details"
    On System B the parameter segment's base comes from `PID_TABLE_REFERENCE` and its length from `PID_MCB_TABLE`.

## `bussard restore <BACKUP_DIR> <ADDRESS>`

Write one device's backed-up link tables back. `restore` picks the newest `<ia>-<timestamp>.json` in `BACKUP_DIR` and runs the `apply` path with the backup as the desired state: plan, confirm, pre-write backup, write, verify.

```console
$ bussard restore knx/captures/backups 1.1.4
$ bussard restore --parameters knx/captures/backups/parameters/<ia>-<unix time>.json 1.1.4
```

`BACKUP_DIR` is a `backup` run, or `<dir>/captures/backups` for the files `apply` leaves. The model is optional here: the tables come from the backup.

| Flag | Default | Meaning |
|---|---|---|
| `<BACKUP_DIR>` | | The backup directory (without `--parameters`). |
| `<ADDRESS>` | | The device to restore, e.g. `1.1.4`. |
| `--parameters <BACKUP_JSON>` | | Replay this parameter backup instead of link tables; takes the address as its only positional argument. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--keyring <FILE>` | the key store | KNX Data Secure tool keys, as for `apply`; the security object is rewritten with the tables. |
| `--tool-key <HEX>` | | A raw 32-hex-character KNX Data Secure tool key, for a simulator or bench device. Conflicts with `--keyring`. |

Behaviour:

- Same plan, same confirmation naming the gateway, same pre-write backup, same verify and same real-gateway gate as `apply`.
- A backup restored onto a device that has not changed plans empty and writes nothing.
- Writes link tables only. Parameter memory in a table backup is reported but not written; put it back with `restore --parameters`.
- Reports the device's [identity verdict](#one-identity-verdict).

### Restoring parameters

`restore --parameters <BACKUP_JSON> <ADDRESS>` replays a parameter backup: the `<dir>/captures/backups/parameters/<ia>-<unix time>.json` that `apply`, `flash --parameters-only` and the MCP `knx_apply_device` write before every parameter write. It reads the device's parameter memory with the product data `bussard.lock` pins and plans the [parameter-only download](#parameter-only-download) back to the backup.

- The backup must be of this device, of the application the device runs and of its mask. Otherwise it is refused before anything is planned:
    - `the backup holds the parameters of application <id>, but <ia> runs <id>`
    - `the backup was read from a device with mask <mask>, but <ia> reports mask <mask>`
    - `the backup is of <ia>, not <ia>`
- Only the octets a parameter is placed in under the model's configuration are compared and written, the set `apply` writes, so a restore puts back everything an apply changed.
- Device-managed octets keep the device's value.
- The plan lists the octets it writes with the parameters behind them ([roles](#octet-attribution-roles), `device` and `backup` values) and the octets it leaves as the device holds them, then asks once.
- The gates are `apply`'s: the real-gateway opt-in, the confirmation (`--yes`), the identity verdict against `bussard.lock`, and the parameter-only identity check. A device that does not run the application (a factory-fresh or unloaded one) is refused and needs `bussard flash`.
- The memory it overwrites is backed up first, and the write is verified by reading it back.
- A device that already holds the backup's octets plans empty and writes nothing.
- Over MCP the same restore is `knx_restore_parameters` (see [MCP tools](../mcp-tools.md)).

## `bussard replace <ADDRESS>`

Put a new device of the same product in place of a dead one: assign its address, flash it and apply the model's tables.

```console
$ bussard replace 1.1.7
```

The steps:

1. Check that nothing answers at `ADDRESS`.
2. Wait for the programming button, read the pressed device's order number, mask and application id, and print its [identity line](#one-identity-verdict).
3. Ask once for confirmation, naming the gateway. Then assign the address (as `assign` does), flash the application with the model's parameters (as `flash` does; skipped with `--no-flash`), and apply the model's tables (as `apply` does).
4. Record `replaced: <RFC3339>` in the device file with a one-line edit; the rest of the file is kept as it is.

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The address of the device being replaced. |
| `--product <FILE>` | pinned archive | The product data to flash the new device with. Default: the archive `bussard.lock` pins for the device in `<dir>/products/`. One that contradicts the lock needs `--force`, which also pins it. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--force` | off | Override the replacement refusals: proceed although the old device answers or the identity does not match, and use a `--product` that contradicts the lock (pinning it). |
| `--no-flash` | off | Leave the application image alone: a spare that already carries it. |
| `--bcu-key <HEX>` | free access | BCU key for the flash step. |
| `--keyring <FILE>` | the key store | KNX Data Secure tool keys for the flash and apply steps. |
| `--tool-key <HEX>` | | A raw 32-hex-character KNX Data Secure tool key, for a simulator or bench device. Conflicts with `--keyring`. |

Behaviour:

- Acts on whatever device is in programming mode, so without a terminal and without `--yes` it refuses before loading the model or opening a connection.
- The pinned archive is resolved before anything reaches the bus: a missing or changed one refuses the run with its recovery step.
- Refuses a device that still answers at `ADDRESS`, unless `--force`.
- Refuses when the pressed device's order number or mask differs from the device file (`product.order_number`, `product.mask`), unless `--force`. A field the model states but the device does not report counts as a mismatch.
- With `--no-flash`, refuses a device whose application id differs from the one `bussard.lock` pins, unless `--force`; drop `--no-flash` to flash it.
- Adds no write of its own: each step is the `assign`, `flash` or `apply` path with its own verification.
- If the flash or apply step fails, the address is already assigned; the error names the command to re-run.

## `bussard restart <ADDRESS>`

Restart one device and wait until it answers again.

```console
$ bussard restart 1.1.39
gateway: 192.168.1.74:3671
restart form: confirmed (M-0002_A-A0ED-10-9B4E is a secure-capable System B application (IsSecureEnabled))
restart 1.1.39 (Binary input) via 192.168.1.74:3671? [y/N] y
1.1.39 restarted: it confirmed the restart (A_Restart_Response, process time 0 s) and answered again after 2.0 s (mask 07B0)
```

A device that gets the basic form is reported as `restart sent`, never `restarted`:

```console
$ bussard restart 1.1.52
gateway: 192.168.1.74:3671
restart form: basic (M-0004_A-A012-12-D63A-O000A is not a secure-capable System B application)
restart 1.1.52 (Presence detector) via 192.168.1.74:3671? [y/N] y
1.1.52: restart sent (a basic A_Restart, which the device does not confirm); it answered again after 2.0 s (mask 0705). The restart itself is not verified.
```

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to restart, e.g. `1.1.39`. |
| `--timeout <SECONDS>` | 30 | How long the device may take to answer again. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--keyring <FILE>` | the key store | KNX Data Secure tool keys: a device the keyring lists is restarted over a secured session. |
| `--tool-key <HEX>` | | A raw 32-hex-character KNX Data Secure tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--json` | off | Print `address`, `form` (`confirmed` or `basic`), `form_reason`, `confirmed` (true only when the device answered the confirmed restart with error code 0), `process_time_s` (`null` for the basic form), `mask` and `answered_after_ms`. |

Behaviour:

- Sends the restart form ETS sends that device, chosen from the product data `bussard.lock` pins for it, with the same rule `flash` uses for the restart that ends a download:
    - **confirmed** for a secure-capable System B application (`IsSecureEnabled`): `A_Restart` master reset with erase code 1 and channel 0. The device answers `A_Restart_Response`; only error code 0 confirms the restart. No answer, or another error code, exits 1. bussard then waits the process time the device reported (at most 60 s).
    - **basic** for every other application, and for a device without product data: a bare `A_Restart`, which a device never answers. The report says the restart was sent and the device answered again, not that it restarted.
- Either form only re-runs the application: parameters, link tables and the individual address are kept. Neither is a factory reset.
- A Data Secure device the keyring lists gets the descriptor reads and the restart inside the secured session, as ETS does.
- Refuses a non-loopback gateway without `--allow-remote-gateway`, and without a terminal and without `--yes` refuses before it sends anything.
- Reads the device's mask first, so a device that does not answer is an error before anything is sent.
- After the restart, waits 2 s and then reconnects every second until the device answers its descriptor read with the mask it reported before. A device that stays silent past `--timeout`, or answers with another mask, exits 1.
- A device may transmit its status objects as it starts, as it does when bus voltage returns.

## Related

- [Global options](../global-options.md): confirmation, `--yes`, the real-gateway gate and exit codes.
- [What each write command does](../../explanation/write-commands.md): why every write is plan, confirm, write, verify.
- [Back up and replace a device](../../how-to/back-up-and-replace.md): the task-shaped walk through `backup`, `restore` and `replace`.
- [Device support](../../explanation/device-support.md): the masks these commands accept.
