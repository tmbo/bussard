# Exchange with ETS

Keep bussard and ETS, the KNX Association's commissioning tool, in step in both directions: your names into an ETS project, and an integrator's new ETS export into your model. For owners who work with an ETS integrator, and for integrators who keep ETS as the tool of record.

None of these steps touch the bus.

## Send your group-address names to ETS

```console
$ bussard export-groups --format ets-csv --out groups.csv
Wrote 62 group address(es) to groups.csv (ETS CSV).
Import it in ETS: Group Addresses -> Import, then pick this file.
```

In ETS, open the project, select *Group Addresses* in the project tree, and use *Import* on the toolbar. The CSV is the three-level form ETS itself exports. `--format ets-xml` writes ETS's group-address XML instead, which keeps the main and middle group names as a tree.

Names, descriptions and DPTs (the data type of each address) cross over as they are. ETS has no field for bussard's `protected` flag, so a protected address carries a leading `[protected]` marker in its description.

## Redo the other changes in ETS by hand

bussard cannot write into a `.knxproj`: ETS signs its project files, so bussard cannot write changes back into one. ETS stays in step only when someone redoes the changes there, so let bussard write the list:

```console
$ bussard diff project.knxproj knx --checklist
```

The output is a Markdown checklist in the order you work in ETS. The lines below are illustrative:

```text
- [ ] 4/1/20 "Aussen dunkel", DPT 1.001, new (main group 4 "Zentral", middle group 4/1 "Wetterdaten")
...
- [ ] Universalkanal C4: Funktion › Helligkeitsschwelle: unter 20 lx (was über 10000 lx)
- [ ] Objekt 105 "C18.1 Logikmodul" (Schalten): sends 1/0/4 (was nothing)
...
Afterwards: export the project and run bussard diff <export> <B>; it should report no changes.
```

1. Group addresses first: new, renamed, DPT, description, security, removed.
2. Then one section per device: name and location, parameters (with the ETS page, the ETS label, the new and the old value), objects and links, security.
3. Last, a *Not in ETS by hand* list for what ETS does not take, such as the gateway and the `protected` flag.

Work through it, export the project from ETS, and run the diff again. When it reports no changes, the two agree. If the checklist says it has no pages for a device, run `bussard device <address>` once and diff again.

## See what a new export would change

Before you import an integrator's new file, ask what it changes:

```console
$ bussard diff knx integrator-2026-10-01.bussard
2 change(s) from knx to integrator-2026-10-01.bussard:
  Group address 1/0/1 is now called "Kitchen ceiling" (was "Light Kitchen").
  Night setback on Living room thermostat: 2 to 3.
```

Each side can be a model directory, a `.bussard` bundle or a `.knxproj`. A renamed group address is one rename, not a removal and an addition. `diff` writes nothing and exits 0 whether or not there are differences.

- A password-protected project takes `--password`, `--password-b` for a second project with another password, or `BUSSARD_PROJECT_PASSWORD` from your `.env`.
- `--json` gives the structured changes, `--raw` a file-level TOML diff.

With an assistant, `knx_diff_project` returns the same sentences. It reads them to you before you import, and says whether a protected address is touched.

## Import the new export

```console
$ bussard import integrator-2026-10-01.bussard --dir knx
```

The import takes the generated data from the file: com-object tables, links and parameters. Names, rooms, descriptions, DPTs and `protected` flags you edited stay yours. Each disagreement is printed as a sentence, and the command exits 3 so you notice:

| Flag | On a disagreement |
|---|---|
| none | Keep your value, exit 3. |
| `--mine` | Keep your value, exit 0. |
| `--theirs` | Take the file's value. |
| `--interactive` | Ask for each one (`m` keeps mine, `t` takes theirs). |

A link you have and the file lacks is a disagreement too, because bussard cannot tell a link you added from one the project dropped. The import snapshots the model first, so `bussard undo` reverts it. Afterwards, run `plan` and `apply` for the devices that changed; the import itself writes no device.

## Next steps

- [Work with an integrator](work-with-an-integrator.md): the full file exchange, with bundles.
- [Change a link](change-a-link.md): push the imported change to the device.
- [Model commands](../reference/commands/model.md): every flag of `diff`, `import` and `export-groups`.
