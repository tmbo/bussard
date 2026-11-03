# bussard.keys

`bussard.keys` is the KNX Secure key store: the tunnelling passwords, the device tool keys and the group keys of a secured installation. `bussard keys import` writes it, and so do `import` and `init` when a `.knxkeys` keyring export sits next to the project and `BUSSARD_KEYRING_PASSWORD` is set. Do not edit it by hand.

## Example

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- bussard key store. ... -->
<Keyring Signature="..." Project="House" CreatedBy="bussard 0.1.0" Created="2026-09-25T10:11:12" Format="bussard.keys/1" xmlns="https://github.com/tmbo/bussard/xml/keys/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="1000" Key="..." />
  <Interface Type="Tunneling" Host="1.1.200" IndividualAddress="1.1.22" UserID="2" Password="..." Authentication="..." />
  <GroupAddresses>
    <Group Address="1/2/3" Key="..." />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="1.1.12" ToolKey="..." SerialNumber="00FA12345678" FDSK="..." SequenceNumber="42" />
  </Devices>
  <UnassignedCertificates>
    <Certificate SerialNumber="00FA01020304" FDSK="..." />
  </UnassignedCertificates>
</Keyring>
```

## Elements

| Key | Type | Meaning |
|---|---|---|
| `Keyring` | root element | `Project`, `Created` (fixed when the store is first written; it seeds the attribute IV), `CreatedBy`, `Format = "bussard.keys/1"`, `Signature`. |
| `Backbone` | element | The multicast (routing) key, address and latency. |
| `Interface` | element | A KNXnet/IP Secure tunnelling user or other interface: tunnel address, host, user id, session password, device authentication code, and the group addresses it may send to. |
| `GroupAddresses/Group` | element | One group key per group address, written three-level (`1/2/3`). |
| `Devices/Device` | element | Tool key, serial number, factory key (FDSK), management password and authentication code. `ToolKey` is optional: a device can be known by its factory key alone. `SequenceNumber` is the value the last ETS export recorded, carried through for the export and the security individual address table. |
| `UnassignedCertificates/Certificate` | element | A factory key entered with `bussard keys add-certificate` whose serial number no device in the store has yet. It moves to a `Device` when `bussard assign` reads that serial off a device, or when a `keys import` brings a device with it. Never written to an export. |

## Notes

- **Who reads it.** Every bus command reads its keys from the store unless `--keyring` or `BUSSARD_KEYRING` names an explicit file. The store wins over the deprecated `connection.keyring`.
- **Git-tracked by design.** A checkout recovers the model and its keys together. `.bussard/` never holds keys.
- **Protection.** The file is the XML of an ETS `.knxkeys` export, protected the same way and with the same password, `BUSSARD_KEYRING_PASSWORD`. Every key and password attribute is AES-128-CBC encrypted under the PBKDF2 keyring key, and the root `Signature` covers every element and attribute, so a wrong password or a hand edit fails the load.
- **What differs from an ETS export.** The `Format` attribute and namespace, the optional `ToolKey`, three-level group addresses, and stable ciphertexts. An unchanged key or password keeps its encrypted bytes across writes (fixed `Created`, keyed password prefixes), so `git diff` shows only the entries that changed plus the signature line.
- **No send sequences.** bussard's own Data Secure send sequences are not stored. They are seeded from the clock (milliseconds since 2018-01-05), so a restored store never makes bussard replay a sequence a device has already seen.
- **Safe writes.** Every write goes through a temporary file and a rename, and keeps the previous store as `bussard.keys.bak` until the next successful write. A write that would produce the same bytes touches nothing.
- **`bussard.keys.meta.toml`.** Next to the store, it records when a write last changed the store and when `bussard keys export` wrote each export: paths and UTC times, no keys. `validate` reads it for W040. Commit it with the store.

## Related

- [Secure commands](../commands/secure.md): `bussard keys` and the commands that change keys.
- [KNX Secure](../../explanation/knx-secure.md): keys, the key store and what secured means.
- [Environment variables](../environment.md): `BUSSARD_KEYRING` and `BUSSARD_KEYRING_PASSWORD`.
- [Diagnostics](../diagnostics.md): the key checks E027 to W042.
