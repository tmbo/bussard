- `knx_find_devices` scans a line from chat, as `bussard scan` does, and runs
  as a job of the server's job table: mask, manufacturer and order number per
  device, names first, with a one-sentence summary and the devices found so
  far while it runs. `knx_show_device` with `live: true` adds what `bussard
  status <ia>` reads over the bus: identity, and for an IP interface its IP
  settings, tunnelling addresses and state. Both only read and are omitted or
  refused in `--passive` mode (#747).
