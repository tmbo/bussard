# The viz API

The JSON and Server-Sent Events endpoints the `bussard viz` page is built on, for scripts and test harnesses that talk to the same server.

The server's flags, its access rules and its offline behaviour are on [`bussard viz`](commands/servers.md#bussard-viz). Every endpoint lives on the listen address, `127.0.0.1:8080` by default.

## Endpoints

```console
$ curl -s http://127.0.0.1:8080/api/state
```

| Endpoint | Returns |
|---|---|
| `GET /` | The website shell. `GET /assets/{file}` serves the embedded JS and CSS modules. |
| `GET /api/model` | The precomputed model projection: devices, groups, ranges, links, senders and listeners, and per device and channel the `parameters` rows `{key, text, value, default, non_default, computed_by}`. `text`, `default` and `non_default` are `null` without the product model. A parameter a `<ParameterCalculation>` computes has the computed value in `value` and the calculation's id in `computed_by` (`null` otherwise). Rebuilt in place by `POST /api/reload`. |
| `GET /api/state` | `{bus: {state, transport, connected, gateway, loopback}, seq, values, prog}`. `gateway` is the resolved endpoint (`192.0.2.10:3671`, or `multicast 224.0.23.12:3671`; `null` in model-only mode) and `loopback` says whether it is a loopback address. `values` is the last value, payload, DPT and source per group address. `prog` is an array of the individual addresses currently seen in programming mode (empty when none, or when `--watch-prog` is off). |
| `GET /api/traffic` | Server-Sent Events, see [the traffic stream](#the-traffic-stream). |
| `POST /api/group-write` | `{address, value?, payload?, dpt?, force?}`. Encodes and sends a GroupValueWrite; returns `200` with an echo of what was written. See [group writes](#group-writes). |
| `POST /api/reload` | Reloads the model from disk and swaps it in atomically. See [reloading the model](#reloading-the-model). |

Errors are `{"error": {"code", "message"}}`.

## The traffic stream

`GET /api/traffic` sends these events:

| Event | Data |
|---|---|
| `bus` | The connection state. Always sent first, and again when it changes. |
| `telegram` | The [telegram JSON](json-output.md) plus `seq`; the event's `id:` is the seq. |
| `model` | The model was reloaded: `{model_version, stats}`, so the page refetches `/api/model`. |
| `prog` | The programming-mode set changed: `{devices: [ia, ...]}`. Only with `--watch-prog`. |
| `gap` | The subscriber fell behind and should re-snapshot. |

`?backlog=N` (default 50) replays recent telegrams. A reconnect with `Last-Event-ID` resumes with no duplicates and no gaps.

## Group writes

!!! warning
    `POST /api/group-write` puts a telegram on the bus, and actuators move. It answers `403 writes_disabled` unless the server was started with `--allow-writes`.

```console
$ curl -s -X POST http://127.0.0.1:8080/api/group-write \
    -H 'Content-Type: application/json' \
    -d '{"address": "1/0/4", "value": "on"}'
```

The request takes exactly one of `value` or `payload`:

- **`value`** is a human string, encoded the same way `bussard write` encodes it. `dpt` overrides the group address's modelled DPT.
- **`payload`** is raw bytes as hex (even length, upper- or lowercase, for example `"0b64"`), sent verbatim, for DPTs with no string grammar.

When a DPT is known for a `payload` write (from the model or `dpt`), the byte length is checked against it. A sub-byte DPT takes exactly one byte with a value of at most `0x3f`, sent packed into the 6-bit field as the `value` path would send it. A byte-sized DPT takes that many whole octets. When no DPT is known anywhere, the raw write is still allowed but sent as a full data octet, the form every device reads correctly.

The success echo carries `payload` (the hex bytes sent) and sets `value` to `null` for raw writes. The write policy matches `bussard write`:

| Status | When |
|---|---|
| `403` `writes_disabled` | Every write, when the server runs without `--allow-writes`. |
| `400` | A bad address, a value that cannot be encoded, bad hex, both or neither of `value` and `payload`, or a payload whose length does not match a known DPT. A secured group address without a key in `--keyring`. |
| `403` | A `protected` group address without `force`; raw writes alike. |
| `422` | No DPT can be resolved for a `value` write; supply `dpt`. |
| `503` | The bus is unavailable (model-only mode, or reconnecting). |

## Reloading the model

`POST /api/reload` picks up edits to the model files without restarting the server. It loads the model directory again and swaps the shared model and its `/api/model` projection in one atomic move, bumping a `model_version` counter (the initial model is version 1). The reload button in the page header, next to the bus status dot, calls it and shows any error inline.

```console
$ curl -s -X POST http://127.0.0.1:8080/api/reload
```

- On success it returns `200` with `{ok, model_version, stats}` (`stats` is `{devices, groups, links}`) and emits a `model` event carrying `{model_version, stats}`, so every connected page refetches `/api/model`.
- On a load error it returns `422` with `{"error": {"code": "model_invalid", "message": ...}}`, the message naming the offending file. The previous model stays in service unchanged, with no swap and no event.
- The protected-address write gate and the live decoder both read the current model, so newly protected group addresses are enforced, and renamed addresses resolve, on the very next write and telegram.

## Watching programming mode

With `--watch-prog`, the server puts a broadcast `A_IndividualAddress_Read` on the bus every few seconds and collects the answers for about a second, as `bussard assign` does. Every device in KNX programming mode answers with its own individual address: the software equivalent of the red programming LED.

- The answering set is in `/api/state`'s `prog` array and, whenever it changes, in a `prog` event carrying `{devices: [ia, ...]}`. The page highlights a device the moment its programming button is pressed and drops the highlight when it is released.
- The probe is active bus traffic, so it is off by default and must never run unnoticed against a real installation. Against a non-loopback gateway it needs `--allow-remote-gateway`.
- It takes effect only while the bus is connected and reuses the server's single tunnel. While the bus is disconnected the set is cleared and probing pauses; it resumes on reconnect.

## Related

- [`bussard viz`](commands/servers.md#bussard-viz): the flags, the access rules and the offline modes.
- [Telegram JSON](json-output.md): the shape of each `telegram` event.
- [Watch the bus](../how-to/watch-the-bus.md): the viz page in a task.
