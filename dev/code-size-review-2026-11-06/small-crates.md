# small crates review

Scope: bussard-project, bussard-transport, bussard-secure, bussard-monitor, bussard-viz, bussard-ha, bussard-testkit (dev-dependency, weighted low). Read-only; every finding verified by reading the code. Line figures use loc.py's rule (code lines, no blanks, comments or `#[cfg(test)]`).

Total product lines: project 5222, transport 5355, secure 2137, monitor 2225, viz 2596, ha 2338 (sum 19,873); testkit 3978 (dev-dep).

Headline: these crates are already lean. Verified savings are about 1,470 lines (~7% of the six product crates) plus ~180 in testkit and ~120 from one cross-crate cleanup. The 40% target will not come from here; it has to come from the surfaces and the big crates.

## Findings (ordered by lines saved, grouped by crate)

### bussard-project

#### F1. One key-material model: fold `Keyring` into `KeyStore`: est. save: 420 lines (confidence high/med)
- Where: `bussard-project/src/keyring.rs:70-280` (Keyring, Backbone, Interface, Device structs + redacting Debug impls), `keyring.rs:538-800` (parse_body, parse_backbone, parse_interface, parse_device, parse_group_key), `keystore.rs:1178-1234` (`to_keyring`), `keystore.rs:897-1094` (`merge_keyring`, 197 lines), `keystore.rs:1675-1900` (parse_store, parse_backbone, parse_interface, parse_device).
- What: the same `.knxkeys`-shaped data is modelled twice. `Keyring {project, created, backbone, interfaces: Vec<Interface>, devices: Vec<Device>, group_keys: HashMap, factory_keys: HashMap}` and `KeyStore {project, created, backbone, interfaces: Vec<StoreInterface>, devices: BTreeMap<IA, StoreDevice>, group_keys: BTreeMap, unassigned}`. `StoreInterface` is `Interface` with `gas: Vec<(GA, Option<String>)>` instead of `gas` + `group_senders`; `StoreDevice` is `Device` with optional tool key. Both files carry a quick-xml event loop over `Keyring/Backbone/Interface/Group/GroupAddresses/Device` whose per-element parsers are near-identical (compare `keyring.rs:671-720` and `keystore.rs:1794-1830`; the only differences are the `Format` attribute check, the `Certificate` element and `parse_number` vs an inline `parse::<u8>()`). `to_keyring` and `merge_keyring` exist only to convert between the two.
- Proposal: keep `KeyStore` as the one model (it is the superset: `Option<tool_key>`, `fdsk`, `serial`, `ets_sequence`, `unassigned`). `parse_keyring(xml, password) -> KeyStore` becomes the existing `parse_store` with the root-attribute check parameterised (`Format` present = store, absent = ETS export). Delete `keyring.rs` structs and body parsers; keep its crypto/signature/canonical-serialisation half (`read_created`, `created_iv`, `verify_signature`, `canonical_serialization`, `decrypt_key`, `decrypt_password`, ~250 lines). `to_keyring` goes away; `merge_keyring` becomes a merge of two `KeyStore`s and loses its field-by-field re-shaping (about half of its 197 lines). The `Keyring::tool_key/group_key/fdsk` accessors already exist on `KeyStore`. `Interface::user_key/device_auth_key` move to `StoreInterface`.
- Risk: 30+ call sites across service (enroll.rs 28, secure.rs 17, group_security, admission, ip_secure, setup/import), cli (conn_cmd, keys_cmd, interface_secure_cmd, monitor/capture/learn), monitor, transport (config.rs, tunnel.rs), mcp and viz take a `Keyring`; mostly they call the three accessors, so the rename is mechanical. The signed export (`export_knxkeys`, `check_export`, `write_body`) is parity-sensitive (ETS must accept the file, issue #349); it stays byte-for-byte because the writer is untouched.

#### F2. Drop the `xknxproject` JSON import escape hatch: est. save: 320 lines (confidence medium, owner decision)
- Where: `bussard-project/src/from_json.rs` (302 lines, incl. its own `build_product`), `lib.rs:120-141` (`import_from_json`, `import_from_json_str`), callers `bussard-cli/src/import_cmd.rs:80-92` (`bussard import --from-json`), `diff_cmd.rs:166-171` (`.json` side), `bussard-service/src/setup/import.rs:43`.
- What: a second importer that builds a `Model` from xknxproject's JSON dump; the module doc calls it "an escape hatch and the test-oracle format". `import_from_json_str` has zero product callers (10 test uses).
- Proposal: delete the module, the two lib fns, the `--from-json` flag and the `.json` branch of `diff`. If the oracle comparison is still wanted, compare our model's JSON against the xknxproject dump in a test (a reader of the dump as test data), not a product importer.
- Risk: the `bussard import --from-json` CLI flag disappears (pre-release, no compat promise per project memory). Tests in `bussard-project/tests/it/` using `import_from_json_str` must move or go.

#### F3. `build::slugify` duplicates `bussard_model::slug`: est. save: 55 lines (confidence high)
- Where: `bussard-project/src/build.rs:1156-1215` vs `bussard-model/src/files.rs:787-815`.
- What: both lowercase, map ä/ö/ü/ß to ae/oe/ue/ss, collapse runs of other chars to one `-`, trim. facts.rs already imports `bussard_model::slug`; build.rs kept its own.
- Proposal: replace with `bussard_model::slug` after confirming the two agree on the edge cases build.rs tests (empty -> `x` fallback in model's version; check `device_name`/`channel` callers tolerate it or keep a one-line wrapper).
- Risk: slug strings land in device file keys and `bussard.lock`; a behavioural difference changes imported file names. Run the import oracle tests (`tests/it/import.rs`, `ets_versions.rs`) before and after.

#### F4. Dead API: est. save: 30 lines (confidence high)
- `keystore.rs:640 record_fdsk` (no callers anywhere), `lib.rs:140 import_from_json_str` (tests only; covered by F2). Also the three `pub mod` re-export shims `dpt_map.rs`, `flag_map.rs`, `hardware.rs`, `manufacturer.rs`, `knx_master.rs` (1 line each) can be plain `use bussard_ets::...` in build.rs.

#### F5. Division of responsibility: `facts.rs` is not import code
- Where: `bussard-project/src/facts.rs` (900 lines), callers `bussard-service/src/adopt/flow.rs:289,636`, `bussard-mcp/src/tools_model.rs:1486-1495`, `build.rs:474`.
- What: the channel-handle / object-key / parameter-key derivation is the lock's key-derivation contract (docs/reference/files). It lives in the `.knxproj` importer crate, so `adopt` (service) and the model-edit tools (mcp) depend on bussard-project only for it, and bussard-project depends on `bussard_ets::dynamic` to host it.
- Proposal: move `facts.rs` next to the Dynamic evaluator (bussard-ets, or bussard-model if the evaluator moves there per CLAUDE.md "shared Dynamic evaluator"). No line saving by itself; it removes a layering inversion and lets `build.rs` and `adopt` share `base_offset_args`/`resolve_placeholders` (`build.rs:65,965`, imported by facts.rs via `crate::build`) without a cycle.

### bussard-transport

#### F6. `devmgmt::Task` is a second copy of `tunnel::TaskState`: est. save: 190 lines (confidence medium)
- Where: `bussard-transport/src/devmgmt.rs:771-1020` (run, fail, send, handle_inbound, heartbeat, disconnect) vs `tunnel.rs:1356-1460` (run), `1552-1646` (send_sequenced, await_ack), `1647-1700` (handle_inbound), `1869-1935` (heartbeat_with), `2094-2130` (disconnect).
- What: both tasks run the same KNXnet/IP channel machine over the same `Link` (UDP or Secure TCP): sequenced request + ACK with repeats, CONNECTIONSTATE heartbeat every 60 s with 3 attempts, inbound sequence check with re-ACK of `seq-1`, DISCONNECT_REQUEST handling, best-effort disconnect on close. The devmgmt copy differs only in the service-type pair (DeviceConfigurationRequest/Ack vs TunnelingRequest/Ack), the ack timeout/repeat constants, and the absence of reconnect and feature-get. `connect_handshake`, `udp_socket`, `open_secure` are already shared (`tunnel.rs:702,743,1113`).
- Proposal: parameterise `TaskState` by a small `ChannelKind { request, ack, ack_timeout, retransmits, reconnect: bool }` and reuse it for device management; `DeviceManagement` keeps only its `Bridge` (the local-cEMI ↔ management-layer adapter, `devmgmt.rs:400-470`) and `request_local`.
- Risk: the tunnel task is the hottest path in the product (every bus command). Keep the tunnel-side behaviour byte-identical: the testkit `MockGateway` suites (`bussard-transport/tests/it/mock_gateway.rs`, `device_mgmt.rs`) cover sequence windows, retransmits and heartbeats on both channel kinds and must stay green unchanged.

#### F7. Unused configuration knobs and exports: est. save: 40 lines (confidence high)
- `config.rs:454 with_multicast_ttl` (no callers), `TunnelReconnect::disabled` (none), `keepalive_risk` (none), `tcp_probe_timeout` (none outside), `knxnet.rs:936 connect_request_tcp` (tests only), `devmgmt.rs:245 local_error_name` (none), `lib.rs` re-exports `is_local_network_refusal`, `classify_fresh_socket_error`, `local_ipv4_interfaces` that no other crate uses (make them private). `wire_trace::` is referenced by nothing outside transport; keep it (deliberate diagnostic) but drop its pub surface.

#### F8. `wire_trace::utc_millis` is a sixth hand-rolled clock: see cross-crate C1.

### bussard-secure

#### F9. Three `random_bytes` and two X25519 key-pair wrappers: est. save: 50 lines (confidence high)
- Where: `crypto.rs:393`, `ipsecure.rs:304`, `enroll.rs:326` (identical bodies, different error types); `ipsecure.rs:245-290 EphemeralKeyPair` vs `enroll.rs:91-135 EnrollKeyPair` (both `StaticSecret` + public, generate/from_secret/public; they differ in Debug redaction and the derived key).
- Proposal: one `random_bytes` in crypto with `CryptoError`, `#[from]` into the other two error enums; one `X25519KeyPair` in crypto with `shared_secret()`; ipsecure and enroll keep only their derivations (`session_key_from_shared`, `derive_key`).
- Risk: none on the wire; test vectors in `dev/enroll/vectors-v2.json` and the ipsecure unit tests pin the bytes.

Otherwise bussard-secure is as small as its spec surface: do not touch asdu/session/group/sequence.

### bussard-monitor

#### F10. Four of five `run_stream*` entry points are unused: est. save: 45 lines (confidence high)
- Where: `stream.rs:152-203`: `run_stream`, `run_stream_cancellable`, `run_stream_with_outbound`, `run_stream_with_outbound_cancellable`, `run_stream_secured_cancellable`. Product callers: only the last (`bussard-cli/src/monitor_cmd.rs`, `capture_cmd.rs`).
- Proposal: keep one `run_stream(config, sink, Options { cancel, outbound, group_keys })`; delete the ladder. Tests that use the others switch to the options struct.

#### F11. Dead API and hand JSON: est. save: 45 lines (confidence med)
- Dead: `secure.rs:117 has_key`, `acceptance.rs:496 write_dpt`, `store.rs:449 dest_ref_to_string`. `format.rs:202-240 json_value` builds the JSON-Lines object by hand from `DecodedTelegram`; a `#[derive(Serialize)]` with `#[serde(rename)]`/`skip_serializing_if` gives the same stable field names (the doc says LLM tooling consumes them: keep the names, add a snapshot test).
- `timefmt.rs` (105 lines) is the best-written of the five calendar copies: it becomes the shared one (C1).

### bussard-viz

#### F12. Three copies of the loopback token page server: est. save: 190 lines (confidence high)
- Where: `pairing_page.rs:197-290` (`PairingPage::start/url/addr/finish`, `Drop`), `password_page.rs:127-215` (same, verbatim), `enroll_local.rs:125-215` (`LocalEnrollServer::start_with/addr/finish`, `Drop`). Each binds `127.0.0.1:0`, builds a current-thread runtime on a named thread, `axum::serve` under a oneshot shutdown, sleeps a grace period on finish, joins on drop. Plus `escape_html` twice (`pairing_page.rs:392`, `password_page.rs:374`; a third `escape` in testkit `ha.rs:360`), and `file`/`respond`/`html` response helpers three ways.
- Proposal: one `LocalServer::start(name, router_for(host_list) -> Router) -> io::Result<LocalServer>` with `addr()`, `url(path)`, `finish()`, `Drop`; the three pages keep only their handlers and HTML. One `escape_html` in viz (or bussard-model's text utils).
- Risk: none on the wire; `bussard-viz/tests/it/enroll_e2e.rs`, `browser_smoke.rs` and the mcp enrol/password tests cover the three pages.

#### F13. A second `ModelHandle`: est. save: 60 lines (confidence medium)
- Where: `state.rs:151-290`: viz wraps `bussard_service::ModelHandle` in its own `ModelHandle` + `ModelSnapshot` only to memoise the `project_model` JSON per model version.
- Proposal: hold `bussard_service::ModelHandle` directly in `AppState` and memoise the projection in a `Mutex<Option<(u64, Arc<Value>)>>` beside it; drop `watching`, `from_shared`, `install`, `shared` forwarding.

`project.rs` (314 lines) is the frontend's JSON contract; it is a view, not a duplicate of `device_view.rs`. `enroll_relay.rs` (457) is product code in local mode (`LocalEnrollServer` is used by `enroll_cmd` and `tools_enroll`). Keep both.

### bussard-ha

#### F14. Dead API: est. save: 10 lines
- `api.rs:151 base_url`. `derive.rs:905-1090` looks like a long match but is a DPT-sub to HA sensor-type table at one line per entry; a static slice would be the same length. `plan.rs` (YAML entity diff) and `automation.rs` are each used by the MCP HA tier. Nothing else to take here.

### bussard-testkit (dev-dependency, weight low)

#### F15. `secure_gateway::tunnel_step` re-implements the tunnelling server: est. save: 180 lines (confidence medium)
- Where: `secure_gateway.rs:706-945` vs `gateway.rs:788-1125` (`on_datagram`, `on_connect`, `on_tunneling_request`, `on_feature_get`, heartbeat/disconnect arms). The secure mock already calls into `gateway::line_replies` for the device line (`secure_gateway.rs:788`); the channel-level arms (CONNECT_REQUEST, CONNECTIONSTATE, DISCONNECT, TUNNELING_ACK, FEATURE_GET, sequence bookkeeping) are a second copy.
- Proposal: factor a `TunnelServer` step (bytes in, replies out, stats) in gateway.rs that both mocks drive; the secure one wraps it in SECURE_WRAPPER.

#### F16. Unused builder knobs: est. save: 20 lines
- `gateway.rs:244 ignore_heartbeats`, `device.rs:896 with_segment_base`, `device.rs:970 with_silence` have no callers in src or tests.

## Cross-crate (outside this scope, reported for the coordinator)

#### C1. Five hand-rolled civil-date / RFC 3339 implementations: est. save: 120 lines (confidence high)
- `bussard-model/src/history.rs:734-790` (`rfc3339`, `civil_from_days`), `bussard-download/src/backup.rs:655-700` (`rfc3339_utc`, `civil_from_days`), `bussard-monitor/src/timefmt.rs` (105 lines, parse + format), `bussard-project/src/keystore.rs:1586-1625` (`now_timestamp`, `civil_from_days`), `bussard-transport/src/wire_trace.rs:113-143` (`utc_millis`). All are the same Howard Hinnant algorithm.
- Proposal: one `bussard_model::timefmt` (bussard-model is the root dependency of all four), with `to_rfc3339`, `to_clock`, `from_rfc3339`; delete the other four. The no-chrono decision (timefmt.rs doc: MSRV) stays.

## Do not touch
- `bussard-transport/src/tunnel.rs:497-1221` (connect planning, secure-user ordering, host locks, probe fallback): every branch is a live-gateway finding (issues #90, #197, #228) and the hottest path in the product.
- `bussard-transport/src/cemi.rs`, `knxnet.rs`: the clean-room wire codec; 1.2k lines for the whole KNXnet/IP + cEMI surface is already tight.
- `bussard-mgmt/src/connection.rs` is not a duplicate of the tunnel: it is the KNX layer-4 (T_Connect/NDT/T_ACK, Style 3) state machine over any `BusConnection`. One retry/sequence machine per layer is correct; the duplication is inside transport (F6), not between transport and mgmt.
- `bussard-secure` asdu/session/group/sequence/crypto: spec-sized, vector-tested.
- `bussard-testkit/src/device.rs` (1326): an in-process mock device next to knx-sim's. knx-sim is deliberately an independent second implementation (its README: "two independent implementations meeting on the wire is the cross-check"), so the mock cannot be replaced by knx-sim code without losing that property. It is also the only device the ~200 nextest mock suites can spin up per process.
- `bussard-project/src/build.rs` resolution chain and `container.rs`: real import logic, one copy.
- `bussard-monitor/src/acceptance.rs` (`bussard test`), `infer.rs` (DPT inference): product features with no twin.

## Estimated total
| crate | product lines | est. save | % |
|---|---|---|---|
| bussard-project | 5222 | 825 (F1 420, F2 320, F3 55, F4 30) | 16% |
| bussard-transport | 5355 | 260 (F6 190, F7 40, C1 share 30) | 5% |
| bussard-secure | 2137 | 50 | 2% |
| bussard-monitor | 2225 | 90 | 4% |
| bussard-viz | 2596 | 250 | 10% |
| bussard-ha | 2338 | 10 | 0% |
| six product crates | 19,873 | ~1,485 | ~7.5% |
| bussard-testkit (dev) | 3978 | 200 | 5% |
| cross-crate C1 (model, download, project, monitor, transport) | | 120 | |
