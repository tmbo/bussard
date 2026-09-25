# demo-model — the synthetic source of `assets/fixture-model.json`

A small fictional KNX installation ("Demo House"): two floors, ten devices and
about thirty group addresses. It exists so the frontend has a realistic model to
develop and self-test against **without shipping anybody's real installation**
in the binary.

Regenerate the checked-in projection after editing anything here:

```sh
cargo run -p bussard-viz --example dump_fixture -- \
  crates/bussard-viz/fixtures/demo-model \
  > crates/bussard-viz/assets/fixture-model.json
```

`tests/fixture_model.rs` fails if the two drift apart.

Everything in here is invented. Never point `dump_fixture` at a real `knx/`
directory and commit the result: the projection carries the room names, device
names and the full group-address plan of that building.

## What it deliberately exercises

* named `ranges:` at both main and main/middle level, plus a GA whose range is
  unnamed;
* devices with and without `[location]` / `product` / `[channel.*]` tables;
* a com-object present in the device table but never linked (the "unused
  com-object" info counter);
* a link-only com-object with no table entry (`dpt`/`flags` project to `null`);
* a GA referenced only by a link and never declared in `groups.toml`
  (synthesized with `name: null`);
* a declared GA with no `dpt` (the write path must refuse it);
* declared-but-unlinked GAs (the "unused group address" info counter);
* one-sided GAs (sender without listener, and listener without sender) so the
  problems panel has both problem types;
* a `protected: true` GA (writes must be refused or confirmed);
* KNX Data Secure, read-only: a security-activated device (1.1.6) and a
  `secure = true` GA (0/2/1), so the inspector and the projection show both;
* a spread of DPTs: 1.001, 1.005, 1.008, 1.011, 3.007, 5.001, 5.010, 9.001,
  9.004, 12.001, 20.102.
