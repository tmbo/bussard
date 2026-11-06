- `bussard-download` is smaller inside (#897): the System B, System 7 and
  property-only flashes run one step loop, the product-corpus sweep moved to
  the test tree, each operation has one function instead of a `_with` /
  `_secured` / `_seeded` ladder, and the crate root no longer re-exports
  items only its own tests use. Nothing written to a device changes. A plan
  against a device whose parameter memory cannot be read lists only the
  parameters the project's configuration shows, as a plan with memory does.
