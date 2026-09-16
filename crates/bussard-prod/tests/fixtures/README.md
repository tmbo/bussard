# Fabricated product-image fixture (sweep regression)

`enum_default_not_a_member.app.xml` is a **fabricated** ApplicationProgram XML
snippet (fake ids/offsets/values, no vendor content). It reproduces the exact
condition that made the Zennio Z40 and Z70 v2 panels refuse at pre-flight during
the product-corpus sweep:

> an enum parameter (`<TypeRestriction>`) whose declared default `Value` is **not**
> one of the enumeration's declared members.

`bussard_prod::compute_parameter_image` rejects such a parameter with
`value \`N\` is not a declared enumeration member`, which `plan_flash` surfaces as
`PlanError::UnresolvableImage: computing the parameter image`. The fixture
declares members `{1, 2}` and a default of `3`, and targets mask `07B0` so it
reaches the flash planner (which gates on System B).

**Verified:** built into a one-file `.knxprod` and run through the real
`read_knxprod` + `plan_flash`, this fixture reproduces
`refused: UnresolvableImage: computing the parameter image` — the same class the
two real panels landed in.

## Intended tests

Wrap the XML into a one-file `.knxprod` (same helper shape as
`crates/bussard-prod/tests/knxprod.rs::build_knxprod`), then:

1. **`bussard-prod`** — `compute_parameter_image` returns `Err` naming this
   parameter and the non-member value `3`. Pin the message shape.
2. **`bussard-download`** — `plan_flash(app, "1.1.1", 0x07B0, &empty)` returns
   `PlanError::UnresolvableImage` whose `reason` contains
   `"not a declared enumeration member"`.
3. **A policy test** — decide whether a vendor's own out-of-enum default should
   hard-refuse an otherwise-flashable device or fall back to encoding the raw
   number with a warning. The sweep showed this alone refused 2 of 46 otherwise
   fully-executable Zennio System B panels, so the strict check has real user
   cost. Whatever the decision, this fixture guards it.

The related `Other`/`Raw` parse fixtures live under
`crates/bussard-ets/tests/fixtures/` (see that dir's README).
