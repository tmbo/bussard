# Fabricated corpus fixtures (conformance-sweep regressions)

Every file here is a **fabricated** ApplicationProgram / product XML snippet:
fake ids, offsets, and values, **no vendor content copied**. They reproduce the
*shapes* the full 500-product corpus sweep found awkward, so the conformance
sweep has committed regression coverage that runs in normal CI without the big,
git-ignored vendor cache. Real `.knxprod` files are copyrighted and are never
committed (see `tests-support/product-corpus/README.md`).

The sweep test (`tests/sweep_fixtures.rs`) assembles these snippets into
one-file/`multi-app` `.knxprod` ZIPs in a temp dir, runs the real
`read_knxprod` + `sweep_corpus` pipeline over them, and asserts each lands in the
bucket its shape implies. It also renders the committed baseline
`tests-support/product-corpus/fixture-conformance.json` and fails on drift.

## Files and the real shape each stands in for

| file | stands in for | expected bucket |
| --- | --- | --- |
| `theben_rm4_multiapp.knxprod.d/` | Theben RM 4: 8 apps across two masks (0705/0701) in one product file | multi-app, all `not-supported-family` (System 7) |
| `zennio_union.app.xml` | union-heavy Zennio: several `<Union>` members overlaying one region | image ok, plan executable (System B) |
| `interra_extension_lie.app.xml` | Interra "extension-lie": a schema/version attr that disagrees with the body but must still parse | parse ok, classified (System B) |
| `enum_default_out_of_range.app.xml` | Zennio Z40/Z70: vendor default outside its own enum, but leniently passed through | image ok (leniency), plan executable |
| `truncated.app.xml` | a truncated/malformed application XML | parse-fail bucket |

Each `.app.xml` is a single ApplicationProgram; the `*.knxprod.d/` directory
holds the several app XMLs (+ `Hardware.xml`) that the test zips into one
multi-app product file.
