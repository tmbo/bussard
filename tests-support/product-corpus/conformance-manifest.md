# Product-corpus conformance sweep

Corpus-driven conformance sweep. Buckets every application in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason and mask family. A new refusal or panic is a regression the checked-in baseline catches. Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). No vendor product data is committed here — only outcome labels and file names.

## Buckets

- Product files: **497** (497 parsed, 0 parse-failed, 0 parse-panicked)
- Application programs: **1354**
  - Image: 1354 ok, 0 refused, 0 panicked
  - Plan: 1135 executable, 101 refused, 118 unsupported-family, 0 panicked

## Plan-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 99 | UnsupportedOp: LdCtrlWriteProp |
| 1 | NoProcedure |
| 1 | UnresolvableImage: no relative segment to write into |

## Image-refusal reasons (ranked by app count)

_(none)_

## Parse-failure reasons (ranked by file count)

_(none)_

## Mask-family coverage

| family | apps | exec | refused | unsupported | panicked |
| --- | ---: | ---: | ---: | ---: | ---: |
| System 1 | 95 | 0 | 0 | 95 | 0 |
| System 7 | 378 | 278 | 100 | 0 | 0 |
| System ? | 23 | 0 | 0 | 23 | 0 |
| System B | 851 | 850 | 1 | 0 | 0 |
| System B (IP) | 1 | 1 | 0 | 0 | 0 |
| System B (RF) | 6 | 6 | 0 | 0 | 0 |

