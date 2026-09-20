# Product-corpus conformance sweep

Corpus-driven conformance sweep. Buckets every application in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason and mask family. A new refusal or panic is a regression the checked-in baseline catches. Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). No vendor product data is committed here — only outcome labels and file names.

## Buckets

- Product files: **5** (4 parsed, 1 parse-failed, 0 parse-panicked)
- Application programs: **11**
  - Image: 11 ok, 0 refused, 0 panicked
  - Plan: 11 executable, 0 refused, 0 unsupported-family, 0 panicked

## Plan-refusal reasons (ranked by app count)

_(none)_

## Image-refusal reasons (ranked by app count)

_(none)_

## Parse-failure reasons (ranked by file count)

| count | reason |
| ---: | --- |
| 1 | parsing application program M-00FF_A-00FF-10-DEAD-O000A |

## Mask-family coverage

| family | apps | exec | refused | unsupported | panicked |
| --- | ---: | ---: | ---: | ---: | ---: |
| System 7 | 8 | 8 | 0 | 0 | 0 |
| System B | 3 | 3 | 0 | 0 | 0 |

