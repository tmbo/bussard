# Product-corpus conformance sweep

Corpus-driven conformance sweep. Buckets every application in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason and mask family. A new refusal or panic is a regression the checked-in baseline catches. Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). No vendor product data is committed here — only outcome labels and file names.

## Buckets

- Product files: **490** (490 parsed, 0 parse-failed, 0 parse-panicked)
- Application programs: **1341**
  - Image: 1336 ok, 5 refused, 0 panicked
  - Plan: 1120 executable, 103 refused, 118 unsupported-family, 0 panicked

## Plan-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 94 | UnsupportedOp: LdCtrlWriteProp |
| 5 | UnresolvableImage: computing the parameter image |
| 1 | NoProcedure |
| 1 | UnresolvableImage: no relative segment to write into |
| 1 | UnresolvableImage: segment M-0002_A-A0AE-10-C64E_RS-04-00000 carries no code image  |
| 1 | UnresolvableImage: segment M-0002_A-A0AF-10-0DEE_RS-04-00000 carries no code image  |

## Image-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 4 | ParameterImage: parameter `0 |
| 1 | ParameterImage: parameter `PA Verbindung Zeit` |

## Parse-failure reasons (ranked by file count)

_(none)_

## Mask-family coverage

| family | apps | exec | refused | unsupported | panicked |
| --- | ---: | ---: | ---: | ---: | ---: |
| System 1 | 95 | 0 | 0 | 95 | 0 |
| System 7 | 377 | 277 | 100 | 0 | 0 |
| System ? | 23 | 0 | 0 | 23 | 0 |
| System B | 839 | 836 | 3 | 0 | 0 |
| System B (IP) | 1 | 1 | 0 | 0 | 0 |
| System B (RF) | 6 | 6 | 0 | 0 | 0 |

