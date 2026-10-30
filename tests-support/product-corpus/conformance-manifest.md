# Product-corpus conformance sweep

Corpus-driven conformance sweep. Buckets every application in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason and mask family. A new refusal or panic is a regression the checked-in baseline catches. Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). No vendor product data is committed here — only outcome labels and file names.

## Buckets

- Product files: **913** (913 parsed, 0 parse-failed, 0 parse-panicked)
- Application programs: **2164**
  - Image: 2146 ok, 18 refused, 0 panicked
  - Plan: 1794 executable, 109 refused, 261 unsupported-family, 0 panicked

## Plan-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 43 | MissingAppMask |
| 27 | UnsupportedOp: LdCtrlMapError |
| 18 | UnresolvableImage: computing the parameter image |
| 16 | UnsupportedOp: LdCtrlDelay |
| 1 | NoProcedure |
| 1 | UnknownObjectSize |
| 1 | UnresolvableImage: no relative segment to write into |
| 1 | UnsupportedOp: LdCtrlAbsSegment |
| 1 | UnsupportedOp: LdCtrlInvokeFunctionProp |

## Image-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 4 | ParameterImage: parameter `D_MW_TEXTOBJEKT_TEXT_A` |
| 3 | ParameterImage: parameter `LedRGB_OnColor_1` |
| 3 | ParameterImage: parameter `WR_MW_TEXT_SUED_OST` |
| 2 | ParameterImage: parameter `FASS_ZEITOEFFNEN_STATUS_STRING` |
| 2 | ParameterImage: parameter `Location name` |
| 1 | ParameterImage: parameter `FASS_AUTO_DELAY_STRING` |
| 1 | ParameterImage: parameter `LedRGB1_OffColor` |
| 1 | ParameterImage: parameter `SEITE_6_DR_EINHEIT` |
| 1 | ParameterImage: parameter `Wettersituation 2 leicht bewölkt` |

## Parse-failure reasons (ranked by file count)

_(none)_

## Mask-family coverage

| family | apps | exec | refused | unsupported | panicked |
| --- | ---: | ---: | ---: | ---: | ---: |
| (no mask) | 43 | 0 | 43 | 0 | 0 |
| System 1 | 101 | 0 | 0 | 101 | 0 |
| System 2 | 101 | 2 | 0 | 99 | 0 |
| System 7 | 634 | 615 | 19 | 0 | 0 |
| System ? | 61 | 0 | 0 | 61 | 0 |
| System B | 1178 | 1131 | 47 | 0 | 0 |
| System B (IP) | 1 | 1 | 0 | 0 | 0 |
| System B (RF) | 45 | 45 | 0 | 0 | 0 |

