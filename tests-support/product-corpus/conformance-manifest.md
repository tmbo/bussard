# Product-corpus conformance sweep

Corpus-driven conformance sweep. Buckets every application in every product through parse -> image-synthesis -> plan-lowering, ranked by refusal reason and mask family. A new refusal or panic is a regression the checked-in baseline catches. Regenerate with the env-gated corpus test (BUSSARD_PRODUCT_CORPUS set, BUSSARD_UPDATE_SWEEP_MANIFEST=1). No vendor product data is committed here — only outcome labels and file names.

## Buckets

- Product files: **913** (913 parsed, 0 parse-failed, 0 parse-panicked)
- Application programs: **2164**
  - Image: 2164 ok, 0 refused, 0 panicked
  - Plan: 1852 executable, 51 refused, 261 unsupported-family, 0 panicked

## Plan-refusal reasons (ranked by app count)

| count | reason |
| ---: | --- |
| 43 | MissingAppMask |
| 1 | NoProcedure |
| 1 | UnknownObjectSize |
| 1 | UnresolvableImage: no relative segment to write into |
| 1 | UnsupportedOp: LdCtrlAbsSegment |
| 1 | UnsupportedOp: LdCtrlInvokeFunctionProp |
| 1 | UnsupportedWriteProp: the write to object 7 PID 211 carries no InlineData and no param |
| 1 | UnsupportedWriteProp: the write to object 8 PID 64 has Count 500, more than 255 elemen |
| 1 | UnsupportedWriteProp: the write to object type 50001 PID 211 carries no InlineData and |

## Image-refusal reasons (ranked by app count)

_(none)_

## Parse-failure reasons (ranked by file count)

_(none)_

## Mask-family coverage

| family | apps | exec | refused | unsupported | panicked |
| --- | ---: | ---: | ---: | ---: | ---: |
| (no mask) | 43 | 0 | 43 | 0 | 0 |
| System 1 | 101 | 0 | 0 | 101 | 0 |
| System 2 | 101 | 2 | 0 | 99 | 0 |
| System 7 | 634 | 632 | 2 | 0 | 0 |
| System ? | 61 | 0 | 0 | 61 | 0 |
| System B | 1178 | 1172 | 6 | 0 | 0 |
| System B (IP) | 1 | 1 | 0 | 0 | 0 |
| System B (RF) | 45 | 45 | 0 | 0 | 0 |

