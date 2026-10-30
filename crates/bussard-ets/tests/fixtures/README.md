# Fabricated application-program fixtures (sweep regression corpus)

These `*.app.xml` files are **fabricated** ApplicationProgram XML snippets. They
reproduce the *structural shape* of constructs discovered during the deep-testing
product-corpus sweep (220 vendor `.knxprod` files across 8 manufacturers) — using
fake ids, fake offsets and fake data. **No vendor content is copied.**

Each file is a single `<KNX>`/`<ApplicationProgram>` document in the same style as
the inline `APP_XML` in `crates/bussard-prod/tests/it/knxprod.rs`. A test can either
parse it directly with `bussard_ets::application::parse_application_program`, or
wrap it into a one-file `.knxprod` ZIP the way `knxprod.rs::build_knxprod` does
(a `knx_master.xml`, a `M-XXXX/Hardware.xml`, and the app XML under `M-XXXX/`).

## Why these exist

The sweep found several `LdCtrl*` load ops and several `<Type*>` parameter types
that the current code does **not** handle as typed variants: the parser keeps
unknown ops as `LoadOp::Raw` and unknown types as `ParameterType::Other`, and the
flash planner refuses any procedure that carries a `Raw` op. These fixtures pin
that behaviour so it is observable and testable, and give a home to grow real
support (each names the intended test below).

## Fixtures and intended tests

| fixture | construct (real source in the wild) | intended test |
| ------- | ----------------------------------- | ------------- |
| `ldctrl_compare_rel_mem.app.xml` | `<LdCtrlCompareRelMem InlineData Mask Invert ObjIdx Offset Size>` — a relative-memory verify op. Seen in MDT BE-GTSx6Tx (07B0) and MDT JTA blind push button (07B0); **caused a `plan_flash` refusal** in the sweep because it parses as `LoadOp::Raw`. | In `bussard-ets`: assert `parse_application_program` yields a `LoadOp::Raw{name:"LdCtrlCompareRelMem",..}` preserving the attrs. In `bussard-download`: assert `plan_flash` returns `PlanError::UnsupportedOp` naming `LdCtrlCompareRelMem` (until a typed `CompareRelMem` variant + lowering exists, then flip to `Ok`). |
| `ldctrl_compare_mem.app.xml` | `<LdCtrlCompareMem Address Size InlineData>` — absolute-memory verify. Seen on System-7 (0705/0701) apps. | Parse → `LoadOp::Raw{name:"LdCtrlCompareMem"}`; documents the absolute-memory verify shape. |
| `ldctrl_task_ctrl2.app.xml` | `<LdCtrlTaskCtrl2 LsmIdx Callback Address Seg0 Seg1>` — task-control variant 2 (RF / coupler masks 2705/27B0). | Parse → `LoadOp::TaskCtrl2` (issue #527); sibling of `TaskCtrl1`. |
| `ldctrl_task_ptr.app.xml` | `<LdCtrlTaskPtr LsmIdx InitPtr SavePtr SerialPtr>` — task-pointer setup (RF masks). | Parse → `LoadOp::TaskPtr` (issue #527). |
| `ldctrl_declare_prop_desc.app.xml` | `<LdCtrlDeclarePropDesc ObjIdx PropId PropType MaxElements ReadAccess WriteAccess Writable>` — declare a property descriptor before writing it (mask 2920 / System-B-like couplers). | Parse → `LoadOp::Raw{name:"LdCtrlDeclarePropDesc"}`. |
| `ldctrl_declare_prop_desc_and_delay.app.xml` | `<LdCtrlDelay MilliSeconds>` — an inter-step delay (35 corpus applications, 200 ms before `LdCtrlRestart`), next to a `LdCtrlDeclarePropDesc`. | Parse → `LoadOp::Delay{milliseconds}` (issue #615); the planners lower it to `FlashStep::Delay`. |
| `other_param_types.app.xml` | one parameter each of `TypeColor Space="RGB"`, `TypeTime SizeInBit Unit`, `TypeIPAddress AddressType`, `TypePicture RefId`, `TypeRawData MaxSize` — the five non-int/enum/text/float/none types the sweep found. | In `bussard-ets`: assert each maps to `ParameterType::Other{kind, size_bits}` with the right `kind`, and none is dropped. (Verified: the parser maps them to `Color{space: Rgb}` (its own type since #616), `Other:TypeTime(bits=16)`, `Other:TypeIPAddress`, `Other:TypePicture`, `Other:TypeRawData`.) |
| `dynamic_tree.app.xml` | Dynamic-section containers: a `<Channel Number TextParameterRefId>`, nested `<ParameterBlock>`s (one titled by `ParamRefId`), a parameter with one ref in a `<when>` that is not taken and one in the taken branch, a parameter with two shown refs, a `<ModuleDef>` channel instantiated twice (`M-2` before `M-1`), a `<ComObjectRef TextParameterRefId>`, `<ParameterRef Text>` overrides and an `<Assign>`-only parameter. Application `A-00D1-…`. Shape seen in Jung and ABB applications. | `tests/it/dynamic_tree.rs`: container parse, transparency of the containers for `evaluate_dynamic`, block paths, module ordinals, `visible_parameter_refs`, label substitution. |

The `UnresolvableImage` parameter-image blocker gets its own fixture next to the
image builder it exercises: **`crates/bussard-prod/tests/fixtures/enum_default_not_a_member.app.xml`**
(see that dir's README). That is the real Zennio Z40/Z70 refusal cause — an enum
parameter whose default value is not a declared member — which the sweep pinned
down (not the raw-data size, as first suspected).

All ids use manufacturer `M-00FA` and application `A-0001-…`, the same fake
namespace the existing `knxprod.rs` fixture uses, so they cannot collide with a
real product. Masks are set to `MV-07B0` where the intent is to reach the flash
planner (which gates on System B), and to the real family otherwise.
