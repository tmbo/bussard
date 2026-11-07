<!-- Maintainer reference. The user-facing summary is docs/reference/product-data.md. -->
# The product model file format

A product model describes one application program: its parameters, com-objects and
Dynamic section, reduced to what the views, the validator and the Dynamic evaluator
read. It is `bussard_model::param_model::ProductModel`, built in one step from the
parsed application program (`bussard_product::product_model::product_model`) and stored
as JSON at `<dir>/.bussard/model-cache/<application id>.json` (issue #906). The
directory holds only data bussard regenerates: when a file is missing or of another
format, the next command rebuilds it from the archive in `products/` through the
parsed-product cache, one model per application a device in the lock pins. Nobody
edits it.

The download never reads it: flashing plans from the parsed application program.

A file is a header and the model:

```json
{"header":{"schema":2,"model_format":14,"application":"M-00FA_A-0001-11-ABCD-O000A"},"model":{
  "program_id": "M-00FA_A-0001-11-ABCD-O000A",
  "bus_current_ma": 10,
  "parameters": {
    "P-1": {
      "kind": {"Int": {"min": 0, "max": 100}},
      "default": "75",
      "text": "Threshold",
      "name": "Threshold",
      "refs": ["P-1_R-1", "P-1_R-2"],
      "integer_width": [8, false]
    },
    "P-9": {
      "kind": {"Enum": {"values": [0, 7]}},
      "default": "0",
      "labels": [[0, "Off"], [7, "On"]],
      "enum_values": [
        {"value": 0, "text": "Off", "default_text": "Off"},
        {"value": 7, "text": "On", "default_text": "On"}
      ]
    }
  },
  "parameter_refs": {
    "P-1_R-1": {"parameter": "P-1"},
    "P-1_R-2": {"parameter": "P-1", "value": "50"}
  },
  "com_objects": {
    "0": {"text": "Switch", "function": "On/Off", "dpt": "1.001", "flags": "CRWT"}
  },
  "unions": [{"size_bits": 8, "memory": null, "members": [
    {"parameter": "P-20", "offset": null, "bit_offset": null, "is_default": true},
    {"parameter": "P-21", "offset": null, "bit_offset": 4, "is_default": false}
  ]}],
  "dynamic": [
    {"channel": {"id": "CH-0", "text": "Generic", "number": 0, "nodes": [
      {"block": {"id": "PB-10", "name": "ChannelA", "param_ref": "P-1_R-1", "nodes": [
        {"p": "P-11_R-11"},
        {"choose": {"ref": "P-11_R-11", "when": [
          {"test": "1", "nodes": [{"p": "P-12_R-12"}]},
          {"nodes": [{"o": "O-1_R-1"}]}
        ]}}
      ]}}
    ]}}
  ],
  "module_dynamics": {"MD-1": [{"p": "MD-1_P-1_R-1"}]}
}}
```

The header is written first, so `product_model_is_current` reads only the head of a
file. A file whose `schema`, `model_format` or `application` does not match this build
is not read, and the next command rebuilds it. Most empty, `null` or `false` fields are
left out. All ids are app-relative (the application id prefix dropped).

Field notes:

- `program_id`: the application id. `system_b` is `true` for a System B mask (`xxB0`).
  `bus_current_ma` is the highest `BusCurrent` of the catalogue parts that map to the
  program (the `L002` topology lint totals it per line).
- `parameters`: keyed by app-relative parameter id. `kind` is `Int {min, max, signed}`,
  `Enum {values}`, `Text {len, encoding}` (`len` in bytes, `encoding` the program's
  `TextParameterEncoding`, #401), `Float`, `None` (also an unresolved type),
  `Color {space}` (`RGB`, `RGBW` or `HSV`, #616) or `Other`. `default` is the
  parameter's own `Value`; `initial_value` a text parameter's `InitialValue` in the
  import language (#473), which wins over the `Value`s. `labels` and `enum_values` are an
  enumeration's members in document order, in the import language. `refs` lists the
  parameter's refs; `base_value` is a module parameter's `BaseValue` argument (#126);
  `integer_width` the bits and signedness of an integer or plain enumeration (what a
  shared union memory is read back with); `is_virtual` a parameter with no memory,
  property or union place (#474).
- `parameter_refs`: every `ParameterRef` by app-relative ref id. `value` is the ref's
  `Value` where it differs from the parameter's (or where the parameter's `default`
  would not give it, an empty `Value`): the value a ref has when nothing is stored, the
  one ETS shows and a download writes. `internal` marks a ref whose effective `Access`
  is `None`, which ETS never shows. `text` is the ref's own `Text` where it differs
  from the parameter's (it titles a page whose `ParamRefId` names the ref).
- `com_objects`: keyed by number, the ref with the smallest id when several share one:
  `text`, `function`, `dpt`, `flags` (compact `CRWTUI`) and `priority` (`High`, `Alert`
  or `System`; left out when it is `Low`, #541). `com_object_refs` holds the other refs
  of the Dynamic section, by app-relative ref id, with their own text, function and DPT
  (a "Switch" object that becomes a "Value" object under another setting).
- `data_secure`: an application that declares `IsSecureEnabled` gets its Data Secure
  table capacities, `max_group_key_table_entries`, `max_individual_address_entries` and
  `max_p2p_key_table_entries` (#537). `describe` shows them.
- `unions`: each `<Union>`'s `size_bits` and its members' `parameter`, `offset`,
  `bit_offset` and `is_default`. A reached member's value fills the shared memory; the
  other members read it back.
- `dynamic` and `module_dynamics`: the application's Dynamic section and each module
  definition's (a submodule's keyed by its own id, `MD-1_SM-1`), in
  `bussard_model::dynamic::DynamicNode`'s serde form: one-key maps. `p` and `o` are a
  `<ParameterRefRef>` and a `<ComObjectRefRef>`; `choose` has the controlling `ref` and
  its `when` branches, each with the `test` as ETS writes it (`1`, `1 2`, `!=0`, `<5`;
  the default branch has none) and the branch's `nodes`; `channel` and `block` are a
  `<Channel>` and a `<ParameterBlock>` with their `id`, `name`, `text`, `number`
  (channel), `text_ref` (`TextParameterRefId`), `param_ref` (block) and `nodes`;
  `module` is a `<Module>` with its `id`, `def`, literal `args` and `computed` arguments
  (an `allocator` or a literal `value`, plus an optional `base`, #449); `repeat` a
  `<Repeat>` with its `id`, the `ref` whose value is the count or a literal `count`, and
  `nodes`; `assign` an `<Assign>` with `target` and `source` or `value`. The
  parsed-product cache stores the trees in the same form.
- `allocators` and `argument_allocates`: each `<Allocator>`'s `start` and
  `max_inclusive`, each module argument's `Allocates` (#449).
- `calculations`: the `<ParameterCalculation>`s in document order (#712), each with its
  `id`, `language`, left-to-right script `lr_script`, and `inputs` and `outputs` (a
  `param_ref` with the `alias` the script names it by). The evaluator runs them over the
  model as over the parsed application program, so the views show a computed output
  with the value a download writes.

The ETS pages `bussard device` and `knx_show_device` list are derived from `dynamic`
when the model loads: one per `<ParameterBlock>` and `<Channel>` of the application's
own section, in the order ETS lists them. Which of them a device shows, and every
value, is the Dynamic evaluator's answer over the tree, the same one the download runs.

History: formats 1 to 13 were YAML files under `.bussard/models/`, read back through a
second struct set and cached as this JSON next to them (#339). Format 14 drops the YAML
(#906): the JSON is the model. On the reference installation (22 pinned applications,
debug build) the product-model data under `.bussard/` shrinks from 50 MB of YAML plus
81 MB of JSON to 62 MB of JSON, and rebuilding every model from the parsed-product
cache takes 6.3 s instead of 12.7 s.
