# Errors

What bussard says when a project file does not parse or does not make sense, and what it says about projects from earlier versions. For anyone fixing a file by hand or reviewing an assistant's edit.

Parse errors keep the TOML parser's caret and message, and add a `help:` line where the raw message misleads.

## Parse errors

The rules, matched on the message and the text around the caret:

| Situation | help |
|---|---|
| `missing key for inline table element` after a line with an unbalanced `{` | the entry on line N is not closed; add `}` before the `,` |
| `missing comma between array elements` with an unclosed `[` above | the array `<name>` opened on line N is never closed; add `]` |
| `missing comma between key-value pairs` right after a `"` inside a string | escape the quote as `\"` or use a literal string `'…'` |
| `invalid literal string, expected '` right after `=` | `<key>` has no value; write `<key> = "…"` or remove it |
| `missing comma between array elements` with a `-` at the caret | TOML arrays have no `-` markers; remove the `-` |
| `string values must be quoted` with curly quotes at the caret | “ ” are not quotes in TOML; use straight `"…"` |
| `duplicate key` | secondary label `first defined here` on the earlier definition |
| `invalid type: floating point` into a string field | `<key>` must be a quoted string: `<key> = "<source text>"` |
| `invalid type: string "true", expected a boolean` | write `<key> = true` |
| `invalid type: string "…", expected a sequence` | write `<key> = ["…"]` |
| `invalid type: string "21", expected u16` | write `<key> = 21` |
| `unknown field` | `did you mean <closest>`, by edit distance over the expected list |

## Semantic errors

A file that parses but contradicts the rest of the project gets a validation diagnostic in the E-code style, with file, line and column. The codes that concern the file format:

| Code | Rule |
|---|---|
| E020 | duplicate group address in `groups.toml` (both lines), duplicate object in a device file |
| E021 | device has channels, parameters or keyed objects but no lock entry |
| E022 | device `product` differs from the lock entry |
| E023 | parameter or object key in a channel that neither the lock nor the product model resolves; lists the channel's keys |
| E024 | object linked to a group address whose main DPT number differs from the object's |
| E025 | `send` on an object without the T flag; `listen` on an object without the W flag |
| E026 | parameter values could not be checked because the product model is missing (warning) |
| E032 | a device's `product_sha256` has no `[[product]]` entry in the lock (warning) |
| E033 | a `[[product]]` entry names a `file` the project folder does not hold (warning) |
| E043 | `[knxnet]` contradicts itself: static without address or netmask, static settings under dhcp, friendly name too long or not Latin-1 |
| E044 | a `[knxnet]` tunnel address twice, or the interface's own |
| E045 | a `[knxnet]` tunnel address off the interface's line |
| E046 | a `[knxnet]` tunnel address that is a device of the project |
| W047 | `[knxnet]` tunnels differ from the key store's tunnelling addresses for the interface (warning) |

A group address a device file mentions but `groups.toml` does not define is a warning during `validate`. `import`, `apply` and the MCP edit tools add it to `groups.toml`, named `<channel name> <object function>` with the object's DPT, and report it as added. Every code, with its severity, is on [Diagnostics](../diagnostics.md).

## Earlier YAML projects

Earlier versions stored the project as YAML: `bussard.yaml`, `groups.yaml`, `links.yaml`, `devices/*.yaml`. bussard does not read those files. A directory that holds only them is refused with a message; re-import the ETS project into an empty directory to get the TOML files.

Product models are generated JSON files under `.bussard/model-cache/` and regenerate from `products/`.

## Related

- [Diagnostics](../diagnostics.md): every validation code and its severity.
- [Project folder](../model-directory.md): strict parsing and how saves keep your formatting.
- [Device files](device-files.md): the keys E021 to E025 check.
