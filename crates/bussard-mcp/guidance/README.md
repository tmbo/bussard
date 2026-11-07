# Assistant guidance

The text the assistant reads from the MCP server, kept as files so it can be
read and reviewed without the Rust around it. The server compiles each file in
with `include_str!`; the bytes of a file are the bytes the assistant gets.

- `tools/<tool_name>.md`: the description of one tool, as `tools/list` returns
  it. `tools/onboarding/` holds the two tools of the setup server that runs
  before a project exists (its `knx_bus_status` says something different).

Rules for every file here:

- One paragraph on one line, no final newline: a newline would become part
  of the text. Write the paragraph as plain sentences; markdown is not
  rendered by every client.
- Every file is referenced by an `include_str!` in `src/`; a test fails on an
  orphan.
