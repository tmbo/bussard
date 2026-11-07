- The assistant's manual is markdown (#915): every MCP tool description is
  `crates/bussard-mcp/guidance/tools/<tool>.md`, and the paragraphs of the
  server instructions and of `capabilities` are `guidance/instructions/*.md`
  and `guidance/capabilities/*.md`, compiled in with `include_str!`. The text
  the assistant reads is byte-identical; a test fails on a guidance file no
  code includes. The hints no transport or download error prints moved from
  `bussard-transport` to `bussard_service::guidance`.
