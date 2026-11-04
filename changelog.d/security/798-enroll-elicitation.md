- `knx_enroll_certificates` shows the certificate page link and its session
  code to you through your chat app (MCP URL elicitation), never through the
  assistant, so a prompt injection cannot hand you another link (#798). No
  tool result carries the link or the code any more. A chat app that cannot
  show a link that way gets a refusal pointing at `bussard keys enroll`.
