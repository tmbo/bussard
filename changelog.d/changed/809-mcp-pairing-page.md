- `knx_enroll_certificates` opens a pairing page in your browser (#809): served
  by the MCP server on 127.0.0.1 under a random path, it shows the session
  code, a QR code of the phone link and the certificates as they arrive. Chat
  apps without URL elicitation can now enrol certificates; the link, the code
  and the page's address never appear in a tool result. Over SSH or without a
  display the tool refuses and points at `bussard keys enroll`.
