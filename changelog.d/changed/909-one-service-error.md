- The service layer has one error type, `ServiceError`, in place of 19
  per-flow wrapper enums; the MCP server turns it into a refusal sentence in
  one place (#909). The device backup and line reconstruction tools now name
  the cause when the source-address check or the output directory fails, as
  the other tools already did.
