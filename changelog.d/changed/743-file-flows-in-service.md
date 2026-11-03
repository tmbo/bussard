- The re-import merge, `import-product` and the keyring export moved from the
  CLI into `bussard-service` (`files`), next to the setup pieces they build on,
  so the CLI and the MCP tools run the same functions; the CLI's output is
  unchanged (#743, #744). The MCP SDK's own log events stop at `info` whatever
  `RUST_LOG` says, because at `debug` it logged each request with its raw
  arguments; bussard's own `tools/call` line still logs every call with string
  values redacted.
