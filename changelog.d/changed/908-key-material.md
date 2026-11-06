- Internal: one model of key material. A `.knxkeys` export and the key store
  `bussard.keys` are read into the same `KeyStore`, there is one keyring
  export type, and the keyring precedence and tunnel credentials are resolved
  in one place in `bussard-service` for the CLI and the MCP server. The signed
  export is byte-identical and no flag, message or `--json` output changes
  (#908).
