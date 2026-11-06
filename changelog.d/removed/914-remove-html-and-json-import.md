- `bussard doc --format html` and the `html` format of the MCP `knx_export`
  `doc` export: the handover documentation is Markdown only, and `bussard doc`
  has no `--format` flag (#914).
- `bussard import --from-json` and the xknxproject `.json` dump as an import,
  `init`, `diff`, `knx_setup` or `knx_import_file` input: import the ETS
  `.knxproj` instead (#914).
