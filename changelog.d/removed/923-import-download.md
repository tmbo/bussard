- `--yes-download` and `--no-download` on `bussard import` and `bussard init`,
  and the `download` argument of the MCP `knx_setup`: a `.knxproj` carries the
  application program of every device it holds (an export without one is
  refused before anything is written), so the import-side download step was
  never reached. `adopt`, `import-product` and `knx_import_file` with
  `order_number` keep their download consent (#923).
