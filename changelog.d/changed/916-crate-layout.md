- The workspace has 13 crates instead of 16 (#916): the bus actor is
  `bussard_transport::bus`, `bussard-product` holds the ETS-XML parsers, the
  `.knxprod` reader and the `.knxproj` import (formerly `bussard-ets`,
  `bussard-prod` and half of `bussard-project`), and `bussard-project` keeps
  the key store. The CLI, MCP and viz crates depend on `bussard-service`,
  `bussard-model` and `bussard-product` only, so a flow cannot bypass the
  service layer.
