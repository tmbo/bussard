- A Data Secure device that was reset to default is recognised: when the
  S-A_Sync under the tool key goes unanswered and the key store holds the
  device's FDSK, bussard tries one Sync under the FDSK and, if it verifies,
  `describe`, `plan`, `apply`, `flash` and `status` (CLI and MCP) say the
  device is back on its factory key and what to do, instead of a generic key
  error; nothing is written under the factory key. `describe` also tries the
  FDSK on a device that refuses plain access before asking for a keyring
  (#532).
