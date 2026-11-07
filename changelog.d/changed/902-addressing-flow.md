- `assign`, `adopt`, `replace` and `commission` and the chat tools
  `knx_add_device`, `knx_replace_device` and `knx_commission_line` give a
  device its address through one flow in `bussard-service` (#902): the wait
  for the programming button, the free-address check, the address write, the
  read-back and the programming-mode re-check. `replace` now prints its
  button prompt on stderr, `commission` says "wrote …; verifying" like the
  other commands, and `adopt --product` reports the stored file the way
  `import-product` does.
