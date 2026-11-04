- `knx_commission_line` commissions a line from chat, the flow of
  `bussard commission` (#753): one yes for the line, then per device it names
  the device to press, checks the pressed device's order number against the
  model, writes the address, reads the device back and returns the label text.
  A different product, no device or several devices pause the job for the
  human's retry, skip or stop. The commission flow moved into
  `bussard-service`, so the CLI and the tool run the same steps; the read-back
  now also fails a device whose serial or mask differs from the one identified.
