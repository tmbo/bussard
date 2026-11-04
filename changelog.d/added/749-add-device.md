- `knx_add_device` adds a new device from chat, the flow of `bussard adopt`
  (#749): it asks the human to press the programming button, identifies the
  device (serial, mask, order number), names the address and the product data
  it would fetch and returns a `plan_digest`; after the human's yes (and a
  separate `download: true` for vendor product data) it writes the address,
  reads the device back at the new address and writes the device file and its
  lock entry. The assign and adopt flows moved into `bussard-service`, so
  `bussard assign`, `bussard adopt` and the tool run the same steps.
