- `knx_replace_device` replaces a dead device from chat, as `bussard replace`
  does (#751): a backup snapshot of the device file and its lock record, the
  press-the-button question, the identity check against the device file and
  the lock, then after one yes the address, the application, the model's
  parameters and links with their read-back, and the record. The flow moved
  into `bussard-service` as a step machine both surfaces run.
