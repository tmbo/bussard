- Internal (offline oracle): `knxtrace statediff`, the device-state
  comparison of a `run=apply` or `run=params` row, also compares the final
  value of every interface-object property element either side wrote in the
  step, so the parameter-only download of a program whose parameters all live
  in properties is compared at all (it writes no memory) (#944).
