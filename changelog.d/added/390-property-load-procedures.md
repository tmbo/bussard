- `bussard flash` executes the property operations of a load procedure
  (#390): `LdCtrlWriteProp` with its `Count` and `Verify` (a read-back right
  after the write), with the value from `InlineData` or, when the op carries
  none, from the program's property-located parameters as ETS composes it;
  `LdCtrlCompareProp` on an object named by type; and the `<choose>` blocks of
  a load procedure, decided under the device's parameters. An object named by
  type is written with the extended property services, as ETS does, and by
  its index when the device refuses them. The 99 System 7 programs refused on
  `LdCtrlWriteProp` now plan, and a property-only procedure on mask 0021 (the
  Jung IPS 300 SREG KNX IP interface) plans and runs without a load-state
  machine, a factory reset or a security-object step, ending with a read-back
  of every property it wrote. The post-write read-back compares those
  properties too.
