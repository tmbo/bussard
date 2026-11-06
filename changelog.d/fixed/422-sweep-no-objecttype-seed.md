- The ETS sweep no longer seeds a device property from a parameter that names
  the device object by type: the Schneider M-0009 programs' `HardwareType`
  parameter disagrees with their own hardware-type compare, and ETS refused
  four products as "Device not compatible" (#422).
