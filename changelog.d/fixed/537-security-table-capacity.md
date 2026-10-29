- A secured download checks the group key table (PID 53) and the security
  individual address table (PID 54) against the device's capacity before it
  opens anything, and refuses with the counts instead of failing after the
  `Unload` (#537). The capacity comes from the application's
  `MaxSecurityGroupKeyTableEntries` and `MaxSecurityIndividualAddressEntries`,
  which the importer now keeps (product model format 9, `data_secure:`;
  `describe` shows them), else from the property description's maximum element
  count read from the device. knx-sim takes the capacities from its product
  and reports them in the description.
