- The pre-flight of a loaded System 7 device now reads the resident
  application's id, `PID_PROGRAM_VERSION` of the application object (KNX 6
  Profiles Annex A.2.6), within one second (#481). An id that names another
  application refuses `flash`, `apply` and `plan` by that id; a matching id,
  or a device that does not answer, leaves the decision to the code sample as
  before. The read writes nothing and changes no image.
