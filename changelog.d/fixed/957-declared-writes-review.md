- A System B property write that names its object by type no longer goes to
  object 0: a program that is not Data Secure enabled writes it at the index
  the device's object list gives the type, a Data Secure enabled one on the
  extended services, as ETS does (#948). Declared property writes take an
  object named by type, are no longer bounded by `MaxElements` or
  `Writable`, and send nothing without a value (#948); their `InlineData` is
  cut only over an all-zero tail and never ends in part of an element, and
  both System B planners share one `Count` rule (#957).
