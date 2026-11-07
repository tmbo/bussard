- A write to a property an `LdCtrlDeclarePropDesc` declared is sized by its
  `Count` whether or not a parameter is placed in it, is read back after the
  flash, keeps the application-id substitution on PID 13, and accepts
  `PDT_BINARY_INFORMATION`. A write without `Count` is taken as one element
  only when the declaration leaves room for no more; otherwise the plan
  refuses it instead of guessing (#945).
