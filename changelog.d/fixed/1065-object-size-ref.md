- `flash` no longer refuses a program whose com-object declares a size without a
  type code (`LegacyVarData`) when every ref of the object states a size that has
  one: the descriptor takes the ref's size (#1065, the Jung fan coil controller
  `A-1111-11-A356`).
