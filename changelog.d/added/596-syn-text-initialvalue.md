- Synthetic product `syn-text-initialvalue` (Nest nameplate, `NEST-NAME`):
  `syn-minimal` with `TextParameterEncoding="utf-8"` and a text parameter
  whose de-DE `InitialValue` translation differs from its default, captured
  with ETS in the sweep's German project (#604 row 24): ETS writes the
  translated text in UTF-8, and so does bussard (regression row for #473).
  The generator renders `InitialValue` and its translations.
