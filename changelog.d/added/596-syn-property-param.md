- Synthetic product `syn-property-param` (Territory marker, `NEST-TERR`):
  `syn-minimal` with a parameter placed by `<Property>` in object 4 PID 201
  and an `LdCtrlWriteProp` without `InlineData` that writes it, captured with
  ETS (#604 row 30): ETS writes `5A` to the property, bussard nothing (#669);
  the row holds `props=differs`. The generator renders `property` placement
  and `LdCtrlWriteProp`; `capture.py` records a property difference in the
  manifest and the row.
