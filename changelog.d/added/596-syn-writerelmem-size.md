- The synthetic product `syn-writerelmem-size` ("Short quill writer",
  `NEST-QUILL`, #604 row 23) allocates and writes 128 octets of a 256-octet
  parameter segment (`LdCtrlRelSegment` and `LdCtrlWriteRelMem Size` 128),
  the shape of #564, captured with ETS: ETS writes 128 octets and the row is
  identical, a regression row for the #564 fix.
