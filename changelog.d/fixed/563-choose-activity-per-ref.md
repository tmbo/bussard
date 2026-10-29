- A `<choose>` on a `ParameterRef` that is not itself shown selects no branch,
  even when another ref of the same parameter or a `<Union>` sibling is shown, as
  in ETS (#563). The ABB / Busch-Jaeger Switching Inputs 2.2 no longer writes a
  hidden "send group feedback" default, and the Busch-Jaeger fan coil, valve drive
  and ABB Caldion programs no longer enable the objects ETS leaves out.
