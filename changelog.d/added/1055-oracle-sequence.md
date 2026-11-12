- The offline oracle compares the order of bussard's state-changing operations
  with ETS's (load-control events, memory writes by segment, property writes,
  function property calls, restarts), after the state comparison's
  normalisations, as `seq=ok(n)` or `seq=differs(first: ...)` next to
  `loadctl=`. A row pins it with `seq=identical`; the reads only one side
  sends are counted in the row's detail, not judged (#1055).
