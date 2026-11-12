- The ETS captures of the #1054 session are committed and gated in CI: 19 new
  synthetic oracle rows (parameter sets, parameter-only and link-change
  downloads, Data Secure reload, partial and apply, `syn-relseg-dataless`),
  every row pinned on its operation order (`seq=`), the knx-sim replay over
  them, and golden request streams for the parameter change, the reload and
  the apply of each product captured that way (#1054).
- The offline oracle runs a Data Secure `run=params`/`run=apply` row against
  knx-sim started `activated` from the row's keyring, so such a row is judged
  instead of refused (#1054).
