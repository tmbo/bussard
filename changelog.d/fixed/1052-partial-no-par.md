- `flash --parameters-only` and `apply` run the mask's own parameter-only
  load procedure (KNX 3/5/3 §3.9.3.6) for a program whose parameters all live
  in properties, with the application's ops whose `AppliesTo` names `par` or
  that have none. Hager `M-0009_A-E802-13-7620` (no `par` allocation, a
  parameter reset with erase code 5) is no longer refused, and E804/E805 now
  send MergeId 7's trailing write as ETS does (#1038). The read-back covers
  every property the download writes. A procedure that would drop an object's
  segment, or reset more than the parameters, is refused before anything is
  sent. The confirmation says when the procedure resets all parameters first
  (#1052).
