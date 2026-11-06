- The management and service internals are shared once instead of per
  command (#913): one device identity read, one line parser and line walker
  for `scan`, `reconstruct --line`, `backup` and `commission`, one
  millisecond parser for the `BUSSARD_*_MS` test hooks, and one step table
  for the KNXnet/IP Secure switch. `reconstruct --line` now authorizes after
  the descriptor read as `scan` does, `backup --line 1.1.4` reads line 1.1,
  and an unreadable link table reports as a malformed response.
