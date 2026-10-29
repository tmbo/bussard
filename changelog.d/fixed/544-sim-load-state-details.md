- knx-sim follows the load state machine transition table (Resources Table
  94): StartLoading in Loading stays Loading, LoadCompleted or an allocation
  in Unloaded stays Unloaded; it refuses PID 5 writes shorter than 10 octets,
  zeroes `PID_TABLE_REFERENCE` on Unload and on a failed allocation (new
  `max_allocation` device option), executes master-reset erase codes 2 to 6
  and 8, and answers error code 3 for a channel number other than 0 (#544).
