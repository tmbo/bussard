- Re-flashing the same application compares each object's memory control
  block from entry 1, as the standard numbers the entries and ETS reads them;
  it read element 0, the number of entries, as entry 1. When the device already
  holds the whole download (every object's image, load state and program
  version), nothing is written and the read-back runs; any difference, refusal
  or timeout runs the full download, as ETS does. Before, a partial match sent
  an unload of object 5 alone and a program version write to a loaded object,
  which no capture shows a device accepting (#1128, #1127).
