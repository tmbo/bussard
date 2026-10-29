- A full `flash` of a bus device with a KNX IP interface built in (an
  application that declares tunnelling addresses, such as the Zennio ALLinBOX
  family or the COMIP2) now writes its KNXnet/IP parameter object after the
  application, as ETS does: installation id, routing multicast address and
  TTL, friendly name, assignment method and tunnel addresses from the device
  file's `[knxnet]` table, each read back (#455). A device file without the
  table, or without one of the values, is refused before anything is written;
  a static assignment is refused until a capture shows what ETS writes for
  one. The ETS sweep rows of the five ALLinBOX and the COMIP2 captures compare
  their property writes `props=identical`.
