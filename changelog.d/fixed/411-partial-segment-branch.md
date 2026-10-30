- `bussard flash` plans a System B load procedure whose `<choose>` branch
  writes only part of a segment (a keep-data branch, as on the MDT JTA-01
  `A-00A2`) instead of refusing it. As in ETS's download, the taken branch's
  octets are written and the rest of the allocation is kept on the device:
  the plan and `--dump-images` name the gap (`object 4 octets 128..256
  kept`), the MCB CRC over that segment is read but not compared, and the
  parameters placed in the gap are listed as kept on the device by `flash`,
  `plan` and the post-flash read-back, never as a difference (#411).
