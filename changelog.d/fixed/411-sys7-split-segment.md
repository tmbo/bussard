- `bussard flash` plans a System 7 load procedure whose `<choose>` branch
  allocates an absolute segment in parts with a parameter placed in the gap
  (the MDT `A-0054-14` and `A-0255-21` with switching times in the device)
  instead of refusing it. As in ETS's download, each part is streamed into
  its allocation and the gap is kept on the device: the plan names it
  (`LSM 3 segment 0x4440 octets 1..3 kept`), and the parameters placed there
  are listed as kept on the device by `flash`, `plan` and the read-back,
  never as a difference (#411).
- `bussard apply` and `bussard flash --parameters-only` refuse a System 7
  parameter change that makes the load procedure allocate the segments
  differently, and ask for a full `bussard flash`: a parameter-only download
  sends no allocation record (#411).
