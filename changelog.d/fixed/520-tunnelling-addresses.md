- `interface secure on` now reads the interface's tunnelling addresses
  (PID_TUNNELLING_ADDRESSES, PID 79) before it writes the tunnelling users,
  and points each user's index into that table, as KNX IP Secure 3/8/9
  §2.3.1.8.3 requires; it wrote the `[knxnet] tunnels` slot instead, which is
  only right when PID 79 lists the slots in order. A tunnel address the
  interface does not use for tunnelling is refused before any write, and an
  interface without PID 79 keeps the slot order with a note. knx-sim serves
  PID 78 and PID 79 and resolves the users through them (#520).
