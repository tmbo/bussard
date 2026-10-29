- The management connection follows the Style 3 transport layer
  (03_03_04 §5.4.3 with AN210) on its error paths (#507): an out-of-window
  numbered telegram draws a `T_NAK` with its sequence instead of a `T_ACK`,
  only a `T_NAK` for the pending sequence triggers a repeat, giving up after
  the acknowledge timeout, a `T_NAK` or a broken channel sends one
  `T_Disconnect` to a device that holds the connection open, and a negative
  `L_Data.con` for the `T_Connect` fails the connection at once on every
  budget instead of after 4 x 3 s. A wrong-sequence `T_ACK` stays ignored, as
  AN210 amends the table. Healthy sessions send the same frames as before.
