- A management connection that idled past the device's 6 s transport-layer
  timeout reconnects at the next request (drain, `T_Disconnect`, `T_Connect`,
  the authorize key presented again) instead of meeting the device's
  `T_Disconnect` (#575). The S-A_Sync retry backs off at most 2 s, so no pause
  outlasts that timeout; after a restart it makes seven attempts over about
  32 s (was five over 30 s) (#575). An `A_MemoryExtended_Write` confirmed with
  `E_SUCCESS_WITH_CRC` (01h) is a success whose CRC is compared with the one
  over the written request (#575).
