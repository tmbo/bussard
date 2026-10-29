- Load-control names and docs match the KNX Standard: the sim's PID 13
  constant is `PID_PROGRAM_VERSION`, the 0701 LSM record's octet 2 is the
  segment ID, the System 7 AbsSegment fields are `access` and `seg_flags`
  (they were swapped), `PID_MCB_TABLE` is documented as seeded by many
  procedures with the product's access octet, and the System 7 notes describe
  `0xB6EC` as the application program's load state (#482).
