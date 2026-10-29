- Defined negative answers of the application layer are reported as what
  they are (#509): an `A_Memory_Response` with number 0 is a named refusal
  (`MemoryRefused`) where a caller needs the data, an extended-memory return
  code is named (`E_ACCESS_DENIED`, `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH`, ...)
  instead of a verify mismatch or a raw code, a device descriptor answer of
  type 3Fh is "type not supported" and one of another type is no longer read
  as the mask, and an `A_Authorize` level between 0 and the minimum (3 or 15)
  is a grant; only the minimum level is an access denial.
