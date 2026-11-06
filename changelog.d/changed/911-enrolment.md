- Certificate enrolment is in one place: one loopback server and one page
  shell behind the pairing page, the password form and `--local`, one
  session status shared by `knx_enroll_status` and the pairing page, and one
  end sentence. `bussard keys enroll` now ends with the same sentence as the
  chat ("Finished on the phone.") instead of "Session closed (...)", and its
  `--json` `end` event carries that sentence (#911).
