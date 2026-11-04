- Certificate enrolment from chat continues by itself when the phone taps
  Finish: `knx_enroll_certificates` keeps the call open until the session
  ends and returns the summary, with progress notifications while it waits
  (`knx_enroll_status` gains `until_end`). The pairing page then says "Done.
  You can close this tab and go back to your chat." and tries to close
  itself.
