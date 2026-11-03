- The KNX Secure device certificate check is plain CRC-4 (x^4 + x + 1, not
  reflected), confirmed on real labels, instead of CRC-4/ITU. Real labels no
  longer show a check mismatch. A label whose check does not match is now
  `invalid` in `keys add-certificate`, `keys enroll` and the enrolment page,
  which no longer offers "Send anyway" (#201).
