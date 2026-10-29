- A plain (unwrapped) SESSION_STATUS no longer decides a KNXnet/IP Secure
  handshake or ends a session: it is logged and dropped, since only a wrapped
  one is valid (KNX IP Secure 3/8/9 §2.2.3.9.2). A SECURE_WRAPPER shorter
  than 44 octets is discarded before the MAC check, and SESSION_RESPONSE and
  SESSION_AUTHENTICATE must be exactly 56 and 24 octets (#522).
