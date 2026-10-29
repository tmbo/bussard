- knx-sim's KNXnet/IP Secure server follows the session state machine of KNX
  IP Secure 3/8/9 §2.2.3.5.2: an unauthenticated session ends after 10 s and
  an idle authenticated one after 60 s (both configurable), a wrapper that
  fails to verify is ignored instead of closing the connection, a wrapped
  keepalive or other frame before authentication gets
  STATUS_UNAUTHENTICATED and a wrapped close gets STATUS_CLOSE, session ids
  are unique and never 0, and a SESSION_REQUEST or SESSION_AUTHENTICATE of
  the wrong length, HPAI or reserved octet is discarded (#521).
