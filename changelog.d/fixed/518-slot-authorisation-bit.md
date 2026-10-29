- The tunnelling-slot status bit 1, read outside a KNXnet/IP Secure session,
  means "no authorisation required" (KNXnet/IP Core 3/8/2 §7.5.4.8), not
  "this client is authorised". `TunnelSlot::authorized` is now
  `authorisation_required`, and the live `knx_audit` reports each slot's
  `authorisation_required` with an `access` of `needs tunnelling credentials`
  or `open`, instead of `authorized: false` on every slot of a secure
  interface (#518).
