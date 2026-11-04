- In a parameter segment without vendor data, the octets no parameter writes now hold
  the fill byte of the full download's `LdCtrlRelSegment` when it pre-fills the
  segment (`00` on Enertex MeTa², MDT and ekinex DALI gateways), as ETS leaves them,
  instead of `0xFF` (#834).
