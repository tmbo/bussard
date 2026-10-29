- `T_Connect`, `T_ACK`, `T_NAK`, `T_Disconnect`, the numbered management
  telegrams and the `A_IndividualAddress_*` broadcasts now go out at system
  priority, as the transport and application layer specify and ETS sends them
  (#506). `Layer4Connection::set_data_priority` changes the priority of the
  numbered data telegrams; group telegrams keep theirs.
