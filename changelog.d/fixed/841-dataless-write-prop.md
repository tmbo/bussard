- `flash` no longer refuses a load procedure whose property write carries no
  data and writes a property no parameter of the application is stored in
  (the Enertex ViTa presence detector, object type 50001 PID 211). As ETS
  does, it reads that property's description and writes nothing. A write
  whose property a parameter is stored in still needs that value or is
  refused (#841).
