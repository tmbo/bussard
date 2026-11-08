- knx-sim answers a frame it refuses as a real device does: the transport
  layer still acknowledges an accepted numbered frame, and a refused property
  read or write (absent object or PID, read-only, missing access, bad length)
  gets the zero-count `A_PropertyValue_Response`. ETS used to repeat the frame
  and report a dead device instead of the refusal (#869).
