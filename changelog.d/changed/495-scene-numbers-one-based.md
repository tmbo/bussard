- Scene numbers (DPT 17.001, 18.001 and the scenes A/B of 1.022) count from 1,
  as ETS and Home Assistant show them (#495, KNX 03_07_02 §3.19 NOTE 9).
  `write 1/0/7 "scene 3"`, `knx_write_group`, the viz and Home Assistant rules
  send the field 2, where they sent 3; `raw 2` sends the field directly.
  `read` and `monitor` print both, `activate scene 3 (raw 2)`.
