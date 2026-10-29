- `monitor` notes a telegram that every conforming receiver drops (KNX
  03_07_01 §2.4): reserved bits set (`18.001` `45`, `17.001` `C1`), fields out
  of range (hour 24 on `10.001`, month 0 on `11.001`, `19.001` hour 24 with
  non-zero seconds), `5.006` tariff 255 and reserved `20.xxx` codes. The value
  still decodes; the note says the devices will not act on it (#502).
