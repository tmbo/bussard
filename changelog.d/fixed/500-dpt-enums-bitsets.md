- The 20.xxx enumerations of KNX 03_07_02 §3.21, §4.3 and §6.3 decode to their
  label (`20.105` `03` is `Cool`, reserved codes `Unknown(n)`) and `write`
  takes the label (`cool`); the 21.xxx and 22.xxx bit sets decode to the names
  of their set bits (`21.001` `0A` is `Fault, InAlarm`); `6.020` shows its five
  status fields and the one-hot mode instead of a signed byte (#500).
