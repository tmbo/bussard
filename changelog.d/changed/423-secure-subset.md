- Internal (ETS sweep): the KNX Data Secure variant runs a representative
  subset with `secure.py run --representative` (`tools/ets-sweep/secure-subset.json`,
  19 applications covering masks, TP devices, tunnelling devices and IP
  interfaces, manufacturers, object counts and key table capacities, all with
  an identical plain oracle row), and `oracle.py --variant secure` compares
  each secure capture with its keyring and a key store imported from it (#423).
