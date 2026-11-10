- Internal (ETS sweep): the links variant runs a representative subset with
  `defaults.py --variant links --representative` (`tools/ets-sweep/links-subset.json`,
  a greedy cover of masks, table layouts, Data Secure, object counts and sizes,
  modules, download plugins and difficult products), and the driver makes all
  links of a device from one opened object table, polling for each dialog
  state instead of fixed pauses (#478).
