- ETS sweep part 7: `defaults.py --variant links` links a few objects before
  each download and `oracle.py --variant links` compares those captures with a
  model carrying the same links; `series.py partial` runs the partial-download
  series (full download with links, a link added, removed, a second address)
  on one representative product per table layout in one sim process, and
  `--oracle` compares each step with `bussard apply` and, for the first
  partial step, `apply --line` (`run=apply-line`) (#478).
