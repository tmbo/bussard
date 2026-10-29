- ETS sweep part 6: `nightly.py` runs the sweep shards, the links variant, the
  oracle over every row, the parity summary and the follow-up drafts in one
  locked run that records the ETS version (launchd agent and cron entry under
  `tools/ets-sweep/schedule/`, install steps in the README); `followups.py`
  drafts, and with `--create` opens, an issue for every identical -> differs
  verdict; a failed run keeps a screenshot, the control trees and the
  driver's trace under `repair/` next to the outcome (#425).
