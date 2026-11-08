- MCP: `knx_plan_device`'s `pending_model_changes` is now a list of sentences
  read from the history (the device's changes since the session last saw it
  hold the project), no longer `[{snapshot, tool, sentences}]` from an
  in-memory ledger. `knx_discard_edits` reads what is pending the same way.
  Internal: a server started on an empty directory is one `BussardMcp` whose
  tool set changes after `knx_setup`, not a second server (#941).
