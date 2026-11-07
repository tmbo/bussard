- Every flow in `bussard-service` reports through one progress and prompt
  vocabulary (#910): a `ProgressSink` of `Event`s (phase, step, note, wait,
  download progress, finished) and a `Prompt` for the write, download and
  conflict questions. The setup `Output`, `DownloadPrompt` and
  `ConflictPrompt`, the assign `WaitEvent`, the line `LineNote` and the IP
  Secure progress callback are gone. The CLI implements both once
  (`progress::Terminal`, `confirm::Answers`), the MCP server once (the job
  table's `JobSink`). What the commands print and the job status keys are
  unchanged.
