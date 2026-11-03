- The MCP server keeps one job table for every tier, and `knx_job_status {job}`
  (registered in every tier, `--passive` included) reads any job: its `step`,
  the `question` it waits on, `done` and `result`. `knx_apply_status` keeps
  its name and payload (#746).
