//! `knx_job_status`: one job of the server's job table, in every tier
//! (issue #746).
//!
//! Every long operation runs as a job of [`crate::jobs::JobTable`], so a
//! call that may outlast a client's 60 s cut answers with a job id. This
//! tool reads any job: its `step`, the `question` it waits on (what the
//! human must do or answer, `null` when none), `done` and, once done,
//! `result`. It reads only the job table and the job records under
//! `.bussard/history`, never the bus, so it is registered in every tier,
//! `--passive` and `--no-model-edits` included. `knx_apply_status` stays
//! registered in the programming tier with its old payload.

use std::path::Path;

use crate::args::Parameters;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::jobs::JobTable;
use crate::server::BussardMcp;

/// Arguments for `knx_job_status`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JobStatusArgs {
    /// The `job` id a tool returned with `started: true`.
    pub job: String,
}

// `pub(crate)`: the router is combined in `BussardMcp::new`.
#[tool_router(router = jobs_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_job_status`.
    #[tool(
        description = "Report ONE job of this server, of any tier: a tool that may run longer \
        than a client allows answers `started: true` with a `job` id, and this reads it. \
        Returns `job`, `kind`, `state` (running, done, or interrupted when the server stopped \
        mid-job), `done`, the current `step`, `question` (what the human must do or answer \
        before the job goes on, such as pressing a device's programming button; null when \
        none: relay it word for word, then keep polling), `progress` and, once done, `result`: \
        exactly what the starting tool would have returned inline. Follow `next_step`. Reads \
        only the server's job table and the job records under .bussard/history; never touches \
        the bus. Poll every few seconds while `done` is false."
    )]
    async fn knx_job_status(
        &self,
        Parameters(args): Parameters<JobStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let job = args.job.trim();
        let value = job_status(&state.jobs, &state.dir, job).unwrap_or_else(|| {
            json!({
                "ok": false,
                "refused": true,
                "job": job,
                "reason": format!(
                    "no job {job:?} in this session or under .bussard/history; a job id comes \
                     from a tool that answered `started: true`"
                ),
            })
        });
        Ok(CallToolResult::structured(value))
    }
}

/// `knx_job_status`'s body: the job's status as the table reports it, with
/// `question` always present (`null` when the job waits on nothing).
/// `None` when neither the session nor a record under `dir` knows `job`.
fn job_status(jobs: &JobTable, dir: &Path, job: &str) -> Option<Value> {
    let mut status = jobs.status(dir, job)?;
    if let Some(map) = status.as_object_mut() {
        map.entry("question").or_insert(Value::Null);
    }
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobKind, Subject};
    use bussard_model::IndividualAddress;

    #[test]
    fn test_job_status_carries_step_question_done_and_result() -> Result<(), String> {
        let jobs = JobTable::new();
        let dir = Path::new("/nonexistent");
        let ia: IndividualAddress = "1.1.42".parse().map_err(|_| "address".to_string())?;
        let id = jobs.claim(JobKind::Apply, Subject::Device(ia))?.id;

        let running = job_status(&jobs, dir, &id).ok_or("job not found")?;
        assert_eq!(running["done"], false, "{running}");
        assert_eq!(running["question"], Value::Null, "{running}");
        assert!(running["step"].is_string(), "{running}");
        assert_eq!(running["result"], Value::Null, "{running}");

        jobs.step(&id, "press_button");
        jobs.ask(
            &id,
            Some("Press the programming button on the new device.".into()),
        );
        let waiting = job_status(&jobs, dir, &id).ok_or("job not found")?;
        assert_eq!(waiting["step"], "press_button", "{waiting}");
        assert_eq!(
            waiting["question"], "Press the programming button on the new device.",
            "{waiting}"
        );

        jobs.finish(&id, json!({"ok": true}));
        let done = job_status(&jobs, dir, &id).ok_or("job not found")?;
        assert_eq!(done["done"], true, "{done}");
        assert_eq!(done["question"], Value::Null, "{done}");
        assert_eq!(done["result"]["ok"], true, "{done}");
        Ok(())
    }

    #[test]
    fn test_job_status_unknown_job_is_none() {
        let jobs = JobTable::new();
        assert!(job_status(&jobs, Path::new("/nonexistent"), "apply-0-1.1.9").is_none());
    }
}
