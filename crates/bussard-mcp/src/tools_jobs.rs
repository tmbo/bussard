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
use serde_json::json;

use crate::jobs::{JobStatus, JobTable};
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
    // `knx_job_status`.
    #[doc = include_str!("../guidance/tools/knx_job_status.md")]
    #[tool]
    async fn knx_job_status(
        &self,
        Parameters(args): Parameters<JobStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let job = args.job.trim();
        let model = state.model.current();
        let value = job_status(&state.jobs, &state.dir, job)
            .map(|status| status.chat(&model))
            .unwrap_or_else(|| {
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

/// `knx_job_status`'s body: the job's status as the table reports it.
/// `None` when neither the session nor a record under `dir` knows `job`.
fn job_status(jobs: &JobTable, dir: &Path, job: &str) -> Option<JobStatus> {
    jobs.status(dir, job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobKind, Subject};
    use bussard_model::IndividualAddress;
    use serde_json::Value;

    #[test]
    fn test_job_status_carries_step_question_done_and_result() -> Result<(), String> {
        let jobs = JobTable::new();
        let dir = Path::new("/nonexistent");
        let ia: IndividualAddress = "1.1.42".parse().map_err(|_| "address".to_string())?;
        let id = jobs.claim(JobKind::Apply, Subject::Device(ia))?.id;

        let status = |jobs: &JobTable| -> Result<Value, String> {
            job_status(jobs, dir, &id)
                .ok_or("job not found")
                .and_then(|s| serde_json::to_value(s).map_err(|_| "serialise"))
                .map_err(str::to_string)
        };
        let running = status(&jobs)?;
        assert_eq!(running["done"], false, "{running}");
        assert_eq!(running["question"], Value::Null, "{running}");
        assert!(running["step"].is_string(), "{running}");
        assert_eq!(running["result"], Value::Null, "{running}");

        jobs.step(&id, "press_button");
        jobs.ask(
            &id,
            Some("Press the programming button on the new device.".into()),
        );
        let waiting = status(&jobs)?;
        assert_eq!(waiting["step"], "press_button", "{waiting}");
        assert_eq!(
            waiting["question"], "Press the programming button on the new device.",
            "{waiting}"
        );

        jobs.finish(&id, json!({"ok": true}));
        let done = status(&jobs)?;
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
