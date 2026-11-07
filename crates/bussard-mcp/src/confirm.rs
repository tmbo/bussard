//! The plan-confirm store (issue #905): every write the server makes after a
//! human's yes presents a digest (or a job id) this session handed out with
//! the question. A [`Store`] remembers what each one was for, for the plan
//! lifetime, bound to its subject (a device, a line, a backup), and answers
//! the one refusal when a digest is unknown, expired or already used. Each
//! digest is built with [`bussard_service::program::plan::Fingerprint`].

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// One entry: what was planned, for whom, and when.
struct Entry<P> {
    /// The subject the plan is bound to, in words (`1.1.4`, `line 1.1`).
    subject: String,
    /// When the plan was handed out.
    created: Instant,
    /// What the write needs from the plan.
    plan: P,
}

/// The plans of one kind this session handed out, by digest (or job id),
/// valid for the plan lifetime and single use.
pub struct Store<P> {
    /// How long a plan stays valid.
    ttl: Duration,
    /// The plans.
    entries: Mutex<HashMap<String, Entry<P>>>,
}

impl<P: Clone> Store<P> {
    /// An empty store whose plans stay valid for `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Store {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How long a plan stays valid.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The plan lifetime in whole minutes, as the refusals say it.
    pub fn ttl_minutes(&self) -> u64 {
        self.ttl.as_secs().div_ceil(60)
    }

    /// When a plan handed out at `now` expires, as RFC 3339.
    pub fn expires_at(&self, now: SystemTime) -> String {
        bussard_monitor::timefmt::to_rfc3339(now + self.ttl)
    }

    /// The entries with the expired ones dropped, recovering from a
    /// poisoned lock (the map holds plain data).
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry<P>>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, e| e.created.elapsed() <= self.ttl);
        entries
    }

    /// Remembers `plan` under `key`, bound to `subject`.
    pub fn insert(&self, key: impl Into<String>, subject: impl Display, plan: P) {
        self.entries().insert(
            key.into(),
            Entry {
                subject: subject.to_string(),
                created: Instant::now(),
                plan,
            },
        );
    }

    /// The fresh plan under `key`, whatever its subject.
    pub fn get(&self, key: &str) -> Option<P> {
        self.entries().get(key).map(|e| e.plan.clone())
    }

    /// The fresh plan under `digest` for `subject`, kept for the write to
    /// [`Store::retire`]; otherwise the refusal: `what` names the plan
    /// (`"restore plan"`), `again` says how to get a new one.
    pub fn fresh(
        &self,
        digest: &str,
        subject: impl Display,
        what: &str,
        again: impl Display,
    ) -> Result<P, String> {
        let subject = subject.to_string();
        match self.entries().get(digest) {
            None => Err(format!(
                "no fresh {what} with digest {digest:?} in this session (plans expire after {} \
                 minute(s) and are single use); {again}",
                self.ttl_minutes()
            )),
            Some(e) if e.subject != subject => Err(format!(
                "{what} {digest} is for {}, not {subject}",
                e.subject
            )),
            Some(e) => Ok(e.plan.clone()),
        }
    }

    /// [`Store::fresh`], and the plan is used up.
    pub fn take(
        &self,
        digest: &str,
        subject: impl Display,
        what: &str,
        again: impl Display,
    ) -> Result<P, String> {
        let plan = self.fresh(digest, subject, what, again)?;
        self.retire(digest);
        Ok(plan)
    }

    /// Drops the plan under `key`: written, or refused because the device
    /// or the model moved.
    pub fn retire(&self, key: &str) {
        self.entries().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_refuses_unknown_other_subject_and_used() -> Result<(), String> {
        let store = Store::new(Duration::from_secs(600));
        store.insert("d", "1.1.4", 7u8);
        let unknown = store.fresh("x", "1.1.4", "plan", "plan again");
        assert!(unknown.is_err_and(|r| r.starts_with("no fresh plan with digest \"x\"")));
        let other = store.fresh("d", "1.1.5", "plan", "plan again");
        assert_eq!(other, Err("plan d is for 1.1.4, not 1.1.5".to_string()));
        assert_eq!(store.take("d", "1.1.4", "plan", "plan again")?, 7);
        assert!(store.get("d").is_none(), "single use");
        Ok(())
    }

    #[test]
    fn test_fresh_refuses_an_expired_plan() {
        let store = Store::new(Duration::ZERO);
        store.insert("d", "1.1.4", ());
        std::thread::sleep(Duration::from_millis(2));
        assert!(store.fresh("d", "1.1.4", "plan", "again").is_err());
    }
}
