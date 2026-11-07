//! The rate limiter of bus reads and writes a long-lived surface shares
//! (the MCP server): a minimum spacing and a concurrency cap.

use std::time::Duration;

use tokio::sync::Mutex;

/// The read rate limiter: enforces a minimum spacing between bus reads and a
/// concurrency cap.
///
/// `last` is a tokio mutex holding the [`Instant`](tokio::time::Instant) of the
/// last read; `permits` is a semaphore bounding concurrent reads.
pub struct ReadLimiter {
    last: Mutex<Option<tokio::time::Instant>>,
    permits: tokio::sync::Semaphore,
    min_interval: Duration,
}

impl ReadLimiter {
    /// Creates a limiter with the given spacing and concurrency cap.
    pub fn new(min_interval: Duration, max_concurrent: usize) -> Self {
        ReadLimiter {
            last: Mutex::new(None),
            permits: tokio::sync::Semaphore::new(max_concurrent.max(1)),
            min_interval,
        }
    }

    /// Acquires the right to perform one bus read, sleeping until the minimum
    /// interval since the previous read has elapsed. The returned permit must be
    /// held for the duration of the read.
    ///
    /// `None` only if the semaphore were closed, which it never is.
    pub async fn acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        // Semaphore first (concurrency cap), then spacing (rate).
        let permit = self.permits.acquire().await.ok();
        let mut last = self.last.lock().await;
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
        }
        *last = Some(tokio::time::Instant::now());
        permit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_limiter_spaces_reads() {
        // A small real interval keeps the test fast while still measurable.
        let limiter = ReadLimiter::new(Duration::from_millis(60), 2);
        let start = std::time::Instant::now();

        // First acquire: no wait.
        {
            let _p = limiter.acquire().await;
        }
        // Second acquire: must wait ~60ms since the first.
        {
            let _p = limiter.acquire().await;
        }
        // Third acquire: another ~60ms.
        {
            let _p = limiter.acquire().await;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(120),
            "three spaced reads should take >= 120ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_read_limiter_caps_concurrency() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let limiter = Arc::new(ReadLimiter::new(Duration::from_millis(0), 2));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..6 {
            let limiter = limiter.clone();
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            handles.push(tokio::spawn(async move {
                let _p = limiter.acquire().await;
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await?;
        }
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "never more than 2 concurrent reads"
        );
        Ok(())
    }
}
