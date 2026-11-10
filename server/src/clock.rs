use std::sync::atomic::{AtomicI64, Ordering};

/// Source de temps (secondes Unix). Injectable pour tester expirations et TOTP.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// Horloge manipulable, pour les tests.
pub struct MockClock(AtomicI64);

impl MockClock {
    pub fn new(t: i64) -> Self {
        Self(AtomicI64::new(t))
    }
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
