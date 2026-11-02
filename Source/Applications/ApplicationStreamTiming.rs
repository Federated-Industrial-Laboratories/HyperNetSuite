// SPDX-License-Identifier: MIT
// Finite, content-free timing samples distinguish companion queue wait from authority work.
use std::{
    io::{self, Write},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    time::Instant,
};

static PLANS: AtomicU64 = AtomicU64::new(0);
static CLEANUPS: AtomicU64 = AtomicU64::new(0);
static OUTPUT: OnceLock<Option<SyncSender<Vec<u8>>>> = OnceLock::new();

pub(super) fn start() {
    OUTPUT.get_or_init(|| writer(io::stderr()));
}

fn writer(mut output: impl Write + Send + 'static) -> Option<SyncSender<Vec<u8>>> {
    let (send, receive) = mpsc::sync_channel::<Vec<u8>>(64);
    std::thread::Builder::new()
        .name("application-timing".into())
        .spawn(move || {
            while let Ok(record) = receive.recv() {
                if output.write_all(&record).is_err() {
                    break;
                }
            }
        })
        .ok()?;
    Some(send)
}

fn submit(send: &SyncSender<Vec<u8>>, record: Vec<u8>) {
    if record.len() < 256 {
        let _ = send.try_send(record);
    }
}

#[derive(Clone, Copy)]
pub(super) struct Timing {
    sample: Option<u64>,
    class: &'static str,
    deadline: u64,
    started: Instant,
}

impl Timing {
    fn new(counter: &AtomicU64, maximum: u64, class: &'static str, deadline: u64) -> Self {
        let sample = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < maximum).then_some(n + 1)
            })
            .ok()
            .map(|n| n + 1);
        Self {
            sample,
            class,
            deadline,
            started: Instant::now(),
        }
    }

    pub fn plan(deadline: u64) -> Self {
        Self::new(&PLANS, 64, "Preparation", deadline)
    }

    pub fn cleanup(deadline: u64) -> Self {
        Self::new(&CLEANUPS, 16, "Cleanup", deadline)
    }

    fn write(&self, output: &mut impl Write, boot: u64, phase: &'static str, state: &'static str) {
        if let Some(sample) = self.sample {
            let _ = writeln!(
                output,
                "ApplicationTiming class={} sample={} phase={} state={} bootMs={} elapsedMs={} deadlineBootMs={}",
                self.class,
                sample,
                phase,
                state,
                boot,
                self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                self.deadline,
            );
        }
    }

    pub fn event(&self, phase: &'static str, state: &'static str) {
        if self.sample.is_some()
            && let Ok(boot) = crate::authority_challenge::boot_time_ms()
        {
            let mut record = Vec::with_capacity(256);
            self.write(&mut record, boot, phase, state);
            if let Some(Some(send)) = OUTPUT.get() {
                submit(send, record);
            }
        }
    }

    pub fn run<T, E>(
        &self,
        phase: &'static str,
        work: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.event(phase, "Begin");
        let result = work();
        self.event(phase, if result.is_ok() { "Complete" } else { "Failed" });
        result
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamTimingTests.rs"]
mod tests;
