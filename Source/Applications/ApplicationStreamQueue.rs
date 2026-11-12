// SPDX-License-Identifier: MIT
// One bounded actor queue gives preparation and cleanup fair turns without sharing the requester.
use super::Job;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{RecvTimeoutError, SendError, TrySendError},
    },
    time::{Duration, Instant},
};

const CAPACITY: usize = 16;

struct State {
    jobs: VecDeque<Job>,
    preparation_turn: bool,
    senders: usize,
    receiver: bool,
}
struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    space: Condvar,
}
pub(super) struct Sender(Arc<Shared>);
pub(super) struct Receiver(Arc<Shared>);

pub(super) fn channel() -> (Sender, Receiver) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            jobs: VecDeque::new(),
            preparation_turn: true,
            senders: 1,
            receiver: true,
        }),
        ready: Condvar::new(),
        space: Condvar::new(),
    });
    (Sender(shared.clone()), Receiver(shared))
}

impl Sender {
    pub fn try_send(&self, job: Job) -> Result<(), TrySendError<()>> {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(TrySendError::Disconnected(())),
        };
        if !state.receiver {
            return Err(TrySendError::Disconnected(()));
        }
        if state.jobs.len() == CAPACITY {
            return Err(TrySendError::Full(()));
        }
        state.jobs.push_back(job);
        self.0.ready.notify_one();
        Ok(())
    }

    pub fn send(&self, job: Job) -> Result<(), SendError<()>> {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(SendError(())),
        };
        while state.receiver && state.jobs.len() == CAPACITY {
            state = match self.0.space.wait(state) {
                Ok(state) => state,
                Err(_) => return Err(SendError(())),
            };
        }
        if !state.receiver {
            return Err(SendError(()));
        }
        state.jobs.push_back(job);
        self.0.ready.notify_one();
        Ok(())
    }
}

impl Clone for Sender {
    fn clone(&self) -> Self {
        self.0
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .senders += 1;
        Self(self.0.clone())
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .senders -= 1;
        self.0.ready.notify_one();
    }
}

impl Receiver {
    #[cfg(test)]
    pub fn recv(&self) -> Result<Job, RecvTimeoutError> {
        self.receive(None)
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Job, RecvTimeoutError> {
        self.receive(Some(Instant::now() + timeout))
    }
    fn receive(&self, deadline: Option<Instant>) -> Result<Job, RecvTimeoutError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| RecvTimeoutError::Disconnected)?;
        loop {
            if !state.jobs.is_empty() {
                let index = state
                    .jobs
                    .iter()
                    .position(|job| matches!(job, Job::Plan(..)) == state.preparation_turn)
                    .unwrap_or(0);
                let job = state.jobs.remove(index).expect("selected queued job");
                state.preparation_turn = !matches!(job, Job::Plan(..));
                self.0.space.notify_one();
                return Ok(job);
            }
            if state.senders == 0 {
                return Err(RecvTimeoutError::Disconnected);
            }
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or(RecvTimeoutError::Timeout)?;
                    self.0
                        .ready
                        .wait_timeout(state, remaining)
                        .map_err(|_| RecvTimeoutError::Disconnected)?
                        .0
                }
                None => self
                    .0
                    .ready
                    .wait(state)
                    .map_err(|_| RecvTimeoutError::Disconnected)?,
            };
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let jobs = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.receiver = false;
            std::mem::take(&mut state.jobs)
        };
        self.0.space.notify_all();
        // Release queued reply channels outside the queue lock.
        drop(jobs);
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamQueueTests.rs"]
mod tests;
