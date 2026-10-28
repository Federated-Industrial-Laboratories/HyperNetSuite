// SPDX-License-Identifier: MIT
// Fresh reads have an independent nonce and never occupy an ordinary operation stream.
use super::*;
use crate::{
    authority_local_transport::{CertifiedReply, HistoryEvidence, LocalControl},
    authority_read::{self as read, Query},
};

/// One pre-handoff caller deadline and at most one replacement certified read.
pub(crate) struct RetryBudget {
    deadline: u64,
    reissued: bool,
    cancelled: Box<dyn Fn() -> bool + Send>,
}
impl RetryBudget {
    pub(crate) fn new(deadline: u64, cancelled: impl Fn() -> bool + Send + 'static) -> Self {
        Self {
            deadline,
            reissued: false,
            cancelled: Box::new(cancelled),
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        ensure!(
            !(self.cancelled)() && !crate::private_route_client::cancelled(),
            "application preparation was cancelled"
        );
        remaining(self.deadline)?;
        Ok(())
    }
    pub(crate) fn clock(
        &self,
        mut sample: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<ClockHealth> {
        loop {
            self.check()?;
            match sample() {
                Err(error) if error.is::<crate::authority_clock::ObservationExpired>() => {
                    self.check()?;
                    std::thread::sleep(std::time::Duration::from_millis(
                        remaining(self.deadline)?.min(25),
                    ));
                }
                result => {
                    self.check()?;
                    return result;
                }
            }
        }
    }
    pub(crate) fn run<T>(&mut self, mut read: impl FnMut(&Self) -> Result<T>) -> Result<T> {
        self.check()?;
        let value = match read(self) {
            Ok(value) => value,
            Err(error) => {
                if self.reissued
                    || !error.is::<crate::authority_floor::ReadExpired>()
                    || self.check().is_err()
                    || !remaining(self.deadline).is_ok_and(|left| left >= DURATION)
                {
                    return Err(error);
                }
                self.reissued = true;
                read(self)?
            }
        };
        self.check()?;
        Ok(value)
    }
}

pub(crate) struct Exchange {
    pub request: Vec<u8>,
    pub challenge: Vec<u8>,
    pub reply: CertifiedReply,
    pub evidence: HistoryEvidence,
    pub deadline: u64,
    pub control: LocalControl,
}

#[cfg(test)]
#[path = "AuthorityReadClientTests.rs"]
pub(crate) mod tests;

#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange(
    query: Query,
    path: &Path,
    signer: &SigningKey,
    store: &Store,
    session: &mut Session,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<Exchange> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        store.resume_ordinary()?.is_none() && store.resume_fence()?.is_none(),
        "reconcile the exact pending operation before a fresh read"
    );
    // Admission and cold ancestry preparation precede the finite challenge interval.
    let control = LocalControl::prepare_authority(path, store)?;
    let nonce = random_id()?;
    let request = read::Request::sign(
        store.descriptor().scope(),
        signer,
        signer.verifying_key().to_bytes(),
        nonce,
        store.prefix().height(),
        query,
    )?;
    let health = clock()?;
    let issued = health.observe()?;
    let challenge = session.issue_read(&request, signer, nonce, DURATION, health)?;
    let deadline = issued
        .boot_ms
        .checked_add(DURATION)
        .context("fresh read deadline overflow")?;
    let result = crate::authority_local_transport::exchange_read(
        store.descriptor(),
        &request,
        &challenge,
        deadline,
        &control,
        store.prefix(),
        store.tree_head(),
        clock,
    );
    match result {
        Ok((reply, evidence)) => Ok(Exchange {
            request,
            challenge,
            reply,
            evidence,
            deadline,
            control,
        }),
        Err(error) => {
            session.discard(&challenge)?;
            Err(error)
        }
    }
}
