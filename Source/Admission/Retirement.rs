// SPDX-License-Identifier: MIT
// Owner removal disables Home participation first and durably retires exact native claims without deleting evidence.
use super::{
    protocol,
    registrar::Registrar,
    store::{Phase, Removal},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::atomic::AtomicBool};
impl Registrar {
    pub(super) fn remove(&mut self, attempt: &str, stop: &AtomicBool) -> Result<Value> {
        ensure!(protocol::identifier(attempt), "invalid participant claim");
        if self.store.state()?.removal.is_none() {
            let Some(target) = self
                .store
                .state()?
                .claims
                .iter()
                .find(|c| c.intent.attempt == attempt)
                .cloned()
            else {
                return Ok(
                    json!({"status":if self.store.state()?.retirements.iter().any(|r|r.attempt==attempt){"ParticipantRemoved"}else{"ParticipantAbsent"}}),
                );
            };
            let account = target
                .intent
                .hrc
                .as_ref()
                .and_then(|h| h.request.pointer("/identity/account"));
            let targets = self
                .store
                .state()?
                .claims
                .iter()
                .filter(|c| {
                    c.intent.attempt == attempt
                        || account.is_some_and(|account| {
                            c.intent
                                .hrc
                                .as_ref()
                                .and_then(|h| h.request.pointer("/classification/operator"))
                                == Some(account)
                        })
                })
                .map(|c| c.intent.attempt.clone())
                .collect::<Vec<_>>();
            self.store.transact(|s| {
                for claim in &mut s.claims {
                    if targets.contains(&claim.intent.attempt) && claim.phase != Phase::Retired {
                        claim.phase = Phase::Revoking;
                    }
                }
                s.removal = Some(Removal {
                    attempt: attempt.into(),
                    targets,
                    home_complete: target.intent.hrc.is_none(),
                    after: None,
                });
                Ok(())
            })?;
        }
        let removal = self.store.state()?.removal.clone().unwrap();
        ensure!(
            removal.attempt == attempt,
            "finish the current participant removal first"
        );
        if !removal.home_complete {
            let hrc = self
                .config
                .hrc
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Home removal helper absent"))?;
            let action = if removal.after.is_some() {
                json!({"operation":"retiredClaims","claimId":attempt,"after":removal.after})
            } else {
                json!({"operation":"revoke","claimId":attempt})
            };
            let response = hrc.call(action, stop)?;
            let status = response.get("status").and_then(Value::as_str);
            if status == Some("refused")
                && response.get("code").and_then(Value::as_str) == Some("AdmissionClaimAbsent")
            {
                ensure!(
                    removal.after.is_none(),
                    "Home lost a retained removal snapshot"
                );
                self.store.transact(|s| {
                    s.removal.as_mut().unwrap().home_complete = true;
                    Ok(())
                })?;
            } else {
                ensure!(
                    matches!(status, Some("revoked" | "retiredClaims"))
                        && response.get("claimId").and_then(Value::as_str) == Some(attempt),
                    "Home removal is not complete"
                );
                let ids = response
                    .get("affectedClaimIds")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Home removal targets absent"))?;
                ensure!(
                    !ids.is_empty() && ids.len() <= 256,
                    "Home removal page exceeds bound"
                );
                let ids = ids
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .filter(|s| protocol::identifier(s))
                            .map(str::to_owned)
                            .ok_or_else(|| anyhow::anyhow!("invalid Home removal claim"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    ids.windows(2).all(|w| w[0] < w[1])
                        && removal.after.as_ref().is_none_or(|after| ids[0] > *after),
                    "Home removal page is not ordered"
                );
                let after = if status == Some("revoked") {
                    match response.get("moreAffected").and_then(Value::as_bool) {
                        Some(true) => ids.last().cloned(),
                        Some(false) => None,
                        None => anyhow::bail!("Home removal continuation absent"),
                    }
                } else {
                    response
                        .get("next")
                        .filter(|v| !v.is_null())
                        .map(|v| {
                            v.as_str()
                                .filter(|s| Some(*s) == ids.last().map(String::as_str))
                                .map(str::to_owned)
                                .ok_or_else(|| anyhow::anyhow!("Home removal cursor differs"))
                        })
                        .transpose()?
                };
                self.store.transact(|s| {
                    let mut targets = s
                        .removal
                        .as_ref()
                        .unwrap()
                        .targets
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>();
                    for claim in &mut s.claims {
                        if ids.contains(&claim.intent.attempt) {
                            targets.insert(claim.intent.attempt.clone());
                            if claim.phase != Phase::Retired {
                                claim.phase = Phase::Revoking;
                            }
                        }
                    }
                    let removal = s.removal.as_mut().unwrap();
                    removal.targets = targets.into_iter().collect();
                    removal.home_complete = after.is_none();
                    removal.after = after;
                    Ok(())
                })?;
            }
            if !self.store.state()?.removal.as_ref().unwrap().home_complete {
                return Ok(json!({"status":"RemovalPending","phase":"HomeTargets"}));
            }
        }
        let targets = self
            .store
            .state()?
            .removal
            .as_ref()
            .unwrap()
            .targets
            .clone();
        if let Some(claim) = self
            .store
            .state()?
            .claims
            .iter()
            .find(|c| targets.contains(&c.intent.attempt) && c.phase == Phase::Revoking)
            .cloned()
        {
            let binding = if let Some(binding) = claim.native_binding.clone() {
                binding
            } else {
                let native=self.config.native.call(json!({"operation":"challenge","claim":claim.native_claim,"requestDigest":claim.intent_digest,"roles":claim.intent.roles,"applicationBinding":claim.intent.application_binding()?}),stop)?;
                native
                    .get("binding")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("removal pending exact native outcome"))?
            };
            self.store.transact(|s| {
                let target = s
                    .claims
                    .iter_mut()
                    .find(|c| c.native_claim == claim.native_claim)
                    .ok_or_else(|| anyhow::anyhow!("removal claim absent"))?;
                ensure!(
                    target
                        .native_binding
                        .as_ref()
                        .is_none_or(|old| old == &binding),
                    "native removal binding changed"
                );
                target.native_binding = Some(binding.clone());
                Ok(())
            })?;
            let retired = self.config.native.call(
                json!({"operation":"revoke","binding":binding,"reason":"Host removed participant"}),
                stop,
            )?;
            ensure!(
                retired.get("status").and_then(Value::as_str) == Some("retired")
                    && retired.get("binding") == Some(&binding),
                "native removal is not complete"
            );
            let proof = retired
                .get("result")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("native retirement proof absent"))?
                .to_owned();
            self.store
                .transact(|s| s.retire(&claim.native_claim, proof))?;
        }
        let remaining = self
            .store
            .state()?
            .claims
            .iter()
            .filter(|c| targets.contains(&c.intent.attempt) && c.phase == Phase::Revoking)
            .count();
        if remaining == 0 {
            self.store.transact(|s| {
                s.removal = None;
                Ok(())
            })?;
            Ok(json!({"status":"ParticipantRemoved"}))
        } else {
            Ok(json!({"status":"RemovalPending","phase":"NativeGrants","remaining":remaining}))
        }
    }
}
