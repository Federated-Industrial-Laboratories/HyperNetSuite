// SPDX-License-Identifier: Apache-2.0
// Adapted from RelayChat's native hosting resource review; lifetimes remain independently explicit.
use crate::{admission::runtime, trust_validity::End};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::PathBuf};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub memory_bytes_per_role: u64,
    pub state_bytes_per_role: u64,
    pub cpu_quota_per_role: u64,
    pub pids_per_role: u64,
    pub connection_bytes: u64,
    pub connection_seconds: u64,
    pub relay_connections: u64,
    pub endpoint_connections: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Clock {
    pub chronyc: PathBuf,
    pub socket: Option<PathBuf>,
    pub chronyd: Option<PathBuf>,
    #[serde(default = "time_server")]
    pub time_server: String,
}
fn time_server() -> String {
    "time.cloudflare.com".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hrc {
    pub executable: PathBuf,
    pub nickname: String,
    pub motd: String,
    pub agents_enabled: bool,
    pub max_agents_per_operator: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub name: String,
    pub advertised_address: Ipv4Addr,
    pub bind_address: Ipv4Addr,
    pub relay_port: u16,
    pub authority_first_port: u16,
    pub subnet_octet: u8,
    pub same_organisation: bool,
    pub access_end: End,
    pub hosting_end: End,
    pub maximum_participants: u32,
    pub clock: Clock,
    pub resources: Resources,
    pub hrc: Option<Hrc>,
}
impl Configuration {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 96
                && !self.name.chars().any(char::is_control),
            "server name must contain 1 to 96 bytes without controls"
        );
        ensure!(
            self.same_organisation,
            "review this single-organisation hosting topology"
        );
        let ip = self.advertised_address;
        ensure!(
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_link_local()
                && ip.octets()[0] != 0
                && self.bind_address == ip,
            "choose a reachable IPv4 assigned to this host"
        );
        ensure!(
            self.relay_port > 1024
                && self.authority_first_port > 1024
                && self.authority_first_port <= 65532
                && !(self.authority_first_port..=self.authority_first_port + 3)
                    .contains(&self.relay_port)
                && (1..=251).contains(&self.subnet_octet),
            "native ports and subnets must be distinct and unprivileged"
        );
        ensure!(
            (2..=if self.hrc.is_some() { 32 } else { 64 }).contains(&self.maximum_participants),
            "participant capacity must include the owner and fit the selected services"
        );
        for end in [self.access_end, self.hosting_end] {
            ensure!(end != End::At(0), "zero is not a persistent lifetime");
        }
        ensure!(
            self.clock.chronyc.is_absolute(),
            "clock executable must be absolute"
        );
        ensure!(
            self.clock.socket.is_some() != self.clock.chronyd.is_some(),
            "choose an existing time observer socket or a private chronyd observer"
        );
        if let Some(socket) = &self.clock.socket {
            ensure!(socket.is_absolute(), "clock socket must be absolute");
        }
        if let Some(executable) = &self.clock.chronyd {
            ensure!(
                executable.is_absolute(),
                "observer executable must be absolute"
            );
        }
        ensure!(
            !self.clock.time_server.is_empty()
                && self.clock.time_server.len() <= 253
                && self
                    .clock
                    .time_server
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')),
            "invalid authenticated time server name"
        );
        let r = &self.resources;
        ensure!(
            (268_435_456..=8_589_934_592).contains(&r.memory_bytes_per_role)
                && (1_073_741_824..=1_099_511_627_776).contains(&r.state_bytes_per_role)
                && (10_000..=800_000).contains(&r.cpu_quota_per_role)
                && (32..=512).contains(&r.pids_per_role)
                && (1_048_576..=1_073_741_824).contains(&r.connection_bytes)
                && (60..=3600).contains(&r.connection_seconds)
                && (8..=1024).contains(&r.relay_connections)
                && (2..=128).contains(&r.endpoint_connections),
            "native resource settings exceed supported bounds"
        );
        if let Some(hrc) = &self.hrc {
            ensure!(
                hrc.executable.is_absolute(),
                "chat executable must be absolute"
            );
            ensure!(
                !hrc.nickname.trim().is_empty()
                    && hrc.nickname.len() <= 64
                    && hrc.nickname.graphemes(true).count() <= 32
                    && !hrc.nickname.chars().any(char::is_control)
                    && hrc.motd.len() <= 4096
                    && !hrc.motd.chars().any(|c| c.is_control() && c != '\n')
                    && (1..=8).contains(&hrc.max_agents_per_operator),
                "invalid chat owner or Agent settings"
            );
        }
        Ok(())
    }
    pub fn clock_runtime(&self, core: PathBuf) -> runtime::Configuration {
        runtime::Configuration {
            version: 1,
            chronyc: self.clock.chronyc.clone(),
            chronyd: self.clock.chronyd.clone(),
            chrony_socket: self.clock.socket.clone(),
            core: Some(core),
            time_server: self.clock.time_server.clone(),
        }
    }
    pub fn governance_end(&self) -> End {
        self.access_end.max(self.hosting_end)
    }
    pub fn role_count(&self) -> u64 {
        if self.hrc.is_some() { 9 } else { 8 }
    }
}
