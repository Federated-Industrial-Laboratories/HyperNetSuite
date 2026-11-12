// SPDX-License-Identifier: MIT
// External Agents receive independent local keys and current operator consent through the shared join engine.
use super::{client, local, protocol, runtime, saved};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[derive(clap::Subcommand)]
pub enum Command {
    /// Prepare a separately keyed Agent and return the exact operator consent request.
    Prepare {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        hrc_executable: PathBuf,
    },
    /// Complete or resume an Agent after its operator approves the exact proposal.
    Complete {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// List unfinished local Agent proposals without connecting.
    Pending {
        #[arg(long)]
        directory: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    operator: Value,
    rooms: Vec<Value>,
    allow_initiate: bool,
    allow_agent_replies: bool,
    successor: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    version: u8,
    agents: Vec<String>,
}
fn index(parent: &Path) -> Result<Index> {
    let path = parent.join("Agents.json");
    let value: Index = if path.try_exists()? {
        saved::read(&path)?
    } else {
        Index {
            version: 1,
            agents: vec![],
        }
    };
    ensure!(
        value.version == 1
            && value.agents.len() <= 128
            && value.agents.iter().all(|s| protocol::identifier(s)),
        "invalid saved Agent list"
    );
    Ok(value)
}
fn pending_request(directory: &Path) -> Result<Option<Value>> {
    if !directory.join("Server.json").try_exists()? {
        return Ok(None);
    }
    let state: saved::State = saved::read(&directory.join("Server.json"))?;
    if state.installed.is_some() {
        return Ok(None);
    }
    let mut request = state
        .intent
        .and_then(|i| i.hrc)
        .map(|h| h.request)
        .ok_or_else(|| anyhow::anyhow!("saved Agent request absent"))?;
    ensure!(
        request
            .pointer("/classification/kind")
            .and_then(Value::as_str)
            == Some("agent"),
        "saved proposal is not an Agent"
    );
    request
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid Agent request"))?
        .remove("operatorConsent");
    Ok(Some(request))
}
pub fn pending(parent: &Path) -> Result<Value> {
    super::private::directory(parent)?;
    let mut agents = vec![];
    for id in index(parent)?.agents {
        let directory = parent.join("Agents").join(id);
        if let Some(request) = pending_request(&directory)? {
            agents.push(json!({"agentDirectory":directory,"runtimeConfiguration":directory.join("Runtime.json"),"request":request}));
        }
    }
    ensure!(agents.len() <= 8, "pending Agent list exceeds capacity");
    Ok(json!({"status":"PendingAgents","agents":agents}))
}
pub fn wait_clock(runtime: &mut runtime::Runtime, stop: &AtomicBool) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(75);
    while !stop.load(Ordering::Acquire) && Instant::now() < until {
        if runtime.clock_ready()? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    ensure!(
        !stop.load(Ordering::Acquire),
        "join cancelled; local progress retained"
    );
    anyhow::bail!(
        "authenticated local clock is not ready; check time service reachability and retry"
    )
}
fn prepare(
    parent: &Path,
    config: &Path,
    executable: &Path,
    proposal: Proposal,
    stop: &AtomicBool,
) -> Result<Value> {
    runtime::executable(executable)?;
    let configuration = local::configuration(parent, config)?;
    ensure!(
        configuration.core.is_some(),
        "Agent chat requires the installed Core clock observer"
    );
    let session = saved::Session::open(parent)?;
    let state = session.state()?;
    let (profile, _) = local::profiles(parent, &state)?;
    let profile = profile.ok_or_else(|| anyhow::anyhow!("join chat as an operator first"))?;
    let person: Value = saved::read(&profile.join("Profile.json"))?;
    ensure!(
        person.pointer("/registration/account") == Some(&proposal.operator)
            && state.metadata.permissions.agents,
        "this operator cannot add Agents on this server"
    );
    ensure!(
        !proposal.rooms.is_empty() && proposal.rooms.len() <= 16,
        "choose between one and sixteen Agent rooms"
    );
    let root = parent.join("Agents");
    saved::create_directory(&root)?;
    let proposal_value = serde_json::to_value(&proposal)?;
    let mut list = index(parent)?;
    let mut unfinished = 0;
    let mut selected = None;
    for id in &list.agents {
        let directory = root.join(id);
        let completed = directory.join("Server.json").try_exists()?
            && saved::read::<saved::State>(&directory.join("Server.json"))?
                .installed
                .is_some();
        if !completed {
            unfinished += 1;
            if saved::read::<Value>(&directory.join("Proposal.json"))? == proposal_value {
                selected = Some(directory);
            }
        }
    }
    let directory = if let Some(directory) = selected {
        directory
    } else {
        ensure!(
            unfinished < 8 && list.agents.len() < 128,
            "local Agent proposal capacity reached"
        );
        let id = crate::random_hex::<32>();
        let directory = root.join(&id);
        saved::create_directory(&directory)?;
        saved::replace(&directory.join("Proposal.json"), &proposal)?;
        saved::replace(&directory.join("Runtime.json"), &configuration)?;
        // Publish the local proposal before any key or remote operation; retries retain it.
        list.agents.push(id);
        saved::replace(&parent.join("Agents.json"), &list)?;
        directory
    };
    drop(session);
    {
        let _ = saved::Session::open(&directory)?;
    }
    let mut runtime = runtime::Runtime::start(&directory, &configuration, stop)?;
    wait_clock(&mut runtime, stop)?;
    let options = client::HrcOptions {
        executable: executable.into(),
        companion: runtime.ipc.clone(),
        clock: runtime
            .hrc_clock
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed chat clock unavailable"))?,
        classification: json!({"kind":"agent","operator":proposal.operator}),
        rooms: proposal.rooms,
        allow_initiate: proposal.allow_initiate,
        allow_agent_replies: proposal.allow_agent_replies,
        successor: proposal.successor,
    };
    client::run(
        &directory,
        &client::Command::Prepare {
            location: state.location,
            display_name: "External Agent".into(),
            minimum_route: 0,
            hrc: Some(options),
        },
        stop,
    )?;
    let request =
        pending_request(&directory)?.ok_or_else(|| anyhow::anyhow!("Agent is already joined"))?;
    Ok(
        json!({"status":"ConsentRequired","agentDirectory":directory,"runtimeConfiguration":directory.join("Runtime.json"),"request":request}),
    )
}
fn complete(directory: &Path, config: &Path, consent: Value, stop: &AtomicBool) -> Result<Value> {
    let configuration = local::configuration(directory, config)?;
    {
        let session = saved::Session::open(directory)?;
        if session.state()?.installed.is_some() {
            drop(session);
            local::desire(directory, true)?;
            runtime::ensure_running(directory, config, stop)?;
            return local::joined(directory, config);
        }
    }
    let mut runtime = runtime::Runtime::start(directory, &configuration, stop)?;
    wait_clock(&mut runtime, stop)?;
    client::run(directory, &client::Command::Consent { consent }, stop)?;
    let result = client::run(
        directory,
        &client::Command::Connect {
            admission: Some(protocol::Admission::Operator),
        },
        stop,
    )?;
    ensure!(
        result.get("status").and_then(Value::as_str) == Some("Joined"),
        "Agent admission remains incomplete: {}",
        result
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("RetrySameProposal")
    );
    drop(runtime);
    runtime::ensure_running(directory, config, stop)?;
    local::joined(directory, config)
}
pub fn run(command: Command, input: Value, stop: &AtomicBool) -> Result<Value> {
    match command {
        Command::Prepare {
            directory,
            config,
            hrc_executable,
        } => prepare(
            &directory,
            &config,
            &hrc_executable,
            serde_json::from_value(input)?,
            stop,
        ),
        Command::Complete { directory, config } => complete(&directory, &config, input, stop),
        Command::Pending { directory } => pending(&directory),
    }
}
