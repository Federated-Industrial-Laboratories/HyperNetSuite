// SPDX-License-Identifier: Apache-2.0
// Native hosting composes shipped commands under one reviewed configuration and retained owner intent.
#[path = "Activation.rs"]
mod activation;
#[path = "Bootstrap.rs"]
mod bootstrap;
#[path = "Certificates.rs"]
mod certificates;
#[path = "Chat.rs"]
mod chat;
#[path = "Configuration.rs"]
mod configuration;
#[path = "Software.rs"]
mod controller_update;
#[path = "Engine.rs"]
mod engine;
#[path = "Files.rs"]
mod files;
#[path = "Lifecycle.rs"]
mod lifecycle;
#[path = "Operator.rs"]
mod operator;
#[path = "Pages.rs"]
mod pages;
#[path = "Policy.rs"]
mod policy;
#[path = "Preview.rs"]
mod preview;
#[path = "Receiver.rs"]
mod receiver;
#[path = "Services.rs"]
mod services;
#[path = "Units.rs"]
mod units;
use crate::admission::{private, protocol, runtime, saved};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use configuration::Configuration;
use engine::{Host, Installation, Journal};
use serde::Deserialize;
use serde_json::Value;
use std::{
    io::Read,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command as Process,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Release);
}
#[derive(Subcommand)]
pub enum Command {
    /// Review and control a native host with one bounded JSON request.
    Request {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        installation: PathBuf,
        #[arg(long, required = true)]
        json_stdin: bool,
    },
    #[command(hide = true)]
    Permitted {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    Clock {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    Supervise {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    Service {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
    },
    #[command(hide = true)]
    MappedInput {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
    },
    #[command(hide = true)]
    MappedDirectory {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
    },
    #[command(hide = true)]
    MappedRemove {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
    },
    #[command(hide = true)]
    MappedRetire {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        outputs: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    action: Action,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
enum Action {
    Preview {
        configuration: Configuration,
    },
    Create {
        configuration: Configuration,
        #[serde(rename = "reviewDigest")]
        review_digest: String,
    },
    Status,
    Start,
    Stop,
    Withdraw,
    RefreshReader,
    RenewCertificates,
    PreviewSoftware,
    UpdateSoftware {
        #[serde(rename = "reviewDigest")]
        review_digest: String,
    },
}
fn journal(root: &Path) -> Result<Journal> {
    private::directory(root)?;
    let state: Journal = saved::read(&root.join("Hosting.json"))?;
    ensure!(
        state.format == "HyperNetNativeHost/1"
            && protocol::digest_value(&state.configuration)? == state.configuration_digest,
        "native host journal differs"
    );
    state.configuration.validate()?;
    Ok(state)
}
fn permitted(root: &Path) -> Result<Journal> {
    let state = journal(root)?;
    ensure!(
        state.desired_running
            && !state.withdrawn
            && state.configuration.hosting_end.contains(engine::now()?),
        "native host is offline, withdrawn or its finite hosting consent ended"
    );
    Ok(state)
}
fn software(state: &Journal) -> Result<(PathBuf, PathBuf)> {
    let core = PathBuf::from(engine::string(&state.installation, "coreExecutable")?);
    let suite = PathBuf::from(engine::string(&state.installation, "suiteExecutable")?);
    for (product, path) in [("core", &core), ("suite", &suite)] {
        let expected = state
            .installation
            .pointer(&format!("/packages/{product}/binarySha256"))
            .and_then(Value::as_str)
            .context("reviewed native software digest absent")?;
        ensure!(
            engine::binary_digest(path)? == expected,
            "native executable changed; review an installed-software successor"
        );
    }
    ensure!(
        engine::binary_digest(&std::env::current_exe()?.canonicalize()?)?
            == engine::binary_digest(&suite)?,
        "native unit must use the reviewed installed Suite"
    );
    Ok((core, suite))
}
fn clock(root: &Path) -> Result<()> {
    let state = permitted(root)?;
    let (core, _) = software(&state)?;
    let mut active =
        runtime::Runtime::start(root, &state.configuration.clock_runtime(core), &STOP)?;
    let mut last = Instant::now();
    while !STOP.load(Ordering::Acquire) {
        if last.elapsed() >= Duration::from_secs(5) {
            permitted(root)?;
            last = Instant::now();
        }
        active.clock_ready()?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
fn service(root: &Path, name: &str) -> Result<()> {
    let state = permitted(root)?;
    let allowed = matches!(
        name,
        "PageStore" | "Relay" | "AuthorityEndpoint" | "PageEndpoint"
    ) || name == "ApplicationEndpoint" && state.configuration.hrc.is_some();
    ensure!(allowed, "unknown native service role");
    let (core, _) = software(&state)?;
    let launch = state
        .results
        .get(&format!("service-launch/{name}"))
        .context("retained service activation absent")?;
    let request = PathBuf::from(engine::string(launch, "request")?);
    let runtime = PathBuf::from(engine::string(launch, "runtime")?);
    ensure!(
        runtime == root.join(name) && request.starts_with(root.join("Activation").join(name)),
        "service activation paths differ"
    );
    ensure!(
        state
            .artifacts
            .get(&engine::text(&request)?)
            .is_some_and(|expected| files::read(&request, 1_048_576)
                .is_ok_and(|b| engine::digest(&b) == *expected)),
        "retained activation request changed"
    );
    let error = Process::new(core)
        .args(["runtime", "services", "start", "--directory"])
        .arg(runtime)
        .arg("--activation-request")
        .arg(request)
        .exec();
    Err(error.into())
}
fn start(root: &Path, installation: &Path, explicit: bool) -> Result<Value> {
    ensure!(
        !controller_update::pending(root)?,
        "complete the reviewed software update before starting"
    );
    let existing = journal(root)?;
    ensure!(
        existing.installation_directory == installation,
        "retained installation differs"
    );
    let verified = Installation::inspect(installation, &STOP)?;
    let mut host = Host::open(root, verified, existing.configuration, &STOP, None)?;
    ensure!(
        !host.state.withdrawn,
        "local hosting withdrawal is terminal; create a separately reviewed host"
    );
    if explicit {
        host.state.desired_running = true;
        host.save()?;
    }
    if !host.state.desired_running {
        return lifecycle::status(&mut host);
    }
    preview::load_image(&host)?;
    lifecycle::complete(&mut host)
}
fn supervise(root: &Path) -> Result<()> {
    let state = permitted(root)?;
    software(&state)?;
    let installation = state.installation_directory;
    let mut recovery = true;
    let mut failures = 0u32;
    let mut next_certificate_check = Instant::now();
    while !STOP.load(Ordering::Acquire) {
        if permitted(root).is_err() {
            return Ok(());
        }
        if recovery {
            match start(root, &installation, false) {
                Ok(_) => {
                    failures = 0;
                    recovery = false;
                    next_certificate_check = Instant::now() + Duration::from_secs(60);
                }
                Err(_) if STOP.load(Ordering::Acquire) => break,
                Err(_) => {
                    failures = failures.saturating_add(1);
                }
            }
        } else {
            let inspect_certificates = Instant::now() >= next_certificate_check;
            match lifecycle::tick(root, &STOP, inspect_certificates) {
                Ok(true) => {
                    if inspect_certificates {
                        next_certificate_check = Instant::now() + Duration::from_secs(60);
                    }
                }
                Ok(false) => return Ok(()),
                Err(_) => recovery = true,
            }
        }
        let until = Instant::now()
            + Duration::from_secs(if recovery {
                (5u64 << failures.min(4)).min(60)
            } else {
                5
            });
        while Instant::now() < until && !STOP.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}
fn ensure_supervisor(root: &Path) -> Result<()> {
    let host = Host::retained(root, &STOP)?;
    if host.state.desired_running && !host.state.withdrawn && host.state.completed {
        host.unit(
            "supervisor",
            &host.c.suite,
            &engine::bytes(&[
                "admission-host",
                "supervise",
                "--directory",
                &engine::text(root)?,
            ]),
        )?;
    }
    Ok(())
}
fn request(root: &Path, installation: &Path) -> Result<Value> {
    let mut input = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().take(1_048_577).read_to_end(&mut input)?;
    ensure!(
        input.len() <= 1_048_576,
        "native host request exceeds bound"
    );
    let request: Envelope = serde_json::from_slice(&input)?;
    ensure!(
        request.format == "HyperNetNativeHost/1",
        "unsupported native host request"
    );
    let cancellation_stops = matches!(
        &request.action,
        Action::Create { .. }
            | Action::Start
            | Action::Stop
            | Action::Withdraw
            | Action::RenewCertificates
    );
    let withdrawal = matches!(&request.action, Action::Withdraw);
    let result = (|| match request.action {
        Action::Preview { configuration } => preview::review(
            root,
            &Installation::inspect(installation, &STOP)?,
            &configuration,
            &STOP,
        ),
        Action::Create {
            configuration,
            review_digest,
        } => {
            ensure!(
                !controller_update::pending(root)?,
                "complete the reviewed software update before starting"
            );
            let verified = Installation::inspect(installation, &STOP)?;
            let review = preview::review(root, &verified, &configuration, &STOP)?;
            ensure!(
                review["reviewDigest"] == review_digest,
                "native review changed; review the exact setup again"
            );
            ensure!(
                review["requirements"]
                    .as_array()
                    .is_some_and(|v| v.iter().all(|r| r["ready"] == true)),
                "native prerequisites are incomplete; review setup requirements"
            );
            let mut host = Host::open(root, verified, configuration, &STOP, Some(&review_digest))?;
            let result = if host.state.desired_running && !host.state.withdrawn {
                preview::load_image(&host)?;
                lifecycle::complete(&mut host)?
            } else {
                lifecycle::status(&mut host)?
            };
            drop(host);
            ensure_supervisor(root)?;
            Ok(result)
        }
        Action::Start => {
            let result = start(root, installation, true)?;
            ensure_supervisor(root)?;
            Ok(result)
        }
        Action::RenewCertificates => {
            ensure!(
                !controller_update::pending(root)?,
                "complete the reviewed software update before certificate maintenance"
            );
            let existing = journal(root)?;
            ensure!(
                existing.installation_directory == installation
                    && existing.desired_running
                    && existing.completed
                    && !existing.withdrawn,
                "certificate renewal requires an online, completed host"
            );
            let verified = Installation::inspect(installation, &STOP)?;
            let mut host = Host::open(root, verified, existing.configuration, &STOP, None)?;
            bootstrap::clock(&mut host)?;
            certificates::renew_now(&mut host)?;
            let result = lifecycle::complete(&mut host)?;
            drop(host);
            ensure_supervisor(root)?;
            Ok(result)
        }
        Action::PreviewSoftware => controller_update::preview(root, installation, &STOP),
        Action::UpdateSoftware { review_digest } => {
            controller_update::update(root, installation, &review_digest, &STOP)
        }
        action => {
            if matches!(action, Action::Stop | Action::Withdraw) {
                let existing = journal(root)?;
                ensure!(
                    existing.installation_directory == installation,
                    "retained installation differs"
                );
                units::stop_owned(
                    root,
                    "supervisor",
                    &STOP,
                    Instant::now() + Duration::from_secs(60),
                )?;
            }
            let mut host = Host::retained(root, &STOP)?;
            ensure!(
                host.c.installation == installation,
                "retained installation differs"
            );
            match action {
                Action::Status => lifecycle::status(&mut host),
                Action::Stop => lifecycle::stop(&mut host, false),
                Action::Withdraw => lifecycle::stop(&mut host, true),
                Action::RefreshReader => {
                    ensure!(
                        host.state.desired_running && !host.state.withdrawn && host.state.completed,
                        "host reader is offline or unavailable"
                    );
                    policy::refresh(&mut host, vec![0])?;
                    let owner = policy::owner_report(&mut host)?;
                    host.remember("owner-report", owner)?;
                    lifecycle::status(&mut host)
                }
                _ => unreachable!(),
            }
        }
    })();
    if result.is_err()
        && cancellation_stops
        && STOP.load(Ordering::Acquire)
        && root.join("Hosting.json").exists()
    {
        let cleanup = AtomicBool::new(false);
        let existing = journal(root)?;
        ensure!(
            existing.installation_directory == installation,
            "retained installation differs"
        );
        units::stop_owned(
            root,
            "supervisor",
            &cleanup,
            Instant::now() + Duration::from_secs(60),
        )?;
        let mut host = Host::retained(root, &cleanup)?;
        let stopped = lifecycle::stop(&mut host, withdrawal)?;
        ensure!(
            matches!(stopped["status"].as_str(), Some("Stopped" | "Withdrawn")),
            "hosting cancelled; offline choice saved but cleanup is incomplete; retry Stop"
        );
    }
    result
}
pub fn run(command: Command) -> Result<()> {
    STOP.store(false, Ordering::Release);
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
    match command {
        Command::Request {
            directory,
            installation,
            json_stdin: _,
        } => crate::print_value(&request(&directory, &installation)?),
        Command::Permitted { directory } => {
            permitted(&directory)?;
            Ok(())
        }
        Command::Clock { directory } => clock(&directory),
        Command::Service { directory, name } => service(&directory, &name),
        Command::Supervise { directory } => supervise(&directory),
        Command::MappedInput { directory, name } => {
            files::mapped(&directory, &name, files::MappedAction::Input)
        }
        Command::MappedDirectory { directory, name } => {
            files::mapped(&directory, &name, files::MappedAction::Directory)
        }
        Command::MappedRemove { directory, name } => {
            files::mapped(&directory, &name, files::MappedAction::Remove)
        }
        Command::MappedRetire { inputs, outputs } => operator::retire_input(&inputs, &outputs),
    }
}
