// SPDX-License-Identifier: MIT
// Shared native admission owns simple joining and typed application extensions.
#[cfg(feature = "gui")]
#[path = "Activation.rs"]
pub mod activation;
#[path = "Agents.rs"]
pub mod agents;
#[path = "Certificates.rs"]
pub mod certificates;
#[path = "Client.rs"]
pub mod client;
#[path = "Control.rs"]
pub mod control;
#[cfg(feature = "gui")]
#[path = "Desktop.rs"]
pub mod desktop;
#[path = "Edge.rs"]
pub mod edge;
#[cfg(feature = "gui")]
#[path = "FolderPicker.rs"]
pub mod folder_picker;
#[path = "Helper.rs"]
pub mod helper;
#[path = "HostChallenge.rs"]
pub mod host_challenge;
#[cfg(feature = "gui")]
#[path = "HostDesktop.rs"]
pub mod host_desktop;
#[path = "HostIsolation.rs"]
pub mod host_isolation;
#[path = "HostService.rs"]
pub mod host_service;
#[path = "HostTls.rs"]
pub mod host_tls;
#[path = "Hosting.rs"]
pub mod hosting;
#[path = "Http.rs"]
pub mod http;
#[cfg(feature = "gui")]
#[path = "Installation.rs"]
pub mod installation;
#[path = "Ipc.rs"]
pub mod ipc;
#[path = "Local.rs"]
pub mod local;
#[path = "Location.rs"]
pub mod location;
#[cfg(feature = "gui")]
#[path = "Pages.rs"]
pub mod pages;
#[path = "Password.rs"]
pub mod password;
#[path = "Private.rs"]
pub mod private;
#[path = "Protocol.rs"]
pub mod protocol;
#[path = "Qr.rs"]
pub mod qr;
#[path = "Registrar.rs"]
pub mod registrar;
#[path = "RegistrarIsolation.rs"]
pub mod registrar_isolation;
#[path = "Retirement.rs"]
pub mod retirement;
#[path = "Runtime.rs"]
pub mod runtime;
#[path = "Saved.rs"]
pub mod saved;
#[path = "Store.rs"]
pub mod store;
#[path = "Transport.rs"]
pub mod transport;
use anyhow::{Result, ensure};
use serde_json::json;
use std::{io::Read, path::PathBuf};

#[derive(clap::Subcommand)]
pub enum Command {
    #[command(hide = true)]
    CertificateChallenge {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
    #[command(hide = true)]
    RegistrarConfiguration {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Open this host's separate owner Page reader.
    HostPages {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    HostPageSession {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    EdgeConfiguration {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        kind: String,
    },
    /// Install or repair the signed native components from the local release bundle.
    SetupDesktop,
    /// Create, review and manage a server through the shared hosting window.
    HostDesktop {
        #[arg(long)]
        hrc_executable: Option<PathBuf>,
    },
    /// Manage a reviewed native host and its isolated public joining endpoint.
    Hosting {
        #[arg(long)]
        directory: PathBuf,
    },
    #[command(hide = true)]
    HostSession {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Register the current installed GUI and private user-bus link handler.
    Install,
    #[command(hide = true)]
    ActivationService,
    /// Open or focus this saved server's separate Page browser.
    Pages {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    #[command(hide = true)]
    PageSession {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Open the shared graphical link, password and QR join flow.
    Desktop {
        #[arg(long, default_value = "native")]
        application: String,
        #[arg(long)]
        hrc_executable: Option<PathBuf>,
    },
    /// Prepare and enrol an external Agent using its current operator's consent.
    Agent {
        #[command(subcommand)]
        command: agents::Command,
    },
    /// Set the saved online choice without changing keys or membership.
    Desire {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, conflicts_with = "offline", required_unless_present = "offline")]
        online: bool,
        #[arg(long, conflicts_with = "online", required_unless_present = "online")]
        offline: bool,
    },
    /// Inspect saved profiles and current local runtime readiness.
    Status {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the saved server's local clock and chat companion until stopped or disconnected.
    Session {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Read one local join workflow command from stdin; retain keys and exact retries.
    Client {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Initialize disabled private admission state with a fixed participant capacity.
    RegistrarInit {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 32)]
        maximum_members: usize,
        /// Require this wall-clock expiry instead of access until removed.
        #[arg(long)]
        expires_ms: Option<u64>,
    },
    /// Run the private registrar behind a separately isolated public listener.
    Registrar {
        #[arg(long)]
        config: PathBuf,
    },
    /// Send one owner control object from stdin to the running private registrar.
    Host {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a stable private certificate authority for native pinned links.
    CertificateInit {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        host: String,
    },
    /// Check a TLS configuration and report its private authority pin when present.
    CertificateInspect {
        #[arg(long)]
        config: PathBuf,
    },
    /// Serve only the public HTTPS admission endpoints using a fixed registrar socket.
    Listen {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a private admission-password verifier from standard input.
    PasswordVerifier {
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect a location from stdin without connecting or revealing invitation secrets.
    Inspect,
    /// Encode a location from stdin as a private QR PNG image.
    Qr {
        #[arg(long)]
        output: PathBuf,
    },
    /// Decode one QR invitation image into a new private text file.
    Scan {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn input() -> Result<location::Location> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(location::MAX_LOCATION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= location::MAX_LOCATION_BYTES,
        "join input exceeds its bound"
    );
    let text = zeroize::Zeroizing::new(String::from_utf8(bytes)?);
    location::Location::parse(&text)
}
pub fn run(command: Command) -> Result<()> {
    let result = match command {
        host_pages @ (Command::HostPages { .. } | Command::HostPageSession { .. }) => {
            #[cfg(feature = "gui")]
            {
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() {
                    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
                }
                ensure!(bytes.len() <= 4096, "Page location exceeds bound");
                let input = if bytes.is_empty() {
                    pages::Input { location: None }
                } else {
                    serde_json::from_slice(&bytes)?
                };
                match host_pages {
                    Command::HostPages { directory } => {
                        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                            signal_hook::flag::register(signal, stop.clone())?;
                        }
                        pages::open_owner(&directory, input, &stop)?
                    }
                    Command::HostPageSession { directory } => {
                        pages::owner_session(&directory, input)?
                    }
                    _ => unreachable!(),
                }
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = host_pages;
                anyhow::bail!("Page windows require the gui feature");
            }
        }
        Command::CertificateChallenge { directory, listen } => {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            host_challenge::serve(&directory, listen, stop)?;
            json!({"status":"CertificateChallengeStopped"})
        }
        Command::RegistrarConfiguration { directory } => {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 65536,
                "registrar configuration exceeds bound"
            );
            registrar_isolation::initialise(&directory, serde_json::from_slice(&bytes)?)?
        }
        Command::EdgeConfiguration { directory, kind } => {
            private::directory(&directory)?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(262145).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 262144, "edge configuration exceeds bound");
            match kind.as_str() {
                "tls" => {
                    let config: certificates::Configuration = serde_json::from_slice(&bytes)?;
                    saved::replace(&directory.join("Tls.json"), &config)?;
                }
                "listener" => {
                    let config: edge::Configuration = serde_json::from_slice(&bytes)?;
                    config.validate()?;
                    saved::replace(&directory.join("Edge.json"), &config)?;
                }
                "certificate" => {
                    let material: certificates::Material = serde_json::from_slice(&bytes)?;
                    material.validate()?;
                    saved::replace(&directory.join("Managed.json"), &material)?;
                }
                _ => anyhow::bail!("unknown edge configuration kind"),
            }
            json!({"status":"EdgeConfigurationWritten"})
        }
        Command::SetupDesktop => {
            #[cfg(feature = "gui")]
            {
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                    signal_hook::flag::register(signal, stop.clone())?;
                }
                installation::run(stop)?
            }
            #[cfg(not(feature = "gui"))]
            {
                anyhow::bail!("the setup window requires the gui feature");
            }
        }
        Command::HostDesktop { hrc_executable } => {
            #[cfg(feature = "gui")]
            {
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                    signal_hook::flag::register(signal, stop.clone())?;
                }
                host_desktop::run(hrc_executable, stop)?
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = hrc_executable;
                anyhow::bail!("the hosting window requires the gui feature");
            }
        }
        host @ (Command::Hosting { .. } | Command::HostSession { .. }) => {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            match host {
                Command::Hosting { directory } => {
                    let mut bytes = zeroize::Zeroizing::new(Vec::new());
                    std::io::stdin().take(65537).read_to_end(&mut bytes)?;
                    ensure!(bytes.len() <= 65536, "hosting request exceeds bound");
                    hosting::request(&directory, serde_json::from_slice(&bytes)?, &stop)?
                }
                Command::HostSession { directory } => hosting::serve(&directory, stop)?,
                _ => unreachable!(),
            }
        }
        command @ (Command::Install | Command::ActivationService) => {
            #[cfg(feature = "gui")]
            {
                if matches!(command, Command::Install) {
                    activation::install()?
                } else {
                    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                        signal_hook::flag::register(signal, stop.clone())?;
                    }
                    activation::serve(stop)?
                }
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = command;
                anyhow::bail!("desktop installation requires the gui feature");
            }
        }
        page @ (Command::Pages { .. } | Command::PageSession { .. }) => {
            #[cfg(feature = "gui")]
            {
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() {
                    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
                }
                ensure!(bytes.len() <= 4096, "Page location exceeds bound");
                let input = if bytes.is_empty() {
                    pages::Input { location: None }
                } else {
                    serde_json::from_slice(&bytes)?
                };
                match page {
                    Command::Pages { directory, config } => {
                        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                            signal_hook::flag::register(signal, stop.clone())?;
                        }
                        pages::open(&directory, &config, input, &stop)?
                    }
                    Command::PageSession { directory, config } => {
                        pages::session(&directory, &config, input)?
                    }
                    _ => unreachable!(),
                }
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = page;
                anyhow::bail!("Page windows require the gui feature");
            }
        }
        Command::Desktop {
            application,
            hrc_executable,
        } => {
            #[cfg(feature = "gui")]
            {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    location: Option<String>,
                }
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() {
                    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
                }
                ensure!(bytes.len() <= 4096, "join location exceeds bound");
                let input: Input = if bytes.is_empty() {
                    Input { location: None }
                } else {
                    serde_json::from_slice(&bytes)?
                };
                let application = match application.as_str() {
                    "native" => location::Application::Native,
                    "hrc" => location::Application::Hrc,
                    _ => anyhow::bail!("unsupported join application"),
                };
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                    signal_hook::flag::register(signal, stop.clone())?;
                }
                let joined =
                    desktop::run(application, hrc_executable, input.location, stop.clone())?;
                if application == location::Application::Native {
                    let directory = std::path::Path::new(
                        joined
                            .get("serverDirectory")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| anyhow::anyhow!("saved server directory absent"))?,
                    );
                    let config = directory.join("Runtime.json");
                    pages::open(directory, &config, pages::Input { location: None }, &stop)?;
                }
                joined
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = (application, hrc_executable);
                anyhow::bail!("graphical joining requires the gui feature");
            }
        }
        Command::Agent { command } => {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 65536, "local Agent request exceeds bound");
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            agents::run(
                command,
                if bytes.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&bytes)?
                },
                &stop,
            )?
        }
        Command::Desire {
            directory,
            online,
            offline: _,
        } => local::desire(&directory, online)?,
        Command::Status { directory, config } => local::status(&directory, &config)?,
        Command::Session { directory, config } => {
            let config = serde_json::from_slice(&crate::files::read_bounded(&config, true)?)?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            runtime::supervise(&directory, &config, stop)?;
            json!({"status":"SavedServerStopped"})
        }
        Command::Client { directory } => {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 65536, "local join request exceeds bound");
            let command = serde_json::from_slice(&bytes)?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            client::run(&directory, &command, &stop)?
        }
        Command::RegistrarInit {
            directory,
            maximum_members,
            expires_ms,
        } => {
            let access = expires_ms.map_or(store::End::UntilRemoved, |expires_ms| {
                store::End::Expires { expires_ms }
            });
            let state = store::State::new(maximum_members, access)?;
            store::Locked::create(&directory, state)?;
            json!({"status":"AdmissionInitialized","enabled":false})
        }
        Command::Registrar { config } => {
            let config = serde_json::from_slice(&crate::files::read_bounded(&config, true)?)?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            control::serve(config, stop)?;
            json!({"status":"AdmissionRegistrarStopped"})
        }
        Command::Host { config } => {
            let config = serde_json::from_slice(&crate::files::read_bounded(&config, true)?)?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 65536, "owner request exceeds bound");
            control::owner(&config, serde_json::from_slice(&bytes)?)?
        }
        Command::CertificateInit { directory, host } => {
            saved::create_directory(&directory)?;
            json!({"certificateAuthorityPin":certificates::initialise(&directory,&host)?})
        }
        Command::CertificateInspect { config } => {
            let config = serde_json::from_slice(&crate::files::read_bounded(&config, true)?)?;
            let (_, pin) = certificates::server(config)?;
            json!({"status":"TlsConfigurationReady","certificateAuthorityPin":pin.map(hex::encode)})
        }
        Command::Listen { config } => {
            let config = serde_json::from_slice(&crate::files::read_bounded(&config, true)?)?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(signal, stop.clone())?;
            }
            edge::serve(config, stop)?;
            json!({"status":"AdmissionListenerStopped"})
        }
        Command::PasswordVerifier { output } => {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(130).read_to_end(&mut bytes)?;
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            let verifier = password::Verifier::create(&bytes)?;
            crate::files::write_new(&output, &serde_json::to_vec(&verifier)?)?;
            json!({"status":"PasswordVerifierCreated","file":output})
        }
        Command::Inspect => {
            let location = input()?;
            json!({"version":1,"origin":location.origin.as_str(),"application":location.application,"identityPinned":location.identity_pin.is_some(),"privateCertificatePinned":location.certificate_authority_pin.is_some(),"privateInvitation":location.invitation.is_some(),"descriptorEndpoint":location.endpoint("/v1/admission/descriptor")?.as_str()})
        }
        Command::Qr { output } => {
            let location = input()?;
            qr::write(&location, &output)?;
            json!({"status":"QrWritten","file":output})
        }
        Command::Scan { image, output } => {
            let location = qr::read(&image)?;
            crate::files::write_new(&output, location.url(false)?.as_bytes())?;
            json!({"status":"InvitationDecoded","file":output,"origin":location.origin.as_str()})
        }
    };
    crate::print_value(&result)
}
