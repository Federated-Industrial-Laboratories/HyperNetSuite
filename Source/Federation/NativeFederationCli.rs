// SPDX-License-Identifier: MIT
// Explicit commands separate bilateral consent, bridge transport and local review.
use super::*;
#[derive(Args)]
pub struct Access {
    #[command(flatten)]
    pub online: Online,
    #[command(flatten)]
    pub capability: Capability,
}
#[derive(Args)]
pub struct Maintenance {
    #[command(flatten)]
    pub online: Online,
    /// Omit only for the exact recorded owner or service's restrictive maintenance.
    #[arg(long)]
    pub grant: Option<String>,
    #[arg(long, requires = "grant")]
    pub grant_record: Option<PathBuf>,
}
#[derive(Clone, Args)]
pub struct Route {
    /// Explicit installed local bridge; it never comes from Page content.
    #[arg(
        long,
        conflicts_with = "service_socket",
        required_unless_present = "service_socket"
    )]
    pub service_directory: Option<PathBuf>,
    /// Explicit private same-UID bridge control socket.
    #[arg(long, conflicts_with = "service_directory")]
    pub service_socket: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    pub core: PathBuf,
    /// Finite transport wait; each authority operation keeps its own signed deadline.
    #[arg(long, default_value_t = 120000)]
    pub exchange_timeout_ms: u64,
}
#[derive(Args)]
pub struct PageSelection {
    #[arg(long)]
    pub agreement: String,
    #[arg(long)]
    pub source_page_id: String,
}
#[derive(Args)]
pub struct Display {
    #[arg(long)]
    pub tui: bool,
    #[arg(long)]
    pub ascii: bool,
    #[command(flatten)]
    pub graphics: crate::terminal_graphics::Options,
    /// Explicit canonical local media files; no source-network host is contacted.
    #[arg(long = "media")]
    pub media: Vec<String>,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Decision {
    Approve,
    Reject,
}
#[derive(Subcommand)]
pub enum TrustCommand {
    Inspect {
        #[arg(long)]
        foreign_bootstrap: PathBuf,
        #[arg(long)]
        foreign_bootstrap_digest: String,
    },
    Accept {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        foreign_bootstrap: PathBuf,
        #[arg(long)]
        foreign_bootstrap_digest: String,
        #[arg(long)]
        foreign_network: String,
        #[arg(long)]
        foreign_incarnation: String,
        #[arg(long)]
        foreign_fingerprint: String,
    },
    Get {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        trust: String,
        /// Export the certified foreign prefix for an exact epoch-history request.
        #[arg(long)]
        retained_output: Option<PathBuf>,
    },
    Withdraw {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        trust: String,
    },
    Seal {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        trust: String,
        #[arg(long)]
        terminal: PathBuf,
        #[arg(long)]
        history: PathBuf,
    },
    Activate {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        trust: String,
        #[arg(long)]
        ready: PathBuf,
    },
}
#[derive(Subcommand)]
pub enum TreatyCommand {
    Create {
        #[arg(long)]
        agreement: Option<String>,
        #[arg(long)]
        source_bootstrap: PathBuf,
        #[arg(long)]
        source_bootstrap_digest: String,
        #[arg(long)]
        destination_bootstrap: PathBuf,
        #[arg(long)]
        destination_bootstrap_digest: String,
        #[arg(long)]
        source_bridge: String,
        #[arg(long)]
        destination_bridge: String,
        #[arg(long)]
        source_namespace: String,
        #[arg(long)]
        destination_namespace: String,
        #[arg(long)]
        media_profile: Vec<String>,
        #[arg(long)]
        source_host: Vec<String>,
        #[arg(long)]
        destination_host: Vec<String>,
        #[arg(long, default_value_t = 0)]
        media_bytes: u64,
        #[arg(long, default_value_t = 0)]
        copies: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[arg(long)]
        input: PathBuf,
    },
    Accept {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        input: PathBuf,
    },
    Get {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        agreement: String,
    },
    List {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        after: Option<String>,
    },
    Withdraw {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        agreement: String,
    },
}
#[derive(Subcommand)]
pub enum BridgeCommand {
    Profile {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        profile_digest: String,
        #[arg(long)]
        volume: String,
        #[arg(long, required = true)]
        treaty: Vec<PathBuf>,
        #[arg(long)]
        state_bytes: u64,
        /// Explicit operator consent for destination-local publication search.
        #[arg(long)]
        search: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        input: PathBuf,
    },
    Register {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        profile: PathBuf,
    },
    Get {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        service: String,
    },
    Withdraw {
        #[command(flatten)]
        access: Maintenance,
        #[arg(long)]
        service: String,
    },
    Sync {
        #[command(flatten)]
        route: Route,
        /// Existing private directory for bounded exchange files.
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        source_page_id: Option<String>,
    },
}
#[derive(Subcommand)]
pub enum Command {
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    Treaty {
        #[command(subcommand)]
        command: TreatyCommand,
    },
    Bridge {
        #[command(subcommand)]
        command: BridgeCommand,
    },
    ShareSign {
        #[command(flatten)]
        access: Access,
        #[command(flatten)]
        selection: PageSelection,
        #[arg(long)]
        output: PathBuf,
    },
    Share {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        input: PathBuf,
    },
    ShareStatus {
        #[command(flatten)]
        access: Maintenance,
        #[command(flatten)]
        selection: PageSelection,
    },
    Unshare {
        #[command(flatten)]
        access: Maintenance,
        #[command(flatten)]
        selection: PageSelection,
    },
    Queue {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        after: Option<String>,
    },
    Inspect {
        #[command(flatten)]
        access: Access,
        #[command(flatten)]
        selection: PageSelection,
        #[command(flatten)]
        route: Route,
        #[command(flatten)]
        display: Display,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a local decision over the exact retained inspection, without a five-second human deadline.
    ReviewSign {
        #[command(flatten)]
        access: Access,
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
        decision: Decision,
        #[arg(long)]
        output: PathBuf,
    },
    /// Obtain a new bilateral lease and apply the saved exact local decision.
    Review {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        route: Route,
        #[arg(long)]
        input: PathBuf,
    },
    Read {
        #[command(flatten)]
        access: Access,
        #[command(flatten)]
        selection: PageSelection,
        #[command(flatten)]
        route: Route,
        #[command(flatten)]
        display: Display,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    List {
        #[command(flatten)]
        access: Access,
        #[command(flatten)]
        route: Route,
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        after: Option<String>,
    },
    Withdraw {
        #[command(flatten)]
        access: Access,
        #[command(flatten)]
        selection: PageSelection,
    },
    Media {
        #[command(subcommand)]
        command: media::Command,
    },
}
