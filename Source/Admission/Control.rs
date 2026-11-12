// SPDX-License-Identifier: MIT
// A fixed private bridge authenticates operating-system peers and bounds every control frame.
use super::{
    protocol,
    registrar::{Configuration, Registrar},
    store,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Admin {
    Status,
    Configure {
        enabled: bool,
        mode: store::Mode,
    },
    Password {
        password: String,
    },
    Invite {
        end: store::End,
        #[serde(rename = "maximumUses")]
        maximum_uses: u32,
    },
    DisableInvite {
        id: String,
    },
    Revoke {
        attempt: String,
    },
}
impl Drop for Admin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Self::Password { password } = self {
            password.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRequest {
    format: String,
    action: Admin,
}
fn peer(socket: &UnixStream) -> Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0
            && size as usize == std::mem::size_of_val(&credentials),
        "admission peer identity unavailable"
    );
    Ok(credentials.uid)
}
fn read(socket: &mut UnixStream, end: Instant) -> Result<Value> {
    fn exact(socket: &mut UnixStream, mut bytes: &mut [u8], end: Instant) -> Result<()> {
        while !bytes.is_empty() {
            socket.set_read_timeout(Some(
                end.checked_duration_since(Instant::now())
                    .ok_or_else(|| anyhow::anyhow!("admission input timed out"))?,
            ))?;
            let count = socket.read(bytes)?;
            ensure!(count > 0, "admission input closed");
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    let mut size = [0u8; 4];
    exact(socket, &mut size, end)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= protocol::REQUEST_BYTES + 1024,
        "admission input exceeds bound"
    );
    let mut bytes = zeroize::Zeroizing::new(vec![0; size]);
    exact(socket, &mut bytes, end)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn write(socket: &mut UnixStream, value: &Value) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(
        bytes.len() <= super::transport::RESPONSE_BYTES,
        "admission response exceeds bound"
    );
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    let frame = zeroize::Zeroizing::new(frame);
    let mut rest = frame.as_slice();
    let end = Instant::now() + Duration::from_secs(5);
    while !rest.is_empty() {
        socket.set_write_timeout(Some(
            end.checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow::anyhow!("admission output timed out"))?,
        ))?;
        let n = socket.write(rest)?;
        ensure!(n > 0, "admission output closed");
        rest = &rest[n..];
    }
    Ok(())
}
fn address(path: &Path, expected_uid: u32) -> Result<(File, PathBuf)> {
    ensure!(
        path.is_absolute() && path.file_name().is_some(),
        "admission socket path must be absolute"
    );
    let parent = path.parent().unwrap();
    ensure!(
        parent.canonicalize()? == parent,
        "bridge directory must be canonical"
    );
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let m = held.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == expected_uid && m.mode() & 0o022 == 0,
        "bridge directory permits replacement"
    );
    let shortened = PathBuf::from(format!("/proc/self/fd/{}/", held.as_raw_fd()))
        .join(path.file_name().unwrap());
    Ok((held, shortened))
}
impl Registrar {
    fn admin(&mut self, action: &Admin, stop: &AtomicBool) -> Result<Value> {
        match action {
            Admin::Status => {
                let s = self.store.state()?;
                Ok(
                    json!({"status":"AdmissionHost","enabled":s.enabled,"mode":s.mode,"access":s.access,"maximumMembers":s.maximum_members,"removal":s.removal,"awaitingRemovalAcknowledgements":s.retirements.len(),"members":s.claims.iter().map(|c|json!({"attempt":c.intent.attempt,"displayName":c.intent.display_name,"phase":c.phase})).collect::<Vec<_>>(),"invitations":s.invitations.iter().map(|i|json!({"id":i.id,"enabled":i.enabled,"end":i.end,"maximumUses":i.maximum_uses,"uses":i.uses})).collect::<Vec<_>>()}),
                )
            }
            Admin::Configure { enabled, mode } => {
                self.store.transact(|s| {
                    ensure!(
                        *mode != store::Mode::Password || s.password.is_some(),
                        "set a password before enabling password joining"
                    );
                    s.enabled = *enabled;
                    s.mode = *mode;
                    Ok(())
                })?;
                Ok(json!({"status":"AdmissionConfigured"}))
            }
            Admin::Password { password } => {
                let verifier = super::password::Verifier::create(password.as_bytes())?;
                self.store.transact(|s| {
                    s.password = Some(verifier);
                    Ok(())
                })?;
                Ok(json!({"status":"PasswordRotated","existingMembersChanged":false}))
            }
            Admin::Invite { end, maximum_uses } => {
                ensure!(*maximum_uses > 0, "invitation requires at least one use");
                let id = crate::random_hex::<32>();
                let mut secret = zeroize::Zeroizing::new([0u8; 32]);
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut *secret);
                let digest = protocol::digest(&*secret);
                self.store.transact(|s| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis() as u64;
                    s.retire_invitations(now);
                    ensure!(
                        s.invitations.len() < store::MAX_INVITATIONS && end.current(now),
                        "invitation capacity or expiry invalid"
                    );
                    s.invitations.push(store::Invitation {
                        id: id.clone(),
                        secret_digest: digest,
                        enabled: true,
                        end: end.clone(),
                        maximum_uses: *maximum_uses,
                        uses: 0,
                    });
                    Ok(())
                })?;
                use base64::Engine;
                Ok(
                    json!({"status":"InvitationCreated","id":id,"secret":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*secret)}),
                )
            }
            Admin::DisableInvite { id } => {
                self.store.transact(|s| {
                    let i = s
                        .invitations
                        .iter_mut()
                        .find(|i| i.id == *id)
                        .ok_or_else(|| anyhow::anyhow!("invitation absent"))?;
                    i.enabled = false;
                    Ok(())
                })?;
                Ok(json!({"status":"InvitationDisabled","existingMembersChanged":false}))
            }
            Admin::Revoke { attempt } => self.remove(attempt, stop),
        }
    }
}
struct Socket {
    path: PathBuf,
    _parent: File,
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
pub fn serve(config: Configuration, stop: Arc<AtomicBool>) -> Result<()> {
    let mut registrar = Registrar::open(config.clone())?;
    let (parent, short) = address(&config.socket, unsafe { libc::geteuid() })?;
    let owner_uid = config
        .owner_uid
        .unwrap_or_else(|| unsafe { libc::geteuid() });
    if let Ok(m) = std::fs::symlink_metadata(&config.socket) {
        ensure!(
            m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() },
            "unexpected bridge socket object"
        );
        std::fs::remove_file(&config.socket)?;
    }
    let listener = UnixListener::bind(&short)?;
    let _socket = Socket {
        path: config.socket.clone(),
        _parent: parent,
    };
    // The socket alone is shared. SO_PEERCRED gates it; private state has no public mount.
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o666))?;
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let result = (|| -> Result<Value> {
                    let uid = peer(&stream)?;
                    ensure!(
                        uid == config.edge_uid || uid == owner_uid,
                        "admission peer refused"
                    );
                    let request = read(&mut stream, Instant::now() + Duration::from_secs(5))?;
                    if request.get("format").and_then(Value::as_str)
                        == Some("HyperNetAdmissionOwner/1")
                    {
                        ensure!(
                            uid == owner_uid && uid != config.edge_uid,
                            "owner control requires its separate private identity"
                        );
                        let request: AdminRequest = serde_json::from_value(request)?;
                        registrar.admin(&request.action, &stop)
                    } else {
                        ensure!(
                            uid == config.edge_uid,
                            "public protocol requires configured edge identity"
                        );
                        registrar.edge(serde_json::from_value(request)?, &stop)
                    }
                })();
                let response = result.unwrap_or_else(|error| {
                    let text = error.to_string();
                    let code = match text.as_str() {
                        "ServerPermissionsChanged" => "ServerPermissionsChanged",
                        "AdmissionChallengeExpired" => "AdmissionChallengeExpired",
                        "AdmissionRecoveryPending" => "AdmissionRecoveryPending",
                        "AdmissionRateLimited" => "AdmissionRateLimited",
                        "admission refused" => "InvalidJoinCredential",
                        "OperatorConsentRequired" => "OperatorConsentRequired",
                        "OperatorAgentQuota" => "OperatorAgentQuota",
                        "admission capacity reached" => "AdmissionCapacity",
                        "new joining is unavailable" => "JoiningPaused",
                        "claim ticket retired; obtain a fresh challenge" => {
                            "AdmissionTicketRetired"
                        }
                        _ => "AdmissionUnavailable",
                    };
                    json!({"status":"refused","code":code})
                });
                let _ = write(&mut stream, &response);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn owner(config: &Configuration, action: Admin) -> Result<Value> {
    ensure!(
        config.edge_uid != unsafe { libc::geteuid() },
        "public edge and owner must have separate host identities"
    );
    owner_at(&config.socket, unsafe { libc::geteuid() }, action)
}
pub fn owner_at(socket: &Path, registrar_uid: u32, action: Admin) -> Result<Value> {
    let (_parent, path) = address(socket, registrar_uid)?;
    let mut channel = super::ipc::Channel::connect(&path, registrar_uid, Duration::from_secs(60))?;
    let request = serde_json::to_vec(&AdminRequest {
        format: "HyperNetAdmissionOwner/1".into(),
        action,
    })?;
    let response =
        zeroize::Zeroizing::new(channel.exchange(&request, super::transport::RESPONSE_BYTES)?);
    Ok(serde_json::from_slice(&response)?)
}
