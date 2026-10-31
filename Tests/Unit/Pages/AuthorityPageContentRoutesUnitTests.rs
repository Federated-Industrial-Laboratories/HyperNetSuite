// SPDX-License-Identifier: MIT
// Unit tests for AuthorityPageContentRoutes.
use super::*;
use std::os::{
    fd::AsRawFd,
    unix::{fs::PermissionsExt, net::UnixListener},
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn first_content_route_is_retained_and_corrupt_or_symlink_routes_refuse() {
    let path = std::env::temp_dir().join(format!("HyperNetRoutes{}", crate::random_hex::<16>()));
    let _cleanup = Directory(path.clone());
    let directory = files::create_directory(&path).unwrap();
    assert!(load(&directory).unwrap().is_empty());
    let socket = path.join("Control.sock");
    let bound =
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join("Control.sock");
    let _listener = UnixListener::bind(bound).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    retain(Options {
        directory: path.clone(),
        host: hex::encode([11; 32]),
        service_socket: Some(socket.clone()),
        service_directory: None,
        core: PathBuf::from("HyperNet"),
    })
    .unwrap();
    let routes = load(&directory).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].host, hex::encode([11; 32]));
    assert_eq!(routes[0].service_socket.as_ref(), Some(&socket));
    std::fs::write(path.join(ROUTES), b"corrupt").unwrap();
    assert!(load(&directory).is_err());
    std::fs::remove_file(path.join(ROUTES)).unwrap();
    std::os::unix::fs::symlink(path.join("Missing.json"), path.join(ROUTES)).unwrap();
    assert!(load(&directory).is_err());
}
