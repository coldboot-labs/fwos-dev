use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

mod peer;
pub use peer::{DiscoveryPackets, NetworkPeer, PendingHttps};

static PROGRESS: AtomicBool = AtomicBool::new(false);

/// Phase lines on stderr for `fwos-dev build` / `run`. Tests stay quiet.
pub fn enable_progress() {
    PROGRESS.store(true, Ordering::Relaxed);
}

fn progress(msg: &str) {
    if PROGRESS.load(Ordering::Relaxed) {
        let _ = writeln!(io::stderr(), "fwos-dev: {msg}");
        let _ = io::stderr().flush();
    }
}

const FEDORA_BOOTC: &str = "quay.io/fedora/fedora-bootc:44";
const HOST_IMAGE_TAG: &str = "localhost/fwos:dev";
const NEXT_IMAGE_TAG: &str = "localhost/fwos:next";
const REGISTRY_IMAGE: &str = "docker.io/library/registry:2";
const HOST_PROGRAM_TAG: &str = "localhost/fwos-fwd-setup:dev";
const NETD_IMAGE_TAG: &str = "localhost/fwos-netd:dev";
const CLI_IMAGE_TAG: &str = "localhost/fwos-cli:dev";
const UI_IMAGE_TAG: &str = "localhost/fwos-ui:dev";
const KEA_IMAGE_TAG: &str = "localhost/fwos-kea:dev";
const UNBOUND_IMAGE_TAG: &str = "localhost/fwos-unbound:dev";
const IMAGE_BUILDER: &str = "quay.io/centos-bootc/bootc-image-builder:latest";
const BOOT_WAIT: Duration = Duration::from_secs(240);
const INSTALL_WAIT: Duration = Duration::from_secs(1800);
const INSTALLER_PROMPT_WAIT: Duration = Duration::from_secs(600);
const QEMU_MEMORY_MIB: &str = "4096";
const OVMF_CODE: &str = "/usr/share/edk2/ovmf/OVMF_CODE.fd";
const SERIAL_BOOTSTRAP: &str = "FWOS Bootstrap console";
const INSTALLER_DISK_PROMPT: &str = "FWOS Installer: pick a disk to wipe";
const INSTALLER_WIPE_PROMPT: &str =
    "The entire disk will be erased and replaced with the Host disk layout";
const EMPTY_DISK_SIZE: &str = "10G";
const MIN_INSTALLED_DISK: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
enum FirstDisk {
    Empty,
    Partitioned,
}

struct IsoLinux {
    kernel: PathBuf,
    initrd: PathBuf,
    append: String,
}

#[derive(Clone, Copy)]
struct QemuStart<'a> {
    boot_disk: &'a Path,
    extra_disks: &'a [&'a Path],
    cdrom: Option<&'a Path>,
    linux: Option<&'a IsoLinux>,
    extra_nics: u8,
    peer_taps: &'a [&'a str],
    user_net_with_peers: bool,
    port_22: u16,
    https_port: u16,
    extra_https_port: Option<u16>,
    serial_log: &'a Path,
    serial_sock: &'a Path,
    monitor: &'a Path,
    no_reboot: bool,
}

/// A QEMU guest started by Workstation tooling.
pub struct Guest {
    child: Child,
    port_22: u16,
    https_port: u16,
    extra_https_port: Option<u16>,
    serial_log: PathBuf,
    serial: Mutex<UnixStream>,
    monitor: PathBuf,
}

/// An ordinary HTTPS client authenticated through the appliance's login flow.
/// Cloning it copies the browser cookie, allowing revoked-cookie replay checks.
#[derive(Clone)]
pub struct HttpsSession<'a> {
    guest: &'a Guest,
    cookie: String,
}

impl HttpsSession<'_> {
    pub fn exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
    ) -> Result<(u16, String), Error> {
        let (code, body, _) = self.guest.https_exchange_headers(
            "10.0.2.15",
            self.guest.https_port,
            method,
            path,
            body,
            max_time_secs,
            &[format!("Cookie: {}", self.cookie)],
        )?;
        Ok((code, body))
    }

    pub fn get(&self, path: &str) -> Result<String, Error> {
        let (code, body) = self.exchange("GET", path, None, 15)?;
        if code == 200 {
            Ok(body)
        } else {
            Err(Error::from_message(format!("HTTPS status {code}: {body}")))
        }
    }
}

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    fn from_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn from_io(context: &str, err: io::Error) -> Self {
        Self {
            message: format!("{context}: {err}"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

fn output_with_input(command: &mut Command, input: &[u8]) -> io::Result<std::process::Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("child stdin unavailable"))
        .and_then(|mut stdin| stdin.write_all(input));
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    child.wait_with_output()
}

impl Guest {
    /// Disk image: no injected SSH key, no default password. Observe via serial and HTTPS.
    pub fn boot_published_host_image() -> Result<Self, Error> {
        let disk_path = build_published_host_image_disk()?;
        Self::boot_disk(&disk_path, 0)
    }

    /// Same Disk image with a second virtio-net (WAN + LAN Traffic NICs).
    pub fn boot_published_host_image_two_nics() -> Result<Self, Error> {
        let disk_path = build_published_host_image_disk()?;
        Self::boot_disk(&disk_path, 1)
    }

    /// Same Disk image with two extra virtio-nets (WAN, LAN, Management NIC).
    pub fn boot_published_host_image_three_nics() -> Result<Self, Error> {
        let disk_path = build_published_host_image_disk()?;
        Self::boot_disk(&disk_path, 2)
    }

    /// Attach Traffic NICs directly to isolated external peers, without NAT or a relay.
    /// Keep the peers alive until the Guest has stopped.
    pub fn boot_published_host_image_with_peers(peers: &[&NetworkPeer]) -> Result<Self, Error> {
        if peers.is_empty() {
            return Err(Error::from_message("at least one network peer is required"));
        }
        let disk_path = build_published_host_image_disk()?;
        let taps: Vec<&str> = peers.iter().map(|peer| peer.tap()).collect();
        Self::boot_disk_with_peers(&disk_path, 0, &taps, false)
    }

    /// Boot with the regular HTTPS user network and task-owned external peers.
    pub fn boot_published_host_image_with_user_net_and_peers(
        peers: &[&NetworkPeer],
    ) -> Result<Self, Error> {
        if peers.is_empty() {
            return Err(Error::from_message("at least one network peer is required"));
        }
        let disk_path = build_published_host_image_disk()?;
        let taps: Vec<&str> = peers.iter().map(|peer| peer.tap()).collect();
        Self::boot_disk_with_peers(&disk_path, 0, &taps, true)
    }

    /// The extra Traffic NIC can be removed by QEMU while LAN and WAN peers stay connected.
    pub fn boot_published_host_image_with_user_net_peers_and_extra_nic(
        peers: &[&NetworkPeer],
    ) -> Result<Self, Error> {
        if peers.is_empty() {
            return Err(Error::from_message("at least one network peer is required"));
        }
        let disk_path = build_published_host_image_disk()?;
        let taps: Vec<&str> = peers.iter().map(|peer| peer.tap()).collect();
        Self::boot_disk_with_peers(&disk_path, 1, &taps, true)
    }

    /// Boot the Installer ISO against an empty virt disk, then observe the installed guest.
    pub fn install_from_iso() -> Result<Self, Error> {
        let disk_path = install_host_image_disk()?;
        Self::boot_disk(&disk_path, 0)
    }

    /// Boot the Installer ISO against one empty virt disk and wait for wipe approval.
    pub fn boot_installer_one_disk() -> Result<Self, Error> {
        Self::boot_installer(1, INSTALLER_WIPE_PROMPT, FirstDisk::Empty)
    }

    /// Boot the Installer ISO against one virt disk that already has partitions.
    pub fn boot_installer_one_partitioned_disk() -> Result<Self, Error> {
        Self::boot_installer(1, INSTALLER_WIPE_PROMPT, FirstDisk::Partitioned)
    }

    /// Boot the Installer ISO with two empty virt disks and wait for the disk pick.
    pub fn boot_installer_two_disks() -> Result<Self, Error> {
        Self::boot_installer(2, INSTALLER_DISK_PROMPT, FirstDisk::Empty)
    }

    fn boot_installer(n_disks: usize, needle: &str, first: FirstDisk) -> Result<Self, Error> {
        ensure_kvm_usable()?;
        ensure_ovmf()?;
        let iso = build_installer_iso()?;
        let work = instance_dir()?;
        let mut disks = Vec::new();
        for i in 0..n_disks {
            let path = work.join(format!("disk{}.qcow2", i + 1));
            if i == 0 && matches!(first, FirstDisk::Partitioned) {
                create_partitioned_qcow2(&path)?;
            } else {
                create_empty_qcow2(&path)?;
            }
            disks.push(path);
        }
        let linux = extract_iso_linux(&iso, &work)?;
        let port = free_localhost_port()?;
        let https_port = free_localhost_port()?;
        let serial_log = work.join("serial.log");
        let serial_sock = work.join("serial.sock");
        let monitor = work.join("monitor.sock");
        let extra: Vec<&Path> = disks.iter().skip(1).map(|p| p.as_path()).collect();
        let mut guest = spawn_guest(QemuStart {
            boot_disk: &disks[0],
            extra_disks: &extra,
            cdrom: Some(&iso),
            linux: Some(&linux),
            extra_nics: 0,
            peer_taps: &[],
            user_net_with_peers: false,
            port_22: port,
            https_port,
            extra_https_port: None,
            serial_log: &serial_log,
            serial_sock: &serial_sock,
            monitor: &monitor,
            no_reboot: false,
        })?;
        let ready = guest.wait_for_serial_timeout(needle, INSTALLER_PROMPT_WAIT);
        guest.wait_or_stop(ready)?;
        Ok(guest)
    }

    fn boot_disk(disk_path: &Path, extra_nics: u8) -> Result<Self, Error> {
        Self::boot_disk_with_peers(disk_path, extra_nics, &[], false)
    }

    fn boot_disk_with_peers(
        disk_path: &Path,
        extra_nics: u8,
        peer_taps: &[&str],
        user_net_with_peers: bool,
    ) -> Result<Self, Error> {
        ensure_kvm_usable()?;
        ensure_ovmf()?;
        let port = free_localhost_port()?;
        let https_port = free_localhost_port()?;
        let extra_https_port = if extra_nics > 0 {
            Some(free_localhost_port()?)
        } else {
            None
        };
        let work = instance_dir()?;
        let overlay = work.join("overlay.qcow2");
        let serial_log = work.join("serial.log");
        let serial_sock = work.join("serial.sock");
        let monitor = work.join("monitor.sock");
        create_overlay(disk_path, &overlay)?;
        let mut guest = spawn_guest(QemuStart {
            boot_disk: &overlay,
            extra_disks: &[],
            cdrom: None,
            linux: None,
            extra_nics,
            peer_taps,
            user_net_with_peers,
            port_22: port,
            https_port,
            extra_https_port,
            serial_log: &serial_log,
            serial_sock: &serial_sock,
            monitor: &monitor,
            no_reboot: false,
        })?;
        let ready = guest.wait_for_serial(SERIAL_BOOTSTRAP);
        guest.wait_or_stop(ready)?;
        Ok(guest)
    }

    pub fn https_port(&self) -> u16 {
        self.https_port
    }

    /// Serial console log (how a published guest is observed).
    pub fn serial(&self) -> String {
        read_serial_all(&self.serial_log)
    }

    /// Reset the virtual machine (QEMU `system_reset`), keeping the same disk.
    pub fn qemu_system_reset(&self) -> Result<(), Error> {
        let mut stream = UnixStream::connect(&self.monitor)
            .map_err(|e| Error::from_io("connecting QEMU monitor", e))?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        stream
            .write_all(b"system_reset\n")
            .map_err(|e| Error::from_io("QEMU system_reset", e))?;
        stream
            .flush()
            .map_err(|e| Error::from_io("flushing QEMU monitor", e))?;
        Ok(())
    }

    /// Remove QEMU's second physical NIC while the appliance is running.
    pub fn qemu_unplug_extra_nic(&self) -> Result<(), Error> {
        let mut stream = UnixStream::connect(&self.monitor)
            .map_err(|e| Error::from_io("connecting QEMU monitor", e))?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut reply = [0u8; 4096];
        let mut welcome = String::new();
        while !welcome.ends_with("(qemu) ") {
            let n = stream
                .read(&mut reply)
                .map_err(|e| Error::from_io("reading QEMU monitor prompt", e))?;
            if n == 0 {
                return Err(Error::from_message("QEMU monitor closed before prompt"));
            }
            welcome.push_str(&String::from_utf8_lossy(&reply[..n]));
        }
        stream
            .write_all(b"device_del fwos-extra0\n")
            .and_then(|_| stream.flush())
            .map_err(|e| Error::from_io("QEMU extra NIC hot-unplug", e))?;
        let mut response = String::new();
        while !response.ends_with("(qemu) ") {
            let n = stream
                .read(&mut reply)
                .map_err(|e| Error::from_io("reading QEMU hot-unplug reply", e))?;
            if n == 0 {
                return Err(Error::from_message("QEMU monitor closed during hot-unplug"));
            }
            response.push_str(&String::from_utf8_lossy(&reply[..n]));
        }
        if let Some(error) = response.split("Error:").nth(1) {
            let message = error.split("\r\n").next().unwrap_or(error).trim();
            return Err(Error::from_message(format!(
                "QEMU extra NIC hot-unplug failed: {message}"
            )));
        }
        Ok(())
    }

    /// Restore the task-owned QEMU extra NIC; network startup sees it on the next reset.
    pub fn qemu_replug_extra_nic(&self) -> Result<(), Error> {
        let mut stream = UnixStream::connect(&self.monitor)
            .map_err(|e| Error::from_io("connecting QEMU monitor", e))?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut reply = [0u8; 4096];
        let mut response = String::new();
        while !response.ends_with("(qemu) ") {
            let n = stream
                .read(&mut reply)
                .map_err(|e| Error::from_io("reading QEMU monitor prompt", e))?;
            if n == 0 {
                return Err(Error::from_message("QEMU monitor closed before prompt"));
            }
            response.push_str(&String::from_utf8_lossy(&reply[..n]));
        }
        stream
            .write_all(
                b"device_add virtio-net-pci,netdev=net1,id=fwos-extra0,bus=fwos-hotplug-port0\n",
            )
            .and_then(|_| stream.flush())
            .map_err(|e| Error::from_io("QEMU extra NIC hot-plug", e))?;
        response.clear();
        while !response.ends_with("(qemu) ") {
            let n = stream
                .read(&mut reply)
                .map_err(|e| Error::from_io("reading QEMU hot-plug reply", e))?;
            if n == 0 {
                return Err(Error::from_message("QEMU monitor closed during hot-plug"));
            }
            response.push_str(&String::from_utf8_lossy(&reply[..n]));
        }
        if let Some(error) = response.split("Error:").nth(1) {
            return Err(Error::from_message(format!(
                "QEMU extra NIC hot-plug failed: {}",
                error.split("\r\n").next().unwrap_or(error).trim()
            )));
        }
        Ok(())
    }

    /// Write bytes to the guest serial console.
    pub fn serial_write(&self, data: &str) -> Result<(), Error> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| Error::from_message("serial lock poisoned"))?;
        serial
            .write_all(data.as_bytes())
            .map_err(|e| Error::from_io("writing guest serial", e))?;
        serial
            .flush()
            .map_err(|e| Error::from_io("flushing guest serial", e))?;
        Ok(())
    }

    /// GET `path` on the guest UI over HTTPS from the Workstation (self-signed).
    pub fn https_get(&self, path: &str) -> Result<String, Error> {
        self.https_ok("GET", path, None, 8)
    }

    /// POST JSON `body` to `path` on the guest UI over HTTPS from the Workstation.
    pub fn https_post(&self, path: &str, body: &str) -> Result<String, Error> {
        self.https_ok("POST", path, Some(body), 90)
    }

    /// Submit credentials through HTTPS, retaining only the returned session cookie.
    /// The anonymous request helpers remain anonymous even after this call.
    pub fn https_login(&self, credentials: &str) -> Result<HttpsSession<'_>, Error> {
        let (code, _, headers) = self.https_exchange_headers(
            "10.0.2.15",
            self.https_port,
            "POST",
            "/api/login",
            Some(credentials),
            15,
            &[],
        )?;
        if code != 200 {
            return Err(Error::from_message(format!("HTTPS login status {code}")));
        }
        let cookie = headers
            .lines()
            .find_map(|header| {
                let (name, value) = header.split_once(':')?;
                if !name.eq_ignore_ascii_case("set-cookie") {
                    return None;
                }
                let mut parts = value.trim().split(';');
                let cookie = parts.next()?;
                if !cookie.starts_with("__Host-fwos=") {
                    return None;
                }
                let attributes: Vec<String> =
                    parts.map(|part| part.trim().to_ascii_lowercase()).collect();
                let protected = ["secure", "httponly", "samesite=strict", "path=/"]
                    .iter()
                    .all(|required| attributes.iter().any(|attribute| attribute == required))
                    && !attributes
                        .iter()
                        .any(|attribute| attribute.starts_with("domain="));
                protected.then(|| cookie.to_string())
            })
            .ok_or_else(|| {
                Error::from_message(
                    "login did not set a Secure, HttpOnly, SameSite=Strict host session cookie",
                )
            })?;
        Ok(HttpsSession {
            guest: self,
            cookie,
        })
    }

    /// Drive real rendered sign-in/status/sign-out through the same HTTPS peer
    /// connection. The Node driver is a client of this Guest, not another runner.
    pub fn browser_login(&self, username: &str, password: &str) -> Result<String, Error> {
        let input = serde_json::to_vec(&serde_json::json!({
            "url": format!("https://127.0.0.1:{}", self.https_port),
            "username": username,
            "password": password,
        }))
        .map_err(|_| Error::from_message("encode browser login input"))?;
        let mut command = Command::new("node");
        command.arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/browser/login.mjs"
        ));
        let output = output_with_input(&mut command, &input)
            .map_err(|error| Error::from_io("run rendered UI driver", error))?;
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| Error::from_message("rendered UI driver returned no valid result"))?;
        if !output.status.success()
            || result["ok"] != true
            || result["scenario"] != "local-identity"
        {
            let stage = result["stage"].as_str().unwrap_or("driver");
            return Err(Error::from_message(format!(
                "rendered local-identity scenario failed at {stage}"
            )));
        }
        result["browser"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::from_message("rendered UI driver omitted browser version"))
    }

    /// Drive the published route editor through rendered HTTPS controls.
    pub fn browser_add_static_route(
        &self,
        username: &str,
        password: &str,
        destination: &str,
        gateway: &str,
        device: &str,
    ) -> Result<(), Error> {
        self.browser_static_route_action(
            "add",
            username,
            password,
            "",
            destination,
            gateway,
            device,
        )
    }

    pub fn browser_static_route_action(
        &self,
        action: &str,
        username: &str,
        password: &str,
        existing_destination: &str,
        destination: &str,
        gateway: &str,
        device: &str,
    ) -> Result<(), Error> {
        let input = serde_json::to_vec(&serde_json::json!({
            "url": format!("https://127.0.0.1:{}", self.https_port),
            "action": action,
            "username": username,
            "password": password,
            "existingDestination": existing_destination,
            "destination": destination,
            "gateway": gateway,
            "device": device,
        }))
        .map_err(|_| Error::from_message("encode route browser input"))?;
        let output = output_with_input(
            Command::new("node").arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/browser/routes.mjs"
            )),
            &input,
        )
        .map_err(|error| Error::from_io("run route browser driver", error))?;
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| Error::from_message("route browser driver returned no valid result"))?;
        if !output.status.success() || result["ok"] != true {
            return Err(Error::from_message(format!(
                "rendered route apply failed at {}: {}; route result: {}",
                result["stage"].as_str().unwrap_or("driver"),
                result["error"].as_str().unwrap_or("no browser detail"),
                result["routeResult"].as_str().unwrap_or("")
            )));
        }
        Ok(())
    }

    /// Check the rendered one-NIC warning as the operator changes WAN tagging.
    pub fn browser_one_nic_bootstrap_warning(&self) -> Result<String, Error> {
        let input = serde_json::to_vec(&serde_json::json!({
            "url": format!("https://127.0.0.1:{}", self.https_port),
        }))
        .map_err(|_| Error::from_message("encode Bootstrap warning browser input"))?;
        let mut command = Command::new("node");
        command.arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/browser/bootstrap-warning.mjs"
        ));
        let output = output_with_input(&mut command, &input)
            .map_err(|error| Error::from_io("run rendered Bootstrap warning driver", error))?;
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| {
            Error::from_message("Bootstrap warning browser driver returned no valid result")
        })?;
        if !output.status.success()
            || result["ok"] != true
            || result["scenario"] != "one-nic-warning"
        {
            let stage = result["stage"].as_str().unwrap_or("driver");
            return Err(Error::from_message(format!(
                "rendered one-NIC Bootstrap warning failed at {stage}"
            )));
        }
        result["browser"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                Error::from_message("Bootstrap warning browser driver omitted browser version")
            })
    }

    /// Create a second administrator through the rendered HTTPS UI.
    pub fn browser_create_administrator(
        &self,
        username: &str,
        password: &str,
        new_username: &str,
        new_password: &str,
    ) -> Result<String, Error> {
        self.browser_administrator_action("create", username, password, new_username, new_password)
    }

    pub fn browser_change_administrator_password(
        &self,
        username: &str,
        password: &str,
        target_username: &str,
        new_password: &str,
    ) -> Result<String, Error> {
        self.browser_administrator_action(
            "change",
            username,
            password,
            target_username,
            new_password,
        )
    }

    pub fn browser_change_own_administrator_password(
        &self,
        username: &str,
        password: &str,
        new_password: &str,
    ) -> Result<String, Error> {
        self.browser_administrator_action("change-self", username, password, username, new_password)
    }

    pub fn browser_remove_administrator(
        &self,
        username: &str,
        password: &str,
        target_username: &str,
    ) -> Result<String, Error> {
        self.browser_administrator_action("remove", username, password, target_username, "")
    }

    fn browser_administrator_action(
        &self,
        action: &str,
        username: &str,
        password: &str,
        new_username: &str,
        new_password: &str,
    ) -> Result<String, Error> {
        let input = serde_json::to_vec(&serde_json::json!({
            "url": format!("https://127.0.0.1:{}", self.https_port),
            "action": action,
            "username": username,
            "password": password,
            "newUsername": new_username,
            "newPassword": new_password,
        }))
        .map_err(|_| Error::from_message("encode administrator browser input"))?;
        let mut command = Command::new("node");
        command.arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/browser/administrators.mjs"
        ));
        let output = output_with_input(&mut command, &input)
            .map_err(|error| Error::from_io("run administrator browser driver", error))?;
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| {
            Error::from_message("administrator browser driver returned no valid result")
        })?;
        if !output.status.success()
            || result["ok"] != true
            || result["scenario"] != format!("{action}-administrator")
        {
            let stage = result["stage"].as_str().unwrap_or("driver");
            return Err(Error::from_message(format!(
                "rendered administrator {action} failed at {stage}"
            )));
        }
        result["browser"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                Error::from_message("administrator browser driver omitted browser version")
            })
    }

    /// GET `path` on the extra virtio-net (10.0.3.15) over HTTPS.
    pub fn https_get_extra(&self, path: &str) -> Result<String, Error> {
        let port = self
            .extra_https_port
            .ok_or_else(|| Error::from_message("guest has no extra NIC HTTPS hostfwd"))?;
        let url = format!("https://10.0.3.15{path}");
        let (code, body) = self.https_exchange_at("10.0.3.15", port, "GET", path, None, 8)?;
        if code == 200 {
            Ok(body)
        } else {
            Err(Error::from_message(format!(
                "curl GET {url} http_code={code}: {}",
                body.trim()
            )))
        }
    }

    /// Exchange HTTPS with the configured UI over the extra Traffic NIC.
    pub fn https_exchange_extra(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout_secs: u64,
    ) -> Result<(u16, String), Error> {
        let port = self
            .extra_https_port
            .ok_or_else(|| Error::from_message("guest has no extra NIC HTTPS hostfwd"))?;
        self.https_exchange_at("10.0.3.15", port, method, path, body, timeout_secs)
    }

    /// HTTPS from the Workstation; returns status and body for any complete HTTP response.
    pub fn https_exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
    ) -> Result<(u16, String), Error> {
        self.https_exchange_at(
            "10.0.2.15",
            self.https_port,
            method,
            path,
            body,
            max_time_secs,
        )
    }

    fn https_exchange_at(
        &self,
        guest_ip: &str,
        host_port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
    ) -> Result<(u16, String), Error> {
        let (code, body, _) = self.https_exchange_headers(
            guest_ip,
            host_port,
            method,
            path,
            body,
            max_time_secs,
            &[],
        )?;
        Ok((code, body))
    }

    fn https_exchange_headers(
        &self,
        guest_ip: &str,
        host_port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
        headers: &[String],
    ) -> Result<(u16, String, String), Error> {
        let url = format!("https://{guest_ip}{path}");
        let connect = format!("{guest_ip}:443:127.0.0.1:{host_port}");
        let mut cmd = Command::new("curl");
        cmd.args([
            "-sk",
            "--include",
            "--noproxy",
            "*",
            "--max-time",
            &max_time_secs.to_string(),
            "--http1.1",
            "-H",
            "Connection: close",
            "-X",
            method,
            "--connect-to",
            &connect,
            "-o",
            "-",
            "-w",
            "\nhttp_code=%{http_code}",
        ]);
        if body.is_some() {
            cmd.args(["-H", "Content-Type: application/json"]);
        }
        for header in headers {
            cmd.args(["-H", header]);
        }
        if body.is_some() {
            // Bootstrap and login credentials must not appear in process argv.
            cmd.args(["--data-binary", "@-"]);
        }
        cmd.arg(&url);
        let output = output_with_input(&mut cmd, body.unwrap_or("").as_bytes())
            .map_err(|e| Error::from_io("running curl", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (body, code) = match stdout.rsplit_once("http_code=") {
            Some((body, rest)) => (body.to_string(), rest.trim().parse::<u16>().ok()),
            None => (stdout.into_owned(), None),
        };
        // A complete HTTP response is usable even if curl exits 56 (no TLS close_notify).
        if let Some(code) = code {
            if code != 0 {
                let (headers, body) = body
                    .split_once("\r\n\r\n")
                    .ok_or_else(|| Error::from_message("incomplete HTTPS response headers"))?;
                return Ok((code, body.to_string(), headers.to_string()));
            }
        }
        Err(Error::from_message(format!(
            "curl {method} {url} failed with {} http_code={}: {}\n{}",
            output.status,
            code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
            String::from_utf8_lossy(&output.stderr).trim(),
            body.trim()
        )))
    }

    fn https_ok(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
    ) -> Result<String, Error> {
        let url = format!("https://10.0.2.15{path}");
        let (code, body) = self.https_exchange(method, path, body, max_time_secs)?;
        if code == 200 {
            Ok(body)
        } else {
            Err(Error::from_message(format!(
                "curl {method} {url} http_code={code}: {}",
                body.trim()
            )))
        }
    }

    /// True if the guest answers on TCP port 22 (hostfwd). A test must fail if so.
    pub fn port_22_reachable(&self) -> bool {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port_22));
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 64];
        matches!(stream.read(&mut buf), Ok(n) if n > 0)
    }

    fn wait_or_stop(&mut self, ready: Result<(), Error>) -> Result<(), Error> {
        if let Err(err) = ready {
            let _ = self.child.kill();
            let _ = self.child.wait();
            return Err(err);
        }
        Ok(())
    }

    fn wait_for_serial(&mut self, needle: &str) -> Result<(), Error> {
        self.wait_for_serial_timeout(needle, BOOT_WAIT)
    }

    fn wait_for_serial_timeout(&mut self, needle: &str, wait: Duration) -> Result<(), Error> {
        progress("waiting for Appliance CLI");
        let deadline = Instant::now() + wait;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|e| Error::from_io("waiting for QEMU", e))?
            {
                let serial = read_serial(&self.serial_log);
                return Err(Error::from_message(format!(
                    "QEMU exited before serial {needle:?} (status {status}). serial log:\n{serial}"
                )));
            }
            let serial = read_serial_all(&self.serial_log);
            if serial.contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::from_message(format!(
                    "serial {needle:?} did not appear within {}s. serial log:\n{serial}",
                    wait.as_secs()
                )));
            }
            thread::sleep(Duration::from_secs(2));
        }
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(dir) = self.serial_log.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn ensure_kvm_usable() -> Result<(), Error> {
    match File::open("/dev/kvm") {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(Error::from_message(
            "KVM is not available at /dev/kvm; Workstation tooling needs KVM to boot a guest",
        )),
        Err(err) => Err(Error::from_message(format!(
            "cannot open /dev/kvm ({err}); add this user to the kvm group or run on a host with KVM"
        ))),
    }
}

fn ensure_ovmf() -> Result<(), Error> {
    if Path::new(OVMF_CODE).exists() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "OVMF firmware not found at {OVMF_CODE}"
        )))
    }
}

fn cache_dir(name: &str) -> Result<PathBuf, Error> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| Error::from_message("HOME is unset; cannot place cache"))?;
    let dir = base.join("fwos-dev").join(name);
    fs::create_dir_all(&dir).map_err(|e| Error::from_io("creating cache dir", e))?;
    Ok(dir)
}

fn host_image_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os("FWOS_IMAGE_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join("Containerfile").is_file() {
            return Ok(dir);
        }
        return Err(Error::from_message(format!(
            "FWOS_IMAGE_DIR {} has no Containerfile",
            dir.display()
        )));
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwos-image");
    if sibling.join("Containerfile").is_file() {
        return sibling
            .canonicalize()
            .map_err(|e| Error::from_io("resolving host-image dir", e));
    }
    Err(Error::from_message(
        "host-image checkout not found; clone coldboot-labs/fwos-image next to fwos-dev or set FWOS_IMAGE_DIR",
    ))
}

fn src_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os("FWOS_SRC_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join("Cargo.toml").is_file() {
            return Ok(dir);
        }
        return Err(Error::from_message(format!(
            "FWOS_SRC_DIR {} has no Cargo.toml",
            dir.display()
        )));
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwos-src");
    if sibling.join("Cargo.toml").is_file() {
        return sibling
            .canonicalize()
            .map_err(|e| Error::from_io("resolving fwos-src dir", e));
    }
    Err(Error::from_message(
        "fwos-src checkout not found; clone coldboot-labs/fwos-src next to fwos-dev or set FWOS_SRC_DIR",
    ))
}

fn builtin_addons_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os("FWOS_ADDONS_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join("netd").join("Containerfile").is_file() {
            return Ok(dir);
        }
        return Err(Error::from_message(format!(
            "FWOS_ADDONS_DIR {} has no netd/Containerfile",
            dir.display()
        )));
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwos-builtin-addons");
    if sibling.join("netd").join("Containerfile").is_file() {
        return sibling
            .canonicalize()
            .map_err(|e| Error::from_io("resolving fwos-builtin-addons dir", e));
    }
    Err(Error::from_message(
        "fwos-builtin-addons checkout not found; clone coldboot-labs/fwos-builtin-addons next to fwos-dev or set FWOS_ADDONS_DIR",
    ))
}

fn instance_dir() -> Result<PathBuf, Error> {
    temp_work_dir("fwos-dev-guest", "creating guest work dir")
}

fn ui_build_context() -> Result<PathBuf, Error> {
    temp_work_dir("fwos-dev-ui", "creating UI image context")
}

fn temp_work_dir(prefix: &str, err: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).map_err(|e| Error::from_io(err, e))?;
    Ok(dir)
}

struct HostImageParts {
    src: PathBuf,
    image_dir: PathBuf,
    addons: PathBuf,
    binary: PathBuf,
    netd: PathBuf,
    cli: PathBuf,
    ui: PathBuf,
    update: PathBuf,
}

fn host_image_parts(image_dir: &Path) -> Result<HostImageParts, Error> {
    let src = src_dir()?;
    progress("building host programs");
    let binary = build_host_program(&src)?;
    let netd = src.join("target/release/netd");
    if !netd.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            netd.display()
        )));
    }
    let addons = builtin_addons_dir()?;
    let cli = src.join("target/release/fwos");
    if !cli.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            cli.display()
        )));
    }
    let ui = src.join("target/release/fwos-ui");
    if !ui.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            ui.display()
        )));
    }
    let update = src.join("target/release/fwos-update");
    if !update.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            update.display()
        )));
    }
    Ok(HostImageParts {
        src,
        image_dir: image_dir.to_path_buf(),
        addons,
        binary,
        netd,
        cli,
        ui,
        update,
    })
}

impl HostImageParts {
    fn build_images(&self) -> Result<(), Error> {
        build_host_program_image(&self.src, &self.binary)?;
        progress("building Built-in addons");
        build_netd_image(&self.addons, &self.netd)?;
        build_cli_image(&self.addons, &self.cli)?;
        build_ui_image(&self.addons, &self.ui)?;
        build_vendor_image(&self.addons.join("kea"), KEA_IMAGE_TAG)?;
        build_vendor_image(&self.addons.join("unbound"), UNBOUND_IMAGE_TAG)
    }

    fn stale(&self, artifact: &Path) -> Result<bool, Error> {
        Ok(!artifact.exists()
            || artifact.metadata().map(|m| m.len() == 0).unwrap_or(true)
            || source_newer_than(&self.image_dir, artifact)?
            || file_newer_than(&self.binary, artifact)?
            || file_newer_than(&self.netd, artifact)?
            || file_newer_than(&self.cli, artifact)?
            || file_newer_than(&self.ui, artifact)?
            || file_newer_than(&self.update, artifact)?
            || file_newer_than(&self.addons.join("netd").join("Containerfile"), artifact)?
            || file_newer_than(&self.addons.join("cli").join("Containerfile"), artifact)?
            || file_newer_than(&self.addons.join("ui").join("Containerfile"), artifact)?
            || ui_sources_newer(&self.addons.join("ui"), artifact)?
            || file_newer_than(&self.addons.join("kea").join("Containerfile"), artifact)?
            || file_newer_than(&self.addons.join("kea").join("run-dhcp4"), artifact)?
            || file_newer_than(&self.addons.join("kea").join("run-dhcp6"), artifact)?
            || file_newer_than(&self.addons.join("unbound").join("Containerfile"), artifact)?
            || optional_newer(&self.image_dir.join("bib.toml"), artifact)?)
    }
}

fn ensure_host_qcow2(disk: &Path, image_dir: &Path) -> Result<(), Error> {
    let parts = host_image_parts(image_dir)?;
    if !parts.stale(disk)? {
        return Ok(());
    }
    parts.build_images()?;
    build_host_container(image_dir)?;
    build_qcow2(disk, image_dir, HOST_IMAGE_TAG)
}

fn ensure_host_iso(iso: &Path, image_dir: &Path) -> Result<(), Error> {
    let parts = host_image_parts(image_dir)?;
    let installer_toml = image_dir.join("installer.toml");
    if !parts.stale(iso)? && !optional_newer(&installer_toml, iso)? {
        return Ok(());
    }
    parts.build_images()?;
    build_host_container(image_dir)?;
    build_anaconda_iso(iso, image_dir)
}

fn optional_newer(file: &Path, disk: &Path) -> Result<bool, Error> {
    if file.exists() {
        file_newer_than(file, disk)
    } else {
        Ok(false)
    }
}

fn file_newer_than(file: &Path, disk: &Path) -> Result<bool, Error> {
    let file_mtime = file
        .metadata()
        .and_then(|m| m.modified())
        .map_err(|e| Error::from_io("reading host-program mtime", e))?;
    let disk_mtime = disk
        .metadata()
        .and_then(|m| m.modified())
        .map_err(|e| Error::from_io("reading disk mtime", e))?;
    Ok(file_mtime > disk_mtime)
}

fn build_host_program(src: &Path) -> Result<PathBuf, Error> {
    let output = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(src)
        .output()
        .map_err(|e| Error::from_io("running cargo build", e))?;
    if !output.status.success() {
        return Err(Error::from_message(format!(
            "cargo build of fwos-fwd-setup failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let binary = src.join("target/release/fwos-fwd-setup");
    if !binary.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            binary.display()
        )));
    }
    Ok(binary)
}

fn build_vendor_image(dir: &Path, tag: &str) -> Result<(), Error> {
    let dockerfile = dir.join("Containerfile");
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", tag, "-f"])
        .arg(&dockerfile)
        .arg(dir)
        .output()
        .map_err(|e| Error::from_io("running podman build for vendor addon", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of {tag} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn ui_sources_newer(ui_dir: &Path, disk: &Path) -> Result<bool, Error> {
    if !ui_dir.exists() {
        return Ok(false);
    }
    let disk_mtime = disk
        .metadata()
        .and_then(|m| m.modified())
        .map_err(|e| Error::from_io("reading disk mtime", e))?;
    Ok(newest_mtime(ui_dir)? > disk_mtime)
}

fn build_ui_image(addons: &Path, binary: &Path) -> Result<(), Error> {
    let context = ui_build_context()?;
    fs::copy(binary, context.join("fwos-ui"))
        .map_err(|e| Error::from_io("copying fwos-ui into image context", e))?;
    fs::copy(
        addons.join("ui").join("Containerfile"),
        context.join("Containerfile"),
    )
    .map_err(|e| Error::from_io("copying UI Containerfile", e))?;
    copy_tree(&addons.join("ui").join("static"), &context.join("static"))?;
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", UI_IMAGE_TAG, "-f"])
        .arg(context.join("Containerfile"))
        .arg(&context)
        .output()
        .map_err(|e| Error::from_io("running podman build for ui", e))?;
    let _ = fs::remove_dir_all(&context);
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of ui failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), Error> {
    fs::create_dir_all(dst).map_err(|e| Error::from_io("creating UI static context", e))?;
    if !src.exists() {
        return Err(Error::from_message(format!(
            "UI static assets missing at {}",
            src.display()
        )));
    }
    for entry in
        fs::read_dir(src).map_err(|e| Error::from_io(&format!("read_dir {}", src.display()), e))?
    {
        let entry = entry.map_err(|e| Error::from_io("read_dir entry", e))?;
        let to = dst.join(entry.file_name());
        let ty = entry
            .file_type()
            .map_err(|e| Error::from_io("stat UI static entry", e))?;
        if ty.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), &to).map_err(|e| Error::from_io("copying UI static file", e))?;
        }
    }
    Ok(())
}

fn build_cli_image(addons: &Path, binary: &Path) -> Result<(), Error> {
    let context = binary
        .parent()
        .ok_or_else(|| Error::from_message("cli path has no parent"))?;
    let dockerfile = addons.join("cli").join("Containerfile");
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", CLI_IMAGE_TAG, "-f"])
        .arg(&dockerfile)
        .arg(context)
        .output()
        .map_err(|e| Error::from_io("running podman build for cli", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of cli failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn build_netd_image(addons: &Path, binary: &Path) -> Result<(), Error> {
    let context = binary
        .parent()
        .ok_or_else(|| Error::from_message("netd path has no parent"))?;
    let dockerfile = addons.join("netd").join("Containerfile");
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", NETD_IMAGE_TAG, "-f"])
        .arg(&dockerfile)
        .arg(context)
        .output()
        .map_err(|e| Error::from_io("running podman build for netd", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of netd failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn build_host_program_image(src: &Path, binary: &Path) -> Result<(), Error> {
    let context = binary
        .parent()
        .ok_or_else(|| Error::from_message("host-program path has no parent"))?;
    let dockerfile = src.join("Containerfile");
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", HOST_PROGRAM_TAG, "-f"])
        .arg(&dockerfile)
        .arg(context)
        .output()
        .map_err(|e| Error::from_io("running podman build for fwos-fwd-setup", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of fwos-fwd-setup failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn source_newer_than(image_dir: &Path, disk: &Path) -> Result<bool, Error> {
    let disk_mtime = disk
        .metadata()
        .and_then(|m| m.modified())
        .map_err(|e| Error::from_io("reading disk mtime", e))?;
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for rel in ["Containerfile", "overlay"] {
        let p = image_dir.join(rel);
        if p.exists() {
            let t = newest_mtime(&p)?;
            if t > newest {
                newest = t;
            }
        }
    }
    Ok(newest > disk_mtime)
}

fn newest_mtime(path: &Path) -> Result<std::time::SystemTime, Error> {
    let meta = path
        .metadata()
        .map_err(|e| Error::from_io(&format!("stat {}", path.display()), e))?;
    let mut newest = meta
        .modified()
        .map_err(|e| Error::from_io(&format!("mtime {}", path.display()), e))?;
    if meta.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|e| Error::from_io(&format!("read_dir {}", path.display()), e))?
        {
            let entry = entry.map_err(|e| Error::from_io("read_dir entry", e))?;
            if entry.file_name() == ".git" {
                continue;
            }
            let t = newest_mtime(&entry.path())?;
            if t > newest {
                newest = t;
            }
        }
    }
    Ok(newest)
}

fn build_host_container(image_dir: &Path) -> Result<(), Error> {
    progress("building Host image");
    pull_image(FEDORA_BOOTC)?;
    let output = Command::new("sudo")
        .args(["podman", "build", "--pull=missing", "-t", HOST_IMAGE_TAG])
        .arg(image_dir)
        .output()
        .map_err(|e| Error::from_io("running podman build", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of the host image failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn image_builder_dirs(artifact: &Path) -> Result<(PathBuf, PathBuf), Error> {
    let parent = artifact
        .parent()
        .ok_or_else(|| Error::from_message("artifact path has no parent"))?;
    let out_dir = parent.join("bib-output");
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)
            .map_err(|e| Error::from_io("clearing image-builder output", e))?;
    }
    fs::create_dir_all(&out_dir).map_err(|e| Error::from_io("creating image-builder output", e))?;
    // osbuild export writes /output/<type>/; create it so a late umount race
    // still has a dest directory.
    fs::create_dir_all(out_dir.join("qcow2"))
        .map_err(|e| Error::from_io("creating image-builder qcow2 dest", e))?;
    fs::create_dir_all(out_dir.join("anaconda-iso"))
        .map_err(|e| Error::from_io("creating image-builder iso dest", e))?;
    let config_dir = parent.join("bib-config");
    fs::create_dir_all(&config_dir)
        .map_err(|e| Error::from_io("creating image-builder config dir", e))?;
    Ok((out_dir, config_dir))
}

fn build_qcow2(disk: &Path, image_dir: &Path, image_ref: &str) -> Result<(), Error> {
    progress("writing Disk image");
    let bib = image_dir.join("bib.toml");
    if !bib.is_file() {
        return Err(Error::from_message(
            "Disk image needs bib.toml in the host-image checkout (no users, no SSH key)",
        ));
    }
    let config =
        fs::read_to_string(&bib).map_err(|e| Error::from_io("reading published bib.toml", e))?;
    let mut last_err = None;
    for attempt in 1..=2 {
        let (out_dir, config_dir) = image_builder_dirs(disk)?;
        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, &config)
            .map_err(|e| Error::from_io("writing image-builder config", e))?;
        match run_image_builder(&config_path, &out_dir, image_ref, false, "qcow2", None) {
            Ok(()) => {
                let produced = out_dir.join("qcow2").join("disk.qcow2");
                if !produced.exists() {
                    last_err = Some(Error::from_message(format!(
                        "image-builder succeeded but {} is missing",
                        produced.display()
                    )));
                    continue;
                }
                fs::rename(&produced, disk)
                    .map_err(|e| Error::from_io("moving qcow2 into cache", e))?;
                return Ok(());
            }
            Err(err) => {
                last_err = Some(err);
                if attempt == 1 {
                    progress("image-builder failed; retrying Disk image write");
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::from_message("image-builder failed")))
}

fn build_anaconda_iso(iso: &Path, image_dir: &Path) -> Result<(), Error> {
    progress("writing Installer ISO");
    let installer_toml = image_dir.join("installer.toml");
    if !installer_toml.is_file() {
        return Err(Error::from_message(format!(
            "Installer needs installer.toml in the host-image checkout (kickstart lives with the Host image); missing {}",
            installer_toml.display()
        )));
    }
    let config = fs::read_to_string(&installer_toml)
        .map_err(|e| Error::from_io("reading installer.toml", e))?;
    let (out_dir, config_dir) = image_builder_dirs(iso)?;
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config)
        .map_err(|e| Error::from_io("writing image-builder installer config", e))?;
    let (id, version) = host_image_id_version()?;
    let def_name = format!("{id}-{version}.yaml");
    let def_host = materialize_iso_distro_def(&config_dir, &def_name, &version)?;
    let def_dest = format!("/usr/share/bootc-image-builder/defs/{def_name}");
    run_image_builder(
        &config_path,
        &out_dir,
        HOST_IMAGE_TAG,
        false,
        "anaconda-iso",
        Some((&def_host, &def_dest)),
    )?;
    let produced = find_iso(&out_dir)?;
    fs::rename(&produced, iso).map_err(|e| Error::from_io("moving Installer ISO into cache", e))?;
    Ok(())
}

fn run_image_builder(
    config_path: &Path,
    out_dir: &Path,
    image_ref: &str,
    pull: bool,
    image_type: &str,
    distro_def: Option<(&Path, &str)>,
) -> Result<(), Error> {
    let (uid, gid) = current_uid_gid()?;
    if pull {
        pull_image(image_ref)?;
    }
    pull_image(IMAGE_BUILDER)?;
    let mut cmd = Command::new("sudo");
    cmd.args([
        "podman",
        "run",
        "--rm",
        "--privileged",
        "--pull=newer",
        "--security-opt",
        "label=type:unconfined_t",
        "-v",
    ])
    .arg(format!("{}:/config.toml:ro", config_path.display()))
    .arg("-v")
    .arg(format!("{}:/output", out_dir.display()));
    if let Some((host, dest)) = distro_def {
        cmd.arg("-v").arg(format!("{}:{dest}:ro", host.display()));
    }
    let output = cmd
        .args([
            "-v",
            "/var/lib/containers/storage:/var/lib/containers/storage",
            IMAGE_BUILDER,
            "--type",
            image_type,
            "--rootfs",
            "ext4",
            "--use-librepo=True",
            "--progress",
            "verbose",
            "--config",
            "/config.toml",
            "--chown",
        ])
        .arg(format!("{uid}:{gid}"))
        .arg(image_ref)
        .output()
        .map_err(|e| Error::from_io("running image-builder (podman)", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "image-builder failed with {} while converting {image_ref} to {image_type}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn host_image_id_version() -> Result<(String, String), Error> {
    let output = Command::new("sudo")
        .args([
            "podman",
            "run",
            "--rm",
            HOST_IMAGE_TAG,
            "cat",
            "/usr/lib/os-release",
        ])
        .output()
        .map_err(|e| Error::from_io("reading host image os-release", e))?;
    if !output.status.success() {
        return Err(Error::from_message(format!(
            "podman run {HOST_IMAGE_TAG} cat /usr/lib/os-release failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let id = os_release_field(&text, "ID")
        .ok_or_else(|| Error::from_message("host image os-release has no ID"))?;
    let version = os_release_field(&text, "VERSION_ID")
        .ok_or_else(|| Error::from_message("host image os-release has no VERSION_ID"))?;
    Ok((id, version))
}

fn os_release_field(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(&prefix)
            .map(|v| v.trim_matches('"').to_string())
    })
}

fn materialize_iso_distro_def(
    config_dir: &Path,
    def_name: &str,
    version: &str,
) -> Result<PathBuf, Error> {
    // anaconda-iso looks up defs/{ID}-{VERSION_ID}.yaml; branded ID=fwos has none.
    let dest = config_dir.join(def_name);
    let mut last_err = String::from("no fedora ISO def in image-builder");
    for candidate in [
        format!("fedora-{version}.yaml"),
        "fedora-42.yaml".into(),
        "fedora-40.yaml".into(),
    ] {
        let output = Command::new("sudo")
            .args([
                "podman",
                "run",
                "--rm",
                "--entrypoint",
                "cat",
                IMAGE_BUILDER,
            ])
            .arg(format!("/usr/share/bootc-image-builder/defs/{candidate}"))
            .output()
            .map_err(|e| Error::from_io("reading image-builder distro def", e))?;
        if output.status.success() && !output.stdout.is_empty() {
            fs::write(&dest, &output.stdout)
                .map_err(|e| Error::from_io("writing ISO distro def", e))?;
            return Ok(dest);
        }
        last_err = format!(
            "{candidate}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Err(Error::from_message(format!(
        "could not materialize {def_name} from image-builder fedora ISO defs: {last_err}"
    )))
}

fn find_iso(dir: &Path) -> Result<PathBuf, Error> {
    let mut found = Vec::new();
    collect_isos(dir, &mut found)?;
    found.into_iter().next().ok_or_else(|| {
        Error::from_message(format!(
            "image-builder succeeded but no ISO was produced under {}",
            dir.display()
        ))
    })
}

fn collect_isos(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), Error> {
    for entry in
        fs::read_dir(dir).map_err(|e| Error::from_io(&format!("read_dir {}", dir.display()), e))?
    {
        let entry = entry.map_err(|e| Error::from_io("read_dir entry", e))?;
        let path = entry.path();
        let ty = entry
            .file_type()
            .map_err(|e| Error::from_io("stat image-builder output", e))?;
        if ty.is_dir() {
            collect_isos(&path, found)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("iso") {
            found.push(path);
        }
    }
    Ok(())
}

fn pull_image(image: &str) -> Result<(), Error> {
    let output = Command::new("sudo")
        .args(["podman", "pull", image])
        .output()
        .map_err(|e| Error::from_io("running podman pull", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman pull {image} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn current_uid_gid() -> Result<(u32, u32), Error> {
    let uid = id_flag("-u")?;
    let gid = id_flag("-g")?;
    Ok((uid, gid))
}

fn id_flag(flag: &str) -> Result<u32, Error> {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .map_err(|e| Error::from_io("running id", e))?;
    if !output.status.success() {
        return Err(Error::from_message(format!("id {flag} failed")));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Error::from_message("id output was not UTF-8"))?
        .trim()
        .parse()
        .map_err(|_| Error::from_message("id output was not a number"))
}

fn create_overlay(base: &Path, overlay: &Path) -> Result<(), Error> {
    let status = Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(base)
        .arg(overlay)
        .status()
        .map_err(|e| Error::from_io("running qemu-img", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "qemu-img create overlay failed with {status}"
        )))
    }
}

fn free_localhost_port() -> Result<u16, Error> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::from_io("binding ephemeral port", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::from_io("reading ephemeral port", e))?
        .port();
    Ok(port)
}

fn spawn_guest(opts: QemuStart<'_>) -> Result<Guest, Error> {
    progress("starting QEMU");
    let mut child = start_qemu(opts)?;
    let serial = match connect_serial(opts.serial_sock, opts.serial_log) {
        Ok(s) => s,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    Ok(Guest {
        child,
        port_22: opts.port_22,
        https_port: opts.https_port,
        extra_https_port: opts.extra_https_port,
        serial_log: opts.serial_log.to_path_buf(),
        serial: Mutex::new(serial),
        monitor: opts.monitor.to_path_buf(),
    })
}

fn start_qemu(opts: QemuStart<'_>) -> Result<Child, Error> {
    let _ = fs::remove_file(opts.monitor);
    let _ = fs::remove_file(opts.serial_sock);
    let qemu_err = opts.serial_log.with_file_name("qemu.stderr");
    let err = File::create(&qemu_err).map_err(|e| Error::from_io("creating qemu stderr", e))?;
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        QEMU_MEMORY_MIB,
        "-bios",
        OVMF_CODE,
        "-drive",
    ])
    .arg(format!(
        "file={},if=virtio,format=qcow2",
        opts.boot_disk.display()
    ));
    for disk in opts.extra_disks {
        cmd.arg("-drive")
            .arg(format!("file={},if=virtio,format=qcow2", disk.display()));
    }
    if let Some(cdrom) = opts.cdrom {
        cmd.arg("-cdrom").arg(cdrom);
    }
    if let Some(linux) = opts.linux {
        cmd.arg("-kernel")
            .arg(&linux.kernel)
            .arg("-initrd")
            .arg(&linux.initrd)
            .arg("-append")
            .arg(&linux.append);
    }
    if opts.no_reboot {
        cmd.arg("-no-reboot");
    }
    if opts.peer_taps.is_empty() || opts.user_net_with_peers {
        cmd.args([
            "-netdev",
            &format!(
                "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:443",
                opts.port_22, opts.https_port
            ),
        ])
        .args(["-device", "virtio-net-pci,netdev=net0"]);
    }
    if !opts.peer_taps.is_empty() {
        for (index, tap) in opts.peer_taps.iter().enumerate() {
            cmd.args([
                "-netdev",
                &format!("tap,id=peer{index},ifname={tap},script=no,downscript=no"),
                "-device",
                &format!("virtio-net-pci,netdev=peer{index}"),
            ]);
        }
    }
    for i in 0..opts.extra_nics {
        let id = format!("net{}", i + 1);
        let net = format!("10.0.{}.0/24", i + 3);
        let mut netdev = format!("user,id={id},net={net}");
        if i == 0 {
            if let Some(port) = opts.extra_https_port {
                netdev.push_str(&format!(",hostfwd=tcp:127.0.0.1:{port}-:443"));
            }
        }
        if i == 0 {
            cmd.args([
                "-device",
                "pcie-root-port,id=fwos-hotplug-port0,chassis=1,slot=1",
            ]);
        }
        let bus = if i == 0 {
            ",bus=fwos-hotplug-port0"
        } else {
            ""
        };
        cmd.args(["-netdev", &netdev]).args([
            "-device",
            &format!("virtio-net-pci,netdev={id},id=fwos-extra{i}{bus}"),
        ]);
    }
    let child = cmd
        .args(["-device", "virtio-rng-pci"])
        .args([
            "-monitor",
            &format!("unix:{},server,nowait", opts.monitor.display()),
        ])
        .args(["-display", "none"])
        .arg("-serial")
        .arg(format!(
            "unix:{},server=on,wait=off",
            opts.serial_sock.display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| Error::from_io("starting QEMU", e))?;
    Ok(child)
}

fn connect_serial(sock: &Path, log: &Path) -> Result<UnixStream, Error> {
    File::create(log).map_err(|e| Error::from_io("creating serial log", e))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let stream = loop {
        match UnixStream::connect(sock) {
            Ok(s) => break s,
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(Error::from_io("connecting guest serial", err));
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    };
    let mut reader = stream
        .try_clone()
        .map_err(|e| Error::from_io("cloning serial stream", e))?;
    let log_path = log.to_path_buf();
    let _ = reader.set_read_timeout(None);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .and_then(|mut f| f.write_all(&buf[..n]));
        }
    });
    Ok(stream)
}

fn read_serial(path: &Path) -> String {
    tail_bytes(path, 8000)
}

fn read_serial_all(path: &Path) -> String {
    match fs::read(path) {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(err) => format!("(could not read serial log: {err})"),
    }
}

fn tail_bytes(path: &Path, keep: usize) -> String {
    let mut buf = Vec::new();
    match File::open(path).and_then(|mut f| f.read_to_end(&mut buf)) {
        Ok(_) => {
            let tail = if buf.len() > keep {
                &buf[buf.len() - keep..]
            } else {
                buf.as_slice()
            };
            String::from_utf8_lossy(tail).into_owned()
        }
        Err(err) => format!("(could not read serial log: {err})"),
    }
}

/// Disk image: no injected SSH key, no default password.
pub fn build_published_host_image_disk() -> Result<PathBuf, Error> {
    let cache = cache_dir("fwos-host")?;
    let disk_path = cache.join("published.qcow2");
    let image_dir = host_image_dir()?;
    ensure_host_qcow2(&disk_path, &image_dir)?;
    Ok(disk_path)
}

/// Anaconda Installer ISO from the same Host image (self-contained, no registry).
pub fn build_installer_iso() -> Result<PathBuf, Error> {
    let cache = cache_dir("fwos-host")?;
    let iso_path = cache.join("installer.iso");
    let image_dir = host_image_dir()?;
    ensure_host_iso(&iso_path, &image_dir)?;
    Ok(iso_path)
}

fn install_host_image_disk() -> Result<PathBuf, Error> {
    let iso = build_installer_iso()?;
    let cache = cache_dir("fwos-host")?;
    let disk = cache.join("installed.qcow2");
    if disk.exists()
        && disk
            .metadata()
            .map(|m| m.len() > MIN_INSTALLED_DISK)
            .unwrap_or(false)
        && !file_newer_than(&iso, &disk)?
    {
        return Ok(disk);
    }
    if let Err(err) = run_iso_install(&iso, &disk) {
        let _ = fs::remove_file(&disk);
        return Err(err);
    }
    Ok(disk)
}

fn run_iso_install(iso: &Path, disk: &Path) -> Result<(), Error> {
    ensure_kvm_usable()?;
    ensure_ovmf()?;
    create_empty_qcow2(disk)?;
    let work = instance_dir()?;
    let linux = extract_iso_linux(iso, &work)?;
    let port = free_localhost_port()?;
    let https_port = free_localhost_port()?;
    let serial_log = work.join("serial.log");
    let serial_sock = work.join("serial.sock");
    let monitor = work.join("monitor.sock");
    let mut child = start_qemu(QemuStart {
        boot_disk: disk,
        extra_disks: &[],
        cdrom: Some(iso),
        linux: Some(&linux),
        extra_nics: 0,
        peer_taps: &[],
        user_net_with_peers: false,
        port_22: port,
        https_port,
        extra_https_port: None,
        serial_log: &serial_log,
        serial_sock: &serial_sock,
        monitor: &monitor,
        no_reboot: true,
    })?;
    let mut serial = match connect_serial(&serial_sock, &serial_log) {
        Ok(s) => s,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&work);
            return Err(err);
        }
    };
    progress("waiting for Installer wipe approval");
    let prompt_deadline = Instant::now() + INSTALLER_PROMPT_WAIT;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| Error::from_io("waiting for installer QEMU", e))?
        {
            let serial = read_serial_all(&serial_log);
            let _ = fs::remove_dir_all(&work);
            return Err(Error::from_message(format!(
                "QEMU exited before Installer wipe approval (status {status}). serial log:\n{serial}"
            )));
        }
        let log = read_serial_all(&serial_log);
        if log.contains(INSTALLER_WIPE_PROMPT) && log.contains("Type yes to wipe") {
            break;
        }
        if Instant::now() >= prompt_deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&work);
            return Err(Error::from_message(format!(
                "Installer wipe approval did not appear within {}s. serial log:\n{log}",
                INSTALLER_PROMPT_WAIT.as_secs()
            )));
        }
        thread::sleep(Duration::from_secs(2));
    }
    if let Err(error) = ready_installer_approval(&mut child, &mut serial, &serial_log) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&work);
        return Err(error);
    }
    serial
        .write_all(b"yes\r\n")
        .map_err(|e| Error::from_io("writing Installer yes", e))?;
    serial
        .flush()
        .map_err(|e| Error::from_io("flushing Installer yes", e))?;
    let deadline = Instant::now() + INSTALL_WAIT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| Error::from_io("waiting for installer QEMU", e))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let serial = read_serial_all(&serial_log);
            let _ = fs::remove_dir_all(&work);
            return Err(Error::from_message(format!(
                "Installer did not finish writing the empty disk within {}s. serial log:\n{serial}",
                INSTALL_WAIT.as_secs()
            )));
        }
        thread::sleep(Duration::from_secs(2));
    };
    let serial = read_serial_all(&serial_log);
    let _ = fs::remove_dir_all(&work);
    let size = disk.metadata().map(|m| m.len()).unwrap_or(0);
    if size < MIN_INSTALLED_DISK {
        return Err(Error::from_message(format!(
            "Installer QEMU exited ({status}) but the disk is too small ({size} bytes). serial log:\n{serial}"
        )));
    }
    Ok(())
}

fn ready_installer_approval(
    child: &mut Child,
    serial: &mut UnixStream,
    serial_log: &Path,
) -> Result<(), Error> {
    // This path creates exactly one empty virtio disk: never approve a disk
    // picker or a different target. Enter declines; only the caller sends yes.
    const PROMPT: &str = "Type yes to wipe /dev/vda: ";
    let started = Instant::now();
    let mut last_size = 0;
    let mut changed = started;
    let mut attempts = 0;
    let mut pending: Option<(usize, Instant)> = None;
    while started.elapsed() < Duration::from_secs(60) {
        if child
            .try_wait()
            .map_err(|error| Error::from_io("checking Installer readiness", error))?
            .is_some()
        {
            return Err(Error::from_message(
                "Installer exited during approval readiness",
            ));
        }
        let log = fs::read(serial_log)
            .map_err(|error| Error::from_io("reading Installer readiness serial", error))?;
        let text = String::from_utf8_lossy(&log);
        let other_target = text.split("Type yes to wipe ").skip(1).any(|tail| {
            tail.split_once(':')
                .is_some_and(|(target, _)| target != "/dev/vda")
        });
        if text.contains(INSTALLER_DISK_PROMPT) || other_target {
            return Err(Error::from_message(
                "Installer approval target changed; refusing automatic approval",
            ));
        }
        if log.len() != last_size {
            last_size = log.len();
            changed = Instant::now();
        }
        if let Some((offset, sent)) = pending {
            let fresh = log.get(offset..).ok_or_else(|| {
                Error::from_message("Installer serial log shrank during approval readiness")
            })?;
            if String::from_utf8_lossy(fresh).contains(PROMPT) {
                return Ok(());
            }
            if sent.elapsed() >= Duration::from_secs(10) {
                pending = None;
                if attempts == 3 {
                    break;
                }
            }
        }
        // Anaconda can reset ttyS0 after its first visible prompt. Wait for
        // terminal output to settle, then require a new response to safe input.
        if pending.is_none() && changed.elapsed() >= Duration::from_secs(2) && text.contains(PROMPT)
        {
            attempts += 1;
            let offset = log.len();
            serial
                .write_all(b"\n")
                .and_then(|_| serial.flush())
                .map_err(|error| Error::from_io("probing Installer approval with Enter", error))?;
            pending = Some((offset, Instant::now()));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(Error::from_message(format!(
        "Installer approval readiness failed: stage=fresh-prompt attempts={attempts} serial_offset={last_size} elapsed_ms={}",
        started.elapsed().as_millis()
    )))
}

fn create_empty_qcow2(path: &Path) -> Result<(), Error> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| Error::from_io("removing old empty disk", e))?;
    }
    let status = Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(path)
        .arg(EMPTY_DISK_SIZE)
        .status()
        .map_err(|e| Error::from_io("running qemu-img create", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "qemu-img create empty disk failed with {status}"
        )))
    }
}

fn create_partitioned_qcow2(path: &Path) -> Result<(), Error> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| Error::from_io("removing old partitioned disk", e))?;
    }
    let raw = path.with_extension("raw");
    let _ = fs::remove_file(&raw);
    let created = Command::new("qemu-img")
        .args(["create", "-f", "raw"])
        .arg(&raw)
        .arg(EMPTY_DISK_SIZE)
        .status()
        .map_err(|e| Error::from_io("running qemu-img create raw", e))?;
    if !created.success() {
        let _ = fs::remove_file(&raw);
        return Err(Error::from_message(format!(
            "qemu-img create partitioned raw disk failed with {created}"
        )));
    }
    let parted = Command::new("parted")
        .args(["-s"])
        .arg(&raw)
        .args([
            "mklabel", "gpt", "mkpart", "p1", "1MiB", "1025MiB", "mkpart", "p2", "1025MiB", "100%",
        ])
        .status()
        .map_err(|e| Error::from_io("running parted", e))?;
    if !parted.success() {
        let _ = fs::remove_file(&raw);
        return Err(Error::from_message(format!(
            "parted gpt partitions failed with {parted}"
        )));
    }
    // 1MiB GPT offset, 1GiB ext4 so udev can report a filesystem when known.
    let mkfs = Command::new("mke2fs")
        .args(["-t", "ext4", "-F", "-E", "offset=1048576", "-b", "4096"])
        .arg(&raw)
        .arg("262144")
        .status()
        .map_err(|e| Error::from_io("running mke2fs", e))?;
    if !mkfs.success() {
        let _ = fs::remove_file(&raw);
        return Err(Error::from_message(format!(
            "mke2fs ext4 on first partition failed with {mkfs}"
        )));
    }
    let converted = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2"])
        .arg(&raw)
        .arg(path)
        .status()
        .map_err(|e| Error::from_io("running qemu-img convert", e))?;
    let _ = fs::remove_file(&raw);
    if converted.success() {
        Ok(())
    } else {
        let _ = fs::remove_file(path);
        Err(Error::from_message(format!(
            "qemu-img convert partitioned disk failed with {converted}"
        )))
    }
}

fn extract_iso_linux(iso: &Path, dest: &Path) -> Result<IsoLinux, Error> {
    let listing = iso_listing(iso)?;
    if !listing.iter().any(|p| {
        let u = p.replace('\\', "/").to_ascii_uppercase();
        u.contains("BOOTX64.EFI") || u.contains("/EFI/BOOT")
    }) {
        return Err(Error::from_message(
            "Installer ISO is not UEFI (no EFI/BOOT)",
        ));
    }
    let kernel_src = iso_find(
        &listing,
        &[
            "/images/pxeboot/vmlinuz",
            "/images/pxeboot/vmlinuz.img",
            "/isolinux/vmlinuz",
        ],
    )
    .ok_or_else(|| {
        Error::from_message(format!(
            "Installer ISO has no kernel under images/pxeboot; contents:\n{}",
            listing
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        ))
    })?;
    let initrd_src = iso_find(
        &listing,
        &[
            "/images/pxeboot/initrd.img",
            "/images/pxeboot/initrd",
            "/isolinux/initrd.img",
        ],
    )
    .ok_or_else(|| Error::from_message("Installer ISO has no initrd under images/pxeboot"))?;
    let ks = listing
        .iter()
        .find(|p| {
            let name = p.rsplit('/').next().unwrap_or(p.as_str());
            name.eq_ignore_ascii_case("osbuild.ks")
        })
        .or_else(|| {
            listing.iter().find(|p| {
                let name = p.rsplit('/').next().unwrap_or(p.as_str());
                name.ends_with(".ks") && !name.contains("osbuild-base")
            })
        })
        .map(|p| p.trim_start_matches('/').to_string())
        .unwrap_or_else(|| "osbuild.ks".into());
    let kernel = dest.join("vmlinuz");
    let initrd = dest.join("initrd.img");
    iso_extract(iso, kernel_src, &kernel)?;
    iso_extract(iso, initrd_src, &initrd)?;
    let append = format!(
        "console=ttyS0,115200 inst.text inst.stage2=cdrom inst.ks=cdrom:/{ks} rd.neednet=0"
    );
    Ok(IsoLinux {
        kernel,
        initrd,
        append,
    })
}

fn iso_listing(iso: &Path) -> Result<Vec<String>, Error> {
    for extra in [Some("-J"), Some("-R"), None] {
        let mut cmd = Command::new("isoinfo");
        cmd.args(["-f", "-i"]).arg(iso);
        if let Some(flag) = extra {
            cmd.arg(flag);
        }
        let output = cmd
            .output()
            .map_err(|e| Error::from_io("running isoinfo", e))?;
        if !output.status.success() {
            continue;
        }
        let paths: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !paths.is_empty() {
            return Ok(paths);
        }
    }
    Err(Error::from_message(format!(
        "isoinfo could not list {}",
        iso.display()
    )))
}

fn iso_find<'a>(paths: &'a [String], names: &[&str]) -> Option<&'a str> {
    for name in names {
        let trimmed = name.trim_start_matches('/');
        for p in paths {
            let ptrim = p.trim_start_matches('/');
            if p.eq_ignore_ascii_case(name) || ptrim.eq_ignore_ascii_case(trimmed) {
                return Some(p.as_str());
            }
        }
    }
    None
}

fn iso_extract(iso: &Path, src: &str, dest: &Path) -> Result<(), Error> {
    for extra in [Some("-J"), Some("-R"), None] {
        let mut cmd = Command::new("isoinfo");
        cmd.arg("-i").arg(iso).arg("-x").arg(src);
        if let Some(flag) = extra {
            cmd.arg(flag);
        }
        let output = cmd
            .output()
            .map_err(|e| Error::from_io("extracting from Installer ISO", e))?;
        if output.status.success() && output.stdout.len() > 1024 {
            fs::write(dest, &output.stdout)
                .map_err(|e| Error::from_io("writing extracted ISO file", e))?;
            return Ok(());
        }
    }
    let status = Command::new("xorriso")
        .args(["-osirrox", "on", "-indev"])
        .arg(iso)
        .arg("-extract")
        .arg(src)
        .arg(dest)
        .arg("--")
        .status()
        .map_err(|e| Error::from_io("running xorriso extract", e))?;
    if status.success() && dest.metadata().map(|m| m.len() > 1024).unwrap_or(false) {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "could not extract {src} from {}",
            iso.display()
        )))
    }
}

/// Workstation-local registry serving a newer Release for Host update tests.
pub struct LocalRegistry {
    container: String,
    port: u16,
}

impl LocalRegistry {
    /// Build a newer Host image (one tag: Host image plus Built-in addons) and serve it over HTTP.
    pub fn publish_next_release() -> Result<Self, Error> {
        Self::publish(false)
    }

    /// Same, but the newer Release has no netd — appliance health must roll it back.
    pub fn publish_dead_netd_release() -> Result<Self, Error> {
        Self::publish(true)
    }

    fn publish(dead_netd: bool) -> Result<Self, Error> {
        let image_dir = host_image_dir()?;
        let parts = host_image_parts(&image_dir)?;
        parts.build_images()?;
        build_host_container(&image_dir)?;
        build_next_release(dead_netd)?;
        let port = free_localhost_port()?;
        let container = format!("fwos-registry-{port}");
        start_registry(&container, port)?;
        if let Err(err) = push_next_release(port) {
            stop_registry(&container);
            return Err(err);
        }
        Ok(Self { container, port })
    }

    /// Image ref the guest uses (QEMU user-net host is 10.0.2.2).
    pub fn guest_image(&self) -> String {
        format!("10.0.2.2:{}/fwos:next", self.port)
    }
}

impl Drop for LocalRegistry {
    fn drop(&mut self) {
        stop_registry(&self.container);
    }
}

fn stop_registry(name: &str) {
    let _ = Command::new("sudo")
        .args(["podman", "rm", "-f", name])
        .status();
}

fn build_next_release(dead_netd: bool) -> Result<(), Error> {
    let ctx = temp_work_dir("fwos-dev-next", "creating next Release context")?;
    let body = if dead_netd {
        "FROM localhost/fwos:dev\n\
         RUN rm -f /usr/share/containers/systemd/fwos-netd.container \\\n\
         && ln -sfn /dev/null /etc/systemd/system/fwos-netd.service \\\n\
         && printf 'next\\n' > /usr/lib/fwos/release \\\n\
         && ostree container commit\n"
    } else {
        "FROM localhost/fwos:dev\nRUN printf 'next\\n' > /usr/lib/fwos/release && ostree container commit\n"
    };
    fs::write(ctx.join("Containerfile"), body)
        .map_err(|e| Error::from_io("writing next Release Containerfile", e))?;
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", NEXT_IMAGE_TAG, "-f"])
        .arg(ctx.join("Containerfile"))
        .arg(&ctx)
        .output()
        .map_err(|e| Error::from_io("running podman build for next Release", e))?;
    let _ = fs::remove_dir_all(&ctx);
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman build of {NEXT_IMAGE_TAG} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn start_registry(name: &str, port: u16) -> Result<(), Error> {
    stop_registry(name);
    pull_image(REGISTRY_IMAGE)?;
    let output = Command::new("sudo")
        .args([
            "podman",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            &format!("127.0.0.1:{port}:5000"),
            REGISTRY_IMAGE,
        ])
        .output()
        .map_err(|e| Error::from_io("starting Workstation-local registry", e))?;
    if !output.status.success() {
        return Err(Error::from_message(format!(
            "podman run {REGISTRY_IMAGE} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if let Err(err) = wait_tcp("127.0.0.1", port, Duration::from_secs(30)) {
        stop_registry(name);
        return Err(err);
    }
    Ok(())
}

fn push_next_release(port: u16) -> Result<(), Error> {
    let dest = format!("127.0.0.1:{port}/fwos:next");
    let tag = Command::new("sudo")
        .args(["podman", "tag", NEXT_IMAGE_TAG, &dest])
        .output()
        .map_err(|e| Error::from_io("tagging next Release for the registry", e))?;
    if !tag.status.success() {
        return Err(Error::from_message(format!(
            "podman tag {NEXT_IMAGE_TAG} {dest} failed with {}: {}",
            tag.status,
            String::from_utf8_lossy(&tag.stderr).trim()
        )));
    }
    let push = Command::new("sudo")
        .args(["podman", "push", "--tls-verify=false", &dest])
        .output()
        .map_err(|e| Error::from_io("pushing next Release", e))?;
    if push.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "podman push {dest} failed with {}: {}",
            push.status,
            String::from_utf8_lossy(&push.stderr).trim()
        )))
    }
}

fn wait_tcp(host: &str, port: u16, wait: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + wait;
    loop {
        if TcpStream::connect((host, port)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::from_message(format!(
                "Workstation-local registry did not listen on {host}:{port} within {}s",
                wait.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
