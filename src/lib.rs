use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const FEDORA_BOOTC: &str = "quay.io/fedora/fedora-bootc:44";
const HOST_IMAGE_TAG: &str = "localhost/fwos:dev";
const HOST_PROGRAM_TAG: &str = "localhost/fwos-fwd-setup:dev";
const NETD_IMAGE_TAG: &str = "localhost/fwos-netd:dev";
const CLI_IMAGE_TAG: &str = "localhost/fwos-cli:dev";
const UI_IMAGE_TAG: &str = "localhost/fwos-ui:dev";
const KEA_IMAGE_TAG: &str = "localhost/fwos-kea:dev";
const UNBOUND_IMAGE_TAG: &str = "localhost/fwos-unbound:dev";
const IMAGE_BUILDER: &str = "quay.io/centos-bootc/bootc-image-builder:latest";
const GUEST_USER: &str = "fwos";
const SSH_WAIT: Duration = Duration::from_secs(240);
const INSTALL_WAIT: Duration = Duration::from_secs(1800);
const INSTALLER_PROMPT_WAIT: Duration = Duration::from_secs(600);
const QEMU_MEMORY_MIB: &str = "4096";
const OVMF_CODE: &str = "/usr/share/edk2/ovmf/OVMF_CODE.fd";
const SERIAL_BOOTSTRAP: &str = "FWOS Bootstrap console";
const INSTALLER_DISK_PROMPT: &str = "FWOS Installer: pick a disk to wipe";
const EMPTY_DISK_SIZE: &str = "10G";
const MIN_INSTALLED_DISK: u64 = 64 * 1024 * 1024;

enum BootWait {
    Ssh,
    SerialBootstrap,
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
    port: u16,
    https_port: u16,
    serial_log: &'a Path,
    serial_sock: &'a Path,
    monitor: &'a Path,
    no_reboot: bool,
}

/// A QEMU guest started by Workstation tooling.
pub struct Guest {
    child: Child,
    port: u16,
    https_port: u16,
    key_path: Option<PathBuf>,
    serial_log: PathBuf,
    serial: Mutex<UnixStream>,
    monitor: PathBuf,
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

impl Guest {
    /// Build a qcow2 from Fedora bootc if needed, boot it under QEMU, wait until SSH works.
    pub fn boot_fedora_bootc() -> Result<Self, Error> {
        let cache = cache_dir("fedora-bootc-44")?;
        let key_path = cache.join("id_ed25519");
        let pub_path = cache.join("id_ed25519.pub");
        let disk_path = cache.join("disk.qcow2");
        ensure_ssh_key(&key_path, &pub_path)?;
        ensure_qcow2(&disk_path, &pub_path, FEDORA_BOOTC, true)?;
        Self::boot_disk(&disk_path, Some(&key_path), 0, BootWait::Ssh)
    }

    /// Build a qcow2 from the FWOS host image if needed, boot it under QEMU, wait until SSH works.
    pub fn boot_host_image() -> Result<Self, Error> {
        let cache = cache_dir("fwos-host")?;
        let key_path = cache.join("id_ed25519");
        let pub_path = cache.join("id_ed25519.pub");
        let disk_path = cache.join("disk.qcow2");
        ensure_ssh_key(&key_path, &pub_path)?;
        let image_dir = host_image_dir()?;
        ensure_host_qcow2(&disk_path, Some(&pub_path), &image_dir)?;
        Self::boot_disk(&disk_path, Some(&key_path), 0, BootWait::Ssh)
    }

    /// Same as `boot_host_image`, with a second virtio-net (no SSH forward).
    pub fn boot_host_image_two_nics() -> Result<Self, Error> {
        let cache = cache_dir("fwos-host")?;
        let key_path = cache.join("id_ed25519");
        let pub_path = cache.join("id_ed25519.pub");
        let disk_path = cache.join("disk.qcow2");
        ensure_ssh_key(&key_path, &pub_path)?;
        let image_dir = host_image_dir()?;
        ensure_host_qcow2(&disk_path, Some(&pub_path), &image_dir)?;
        Self::boot_disk(&disk_path, Some(&key_path), 1, BootWait::Ssh)
    }

    /// Published Disk image: no injected SSH key, no default password. Observe via serial.
    pub fn boot_published_host_image() -> Result<Self, Error> {
        let disk_path = build_published_host_image_disk()?;
        Self::boot_disk(&disk_path, None, 0, BootWait::SerialBootstrap)
    }

    /// Same published Disk image with a second virtio-net (Management NIC + Traffic NIC).
    pub fn boot_published_host_image_two_nics() -> Result<Self, Error> {
        let disk_path = build_published_host_image_disk()?;
        Self::boot_disk(&disk_path, None, 1, BootWait::SerialBootstrap)
    }

    /// Boot the Installer ISO against an empty virt disk, then observe the installed guest.
    pub fn install_from_iso() -> Result<Self, Error> {
        let disk_path = install_host_image_disk()?;
        Self::boot_disk(&disk_path, None, 0, BootWait::SerialBootstrap)
    }

    /// Boot the Installer ISO with two empty virt disks and wait for the disk pick.
    pub fn boot_installer_two_disks() -> Result<Self, Error> {
        ensure_kvm_usable()?;
        ensure_ovmf()?;
        let iso = build_installer_iso()?;
        let work = instance_dir()?;
        let disk1 = work.join("disk1.qcow2");
        let disk2 = work.join("disk2.qcow2");
        create_empty_qcow2(&disk1)?;
        create_empty_qcow2(&disk2)?;
        let linux = extract_iso_linux(&iso, &work)?;
        let port = free_localhost_port()?;
        let https_port = free_localhost_port()?;
        let serial_log = work.join("serial.log");
        let serial_sock = work.join("serial.sock");
        let monitor = work.join("monitor.sock");
        let extra = [disk2.as_path()];
        let mut guest = spawn_guest(
            QemuStart {
                boot_disk: &disk1,
                extra_disks: &extra,
                cdrom: Some(&iso),
                linux: Some(&linux),
                extra_nics: 0,
                port,
                https_port,
                serial_log: &serial_log,
                serial_sock: &serial_sock,
                monitor: &monitor,
                no_reboot: false,
            },
            None,
        )?;
        let ready = guest.wait_for_serial_timeout(INSTALLER_DISK_PROMPT, INSTALLER_PROMPT_WAIT);
        guest.wait_or_stop(ready)?;
        Ok(guest)
    }

    fn boot_disk(
        disk_path: &Path,
        key_path: Option<&Path>,
        extra_nics: u8,
        wait: BootWait,
    ) -> Result<Self, Error> {
        ensure_kvm_usable()?;
        ensure_ovmf()?;
        let port = free_localhost_port()?;
        let https_port = free_localhost_port()?;
        let work = instance_dir()?;
        let overlay = work.join("overlay.qcow2");
        let serial_log = work.join("serial.log");
        let serial_sock = work.join("serial.sock");
        let monitor = work.join("monitor.sock");
        create_overlay(disk_path, &overlay)?;
        let mut guest = spawn_guest(
            QemuStart {
                boot_disk: &overlay,
                extra_disks: &[],
                cdrom: None,
                linux: None,
                extra_nics,
                port,
                https_port,
                serial_log: &serial_log,
                serial_sock: &serial_sock,
                monitor: &monitor,
                no_reboot: false,
            },
            key_path.map(Path::to_path_buf),
        )?;
        let ready = match wait {
            BootWait::Ssh => guest.wait_for_ssh(),
            BootWait::SerialBootstrap => guest.wait_for_serial(SERIAL_BOOTSTRAP),
        };
        guest.wait_or_stop(ready)?;
        Ok(guest)
    }

    /// Run `command` over SSH; return stdout.
    pub fn ssh(&self, command: &str) -> Result<String, Error> {
        let key = self
            .key_path
            .as_ref()
            .ok_or_else(|| Error::from_message("published Disk image has no injected SSH key"))?;
        ssh_output(key, self.port, command)
    }

    pub fn ssh_port(&self) -> u16 {
        self.port
    }

    pub fn https_port(&self) -> u16 {
        self.https_port
    }

    /// Serial console log (how a published guest is observed).
    pub fn serial(&self) -> String {
        read_serial_all(&self.serial_log)
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

    /// HTTPS from the Workstation; returns status and body for any complete HTTP response.
    pub fn https_exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        max_time_secs: u64,
    ) -> Result<(u16, String), Error> {
        let url = format!("https://10.0.2.15{path}");
        let connect = format!("10.0.2.15:443:127.0.0.1:{}", self.https_port);
        let mut cmd = Command::new("curl");
        cmd.args([
            "-sk",
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
        if let Some(body) = body {
            cmd.args(["--data-binary", body]);
        }
        cmd.arg(&url);
        let output = cmd
            .output()
            .map_err(|e| Error::from_io("running curl", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (body, code) = match stdout.rsplit_once("http_code=") {
            Some((body, rest)) => (body.to_string(), rest.trim().parse::<u16>().ok()),
            None => (stdout.into_owned(), None),
        };
        // A complete HTTP response is usable even if curl exits 56 (no TLS close_notify).
        if let Some(code) = code {
            if code != 0 {
                return Ok((code, body));
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

    /// SSH identification string if port 22 answers the SSH protocol.
    pub fn ssh_ident(&self) -> Option<String> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        let line = text.lines().next().unwrap_or("").trim();
        line.starts_with("SSH-").then(|| line.to_string())
    }

    pub fn reboot(&mut self) -> Result<(), Error> {
        let before = self
            .ssh("cat /proc/sys/kernel/random/boot_id")
            .map_err(|e| Error::from_message(format!("reading boot_id before reset: {e}")))?;
        let before = before.trim().to_string();
        let mut mon = UnixStream::connect(&self.monitor)
            .map_err(|e| Error::from_io("connecting QEMU monitor", e))?;
        mon.write_all(b"system_reset\n")
            .map_err(|e| Error::from_io("sending system_reset", e))?;
        let _ = mon.flush();
        let drop_deadline = Instant::now() + Duration::from_secs(60);
        while self.ssh("true").is_ok() {
            if Instant::now() >= drop_deadline {
                return Err(Error::from_message(
                    "QEMU system_reset did not drop SSH within 60s",
                ));
            }
            thread::sleep(Duration::from_millis(500));
        }
        self.wait_for_ssh()?;
        // sshd may move into mgmt as soon as SSH is back; retry the boot_id read.
        let id_deadline = Instant::now() + Duration::from_secs(60);
        let after = loop {
            match self.ssh("cat /proc/sys/kernel/random/boot_id") {
                Ok(s) => break s,
                Err(err) => {
                    if Instant::now() >= id_deadline {
                        return Err(Error::from_message(format!(
                            "reading boot_id after reset: {err}"
                        )));
                    }
                    thread::sleep(Duration::from_millis(500));
                }
            }
        };
        if after.trim() == before {
            return Err(Error::from_message(
                "SSH came back after system_reset but boot_id did not change",
            ));
        }
        Ok(())
    }

    fn wait_for_ssh(&mut self) -> Result<(), Error> {
        let key = self
            .key_path
            .as_ref()
            .ok_or_else(|| Error::from_message("wait_for_ssh requires an injected SSH key"))?;
        let deadline = Instant::now() + SSH_WAIT;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|e| Error::from_io("waiting for QEMU", e))?
            {
                let serial = read_serial(&self.serial_log);
                return Err(Error::from_message(format!(
                    "QEMU exited before SSH was up (status {status}). serial log:\n{serial}"
                )));
            }
            let ssh_err = match ssh_output(key, self.port, "true") {
                Ok(_) => return Ok(()),
                Err(err) => err,
            };
            if Instant::now() >= deadline {
                let serial = read_serial(&self.serial_log);
                return Err(Error::from_message(format!(
                    "SSH to 127.0.0.1:{} as {GUEST_USER} did not come up within {}s. last ssh error: {ssh_err}. serial log:\n{serial}",
                    self.port,
                    SSH_WAIT.as_secs()
                )));
            }
            thread::sleep(Duration::from_secs(2));
        }
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
        self.wait_for_serial_timeout(needle, SSH_WAIT)
    }

    fn wait_for_serial_timeout(&mut self, needle: &str, wait: Duration) -> Result<(), Error> {
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

fn ensure_ssh_key(private: &Path, public: &Path) -> Result<(), Error> {
    if private.exists() && public.exists() {
        return Ok(());
    }
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(private)
        .status()
        .map_err(|e| Error::from_io("running ssh-keygen", e))?;
    if !status.success() {
        return Err(Error::from_message(format!(
            "ssh-keygen failed with {status}"
        )));
    }
    Ok(())
}

fn ensure_qcow2(disk: &Path, public_key: &Path, image_ref: &str, pull: bool) -> Result<(), Error> {
    if disk.exists() && disk.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Ok(());
    }
    build_qcow2(disk, Some(public_key), None, image_ref, pull)
}

struct HostImageParts {
    image_dir: PathBuf,
    addons: PathBuf,
    binary: PathBuf,
    netd: PathBuf,
    cli: PathBuf,
    ui: PathBuf,
}

fn prepare_host_image_parts(image_dir: &Path) -> Result<HostImageParts, Error> {
    let src = src_dir()?;
    let binary = build_host_program(&src)?;
    build_host_program_image(&src, &binary)?;
    let netd = src.join("target/release/netd");
    if !netd.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            netd.display()
        )));
    }
    let addons = builtin_addons_dir()?;
    build_netd_image(&addons, &netd)?;
    let cli = src.join("target/release/fwos");
    if !cli.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            cli.display()
        )));
    }
    build_cli_image(&addons, &cli)?;
    let ui = src.join("target/release/fwos-ui");
    if !ui.is_file() {
        return Err(Error::from_message(format!(
            "cargo build did not produce {}",
            ui.display()
        )));
    }
    build_ui_image(&addons, &ui)?;
    build_vendor_image(&addons.join("kea"), KEA_IMAGE_TAG)?;
    build_vendor_image(&addons.join("unbound"), UNBOUND_IMAGE_TAG)?;
    Ok(HostImageParts {
        image_dir: image_dir.to_path_buf(),
        addons,
        binary,
        netd,
        cli,
        ui,
    })
}

impl HostImageParts {
    fn stale(&self, artifact: &Path) -> Result<bool, Error> {
        Ok(!artifact.exists()
            || artifact.metadata().map(|m| m.len() == 0).unwrap_or(true)
            || source_newer_than(&self.image_dir, artifact)?
            || file_newer_than(&self.binary, artifact)?
            || file_newer_than(&self.netd, artifact)?
            || file_newer_than(&self.cli, artifact)?
            || file_newer_than(&self.ui, artifact)?
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

fn ensure_host_qcow2(
    disk: &Path,
    public_key: Option<&Path>,
    image_dir: &Path,
) -> Result<(), Error> {
    let parts = prepare_host_image_parts(image_dir)?;
    if !parts.stale(disk)? {
        return Ok(());
    }
    build_host_container(image_dir)?;
    build_qcow2(disk, public_key, Some(image_dir), HOST_IMAGE_TAG, false)
}

fn ensure_host_iso(iso: &Path, image_dir: &Path) -> Result<(), Error> {
    let parts = prepare_host_image_parts(image_dir)?;
    let installer_toml = image_dir.join("installer.toml");
    if !parts.stale(iso)? && !optional_newer(&installer_toml, iso)? {
        return Ok(());
    }
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
    let config_dir = parent.join("bib-config");
    fs::create_dir_all(&config_dir)
        .map_err(|e| Error::from_io("creating image-builder config dir", e))?;
    Ok((out_dir, config_dir))
}

fn build_qcow2(
    disk: &Path,
    public_key: Option<&Path>,
    image_dir: Option<&Path>,
    image_ref: &str,
    pull: bool,
) -> Result<(), Error> {
    let (out_dir, config_dir) = image_builder_dirs(disk)?;
    let config_path = config_dir.join("config.toml");
    let config = match public_key {
        Some(public_key) => {
            let pubkey = fs::read_to_string(public_key)
                .map_err(|e| Error::from_io("reading SSH public key", e))?;
            let pubkey = pubkey.trim();
            if pubkey.is_empty() {
                return Err(Error::from_message("SSH public key is empty"));
            }
            format!(
                "[[customizations.user]]\nname = \"{GUEST_USER}\"\nkey = \"{pubkey}\"\ngroups = [\"wheel\"]\n"
            )
        }
        None => {
            let path = image_dir
                .map(|d| d.join("bib.toml"))
                .filter(|p| p.is_file())
                .ok_or_else(|| {
                    Error::from_message(
                        "published Disk image needs bib.toml in the host-image checkout (no users, no SSH key)",
                    )
                })?;
            fs::read_to_string(&path)
                .map_err(|e| Error::from_io("reading published bib.toml", e))?
        }
    };
    fs::write(&config_path, config)
        .map_err(|e| Error::from_io("writing image-builder config", e))?;

    run_image_builder(&config_path, &out_dir, image_ref, pull, "qcow2", None)?;
    let produced = out_dir.join("qcow2").join("disk.qcow2");
    if !produced.exists() {
        return Err(Error::from_message(format!(
            "image-builder succeeded but {} is missing",
            produced.display()
        )));
    }
    fs::rename(&produced, disk).map_err(|e| Error::from_io("moving qcow2 into cache", e))?;
    Ok(())
}

fn build_anaconda_iso(iso: &Path, image_dir: &Path) -> Result<(), Error> {
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

fn spawn_guest(opts: QemuStart<'_>, key_path: Option<PathBuf>) -> Result<Guest, Error> {
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
        port: opts.port,
        https_port: opts.https_port,
        key_path,
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
    cmd.args([
        "-netdev",
        &format!(
            "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:443",
            opts.port, opts.https_port
        ),
    ])
    .args(["-device", "virtio-net-pci,netdev=net0"]);
    for i in 0..opts.extra_nics {
        let id = format!("net{}", i + 1);
        let net = format!("10.0.{}.0/24", i + 3);
        cmd.args(["-netdev", &format!("user,id={id},net={net}")])
            .args(["-device", &format!("virtio-net-pci,netdev={id}")]);
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

fn ssh_output(key: &Path, port: u16, command: &str) -> Result<String, Error> {
    let output = Command::new("ssh")
        .args(["-i"])
        .arg(key)
        .args([
            "-p",
            &port.to_string(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=2",
            "-o",
            "ServerAliveCountMax=5",
        ])
        .arg(format!("{GUEST_USER}@127.0.0.1"))
        .arg(command)
        .output()
        .map_err(|e| Error::from_io("running ssh", e))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::from_message(format!(
            "ssh {command:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
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

/// Ensure the host-image qcow2 exists in the cache (for the CLI `build` command).
pub fn build_host_image_disk() -> Result<PathBuf, Error> {
    let cache = cache_dir("fwos-host")?;
    let key_path = cache.join("id_ed25519");
    let pub_path = cache.join("id_ed25519.pub");
    let disk_path = cache.join("disk.qcow2");
    ensure_ssh_key(&key_path, &pub_path)?;
    let image_dir = host_image_dir()?;
    ensure_host_qcow2(&disk_path, Some(&pub_path), &image_dir)?;
    Ok(disk_path)
}

/// Published Disk image: no injected SSH key, no default password.
pub fn build_published_host_image_disk() -> Result<PathBuf, Error> {
    let cache = cache_dir("fwos-host")?;
    let disk_path = cache.join("published.qcow2");
    let image_dir = host_image_dir()?;
    ensure_host_qcow2(&disk_path, None, &image_dir)?;
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
    if let Err(err) = run_unattended_install(&iso, &disk) {
        let _ = fs::remove_file(&disk);
        return Err(err);
    }
    Ok(disk)
}

fn run_unattended_install(iso: &Path, disk: &Path) -> Result<(), Error> {
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
        port,
        https_port,
        serial_log: &serial_log,
        serial_sock: &serial_sock,
        monitor: &monitor,
        no_reboot: true,
    })?;
    let _serial = match connect_serial(&serial_sock, &serial_log) {
        Ok(s) => s,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&work);
            return Err(err);
        }
    };
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

/// Path to the cached SSH private key used to log into the host-image guest.
pub fn cached_ssh_key() -> Result<PathBuf, Error> {
    Ok(cache_dir("fwos-host")?.join("id_ed25519"))
}
