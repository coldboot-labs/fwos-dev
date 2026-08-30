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
const QEMU_MEMORY_MIB: &str = "4096";
const OVMF_CODE: &str = "/usr/share/edk2/ovmf/OVMF_CODE.fd";
const SERIAL_BOOTSTRAP: &str = "FWOS Bootstrap console";

enum BootWait {
    Ssh,
    SerialBootstrap,
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
        let child = start_qemu(
            &overlay,
            port,
            https_port,
            &serial_log,
            &serial_sock,
            &monitor,
            extra_nics,
        )?;
        let serial = connect_serial(&serial_sock, &serial_log)?;
        let mut guest = Self {
            child,
            port,
            https_port,
            key_path: key_path.map(Path::to_path_buf),
            serial_log,
            serial: Mutex::new(serial),
            monitor,
        };
        let ready = match wait {
            BootWait::Ssh => guest.wait_for_ssh(),
            BootWait::SerialBootstrap => guest.wait_for_serial(SERIAL_BOOTSTRAP),
        };
        if let Err(err) = ready {
            let _ = guest.child.kill();
            let _ = guest.child.wait();
            return Err(err);
        }
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
        let url = format!("https://10.0.2.15{path}");
        let connect = format!("10.0.2.15:443:127.0.0.1:{}", self.https_port);
        let output = Command::new("curl")
            .args([
                "-sk",
                "--max-time",
                "8",
                "--http1.1",
                "-H",
                "Connection: close",
                "--connect-to",
                &connect,
                "-o",
                "-",
                "-w",
                "\nhttp_code=%{http_code}",
                &url,
            ])
            .output()
            .map_err(|e| Error::from_io("running curl", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (body, code) = match stdout.rsplit_once("http_code=") {
            Some((body, rest)) => (body.to_string(), rest.trim().parse::<u16>().ok()),
            None => (stdout.into_owned(), None),
        };
        // Python ssl http.server often omits TLS close_notify; curl then exits
        // 56 (CURLE_RECV_ERROR) after a complete 200. HTTP status is the result.
        if code == Some(200) {
            Ok(body)
        } else {
            Err(Error::from_message(format!(
                "curl {url} failed with {} http_code={}: {}\n{}",
                output.status,
                code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
                String::from_utf8_lossy(&output.stderr).trim(),
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

    fn wait_for_serial(&mut self, needle: &str) -> Result<(), Error> {
        let deadline = Instant::now() + SSH_WAIT;
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
                    SSH_WAIT.as_secs()
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
    let dir = std::env::temp_dir().join(format!(
        "fwos-dev-guest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).map_err(|e| Error::from_io("creating guest work dir", e))?;
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

fn ensure_host_qcow2(
    disk: &Path,
    public_key: Option<&Path>,
    image_dir: &Path,
) -> Result<(), Error> {
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
    build_ui_image(&addons)?;
    build_vendor_image(&addons.join("kea"), KEA_IMAGE_TAG)?;
    build_vendor_image(&addons.join("unbound"), UNBOUND_IMAGE_TAG)?;
    let stale = !disk.exists()
        || disk.metadata().map(|m| m.len() == 0).unwrap_or(true)
        || source_newer_than(image_dir, disk)?
        || file_newer_than(&binary, disk)?
        || file_newer_than(&netd, disk)?
        || file_newer_than(&cli, disk)?
        || file_newer_than(&addons.join("netd").join("Containerfile"), disk)?
        || file_newer_than(&addons.join("cli").join("Containerfile"), disk)?
        || file_newer_than(&addons.join("ui").join("Containerfile"), disk)?
        || file_newer_than(&addons.join("ui").join("fwos-ui"), disk)?
        || file_newer_than(&addons.join("kea").join("Containerfile"), disk)?
        || file_newer_than(&addons.join("kea").join("run-dhcp4"), disk)?
        || file_newer_than(&addons.join("kea").join("run-dhcp6"), disk)?
        || file_newer_than(&addons.join("unbound").join("Containerfile"), disk)?
        || optional_newer(&image_dir.join("bib.toml"), disk)?;
    if !stale {
        return Ok(());
    }
    build_host_container(image_dir)?;
    build_qcow2(disk, public_key, Some(image_dir), HOST_IMAGE_TAG, false)
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

fn build_ui_image(addons: &Path) -> Result<(), Error> {
    let context = addons.join("ui");
    let dockerfile = context.join("Containerfile");
    let output = Command::new("sudo")
        .args(["podman", "build", "-t", UI_IMAGE_TAG, "-f"])
        .arg(&dockerfile)
        .arg(&context)
        .output()
        .map_err(|e| Error::from_io("running podman build for ui", e))?;
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

fn build_qcow2(
    disk: &Path,
    public_key: Option<&Path>,
    image_dir: Option<&Path>,
    image_ref: &str,
    pull: bool,
) -> Result<(), Error> {
    let out_dir = disk
        .parent()
        .ok_or_else(|| Error::from_message("disk path has no parent"))?
        .join("bib-output");
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)
            .map_err(|e| Error::from_io("clearing image-builder output", e))?;
    }
    fs::create_dir_all(&out_dir).map_err(|e| Error::from_io("creating image-builder output", e))?;

    let config_dir = disk
        .parent()
        .ok_or_else(|| Error::from_message("disk path has no parent"))?
        .join("bib-config");
    fs::create_dir_all(&config_dir)
        .map_err(|e| Error::from_io("creating image-builder config dir", e))?;
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

    let (uid, gid) = current_uid_gid()?;
    if pull {
        pull_image(image_ref)?;
    }
    pull_image(IMAGE_BUILDER)?;

    let output = Command::new("sudo")
        .args([
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
        .arg(format!("{}:/output", out_dir.display()))
        .args([
            "-v",
            "/var/lib/containers/storage:/var/lib/containers/storage",
            IMAGE_BUILDER,
            "--type",
            "qcow2",
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
    if !output.status.success() {
        return Err(Error::from_message(format!(
            "image-builder failed with {} while converting {image_ref} to qcow2\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

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

fn start_qemu(
    overlay: &Path,
    port: u16,
    https_port: u16,
    serial_log: &Path,
    serial_sock: &Path,
    monitor: &Path,
    extra_nics: u8,
) -> Result<Child, Error> {
    let _ = fs::remove_file(monitor);
    let _ = fs::remove_file(serial_sock);
    let qemu_err = serial_log.with_file_name("qemu.stderr");
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
    .arg(format!("file={},if=virtio,format=qcow2", overlay.display()))
    .args([
        "-netdev",
        &format!(
            "user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22,hostfwd=tcp:127.0.0.1:{https_port}-:443"
        ),
    ])
    .args(["-device", "virtio-net-pci,netdev=net0"]);
    for i in 0..extra_nics {
        let id = format!("net{}", i + 1);
        let net = format!("10.0.{}.0/24", i + 3);
        cmd.args(["-netdev", &format!("user,id={id},net={net}")])
            .args(["-device", &format!("virtio-net-pci,netdev={id}")]);
    }
    let child = cmd
        .args(["-device", "virtio-rng-pci"])
        .args([
            "-monitor",
            &format!("unix:{},server,nowait", monitor.display()),
        ])
        .args(["-display", "none"])
        .arg("-serial")
        .arg(format!("unix:{},server=on,wait=off", serial_sock.display()))
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

/// Path to the cached SSH private key used to log into the host-image guest.
pub fn cached_ssh_key() -> Result<PathBuf, Error> {
    Ok(cache_dir("fwos-host")?.join("id_ed25519"))
}
