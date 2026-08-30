use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

/// A QEMU guest started by Workstation tooling.
pub struct Guest {
    child: Child,
    port: u16,
    key_path: PathBuf,
    serial_log: PathBuf,
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
        Self::boot_disk(&disk_path, &key_path, 0)
    }

    /// Build a qcow2 from the FWOS host image if needed, boot it under QEMU, wait until SSH works.
    pub fn boot_host_image() -> Result<Self, Error> {
        let cache = cache_dir("fwos-host")?;
        let key_path = cache.join("id_ed25519");
        let pub_path = cache.join("id_ed25519.pub");
        let disk_path = cache.join("disk.qcow2");
        ensure_ssh_key(&key_path, &pub_path)?;
        let image_dir = host_image_dir()?;
        ensure_host_qcow2(&disk_path, &pub_path, &image_dir)?;
        Self::boot_disk(&disk_path, &key_path, 0)
    }

    /// Same as `boot_host_image`, with a second virtio-net (no SSH forward).
    pub fn boot_host_image_two_nics() -> Result<Self, Error> {
        let cache = cache_dir("fwos-host")?;
        let key_path = cache.join("id_ed25519");
        let pub_path = cache.join("id_ed25519.pub");
        let disk_path = cache.join("disk.qcow2");
        ensure_ssh_key(&key_path, &pub_path)?;
        let image_dir = host_image_dir()?;
        ensure_host_qcow2(&disk_path, &pub_path, &image_dir)?;
        Self::boot_disk(&disk_path, &key_path, 1)
    }

    fn boot_disk(disk_path: &Path, key_path: &Path, extra_nics: u8) -> Result<Self, Error> {
        ensure_kvm_usable()?;
        ensure_ovmf()?;
        let port = free_localhost_port()?;
        let work = instance_dir()?;
        let overlay = work.join("overlay.qcow2");
        let serial_log = work.join("serial.log");
        let monitor = work.join("monitor.sock");
        create_overlay(disk_path, &overlay)?;
        let child = start_qemu(&overlay, port, &serial_log, &monitor, extra_nics)?;
        let mut guest = Self {
            child,
            port,
            key_path: key_path.to_path_buf(),
            serial_log,
            monitor,
        };
        if let Err(err) = guest.wait_for_ssh() {
            let _ = guest.child.kill();
            let _ = guest.child.wait();
            return Err(err);
        }
        Ok(guest)
    }

    /// Run `command` over SSH; return stdout.
    pub fn ssh(&self, command: &str) -> Result<String, Error> {
        ssh_output(&self.key_path, self.port, command)
    }

    pub fn ssh_port(&self) -> u16 {
        self.port
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
            let ssh_err = match ssh_output(&self.key_path, self.port, "true") {
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
    build_qcow2(disk, public_key, image_ref, pull)
}

fn ensure_host_qcow2(disk: &Path, public_key: &Path, image_dir: &Path) -> Result<(), Error> {
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
        || file_newer_than(&addons.join("unbound").join("Containerfile"), disk)?;
    if !stale {
        return Ok(());
    }
    build_host_container(image_dir)?;
    build_qcow2(disk, public_key, HOST_IMAGE_TAG, false)
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

fn build_qcow2(disk: &Path, public_key: &Path, image_ref: &str, pull: bool) -> Result<(), Error> {
    let pubkey =
        fs::read_to_string(public_key).map_err(|e| Error::from_io("reading SSH public key", e))?;
    let pubkey = pubkey.trim();
    if pubkey.is_empty() {
        return Err(Error::from_message("SSH public key is empty"));
    }

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
    let config = format!(
        "[[customizations.user]]\nname = \"{GUEST_USER}\"\nkey = \"{pubkey}\"\ngroups = [\"wheel\"]\n"
    );
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
    serial_log: &Path,
    monitor: &Path,
    extra_nics: u8,
) -> Result<Child, Error> {
    let _ = fs::remove_file(monitor);
    let serial = File::create(serial_log).map_err(|e| Error::from_io("creating serial log", e))?;
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
        &format!("user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22"),
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
        .arg("stdio")
        .stdout(Stdio::from(
            serial
                .try_clone()
                .map_err(|e| Error::from_io("cloning serial log", e))?,
        ))
        .stderr(Stdio::from(serial))
        .spawn()
        .map_err(|e| Error::from_io("starting QEMU", e))?;
    Ok(child)
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
    let mut buf = Vec::new();
    match File::open(path).and_then(|mut f| f.read_to_end(&mut buf)) {
        Ok(_) => {
            const KEEP: usize = 8000;
            let tail = if buf.len() > KEEP {
                &buf[buf.len() - KEEP..]
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
    ensure_host_qcow2(&disk_path, &pub_path, &image_dir)?;
    Ok(disk_path)
}

/// Path to the cached SSH private key used to log into the host-image guest.
pub fn cached_ssh_key() -> Result<PathBuf, Error> {
    Ok(cache_dir("fwos-host")?.join("id_ed25519"))
}
