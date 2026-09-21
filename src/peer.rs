use super::{current_uid_gid, Error};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_PEER: AtomicU32 = AtomicU32::new(0);

/// An isolated external Ethernet peer. Only task-owned links and namespace are
/// changed; the Workstation's addresses, routes and sysctls are untouched.
pub struct NetworkPeer {
    namespace: String,
    bridge: String,
    tap: String,
    uplink: String,
    owned_namespace: bool,
    owned_bridge: bool,
    owned_tap: bool,
    owned_uplink: bool,
}

impl NetworkPeer {
    pub fn new() -> Result<Self, Error> {
        let sequence = NEXT_PEER.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{:x}{sequence:x}", std::process::id());
        let mut peer = Self {
            namespace: format!("fwos-peer-{suffix}"),
            bridge: format!("fwb{suffix}"),
            tap: format!("fwt{suffix}"),
            uplink: format!("fwp{suffix}"),
            owned_namespace: false,
            owned_bridge: false,
            owned_tap: false,
            owned_uplink: false,
        };
        let (uid, _) = current_uid_gid()?;
        ip(&["netns", "add", &peer.namespace])?;
        peer.owned_namespace = true;
        ip(&["link", "add", &peer.bridge, "type", "bridge"])?;
        peer.owned_bridge = true;
        ip(&[
            "tuntap",
            "add",
            "dev",
            &peer.tap,
            "mode",
            "tap",
            "user",
            &uid.to_string(),
        ])?;
        peer.owned_tap = true;
        ip(&["link", "set", &peer.tap, "master", &peer.bridge])?;
        ip(&[
            "link",
            "add",
            &peer.uplink,
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            &peer.namespace,
        ])?;
        peer.owned_uplink = true;
        ip(&["link", "set", &peer.uplink, "master", &peer.bridge])?;
        for name in [&peer.bridge, &peer.tap, &peer.uplink] {
            // The Workstation is not a participant on this test segment. In
            // particular an RA fixture must never add a Workstation route.
            let output = Command::new("sudo")
                .args(["-n", "sysctl", "-w"])
                .arg(format!("net.ipv6.conf.{name}.disable_ipv6=1"))
                .output()
                .map_err(|e| Error::from_io("disable external-link IPv6", e))?;
            if !output.status.success() {
                return Err(Error::from_message("could not isolate external-link IPv6"));
            }
            ip(&["link", "set", name, "up"])?;
        }
        ip(&["-n", &peer.namespace, "link", "set", "lo", "up"])?;
        ip(&["-n", &peer.namespace, "link", "set", "eth0", "up"])?;
        Ok(peer)
    }

    pub(crate) fn tap(&self) -> &str {
        &self.tap
    }

    /// Add an on-link peer address, not an address inside the appliance.
    pub fn add_address(&self, cidr: &str) -> Result<(), Error> {
        ip(&[
            "-n",
            &self.namespace,
            "address",
            "add",
            cidr,
            "dev",
            "eth0",
            "nodad",
        ])
    }

    /// Request the appliance directly over this Ethernet segment.
    pub fn https_get(&self, address: &str, path: &str) -> Result<String, Error> {
        let host = if address.contains(':') {
            format!("[{address}]")
        } else {
            address.to_owned()
        };
        let output = self
            .command("curl")
            .args([
                "--noproxy",
                "*",
                "--insecure",
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                "2",
                "--max-time",
                "3",
            ])
            .arg(format!("https://{host}{path}"))
            .output()
            .map_err(|e| Error::from_io("external-peer HTTPS", e))?;
        if !output.status.success() {
            return Err(Error::from_message(format!(
                "external-peer HTTPS failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Verify neighbor discovery through ordinary peer traffic, not guest state.
    pub fn ping(&self, address: &str) -> Result<(), Error> {
        let output = self
            .command("ping")
            .args(["-I", "eth0", "-c", "1", "-W", "2", address])
            .output()
            .map_err(|e| Error::from_io("external-peer ping", e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::from_message(format!(
                "external-peer ping failed: {}",
                String::from_utf8_lossy(&output.stdout)
            )))
        }
    }

    fn command(&self, executable: &str) -> Command {
        let mut command = Command::new("sudo");
        command.args(["-n", "ip", "netns", "exec", &self.namespace, executable]);
        command
    }
}

impl Drop for NetworkPeer {
    fn drop(&mut self) {
        // These names are generated exclusively for this peer. Removing the
        // namespace also removes its veth; no broad network cleanup is used.
        for (owned, args) in [
            (
                self.owned_namespace,
                vec!["netns", "delete", &self.namespace],
            ),
            (self.owned_tap, vec!["link", "delete", &self.tap]),
            (self.owned_uplink, vec!["link", "delete", &self.uplink]),
            (self.owned_bridge, vec!["link", "delete", &self.bridge]),
        ] {
            if owned {
                let _ = ip(&args);
            }
        }
    }
}

fn ip(args: &[&str]) -> Result<(), Error> {
    let output = Command::new("sudo")
        .args(["-n", "ip"])
        .args(args)
        .output()
        .map_err(|e| Error::from_io("configuring external peer", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::from_message(format!(
            "external peer: ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}
