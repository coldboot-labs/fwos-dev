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

    /// Route test traffic through the appliance using only peer-owned routes.
    pub fn add_route(&self, destination: &str, gateway: &str) -> Result<(), Error> {
        let family = if destination.contains(':') {
            "-6"
        } else {
            "-4"
        };
        ip(&[
            "-n",
            &self.namespace,
            family,
            "route",
            "add",
            destination,
            "via",
            gateway,
            "dev",
            "eth0",
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

    /// Any HTTPS response counts as exposure, including 4xx/5xx. Only a refused
    /// connection or timeout with no HTTP response establishes unreachability;
    /// broken peer commands, malformed URLs and TLS errors remain test errors.
    pub fn https_response(&self, address: &str) -> Result<Option<u16>, Error> {
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
                "--connect-timeout",
                "2",
                "--max-time",
                "3",
                "--output",
                "/dev/null",
                "--write-out",
                "%{response_code}",
            ])
            .arg(format!("https://{host}/"))
            .output()
            .map_err(|e| Error::from_io("external-peer HTTPS probe", e))?;
        let response = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u16>()
            .map_err(|_| Error::from_message("external-peer HTTPS probe returned no status"))?;
        if response >= 100 {
            return Ok(Some(response));
        }
        if matches!(output.status.code(), Some(7 | 28)) && response == 0 {
            return Ok(None);
        }
        Err(Error::from_message(format!(
            "external-peer HTTPS probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Inspect the external peer's neighbor discovery result after real traffic.
    /// This does not require the appliance to offer ICMP Echo service.
    pub fn neighbor_resolved(&self, address: &str) -> Result<bool, Error> {
        let output = self
            .command("ip")
            .args(["-j", "neigh", "show", "to", address, "dev", "eth0"])
            .output()
            .map_err(|e| Error::from_io("external-peer neighbor discovery", e))?;
        if !output.status.success() {
            return Err(Error::from_message(format!(
                "reading external-peer neighbors: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let neighbors: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .map_err(|e| Error::from_message(format!("external-peer neighbor JSON: {e}")))?;
        Ok(neighbors.iter().any(|neighbor| {
            neighbor["lladdr"]
                .as_str()
                .is_some_and(|mac| !mac.is_empty())
                && neighbor["state"].as_array().is_some_and(|states| {
                    states.iter().any(|state| {
                        matches!(
                            state.as_str(),
                            Some("REACHABLE" | "STALE" | "DELAY" | "PROBE")
                        )
                    })
                })
        }))
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
