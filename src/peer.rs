use super::{current_uid_gid, Error};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

mod discovery;
use discovery::Discovery;
pub use discovery::DiscoveryPackets;

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
    discovery: Option<Discovery>,
    upstream: Option<(Child, std::path::PathBuf)>,
    dns: Option<(Child, std::path::PathBuf)>,
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
            discovery: None,
            upstream: None,
            dns: None,
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
        let output = peer
            .command("sysctl")
            .args([
                "-w",
                "net.ipv6.conf.eth0.accept_ra=0",
                "net.ipv6.conf.eth0.autoconf=0",
            ])
            .output()
            .map_err(|e| Error::from_io("isolate peer IPv6 configuration", e))?;
        if !output.status.success() {
            return Err(Error::from_message(
                "could not isolate peer IPv6 configuration",
            ));
        }
        ip(&["-n", &peer.namespace, "link", "set", "eth0", "up"])?;
        Ok(peer)
    }

    pub(crate) fn tap(&self) -> &str {
        &self.tap
    }

    /// Start real DHCP/RA service and capture guest discovery packets before boot.
    /// Addresses and prefixes belong only to this peer's isolated segment.
    pub fn advertise(&mut self, lease: &str, netmask: &str, ula_prefix: &str) -> Result<(), Error> {
        if self.discovery.is_some() {
            return Err(Error::from_message("peer discovery already started"));
        }
        self.discovery = Some(Discovery::start(self, lease, netmask, ula_prefix)?);
        Ok(())
    }

    pub fn discovery_packets(&mut self) -> Result<DiscoveryPackets, Error> {
        self.discovery
            .as_mut()
            .ok_or_else(|| Error::from_message("peer discovery not started"))?
            .packets()
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

    /// Add an address on a named interface in this peer.
    pub fn add_address_on(&self, device: &str, cidr: &str) -> Result<(), Error> {
        ip(&[
            "-n",
            &self.namespace,
            "address",
            "add",
            cidr,
            "dev",
            device,
            "nodad",
        ])
    }

    /// Add a tagged interface on this peer so it can reach a VLAN on the attached NIC.
    pub fn add_vlan(&self, id: u16, cidr: &str) -> Result<(), Error> {
        let name = format!("eth0.{id}");
        ip(&[
            "-n",
            &self.namespace,
            "link",
            "add",
            "link",
            "eth0",
            "name",
            &name,
            "type",
            "vlan",
            "id",
            &id.to_string(),
        ])?;
        ip(&["-n", &self.namespace, "link", "set", &name, "up"])?;
        ip(&[
            "-n",
            &self.namespace,
            "address",
            "add",
            cidr,
            "dev",
            &name,
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

    /// Observe packet forwarding from the isolated peer, outside the guest.
    pub fn ping(&self, address: &str) -> Result<bool, Error> {
        let output = self
            .command("ping")
            .args(["-n", "-c", "1", "-W", "2", address])
            .output()
            .map_err(|e| Error::from_io("external-peer ICMP probe", e))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(Error::from_message(format!(
                "external-peer ICMP probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        }
    }

    /// Report whether a UDP port is bound rather than refusing the packet.
    pub fn udp_port_listening(&self, address: &str, port: u16) -> Result<bool, Error> {
        let script = format!(
            r#"import socket,sys
server,port=sys.argv[1],int(sys.argv[2])
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.sendto(b"fwos",(server,port))
icmp=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
icmp.settimeout(2)
try:
    while True:
        packet,_=icmp.recvfrom(1500)
        ihl=(packet[0]&0x0F)*4
        if len(packet)>=ihl+2 and packet[ihl]==3 and packet[ihl+1]==3:
            print("closed"); raise SystemExit(1)
except socket.timeout:
    print("listening"); raise SystemExit(0)
"#
        );
        let output = self
            .command("python3")
            .arg("-c")
            .arg(&script)
            .arg(address)
            .arg(port.to_string())
            .output()
            .map_err(|error| Error::from_io("external-peer UDP probe", error))?;
        Ok(output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("listening"))
    }

    /// Report whether a TCP connection to `address` and `port` succeeds from this peer.
    pub fn tcp_port_open(&self, address: &str, port: u16) -> Result<bool, Error> {
        let output = self
            .command("python3")
            .arg("-c")
            .arg("import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2).close()")
            .arg(address)
            .arg(port.to_string())
            .stderr(Stdio::null())
            .output()
            .map_err(|error| Error::from_io("external-peer TCP probe", error))?;
        Ok(output.status.success())
    }

    /// Ask the appliance DNS resolver and report whether it sends a DNS answer.
    pub fn dns_resolves(&self, server: &str, name: &str, source: &str) -> Result<bool, Error> {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer/dns-query.py");
        let output = self
            .command("python3")
            .arg(script)
            .arg(server)
            .arg(name)
            .arg(source)
            .output()
            .map_err(|error| Error::from_io("external-peer DNS query", error))?;
        Ok(output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("resolved"))
    }

    /// Request a real DHCPv4 offer from this external LAN segment.
    pub fn dhcp_offer(&self) -> Result<Option<String>, Error> {
        self.dhcp_offer_on("eth0")
    }

    /// Request a real DHCPv4 offer on one interface, such as a VLAN subinterface.
    pub fn dhcp_offer_on(&self, device: &str) -> Result<Option<String>, Error> {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer/dhcp-discover.py");
        let output = self
            .command("python3")
            .arg(script)
            .arg(device)
            .output()
            .map_err(|error| Error::from_io("external-peer DHCP discover", error))?;
        if !output.status.success() {
            return Err(Error::from_message(format!(
                "external-peer DHCP discover failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| Error::from_message(format!("external-peer DHCP result: {error}")))?;
        match &result["address"] {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(address) => Ok(Some(address.clone())),
            _ => Err(Error::from_message(
                "external-peer DHCP result has no offer address",
            )),
        }
    }

    /// Capture only externally visible DHCP packets while probing this peer.
    pub fn dhcp_offer_with_trace(&self) -> Result<(Option<String>, String), Error> {
        let capture = self
            .command("timeout")
            .args([
                "5", "tcpdump", "-n", "-i", "eth0", "-l", "udp", "port", "67", "or", "udp", "port",
                "68",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Error::from_io("external DHCP packet capture", error))?;
        std::thread::sleep(Duration::from_millis(200));
        let offered = self.dhcp_offer()?;
        let output = capture
            .wait_with_output()
            .map_err(|error| Error::from_io("external DHCP packet capture", error))?;
        Ok((
            offered,
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }

    /// Request the appliance directly over this Ethernet segment.
    pub fn https_get(&self, address: &str, path: &str) -> Result<String, Error> {
        let output = self
            .https_command(address, path)
            .arg("--fail")
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
        let output = self
            .https_command(address, "/")
            .args(["--output", "/dev/null", "--write-out", "%{response_code}"])
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

    /// Drive the rendered interface editor from inside this peer's namespace.
    pub fn browser_configure_interfaces(
        &self,
        url: &str,
        action: &str,
        username: &str,
        password: &str,
        edits: &serde_json::Value,
        expect_in_review: &str,
    ) -> Result<(), Error> {
        super::run_interface_browser(
            Some(&self.namespace),
            url,
            action,
            username,
            password,
            edits,
            expect_in_review,
        )
    }

    /// HTTPS request from this peer, including a non-2xx response body.
    pub fn https_exchange(
        &self,
        method: &str,
        address: &str,
        path: &str,
        body: Option<&str>,
        cookie: Option<&str>,
        max_time_secs: u64,
    ) -> Result<(u16, String), Error> {
        let max_time = max_time_secs.to_string();
        let mut command = self.https_command(address, path);
        command.args([
            "--http1.1",
            "-H",
            "Connection: close",
            "-H",
            "Expect:",
            "-X",
            method,
            "--output",
            "-",
            "--write-out",
            "\nhttp_code=%{http_code}",
            "--connect-timeout",
            "10",
            "--max-time",
            &max_time,
        ]);
        if let Some(cookie) = cookie {
            command.args(["--cookie", cookie]);
        }
        let body_file = body.map(|body| {
            let path = std::env::temp_dir().join(format!(
                "fwos-peer-body-{}-{}",
                std::process::id(),
                self.namespace
            ));
            (path, body)
        });
        if let Some((path, body)) = &body_file {
            std::fs::write(path, body)
                .map_err(|error| Error::from_io("writing peer HTTPS body", error))?;
            command.args(["-H", "Content-Type: application/json", "--data-binary"]);
            command.arg(format!("@{}", path.display()));
        }
        let output = command
            .output()
            .map_err(|error| Error::from_io("external-peer HTTPS exchange", error))?;
        if let Some((path, _)) = &body_file {
            let _ = std::fs::remove_file(path);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let Some((payload, code)) = text.rsplit_once("http_code=") else {
            return Err(Error::from_message(format!(
                "external-peer HTTPS exchange failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        };
        let code = code.trim().parse::<u16>().unwrap_or(0);
        if code == 0 {
            return Err(Error::from_message(format!(
                "external-peer HTTPS exchange failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok((code, payload.to_string()))
    }

    fn https_command(&self, address: &str, path: &str) -> Command {
        let host = if address.contains(':') {
            format!("[{address}]")
        } else {
            address.to_owned()
        };
        let mut command = self.command("curl");
        command
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
            ])
            .arg(format!("https://{host}{path}"));
        command
    }

    /// Establish real TLS and hold an incomplete HTTP request across a network change.
    pub fn begin_https_request(&self, address: &str) -> Result<PendingHttps, Error> {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer/pending-https.mjs");
        let mut child = self
            .command("node")
            .arg(script)
            .arg(address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::from_io("starting pending HTTPS request", e))?;
        let stdout = child.stdout.take().expect("piped pending HTTPS stdout");
        let mut pending = PendingHttps {
            child,
            output: BufReader::new(stdout),
        };
        if pending.message()?["ready"] != true {
            return Err(Error::from_message("pending HTTPS TLS handshake failed"));
        }
        Ok(pending)
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

    /// Resolve a fresh neighbor from this isolated peer, even if its ICMP input is blocked.
    pub fn resolve_neighbor(&self, address: &str) -> Result<bool, Error> {
        ip(&[
            "-n",
            &self.namespace,
            "neigh",
            "flush",
            "to",
            address,
            "dev",
            "eth0",
        ])?;
        let _ = self.ping(address)?;
        self.neighbor_resolved(address)
    }

    /// Act as the IPv6 upstream on this segment: RA for `ra_prefix`/64 and
    /// DHCPv6 with an address and, when given, a delegated prefix routed to
    /// the client like an ISP would. `None` answers NoPrefixAvail.
    pub fn start_ipv6_upstream(&mut self, ra_prefix: &str, delegate: Option<&str>) -> Result<(), Error> {
        self.start_ipv6_upstream_with_dns(ra_prefix, delegate, None)
    }

    /// Same, and DHCPv6 also names `dns_server` as the recursive resolver.
    pub fn start_ipv6_upstream_with_dns(
        &mut self,
        ra_prefix: &str,
        delegate: Option<&str>,
        dns_server: Option<&str>,
    ) -> Result<(), Error> {
        if self.upstream.is_some() {
            return Err(Error::from_message("IPv6 upstream already started"));
        }
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer/ipv6-upstream.py");
        let log = std::env::temp_dir().join(format!("fwos-ipv6-upstream-{}.log", self.namespace));
        let file = std::fs::File::create(&log)
            .map_err(|error| Error::from_io("IPv6 upstream log", error))?;
        let child = self
            .command("python3")
            .arg(script)
            .args(["eth0", ra_prefix, delegate.unwrap_or("none")])
            .args(dns_server)
            .stdout(file)
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Error::from_io("start IPv6 upstream", error))?;
        self.upstream = Some((child, log));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.ipv6_upstream_events()?.iter().any(|event| event["event"] == "ready") {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Error::from_message("IPv6 upstream did not start"))
    }

    /// Bindings the IPv6 upstream handed out, as reported by the upstream itself.
    pub fn ipv6_upstream_events(&self) -> Result<Vec<serde_json::Value>, Error> {
        let (_, log) = self
            .upstream
            .as_ref()
            .ok_or_else(|| Error::from_message("IPv6 upstream not started"))?;
        let text = std::fs::read_to_string(log)
            .map_err(|error| Error::from_io("read IPv6 upstream log", error))?;
        Ok(text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }

    /// Serve DNS on this segment, like an ISP resolver: `name` has the one
    /// AAAA record `address`, and every query is logged for `dns_queries`.
    pub fn serve_dns(&mut self, name: &str, address: &str) -> Result<(), Error> {
        if self.dns.is_some() {
            return Err(Error::from_message("peer DNS already started"));
        }
        let log = std::env::temp_dir().join(format!("fwos-dns-{}.log", self.namespace));
        let file = std::fs::File::create(&log)
            .map_err(|error| Error::from_io("peer DNS log", error))?;
        let mut child = self
            .command("dnsmasq")
            .args([
                "--conf-file=/dev/null",
                "--no-resolv",
                "--no-hosts",
                "--port=53",
                "--interface=eth0",
                "--bind-dynamic",
                "--keep-in-foreground",
                "--user=root",
                "--log-queries",
                "--log-facility=-",
            ])
            .arg(format!("--host-record={name},{address}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(file)
            .spawn()
            .map_err(|error| Error::from_io("start peer DNS", error))?;
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(Some(status)) = child.try_wait() {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let _ = std::fs::remove_file(&log);
            return Err(Error::from_message(format!("peer DNS exited {status}: {text}")));
        }
        self.dns = Some((child, log));
        Ok(())
    }

    /// Queries the peer DNS answered, as `query[TYPE] name from source` lines.
    pub fn dns_queries(&self) -> Result<Vec<String>, Error> {
        let (_, log) = self
            .dns
            .as_ref()
            .ok_or_else(|| Error::from_message("peer DNS not started"))?;
        let text = std::fs::read_to_string(log)
            .map_err(|error| Error::from_io("read peer DNS log", error))?;
        Ok(text
            .lines()
            .filter_map(|line| line.find("query[").map(|at| line[at..].to_owned()))
            .collect())
    }

    /// The Workstation path of this peer's network namespace.
    pub(crate) fn namespace_path(&self) -> String {
        format!("/run/netns/{}", self.namespace)
    }

    /// Let this peer autoconfigure from Router Advertisements, like a LAN host.
    pub fn enable_slaac(&self) -> Result<(), Error> {
        let output = self
            .command("sysctl")
            .args([
                "-w",
                "net.ipv6.conf.eth0.accept_ra=1",
                "net.ipv6.conf.eth0.autoconf=1",
            ])
            .output()
            .map_err(|e| Error::from_io("enable peer SLAAC", e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::from_message("could not enable peer SLAAC"))
        }
    }

    /// Global IPv6 addresses on this peer's segment interface.
    pub fn global_ipv6(&self) -> Result<Vec<String>, Error> {
        let output = self
            .command("ip")
            .args(["-j", "-6", "address", "show", "dev", "eth0", "scope", "global"])
            .output()
            .map_err(|e| Error::from_io("read peer IPv6 addresses", e))?;
        let links: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| Error::from_message(format!("peer IPv6 address JSON: {e}")))?;
        Ok(links
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|link| link["addr_info"].as_array().cloned().unwrap_or_default())
            .filter_map(|address| address["local"].as_str().map(str::to_owned))
            .collect())
    }

    /// The IPv6 default router this peer learned from Router Advertisements.
    pub fn ipv6_default_router(&self) -> Result<Option<String>, Error> {
        let output = self
            .command("ip")
            .args(["-j", "-6", "route", "show", "default", "dev", "eth0"])
            .output()
            .map_err(|e| Error::from_io("read peer IPv6 default route", e))?;
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| Error::from_message(format!("peer IPv6 route JSON: {e}")))?;
        Ok(routes
            .get(0)
            .and_then(|route| route["gateway"].as_str())
            .map(str::to_owned))
    }

    /// Record source addresses of ICMPv6 echo requests that reach this peer
    /// while `traffic` runs elsewhere.
    pub fn echo_request_sources(&self, traffic: impl FnOnce()) -> Result<Vec<String>, Error> {
        let capture = self
            .command("timeout")
            .args([
                "8", "tcpdump", "-n", "-l", "-i", "eth0", "icmp6", "and", "ip6[40]", "==", "128",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Error::from_io("external ICMPv6 capture", error))?;
        std::thread::sleep(Duration::from_millis(500));
        traffic();
        let output = capture
            .wait_with_output()
            .map_err(|error| Error::from_io("external ICMPv6 capture", error))?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                words.find(|word| *word == "IP6")?;
                words.next().map(str::to_owned)
            })
            .collect())
    }

    fn command(&self, executable: &str) -> Command {
        let mut command = Command::new("sudo");
        command.args(["-n", "ip", "netns", "exec", &self.namespace, executable]);
        command
    }
}

/// A real external HTTPS request that has not finished sending its headers.
pub struct PendingHttps {
    child: Child,
    output: BufReader<ChildStdout>,
}

impl PendingHttps {
    fn message(&mut self) -> Result<serde_json::Value, Error> {
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .map_err(|e| Error::from_io("reading pending HTTPS result", e))?;
        let message: serde_json::Value = serde_json::from_str(&line)
            .map_err(|_| Error::from_message("pending HTTPS driver returned no valid result"))?;
        if message.get("error").is_some() {
            return Err(Error::from_message("pending HTTPS driver failed"));
        }
        Ok(message)
    }

    pub fn finish(mut self) -> Result<Option<u16>, Error> {
        self.child
            .stdin
            .as_mut()
            .ok_or_else(|| Error::from_message("pending HTTPS stdin missing"))?
            .write_all(b"finish\n")
            .map_err(|e| Error::from_io("completing pending HTTPS request", e))?;
        let result = self.message()?;
        match result.get("status") {
            Some(serde_json::Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .filter(|code| (100..=599).contains(code))
                .map(|code| Some(code as u16))
                .ok_or_else(|| Error::from_message("invalid pending HTTPS status")),
            None => Err(Error::from_message("pending HTTPS result has no status")),
        }
    }
}

impl Drop for PendingHttps {
    fn drop(&mut self) {
        // EOF tells the bounded driver to destroy its socket, including when a
        // test panics between handshake and completion.
        self.child.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for NetworkPeer {
    fn drop(&mut self) {
        if self.owned_namespace {
            // Processes in this exclusively owned namespace are only fixture
            // helpers. Stop them before removing links or dropping log files.
            if let Ok(output) = Command::new("sudo")
                .args(["-n", "ip", "netns", "pids", &self.namespace])
                .output()
            {
                for pid in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                    if pid.parse::<u32>().is_ok() {
                        let _ = Command::new("sudo")
                            .args(["-n", "kill", "-TERM", pid])
                            .output();
                    }
                }
            }
        }
        self.discovery.take();
        for (mut child, log) in [self.upstream.take(), self.dns.take()].into_iter().flatten() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(log);
        }
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
