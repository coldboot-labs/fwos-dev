use std::sync::Mutex;

use fwos_dev::Guest;

static GUEST_LOCK: Mutex<()> = Mutex::new(());

fn guest_lock() -> std::sync::MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn ssh_into_booted_fedora_bootc_guest() {
    let _guard = guest_lock();
    let guest = Guest::boot_fedora_bootc().expect("guest must boot under QEMU");
    let out = guest
        .ssh("uname -s")
        .expect("SSH into the guest Host netns");
    assert_eq!(out.trim(), "Linux");
    let os = guest
        .ssh("cat /etc/os-release")
        .expect("os-release on stock Fedora bootc");
    assert!(
        os.lines().any(|l| l == "ID=fedora"),
        "stock Fedora bootc should identify as fedora, got:\n{os}"
    );
    assert!(
        !os.lines().any(|l| l == "ID=fwos"),
        "stock Fedora bootc must not pass FWOS branding, got:\n{os}"
    );
}

#[test]
fn ssh_into_booted_fwos_host_image() {
    let _guard = guest_lock();
    let guest = Guest::boot_host_image().expect("host image guest must boot under QEMU");
    let os = guest
        .ssh("cat /etc/os-release")
        .expect("os-release on the host image");
    assert!(
        os.lines().any(|l| l == "ID=fwos"),
        "host image must identify as FWOS (stock Fedora bootc must not pass); got:\n{os}"
    );
    let ip = guest
        .ssh("command -v ip")
        .expect("rescue ip must be present");
    assert!(
        ip.trim().ends_with("/ip"),
        "rescue ip missing from PATH: {ip:?}"
    );
    let links = guest
        .ssh("ip -o link show")
        .expect("link list in the Host netns");
    assert!(
        has_ethernet(&links),
        "expected a virtio-net NIC in the Host netns, got:\n{links}"
    );
}

fn has_ethernet(links: &str) -> bool {
    links.lines().any(|l| {
        let name = l.split(':').nth(1).map(str::trim).unwrap_or("");
        name.starts_with("enp") || name.starts_with("eth")
    })
}

fn assert_empty_fwd_and_mgmt(guest: &Guest) {
    let list = guest
        .ssh("ip netns list")
        .expect("ip netns list from the Host netns");
    for name in ["fwd", "mgmt"] {
        assert!(
            list.lines()
                .any(|l| l.split_whitespace().next() == Some(name)),
            "expected named netns {name}, got:\n{list}"
        );
        let links = guest
            .ssh(&format!("sudo -n ip netns exec {name} ip -o link show"))
            .unwrap_or_else(|e| panic!("ip netns exec {name}: {e}"));
        let names: Vec<&str> = links
            .lines()
            .filter_map(|l| l.split(':').nth(1).map(str::trim))
            .collect();
        assert_eq!(names, ["lo"], "{name} must contain only lo, got:\n{links}");
    }
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    assert!(
        has_ethernet(&host),
        "virtio-net must remain in the Host netns, got:\n{host}"
    );
    assert!(
        !host.contains("veth"),
        "no veth on first boot, got:\n{host}"
    );
}

#[test]
fn first_boot_creates_empty_fwd_and_mgmt() {
    let _guard = guest_lock();
    let mut guest = Guest::boot_host_image().expect("host image guest must boot under QEMU");
    assert_empty_fwd_and_mgmt(&guest);
    guest.reboot().expect("guest must come back after reboot");
    assert_empty_fwd_and_mgmt(&guest);
}

#[test]
fn netd_is_up_in_fwd() {
    let _guard = guest_lock();
    let guest = Guest::boot_host_image().expect("host image guest must boot under QEMU");
    assert_empty_fwd_and_mgmt(&guest);

    let sock = guest
        .ssh("test -S /var/lib/fwos/netd.sock && echo yes || echo no")
        .expect("probe netd socket on /var");
    assert_eq!(
        sock.trim(),
        "yes",
        "netd unix socket must exist at /var/lib/fwos/netd.sock"
    );

    let report = guest
        .ssh(
            r#"
set -e
found=
extra=
while read -r pid; do
  [ -n "$pid" ] || continue
  comm=$(tr -d '\0' < /proc/$pid/comm)
  cap=$(awk '/^CapEff:/ {print $2}' /proc/$pid/status)
  has=0
  [ "$((0x${cap} & 4096))" -ne 0 ] && has=1
  echo "pid=$pid comm=$comm CapEff=$cap net_admin=$has"
  if [ "$comm" = netd ]; then
    found=1
    [ "$has" -eq 1 ] || echo NETD_NO_CAP
  elif [ "$has" -eq 1 ]; then
    extra="$extra $comm"
  fi
done <<EOF
$(sudo -n ip netns pids fwd)
EOF
[ -n "$found" ] && echo FOUND_NETD || echo MISSING_NETD
[ -z "$extra" ] && echo NO_EXTRA_CAP || echo EXTRA_CAP:$extra
"#,
        )
        .expect("list processes in fwd");
    assert!(
        report.contains("FOUND_NETD"),
        "netd must be running in fwd, got:\n{report}"
    );
    assert!(
        !report.contains("NETD_NO_CAP"),
        "netd in fwd must have CAP_NET_ADMIN, got:\n{report}"
    );
    assert!(
        report.contains("NO_EXTRA_CAP"),
        "only netd in fwd may have CAP_NET_ADMIN, got:\n{report}"
    );

    let ssh_ok = guest
        .ssh("true")
        .expect("SSH into Host netns after netd is up");
    assert_eq!(ssh_ok, "");
}

fn ethernet_names(links: &str) -> Vec<String> {
    links
        .lines()
        .filter_map(|l| l.split(':').nth(1).map(str::trim))
        .filter(|name| name.starts_with("enp") || name.starts_with("eth"))
        .map(|s| s.to_string())
        .collect()
}

fn hex_encode(data: &str) -> String {
    data.bytes().map(|b| format!("{b:02x}")).collect()
}

fn apply_desired_result(guest: &Guest, json: &str) -> Result<String, String> {
    // One-line remote command: multiline SSH heredocs are flaky against this guest.
    let py = format!(
        "import json,socket\nbody={json}\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(60)\ns.connect('/var/lib/fwos/netd.sock')\ns.sendall(json.dumps(body).encode())\ns.shutdown(socket.SHUT_WR)\nprint(s.recv(65536).decode(),end='')\n"
    );
    let hex = hex_encode(&py);
    guest
        .ssh(&format!(
            "python3 -c 'exec(bytes.fromhex(\"{hex}\").decode())'"
        ))
        .map_err(|e| e.to_string())
}

fn apply_desired(guest: &Guest, json: &str) -> String {
    apply_desired_result(guest, json).unwrap_or_else(|e| panic!("JSON apply on netd socket: {e}"))
}

fn assert_traffic_placed(guest: &Guest, ssh_nic: &str, traffic_nic: &str) {
    let fwd = guest
        .ssh("sudo -n ip netns exec fwd ip -o link show")
        .expect("fwd links");
    let fwd_nics = ethernet_names(&fwd);
    assert_eq!(
        fwd_nics,
        vec![traffic_nic.to_string()],
        "exactly one Traffic NIC in fwd, got:\n{fwd}"
    );
    let addrs = guest
        .ssh(&format!(
            "sudo -n ip netns exec fwd ip -o addr show dev {traffic_nic}"
        ))
        .expect("traffic addresses");
    assert!(
        addrs.contains("192.0.2.1/24"),
        "Traffic NIC must have 192.0.2.1/24, got:\n{addrs}"
    );
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let host_nics = ethernet_names(&host);
    assert!(
        host_nics.iter().any(|n| n == ssh_nic),
        "SSH NIC {ssh_nic} must stay in the Host netns, got:\n{host}"
    );
    assert!(
        !host_nics.iter().any(|n| n == traffic_nic),
        "Traffic NIC {traffic_nic} must not remain in the Host netns, got:\n{host}"
    );
    assert!(!host.contains("veth"), "no veth extra hop, got:\n{host}");
    let nft = guest
        .ssh("sudo -n ip netns exec fwd nft list ruleset")
        .expect("nft in fwd");
    let nft_l = nft.to_ascii_lowercase();
    assert!(
        nft_l.contains("masquerade"),
        "NAT44 masquerade missing in fwd nft, got:\n{nft}"
    );
    assert!(
        nft_l.contains("drop"),
        "WAN inbound drop missing in fwd nft, got:\n{nft}"
    );
    assert!(
        nft_l.contains("accept"),
        "LAN outbound allow missing in fwd nft, got:\n{nft}"
    );
}

#[test]
fn json_places_a_traffic_nic() {
    let _guard = guest_lock();
    let mut guest =
        Guest::boot_host_image_two_nics().expect("two-NIC host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    assert_eq!(
        nics.len(),
        2,
        "expected two virtio-net NICs in the Host netns, got:\n{host}"
    );
    let route = guest
        .ssh("ip -o route show default")
        .expect("default route (SSH NIC)");
    let ssh_nic = nics
        .iter()
        .find(|n| route.contains(*n as &str))
        .cloned()
        .unwrap_or_else(|| {
            panic!("default route must name the SSH NIC, got route={route} nics={nics:?}")
        });
    let traffic_nic = nics
        .iter()
        .find(|n| *n != &ssh_nic)
        .cloned()
        .expect("second NIC is the Traffic NIC");

    let json = format!(
        r#"{{"interfaces":[{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}]}}"#
    );
    let reply = apply_desired(&guest, &json);
    assert!(
        reply.contains("\"ok\": true") || reply.contains("\"ok\":true"),
        "first apply must succeed, got:\n{reply}"
    );
    assert_traffic_placed(&guest, &ssh_nic, &traffic_nic);

    let reply2 = apply_desired(&guest, &json);
    assert!(
        reply2.contains("\"ok\": true") || reply2.contains("\"ok\":true"),
        "second apply must be idempotent, got:\n{reply2}"
    );
    assert_traffic_placed(&guest, &ssh_nic, &traffic_nic);

    guest.reboot().expect("guest must come back after reboot");
    assert_traffic_placed(&guest, &ssh_nic, &traffic_nic);
    guest.ssh("true").expect("SSH into Host netns after reboot");
}

fn host_cmd(cmd: &str) -> String {
    format!("sudo -n nsenter -t 1 -n {cmd}")
}

fn apply_diag(guest: &Guest) -> String {
    let mut parts = Vec::new();
    for cmd in [
        "cat /var/lib/fwos/desired.toml 2>/dev/null || echo NO_DESIRED",
        "test -S /var/lib/fwos/netd.sock && echo SOCK_YES || echo SOCK_NO",
        "systemctl is-active fwos-netd.service fwos-sshd.service sshd.service || true",
        "sudo -n ip netns exec mgmt ip -o link show || true",
        "sudo -n nsenter -t 1 -n ip -o link show || true",
    ] {
        let v = guest.ssh(cmd).unwrap_or_else(|e| format!("ssh: {e}"));
        parts.push(format!("{cmd} => {v}"));
    }
    parts.join(" | ")
}

fn wait_until_mgmt(guest: &Guest, ssh_nic: &str, apply_status: &str) {
    let mut last = String::from("(no probe)");
    for _ in 0..180 {
        match guest.ssh("sudo -n ip netns exec mgmt ip -o link show") {
            Ok(mgmt) => {
                last = mgmt.clone();
                if ethernet_names(&mgmt).iter().any(|n| n == ssh_nic) {
                    let session = guest.ssh("readlink /proc/self/ns/net").unwrap_or_default();
                    let host_ns = guest
                        .ssh(&host_cmd("readlink /proc/self/ns/net"))
                        .unwrap_or_default();
                    if !session.is_empty()
                        && !host_ns.is_empty()
                        && session.trim() != host_ns.trim()
                    {
                        return;
                    }
                    last = format!(
                        "nic in mgmt but session still host; session={session:?} host={host_ns:?} links={mgmt}"
                    );
                }
            }
            Err(e) => last = format!("ssh: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!(
        "Management NIC {ssh_nic} / sshd not in mgmt within 180s; apply={apply_status}; last={last}; {}",
        apply_diag(guest)
    );
}

fn assert_mgmt_placed(guest: &Guest, ssh_nic: &str, traffic_nic: &str) {
    let mgmt = guest
        .ssh("sudo -n ip netns exec mgmt ip -o link show")
        .expect("mgmt links");
    let mgmt_nics = ethernet_names(&mgmt);
    assert!(
        mgmt_nics.iter().any(|n| n == ssh_nic),
        "Management NIC {ssh_nic} must be in mgmt, got:\n{mgmt}"
    );
    assert!(
        !mgmt_nics.iter().any(|n| n == traffic_nic),
        "Traffic NIC {traffic_nic} must not be in mgmt, got:\n{mgmt}"
    );
    let fwd = guest
        .ssh("sudo -n ip netns exec fwd ip -o link show")
        .expect("fwd links");
    assert!(
        ethernet_names(&fwd).iter().any(|n| n == traffic_nic),
        "Traffic NIC {traffic_nic} must stay in fwd, got:\n{fwd}"
    );
    let host = guest
        .ssh(&host_cmd("ip -o link show"))
        .expect("Host netns links");
    let host_nics = ethernet_names(&host);
    assert!(
        !host_nics.iter().any(|n| n == ssh_nic || n == traffic_nic),
        "Host netns must not keep Traffic or Management NICs, got:\n{host}"
    );
    assert!(
        host.contains("veth") || host.contains("h0mgmt"),
        "Host netns must have a veth to mgmt, got:\n{host}"
    );
    let route = guest
        .ssh(&host_cmd("ip -o route show default"))
        .expect("host default route");
    assert!(
        route.contains("169.254.127.2") || route.contains("h0mgmt"),
        "host default must go via mgmt veth, got:\n{route}"
    );
    assert!(
        !route.contains(traffic_nic),
        "host default must not be a LAN↔WAN hop via {traffic_nic}, got:\n{route}"
    );
    let session_ns = guest
        .ssh("readlink /proc/self/ns/net")
        .expect("SSH session netns");
    let host_ns = guest
        .ssh(&host_cmd("readlink /proc/self/ns/net"))
        .expect("host netns inode");
    let mgmt_ns = guest
        .ssh("sudo -n ip netns exec mgmt readlink /proc/self/ns/net")
        .expect("mgmt netns inode");
    let fwd_ns = guest
        .ssh("sudo -n ip netns exec fwd readlink /proc/self/ns/net")
        .expect("fwd netns inode");
    assert_eq!(
        session_ns.trim(),
        mgmt_ns.trim(),
        "injected-key SSH must land in mgmt, session={session_ns} mgmt={mgmt_ns}"
    );
    assert_ne!(
        session_ns.trim(),
        host_ns.trim(),
        "sshd must not remain in the Host netns"
    );
    assert_ne!(session_ns.trim(), fwd_ns.trim(), "sshd must not run in fwd");
}

#[test]
fn json_places_management_nic() {
    let _guard = guest_lock();
    let mut guest =
        Guest::boot_host_image_two_nics().expect("two-NIC host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    assert_eq!(nics.len(), 2, "expected two virtio-net NICs, got:\n{host}");
    let route = guest
        .ssh("ip -o route show default")
        .expect("default route (SSH NIC)");
    let ssh_nic = nics
        .iter()
        .find(|n| route.contains(*n as &str))
        .cloned()
        .unwrap_or_else(|| {
            panic!("default route must name the SSH NIC, got route={route} nics={nics:?}")
        });
    let traffic_nic = nics
        .iter()
        .find(|n| *n != &ssh_nic)
        .cloned()
        .expect("second NIC is the Traffic NIC");

    let json = format!(
        r#"{{"interfaces":[{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{ssh_nic}","placement":"mgmt"}}]}}"#
    );
    let apply_status = apply_desired_result(&guest, &json);
    wait_until_mgmt(&guest, &ssh_nic, &format!("{apply_status:?}"));
    assert_mgmt_placed(&guest, &ssh_nic, &traffic_nic);

    guest.reboot().expect("guest must come back after reboot");
    wait_until_mgmt(&guest, &ssh_nic, "reboot");
    assert_mgmt_placed(&guest, &ssh_nic, &traffic_nic);
    guest
        .ssh("true")
        .expect("SSH after reboot with sshd in mgmt");
}

const APPLIANCE_CLI: &str = "/usr/lib/fwos/addons/cli/usr/bin/fwos";
// WireGuard test vector (docs.wireguard.com).
const WG_PRIVATE: &str = "yAnz5TF+lXXJte14tji3dzMe2arW8mOcy4V+1RU4hQE=";

fn apply_cli(guest: &Guest, body: &str) -> String {
    let hex = hex_encode(body);
    guest
        .ssh(&format!(
            "python3 -c 'open(\"/tmp/fwos-apply\",\"wb\").write(bytes.fromhex(\"{hex}\"))' && {APPLIANCE_CLI} apply /tmp/fwos-apply"
        ))
        .unwrap_or_else(|e| panic!("Appliance CLI apply: {e}"))
}

fn assert_full_desired(guest: &Guest, traffic_nic: &str) {
    let fwd_links = guest
        .ssh("sudo -n ip netns exec fwd ip -o link show")
        .expect("fwd links");
    assert!(
        fwd_links.contains("wg0"),
        "WireGuard wg0 must be in fwd, got:\n{fwd_links}"
    );
    let nft = guest
        .ssh("sudo -n ip netns exec fwd nft list ruleset")
        .expect("nft in fwd");
    assert!(
        nft.contains("203.0.113.50"),
        "extra nft rule missing in fwd, got:\n{nft}"
    );
    let routes = guest
        .ssh("sudo -n ip netns exec fwd ip -o route show")
        .expect("fwd routes");
    assert!(
        routes.contains("198.51.100.0/24"),
        "static route missing in fwd, got:\n{routes}"
    );
    let qdisc = guest
        .ssh(&format!(
            "sudo -n ip netns exec fwd tc qdisc show dev {traffic_nic}"
        ))
        .expect("qdisc on Traffic NIC");
    let q = qdisc.to_ascii_lowercase();
    assert!(
        q.contains("fq_codel") || q.contains("cake"),
        "qdisc CAKE or FQ-CoDel missing on {traffic_nic}, got:\n{qdisc}"
    );
}

#[test]
fn cli_applies_full_desired_state() {
    let _guard = guest_lock();
    let mut guest =
        Guest::boot_host_image_two_nics().expect("two-NIC host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    assert_eq!(nics.len(), 2, "expected two virtio-net NICs, got:\n{host}");
    let route = guest
        .ssh("ip -o route show default")
        .expect("default route (SSH NIC)");
    let ssh_nic = nics
        .iter()
        .find(|n| route.contains(*n as &str))
        .cloned()
        .unwrap_or_else(|| {
            panic!("default route must name the SSH NIC, got route={route} nics={nics:?}")
        });
    let traffic_nic = nics
        .iter()
        .find(|n| *n != &ssh_nic)
        .cloned()
        .expect("second NIC is the Traffic NIC");

    let place = format!(
        r#"{{"interfaces":[{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{ssh_nic}","placement":"mgmt"}}]}}"#
    );
    let apply_status = apply_desired_result(&guest, &place);
    wait_until_mgmt(&guest, &ssh_nic, &format!("{apply_status:?}"));

    let present = guest
        .ssh(&format!(
            "test -x {APPLIANCE_CLI} && echo yes || echo no; test -e /usr/bin/fwos && echo HOST || echo ADDON"
        ))
        .expect("probe Appliance CLI path");
    assert!(
        present.contains("yes"),
        "Appliance CLI missing at {APPLIANCE_CLI}, got:\n{present}"
    );
    assert!(
        present.contains("ADDON"),
        "Appliance CLI must not be a Host program at /usr/bin/fwos, got:\n{present}"
    );

    let session = guest
        .ssh("readlink /proc/self/ns/net")
        .expect("SSH session netns");
    let mgmt_ns = guest
        .ssh("sudo -n ip netns exec mgmt readlink /proc/self/ns/net")
        .expect("mgmt netns");
    assert_eq!(
        session.trim(),
        mgmt_ns.trim(),
        "CLI must be invoked from mgmt (SSH session)"
    );

    let full = format!(
        r#"{{"interfaces":[{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{ssh_nic}","placement":"mgmt"}}],"wireguard":[{{"name":"wg0","private_key":"{WG_PRIVATE}","listen_port":51820,"addresses":["10.13.13.1/24"]}}],"routes":[{{"to":"198.51.100.0/24","via":"192.0.2.254"}}],"nft_extra":["ip saddr 203.0.113.50 drop"],"qdiscs":[{{"dev":"{traffic_nic}","kind":"fq_codel"}}]}}"#
    );
    let reply = apply_cli(&guest, &full);
    assert!(
        reply.contains("\"ok\": true") || reply.contains("\"ok\":true"),
        "CLI apply must succeed, got:\n{reply}"
    );
    assert_full_desired(&guest, &traffic_nic);

    let toml = guest
        .ssh("cat /var/lib/fwos/desired.toml")
        .expect("Desired state TOML");
    assert!(
        toml.contains("wg0") && toml.contains("198.51.100.0/24") && toml.contains("fq_codel"),
        "TOML on /var must match the socket apply, got:\n{toml}"
    );
    let toml_reply = guest
        .ssh(&format!("{APPLIANCE_CLI} apply /var/lib/fwos/desired.toml"))
        .expect("CLI apply of break-glass TOML");
    assert!(
        toml_reply.contains("\"ok\": true") || toml_reply.contains("\"ok\":true"),
        "CLI must apply TOML Desired state, got:\n{toml_reply}"
    );

    guest.reboot().expect("guest must come back after reboot");
    wait_until_mgmt(&guest, &ssh_nic, "reboot");
    assert_full_desired(&guest, &traffic_nic);
}

fn py_exec(guest: &Guest, script: &str) -> Result<String, String> {
    let hex = hex_encode(script);
    guest
        .ssh(&format!(
            "python3 -c 'exec(bytes.fromhex(\"{hex}\").decode())'"
        ))
        .map_err(|e| e.to_string())
}

fn guest_ipv4(guest: &Guest, nic: &str) -> String {
    let out = guest
        .ssh(&format!(
            "ip -4 -o addr show dev {nic} | awk '{{print $4}}' | cut -d/ -f1 | head -1"
        ))
        .expect("IPv4 on NIC");
    let ip = out.trim().to_string();
    assert!(!ip.is_empty(), "expected IPv4 on {nic}, got:\n{out}");
    ip
}

fn assert_https_ui(guest: &Guest, ip: &str) -> String {
    let mut last = String::new();
    for _ in 0..60 {
        match py_exec(
            guest,
            &format!(
                r#"
import ssl, urllib.request, sys
ctx = ssl._create_unverified_context()
try:
    body = urllib.request.urlopen("https://{ip}/", context=ctx, timeout=5).read().decode()
    print(body)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"#
            ),
        ) {
            Ok(page) => {
                last = page;
                break;
            }
            Err(e) => last = e,
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let page = last;
    if !page.to_ascii_lowercase().contains("html")
        && !page.to_ascii_lowercase().contains("hostname")
    {
        panic!("HTTPS UI at https://{ip}/: {page}");
    }
    let http = py_exec(
        guest,
        &format!(
            r#"
import urllib.request, sys
try:
    urllib.request.urlopen("http://{ip}/", timeout=2)
    print("HTTP_OK")
except Exception:
    print("HTTP_FAIL")
"#
        ),
    )
    .unwrap_or_else(|_| "HTTP_FAIL".into());
    assert!(
        http.contains("HTTP_FAIL"),
        "UI must not serve HTTP, got:\n{http}"
    );
    page
}

fn assert_ui_bind_filter(guest: &Guest) {
    let listeners = guest
        .ssh("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"0A\" {print $2}'")
        .expect("listen sockets");
    // 00000000:01BB is 0.0.0.0:443; 00000000:0050 is :80.
    assert!(
        !listeners.to_ascii_uppercase().contains("00000000:01BB"),
        "UI must not listen on 0.0.0.0:443, got:\n{listeners}"
    );
    assert!(
        !listeners.to_ascii_uppercase().contains("00000000:0050"),
        "UI must not listen on 0.0.0.0:80, got:\n{listeners}"
    );
    let addrs = guest
        .ssh("ip -o addr show")
        .expect("addresses while UI is up");
    for line in addrs.lines() {
        for tok in line.split_whitespace() {
            let ip = tok.split('/').next().unwrap_or("");
            if ip.starts_with("100.64.") || ip.starts_with("100.65.") || ip.starts_with("100.127.")
            {
                panic!("CGNAT address present while asserting bind filter: {line}");
            }
        }
    }
}

#[test]
fn https_ui_completes_bootstrap() {
    let _guard = guest_lock();
    let guest =
        Guest::boot_host_image_two_nics().expect("two-NIC host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    assert_eq!(nics.len(), 2, "expected two virtio-net NICs, got:\n{host}");
    let route = guest
        .ssh("ip -o route show default")
        .expect("default route (SSH NIC)");
    let ssh_nic = nics
        .iter()
        .find(|n| route.contains(*n as &str))
        .cloned()
        .unwrap_or_else(|| {
            panic!("default route must name the SSH NIC, got route={route} nics={nics:?}")
        });
    let traffic_nic = nics
        .iter()
        .find(|n| *n != &ssh_nic)
        .cloned()
        .expect("second NIC is the Traffic NIC");
    let ip = guest_ipv4(&guest, &ssh_nic);

    let page = assert_https_ui(&guest, &ip);
    assert!(
        page.to_ascii_lowercase().contains("hostname")
            && page.to_ascii_lowercase().contains("admin"),
        "bootstrap UI must offer hostname and admin, got:\n{page}"
    );
    let lower = page.to_ascii_lowercase();
    assert!(
        !lower.contains("wireguard") && !lower.contains("qdisc") && !lower.contains("addon"),
        "v1 UI must not offer WG/qdisc/addons, got:\n{page}"
    );
    assert_ui_bind_filter(&guest);

    let host_ns = guest
        .ssh(&host_cmd("readlink /proc/self/ns/net"))
        .expect("host netns");
    let session = guest
        .ssh("readlink /proc/self/ns/net")
        .expect("SSH session netns");
    assert_eq!(
        session.trim(),
        host_ns.trim(),
        "before Bootstrap, SSH reaches the UI in the Host netns"
    );

    let post = format!(
        r#"
import ssl, urllib.request, urllib.parse, sys
ctx = ssl._create_unverified_context()
body = urllib.parse.urlencode({{
  "hostname": "fwos-box",
  "admin": "alice",
  "password": "secret12",
  "mgmt": "{ssh_nic}",
  "wan": "{traffic_nic}",
  "wan_addr": "192.0.2.1/24",
  "wan_addr6": "2001:db8::1/64",
  "wan_pd": "2001:db8:1::/48",
  "lan_prefix": "192.168.1.0/24",
  "dhcp_pool": "192.168.1.100-192.168.1.200",
}}).encode()
req = urllib.request.Request("https://{ip}/bootstrap", data=body, method="POST")
try:
    print(urllib.request.urlopen(req, context=ctx, timeout=30).read().decode())
except Exception as e:
    print("POST_ERR", e)
"#
    );
    let _ = py_exec(&guest, &post);
    wait_until_mgmt(&guest, &ssh_nic, "ui-bootstrap");
    assert_mgmt_placed(&guest, &ssh_nic, &traffic_nic);

    let mut hn = String::new();
    for _ in 0..30 {
        hn = guest.ssh("hostname").unwrap_or_default();
        if hn.contains("fwos-box") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        hn.contains("fwos-box"),
        "wizard must set hostname, got:\n{hn}"
    );
    let admin = guest
        .ssh("getent passwd alice || true")
        .expect("admin user");
    assert!(
        admin.starts_with("alice:"),
        "wizard must create admin, got:\n{admin}"
    );
    let toml = guest
        .ssh("cat /var/lib/fwos/desired.toml")
        .expect("Desired state after wizard");
    assert!(
        toml.contains("192.168.1.0/24")
            && toml.contains("192.168.1.100-192.168.1.200")
            && toml.contains("2001:db8::1/64")
            && toml.contains("2001:db8:1::/48"),
        "LAN prefix, DHCP pool, WAN v6 and PD must be Desired state, got:\n{toml}"
    );
    let nft = guest
        .ssh("sudo -n ip netns exec fwd nft list ruleset")
        .expect("nft after wizard");
    let nft_l = nft.to_ascii_lowercase();
    assert!(
        nft_l.contains("masquerade") && nft_l.contains("drop"),
        "default policy missing after wizard, got:\n{nft}"
    );

    let mgmt_ip = guest_ipv4(&guest, &ssh_nic);
    let page2 = assert_https_ui(&guest, &mgmt_ip);
    assert!(
        page2.to_ascii_lowercase().contains("hostname"),
        "same UI must still serve HTTPS in mgmt, got:\n{page2}"
    );
    guest.ssh("true").expect("injected-key SSH after wizard");
}
