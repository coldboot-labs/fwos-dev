use fwos_dev::{Guest, NetworkPeer};
use std::thread;
use std::time::{Duration, Instant};

fn guest_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn console_nics(guest: &Guest) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let serial = loop {
        let serial = guest.serial();
        if serial.contains("Reach the UI:") {
            break serial;
        }
        assert!(
            Instant::now() < deadline,
            "console NIC list is incomplete: {serial}"
        );
        thread::sleep(Duration::from_millis(100));
    };
    serial
        .rsplit("NICs:")
        .next()
        .unwrap_or("")
        .split("Reach the UI:")
        .next()
        .unwrap_or("")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "(none)")
        .map(str::to_owned)
        .collect()
}

fn select_static(guest: &Guest, nic: &str, cidr: &str) {
    console_command(guest, &format!("static {nic} {cidr}"));
}

fn console_command(guest: &Guest, command: &str) -> String {
    let before = guest.serial().len();
    guest
        .serial_write(&format!("{command}\n"))
        .expect("select temporary address through console");
    wait_console_since(guest, before, Duration::from_secs(40))
}

fn wait_console_since(guest: &Guest, before: usize, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let serial = guest.serial();
        let tail = serial.get(before..).unwrap_or("");
        if tail.contains("FWOS Bootstrap console") && tail.contains("Reach the UI:") {
            return tail.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "console did not finish selection: {tail}"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn assert_bootstrap_https(peer: &NetworkPeer, address: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = peer.https_get(address, "/api/status");
        if let Ok(body) = &response {
            let status: serde_json::Value =
                serde_json::from_str(body).expect("Bootstrap JSON status");
            assert_eq!(status["bootstrapped"], false);
            assert_eq!(
                status["interfaces"],
                serde_json::json!([]),
                "temporary reachability must not become Desired interfaces"
            );
            assert_eq!(
                status["ui_exposure"],
                serde_json::json!([]),
                "temporary reachability must not become Desired UI exposure"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "private Bootstrap HTTPS at {address}: {response:?}"
        );
        thread::sleep(Duration::from_secs(1));
    }
}

fn nic_addresses(status: &str, nic: &str) -> Vec<String> {
    status
        .rsplit("NICs:")
        .next()
        .unwrap_or("")
        .split("Reach the UI:")
        .next()
        .unwrap_or("")
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(nic)).then(|| fields.map(str::to_owned).collect())
        })
        .unwrap_or_else(|| panic!("missing NIC {nic} in public console: {status}"))
}

fn assert_no_acquisition(peer: &mut NetworkPeer) {
    let packets = peer
        .discovery_packets()
        .expect("live external discovery capture");
    assert_eq!(
        (packets.dhcp_v4, packets.dhcp_v6, packets.router_discovery),
        (0, 0, 0),
        "unselected NIC emitted address discovery: {packets:?}"
    );
}

#[test]
fn temporary_dynamic_selection_keeps_other_nics_quiet_and_survives_reboot() {
    let _guard = guest_lock();
    let mut peers = [NetworkPeer::new().unwrap(), NetworkPeer::new().unwrap()];
    let leases = ["10.57.5.100", "10.58.5.100"];
    let prefixes = ["fd57:1:", "fd57:2:"];
    for (index, peer) in peers.iter_mut().enumerate() {
        let octet = 57 + index;
        peer.add_address(&format!("10.{octet}.0.2/16")).unwrap();
        peer.add_address(&format!("fd57:{}::2/64", index + 1))
            .unwrap();
        peer.advertise(
            leases[index],
            "255.255.0.0",
            &format!("fd57:{}::", index + 1),
        )
        .expect("real isolated DHCP/RA service with capture ready before boot");
    }
    let guest = Guest::boot_published_host_image_with_peers(&[&peers[0], &peers[1]])
        .expect("two-NIC published appliance");
    let nics = console_nics(&guest);
    assert_eq!(nics.len(), 2);
    thread::sleep(Duration::from_secs(5));
    let status = console_command(&guest, "status");
    for (index, peer) in peers.iter_mut().enumerate() {
        assert_no_acquisition(peer);
        assert!(
            peer.https_response(leases[index]).unwrap().is_none(),
            "no pre-opt HTTPS on either NIC"
        );
    }
    for nic in &nics {
        assert!(
            nic_addresses(&status, nic)
                .iter()
                .all(|address| address.starts_with("fe80:")),
            "passive peer RA must not configure an unselected NIC: {status}"
        );
    }

    let dhcp = console_command(&guest, &format!("dhcp {}", nics[0]));
    let selected = leases
        .iter()
        .position(|lease| {
            nic_addresses(&dhcp, &nics[0])
                .iter()
                .any(|addr| addr == lease)
        })
        .unwrap_or_else(|| panic!("selected NIC did not acquire an advertised DHCP lease: {dhcp}"));
    let other = 1 - selected;
    assert_bootstrap_https(&peers[selected], leases[selected]);
    assert!(
        peers[selected].discovery_packets().unwrap().dhcp_v4 > 0,
        "positive control: capture must observe the real selected DHCP exchange"
    );
    assert_no_acquisition(&mut peers[other]);
    assert!(
        nic_addresses(&dhcp, &nics[1])
            .iter()
            .all(|address| address.starts_with("fe80:")),
        "unselected NIC must ignore passive RA: {dhcp}"
    );

    let before = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("reboot persisted DHCP selection");
    wait_console_since(&guest, before, Duration::from_secs(120));
    let dhcp_rebooted = console_command(&guest, "status");
    assert!(
        nic_addresses(&dhcp_rebooted, &nics[0])
            .iter()
            .any(|address| address == leases[selected]),
        "persisted DHCP mode must reacquire the fixture's lease: {dhcp_rebooted}"
    );
    assert_bootstrap_https(&peers[selected], leases[selected]);
    assert_no_acquisition(&mut peers[other]);
    assert!(
        nic_addresses(&dhcp_rebooted, &nics[1])
            .iter()
            .all(|address| address.starts_with("fe80:")),
        "unselected NIC must remain unconfigured after DHCP reboot: {dhcp_rebooted}"
    );

    let slaac = console_command(&guest, &format!("slaac {}", nics[0]));
    let first_ula = nic_addresses(&slaac, &nics[0])
        .into_iter()
        .find(|address| address.starts_with(prefixes[selected]))
        .unwrap_or_else(|| panic!("selected NIC did not acquire advertised ULA: {slaac}"));
    assert_bootstrap_https(&peers[selected], &first_ula);
    assert!(
        peers[selected]
            .https_response(leases[selected])
            .unwrap()
            .is_none(),
        "mode replacement removes DHCP exposure"
    );
    assert_no_acquisition(&mut peers[other]);

    let replacement = console_command(&guest, &format!("slaac {}", nics[1]));
    let current_ula = nic_addresses(&replacement, &nics[1])
        .into_iter()
        .find(|address| address.starts_with(prefixes[other]))
        .unwrap_or_else(|| panic!("replacement NIC did not acquire advertised ULA: {replacement}"));
    assert_bootstrap_https(&peers[other], &current_ula);
    assert!(
        peers[selected]
            .https_response(&first_ula)
            .unwrap()
            .is_none(),
        "NIC replacement removes old HTTPS exposure"
    );
    assert!(
        nic_addresses(&replacement, &nics[0])
            .iter()
            .all(|address| address.starts_with("fe80:")),
        "previously selected NIC must become unconfigured: {replacement}"
    );
    let previous_capture = peers[selected].discovery_packets().unwrap();

    let before = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("external appliance reset on same disk");
    wait_console_since(&guest, before, Duration::from_secs(120));
    thread::sleep(Duration::from_secs(5));
    let rebooted = console_command(&guest, "status");
    let rebooted_ula = nic_addresses(&rebooted, &nics[1])
        .into_iter()
        .find(|address| address.starts_with(prefixes[other]))
        .unwrap_or_else(|| {
            panic!("selected SLAAC NIC must reacquire an advertised ULA: {rebooted}")
        });
    assert!(
        nic_addresses(&rebooted, &nics[0])
            .iter()
            .all(|address| address.starts_with("fe80:")),
        "old NIC must ignore RA after reboot: {rebooted}"
    );
    assert_bootstrap_https(&peers[other], &rebooted_ula);
    assert!(peers[selected]
        .https_response(&first_ula)
        .unwrap()
        .is_none());
    let after = peers[selected].discovery_packets().unwrap();
    assert_eq!(
        (after.dhcp_v4, after.dhcp_v6, after.router_discovery),
        (
            previous_capture.dhcp_v4,
            previous_capture.dhcp_v6,
            previous_capture.router_discovery
        ),
        "deselected NIC must remain quiet through reboot"
    );
    for peer in &mut peers {
        assert!(
            peer.discovery_packets().unwrap().neighbor_discovery > 0,
            "positive control: both captures must observe real selected IPv6 traffic"
        );
    }
}

#[test]
fn bootstrap_slaac_exposes_a_ula_advertised_after_console_selection_finishes() {
    let _guard = guest_lock();
    let mut peer = NetworkPeer::new().expect("isolated late-RA peer");
    peer.add_address("10.59.0.2/24").unwrap();
    peer.add_address("fd59::2/64").unwrap();
    let guest = Guest::boot_published_host_image_with_peers(&[&peer]).expect("published appliance");
    let nics = console_nics(&guest);
    assert_eq!(nics.len(), 1);
    let selected = console_command(&guest, &format!("slaac {}", nics[0]));
    assert!(
        nic_addresses(&selected, &nics[0])
            .iter()
            .all(|address| address.starts_with("fe80:")),
        "no router has advertised a ULA yet: {selected}"
    );
    // Start the real router only after the command's acquisition wait ends.
    peer.advertise("10.59.0.100", "255.255.255.0", "fd59::")
        .expect("start delayed external RA");
    let deadline = Instant::now() + Duration::from_secs(30);
    let address = loop {
        let status = console_command(&guest, "status");
        if let Some(address) = nic_addresses(&status, &nics[0])
            .into_iter()
            .find(|address| address.starts_with("fd59:"))
        {
            break address;
        }
        assert!(
            Instant::now() < deadline,
            "late RA must configure selected NIC: {status}"
        );
        thread::sleep(Duration::from_secs(1));
    };
    assert_bootstrap_https(&peer, &address);
    assert!(
        peer.discovery_packets().unwrap().neighbor_discovery > 0,
        "positive control for delayed-RA capture and IPv6 traffic"
    );
}

#[test]
fn bootstrap_https_excludes_non_private_address_classes() {
    let _guard = guest_lock();
    let peer = NetworkPeer::new().expect("isolated external peer");
    for cidr in [
        "10.56.0.2/24",
        "169.254.56.2/16",
        "100.64.56.2/24",
        "8.8.8.2/24",
        "fd56::2/64",
        "2001:4860:56::2/64",
        "fe80::2/64",
    ] {
        peer.add_address(cidr)
            .expect("configure external peer address");
    }
    let guest = Guest::boot_published_host_image_with_peers(&[&peer])
        .expect("published appliance on external Ethernet");
    let nics = console_nics(&guest);
    assert_eq!(
        nics.len(),
        1,
        "console must list one Traffic NIC: {}",
        guest.serial()
    );
    let nic = &nics[0];
    assert!(
        peer.https_response("10.56.0.1")
            .expect("probe pre-opt HTTPS")
            .is_none(),
        "no HTTPS before console opt-in"
    );
    select_static(&guest, nic, "10.56.0.1/24");
    assert_bootstrap_https(&peer, "10.56.0.1");

    for (kind, cidr, address) in [
        ("IPv4 link-local", "169.254.56.1/16", "169.254.56.1"),
        ("CGNAT", "100.64.56.1/24", "100.64.56.1"),
        ("global IPv4", "8.8.8.1/24", "8.8.8.1"),
        ("IPv6 GUA", "2001:4860:56::1/64", "2001:4860:56::1"),
        ("IPv6 link-local", "fe80::1/64", "fe80::1%eth0"),
    ] {
        select_static(&guest, nic, cidr);
        thread::sleep(Duration::from_secs(2));
        assert!(
            peer.https_response(address)
                .expect("probe excluded-address HTTPS")
                .is_none(),
            "{kind} must not expose Bootstrap HTTPS"
        );
        if kind == "IPv6 link-local" {
            assert!(
                peer.neighbor_resolved("fe80::1")
                    .expect("read external peer's neighbor discovery result"),
                "excluding link-local HTTPS must not break IPv6 neighbor discovery"
            );
        }
        assert!(
            peer.https_response("10.56.0.1")
                .expect("probe prior-address HTTPS")
                .is_none(),
            "replacing the temporary address removes old exposure"
        );
    }
}

#[test]
fn bootstrap_ula_https_works_after_a_fresh_static_selection() {
    let _guard = guest_lock();
    let peer = NetworkPeer::new().expect("isolated IPv6 external peer");
    peer.add_address("fd56::2/64")
        .expect("on-link ULA peer address");
    let guest = Guest::boot_published_host_image_with_peers(&[&peer])
        .expect("published appliance on external IPv6 Ethernet");
    let nics = console_nics(&guest);
    assert_eq!(nics.len(), 1);
    select_static(&guest, &nics[0], "fd56::1/64");
    assert_bootstrap_https(&peer, "fd56::1");
}

#[test]
fn bootstrap_https_cannot_bypass_exposure_by_routing_to_internal_addresses() {
    let _guard = guest_lock();
    let peer = NetworkPeer::new().expect("isolated routing peer");
    peer.add_address("10.56.0.2/24").expect("IPv4 peer");
    peer.add_address("fd56::2/64").expect("IPv6 peer");
    let guest = Guest::boot_published_host_image_with_peers(&[&peer]).expect("published appliance");
    let nics = console_nics(&guest);
    assert_eq!(nics.len(), 1);
    for (cidr, address, internal, route) in [
        (
            "10.56.0.1/24",
            "10.56.0.1",
            "169.254.127.6",
            "169.254.127.6/32",
        ),
        ("fd56::1/64", "fd56::1", "fd53:1:1::6", "fd53:1:1::6/128"),
    ] {
        select_static(&guest, &nics[0], cidr);
        assert_bootstrap_https(&peer, address);
        peer.add_route(route, address)
            .expect("external peer route through selected NIC");
        assert!(
            peer.https_response(internal)
                .expect("probe direct internal HTTPS")
                .is_none(),
            "routing directly to internal {internal} must not bypass Bootstrap exposure"
        );
    }
}

#[test]
fn replacing_an_address_revokes_an_already_connected_bootstrap_request() {
    let _guard = guest_lock();
    let peer = NetworkPeer::new().expect("isolated external peer");
    peer.add_address("10.56.0.2/24").expect("IPv4 peer");
    let guest = Guest::boot_published_host_image_with_peers(&[&peer]).expect("published appliance");
    let nics = console_nics(&guest);
    assert_eq!(nics.len(), 1);
    select_static(&guest, &nics[0], "10.56.0.1/24");
    assert_bootstrap_https(&peer, "10.56.0.1");
    let pending = peer
        .begin_https_request("10.56.0.1")
        .expect("establish HTTPS before replacing address");
    select_static(&guest, &nics[0], "10.56.0.9/24");
    assert_bootstrap_https(&peer, "10.56.0.9");
    assert_eq!(
        pending
            .finish()
            .expect("finish request over the prior connection"),
        None,
        "an existing connection to the previous address must not retain Bootstrap exposure"
    );
    let current = peer
        .begin_https_request("10.56.0.9")
        .expect("establish HTTPS on current address");
    assert_eq!(
        current
            .finish()
            .expect("positive control for held HTTP requests"),
        Some(200)
    );
}
