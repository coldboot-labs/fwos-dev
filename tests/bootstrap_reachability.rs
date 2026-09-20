use fwos_dev::{Guest, NetworkPeer};
use std::thread;
use std::time::{Duration, Instant};

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
    let before = guest.serial().len();
    guest
        .serial_write(&format!("static {nic} {cidr}\n"))
        .expect("select temporary address through console");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let serial = guest.serial();
        let tail = serial.get(before..).unwrap_or("");
        if tail.contains("FWOS Bootstrap console") && tail.contains("Reach the UI:") {
            return;
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
            return;
        }
        assert!(
            Instant::now() < deadline,
            "private Bootstrap HTTPS at {address}: {response:?}"
        );
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn bootstrap_https_excludes_non_private_address_classes() {
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
