use fwos_dev::{Guest, NetworkPeer};
use std::thread;
use std::time::{Duration, Instant};

fn console_nics(guest: &Guest) -> Vec<String> {
    guest
        .serial()
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
fn bootstrap_https_only_uses_rfc1918_or_ula_on_the_selected_nic() {
    let peer = NetworkPeer::new().expect("isolated external peer");
    for cidr in [
        "10.56.0.2/24",
        "169.254.56.2/16",
        "100.64.56.2/24",
        "198.51.100.2/24",
        "fd56::2/64",
        "2001:db8:56::2/64",
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
        peer.https_get("10.56.0.1", "/").is_err(),
        "no HTTPS before console opt-in"
    );
    select_static(&guest, nic, "10.56.0.1/24");
    assert_bootstrap_https(&peer, "10.56.0.1");

    for (kind, cidr, address) in [
        ("IPv4 link-local", "169.254.56.1/16", "169.254.56.1"),
        ("CGNAT", "100.64.56.1/24", "100.64.56.1"),
        ("global IPv4", "198.51.100.1/24", "198.51.100.1"),
        ("IPv6 GUA", "2001:db8:56::1/64", "2001:db8:56::1"),
        ("IPv6 link-local", "fe80::1/64", "fe80::1%eth0"),
    ] {
        select_static(&guest, nic, cidr);
        thread::sleep(Duration::from_secs(2));
        peer.ping(address)
            .expect("selected interface remains on-link, including neighbor discovery");
        assert!(
            peer.https_get(address, "/").is_err(),
            "{kind} must not expose Bootstrap HTTPS"
        );
        assert!(
            peer.https_get("10.56.0.1", "/").is_err(),
            "replacing the temporary address removes old exposure"
        );
    }
    select_static(&guest, nic, "fd56::1/64");
    peer.ping("fd56::1")
        .expect("IPv6 neighbor discovery still works");
    assert_bootstrap_https(&peer, "fd56::1");
}
