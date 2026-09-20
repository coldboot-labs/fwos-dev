use fwos_dev::Guest;
use std::thread;
use std::time::{Duration, Instant};

fn wait_for_https(guest: &Guest) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 3) {
            assert!(
                body.contains("\"bootstrapped\":false") || body.contains("\"bootstrapped\": false"),
                "the selected NIC must reach the Bootstrap UI: {body}"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "selected NIC did not reach HTTPS; serial:\n{}",
            guest.serial()
        );
        thread::sleep(Duration::from_secs(1));
    }
}

fn console_nics(serial: &str) -> Vec<(String, String)> {
    serial
        .rsplit("NICs:")
        .next()
        .unwrap_or("")
        .split("Reach the UI:")
        .next()
        .unwrap_or("")
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            Some((name.to_owned(), fields.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

#[test]
fn startup_preserves_single_nic_bootstrap_exposure_after_reboot() {
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("the published two-NIC Disk image must boot");
    let deadline = Instant::now() + Duration::from_secs(30);
    let nics = loop {
        let nics = console_nics(&guest.serial());
        if nics.len() == 2 {
            break nics;
        }
        assert!(
            Instant::now() < deadline,
            "Bootstrap console must list both Traffic NICs"
        );
        guest.serial_write("\n").expect("refresh Bootstrap console");
        thread::sleep(Duration::from_secs(1));
    };
    for (nic, addresses) in &nics {
        assert!(
            !addresses.contains("10.0.2.") && !addresses.contains("10.0.3."),
            "unselected NIC {nic} acquired a QEMU peer address: {addresses}"
        );
    }
    assert!(
        guest.https_get("/").is_err(),
        "HTTPS answered before console opt-in"
    );
    assert!(
        guest.https_get_extra("/").is_err(),
        "the second NIC answered HTTPS before console opt-in"
    );

    // Identify the public user-network NIC through the supported console and
    // peer connection, without consulting guest internals or assuming NIC names.
    let mut selected = None;
    for (nic, _) in &nics {
        guest
            .serial_write(&format!("static {nic} 10.0.2.15/24\n"))
            .expect("select Bootstrap NIC");
        for _ in 0..10 {
            if let Ok((200, _)) = guest.https_exchange("GET", "/api/status", None, 2) {
                selected = Some(nic.clone());
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if selected.is_some() {
            break;
        }
    }
    let selected = selected.expect("console selection must make one NIC reachable");
    wait_for_https(&guest);
    assert!(
        guest.https_get_extra("/").is_err(),
        "the unselected NIC became reachable after selecting {selected}"
    );

    let before_reset = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("reset published guest externally");
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let serial = guest.serial();
        if serial
            .get(before_reset..)
            .unwrap_or("")
            .contains("FWOS Bootstrap console")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Bootstrap console did not return after reboot: {serial}"
        );
        thread::sleep(Duration::from_secs(1));
    }
    wait_for_https(&guest);
    assert!(
        guest.https_get_extra("/").is_err(),
        "reconstructing startup networking exposed the unselected NIC"
    );
    assert!(
        !guest.port_22_reachable(),
        "network SSH must remain unavailable"
    );
    guest
        .serial_write("\n")
        .expect("refresh recovered Bootstrap console");
    thread::sleep(Duration::from_secs(1));
    let serial = guest.serial();
    let after = console_nics(&serial);
    assert_eq!(
        after.len(),
        2,
        "both Traffic NICs must survive reboot: {serial}"
    );
    for (nic, addresses) in after {
        if nic == selected {
            assert!(
                addresses.contains("10.0.2.15"),
                "the selected NIC lost its temporary address after reboot: {serial}"
            );
        } else {
            assert!(
                !addresses.contains("10.0.2.") && !addresses.contains("10.0.3."),
                "the unselected NIC acquired an address after reboot: {serial}"
            );
        }
    }
}
