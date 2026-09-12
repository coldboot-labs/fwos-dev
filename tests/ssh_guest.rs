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

#[test]
fn published_disk_image_has_no_network_ssh_before_bootstrap() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published Disk image guest must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published guest is observed on the Bootstrap console, not Host-netns SSH; serial:\n{serial}"
    );
    let mut banner = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(ident) = guest.ssh_ident() {
            banner = Some(ident);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if let Some(ident) = banner {
        panic!(
            "published Disk image must not accept network SSH before Bootstrap, got banner {ident}; serial:\n{serial}"
        );
    }
}

#[test]
fn published_guest_serial_and_https_without_ssh() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published Disk image guest must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "tests observe published guests on the Bootstrap console; serial:\n{serial}"
    );
    guest
        .serial_write("\n")
        .expect("tests must write the guest serial console");
    let mut last = String::new();
    for _ in 0..5 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if last.matches("FWOS Bootstrap console").count() >= 2 {
            break;
        }
    }
    assert!(
        last.matches("FWOS Bootstrap console").count() >= 2,
        "serial write must reach the Bootstrap console; serial:\n{last}"
    );

    let mut page = String::new();
    let mut err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                page = body;
                if page.to_ascii_lowercase().contains("hostname")
                    || page.to_ascii_lowercase().contains("html")
                {
                    break;
                }
            }
            Err(e) => err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let lower = page.to_ascii_lowercase();
    assert!(
        lower.contains("hostname") || lower.contains("html") || lower.contains("admin"),
        "Workstation must reach the UI over HTTPS, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );
    assert!(
        lower.contains("hostname") && lower.contains("admin"),
        "wizard HTML must collect hostname and admin, body:\n{page}"
    );
    for needle in ["fwd", "mgmt", "vlan", "dhcp", "static", "lan", "pool", "pd"] {
        assert!(
            lower.contains(needle),
            "wizard HTML must collect {needle} (NIC placement, stick VLANs, static/DHCP, LAN prefix, DHCP pool, WAN v6/PD), body:\n{page}"
        );
    }
    assert!(
        !lower.contains("wireguard") && !lower.contains("qdisc") && !lower.contains("addon"),
        "v1 UI must not offer WG/qdisc/addons, body:\n{page}"
    );

    let mut status = String::new();
    let mut status_err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                status = body;
                if status.contains("bootstrapped") {
                    break;
                }
            }
            Err(e) => status_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let trimmed = status.trim_start();
    assert!(
        trimmed.starts_with('{'),
        "browser uses HTTPS JSON; /api/status must be JSON, last={status_err}; body:\n{status}; serial:\n{}",
        guest.serial()
    );
    assert!(
        status.contains("\"bootstrapped\"") && status.contains("false"),
        "published wizard is pre-Bootstrap; last={status_err}; body:\n{status}"
    );
    assert!(
        status.contains("\"nics\"") && status.contains("hostname"),
        "status JSON must list NICs and hostname; body:\n{status}"
    );

    let mut banner = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(ident) = guest.ssh_ident() {
            banner = Some(ident);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if let Some(ident) = banner {
        panic!(
            "published guest must not answer SSH, got banner {ident}; serial:\n{}",
            guest.serial()
        );
    }
}

#[test]
fn published_guest_bootstrap_console_on_serial() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published Disk image guest must boot under QEMU");
    let serial = guest.serial();
    let lower = serial.to_ascii_lowercase();
    assert!(
        !lower.contains("login:"),
        "Appliance CLI owns serial; no Host shell login, serial:\n{serial}"
    );
    assert!(
        lower.contains("bootstrap"),
        "first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let nic = serial_ethernet_name(&serial).unwrap_or_else(|| {
        panic!("Bootstrap console must list Host-netns NICs, serial:\n{serial}")
    });

    guest
        .serial_write(&format!("static {nic} 192.168.200.50/24\n"))
        .expect("set ephemeral addressing on serial");
    let mut last = serial;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if last.contains("https://192.168.200.50/") {
            break;
        }
    }
    assert!(
        last.contains("192.168.200.50"),
        "ephemeral static addressing is not Desired state; serial:\n{last}"
    );
    assert!(
        last.contains("https://192.168.200.50/"),
        "Bootstrap console must print how to reach the UI, serial:\n{last}"
    );

    guest
        .serial_write("echo SHELL_RAN\n")
        .expect("probe Host shell");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let after = guest.serial();
    assert!(
        after.contains("unknown command"),
        "Bootstrap console must reject a shell command, serial:\n{after}"
    );
    assert!(
        !after.lines().any(|l| l.trim() == "SHELL_RAN"),
        "serial must not be a Host shell, serial:\n{after}"
    );

    let mut banner = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(ident) = guest.ssh_ident() {
            banner = Some(ident);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if let Some(ident) = banner {
        panic!(
            "published guest must not answer SSH, got banner {ident}; serial:\n{}",
            guest.serial()
        );
    }
}

#[test]
fn published_first_boot_console_wizard_ui_in_mgmt_no_ssh() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let lower = serial.to_ascii_lowercase();
    assert!(
        !lower.contains("login:") && !lower.contains("admin:"),
        "unauthenticated Bootstrap console is not the admin Appliance CLI, serial:\n{serial}"
    );
    assert_no_ssh(&guest, "before Bootstrap");

    let (mgmt_nic, traffic_nic) = published_mgmt_and_traffic(&serial);
    let mut page = String::new();
    let mut err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                page = body;
                if page.to_ascii_lowercase().contains("hostname")
                    && page.to_ascii_lowercase().contains("admin")
                {
                    break;
                }
            }
            Err(e) => err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let lower = page.to_ascii_lowercase();
    assert!(
        lower.contains("hostname") && lower.contains("admin"),
        "Workstation must reach the HTTPS wizard, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );

    let mut status = String::new();
    for _ in 0..90 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                status = body;
                if status.contains("\"bootstrapped\"") {
                    break;
                }
            }
            Err(e) => status = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        status.contains("\"bootstrapped\"") && status.contains("false"),
        "wizard is pre-Bootstrap; body:\n{status}; serial:\n{}",
        guest.serial()
    );

    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{mgmt_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    );
    let mut post = String::from("(no POST)");
    let mut post_ok = false;
    for _ in 0..90 {
        match guest.https_exchange("POST", "/api/bootstrap", Some(&payload), 90) {
            Ok((200, body)) => {
                post = body;
                if post.contains("\"ok\"") {
                    post_ok = true;
                    break;
                }
            }
            Ok((409, body)) => {
                // UI restart after a successful apply can drop the 200; stamp is on /var.
                post = body;
                post_ok = true;
                break;
            }
            Ok((code, body)) => post = format!("http_code={code} {body}"),
            Err(e) => post = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        post_ok,
        "HTTPS wizard POST must complete Bootstrap, last={post}; serial:\n{}",
        guest.serial()
    );

    let mut after = String::new();
    for _ in 0..180 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                after = body;
                if after.contains("\"bootstrapped\"") && after.contains("true") {
                    break;
                }
            }
            Err(e) => after = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        after.contains("\"bootstrapped\"") && after.contains("true"),
        "after Bootstrap, UI status must report bootstrapped (UI in mgmt); got:\n{after}; serial:\n{}",
        guest.serial()
    );
    assert!(
        after.contains("fwos-box") && after.contains("192.168.1.0/24"),
        "status JSON must show hostname and LAN prefix, got:\n{after}"
    );
    assert!(
        after.contains("\"mgmt\"") && after.contains("\"fwd\""),
        "status JSON must show NIC placement, got:\n{after}"
    );
    let after_l = after.to_ascii_lowercase();
    assert!(
        !after_l.contains("password")
            && !after_l.contains("wireguard")
            && !after_l.contains("qdisc")
            && !after_l.contains("private_key"),
        "v1 status must not expose a rule editor, WG, qdisc, or secrets, got:\n{after}"
    );

    let mut saw_409 = false;
    let mut post2 = String::from("(no POST)");
    for _ in 0..90 {
        match guest.https_exchange("POST", "/api/bootstrap", Some(&payload), 15) {
            Ok((409, body)) => {
                post2 = body;
                saw_409 = true;
                break;
            }
            Ok((200, body)) => panic!(
                "wizard must not accept POST after Bootstrap, got 200: {body}; serial:\n{}",
                guest.serial()
            ),
            Ok((code, body)) => post2 = format!("http_code={code} {body}"),
            Err(e) => post2 = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        saw_409 && post2.to_ascii_lowercase().contains("bootstrapped"),
        "POST after Bootstrap must 409; last={post2}; serial:\n{}",
        guest.serial()
    );

    let mut last = guest.serial();
    for _ in 0..60 {
        let _ = guest.serial_write("\n");
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if last.contains("FWOS Appliance CLI") {
            break;
        }
    }
    assert!(
        last.contains("FWOS Appliance CLI"),
        "after Bootstrap, serial must be the admin Appliance CLI, not the Bootstrap console; serial:\n{last}"
    );
    let tail = serial_tail(&last, 4000).to_ascii_lowercase();
    assert!(
        !tail.contains("fwos bootstrap console")
            && !tail.contains("ephemeral")
            && !tail.contains("reach the ui"),
        "admin Appliance CLI must not keep first-boot ephemeral addressing as the UX; serial:\n{last}"
    );

    guest
        .serial_write("alice\n")
        .expect("admin name on Appliance CLI");
    let mut saw_password = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if serial_tail(&last, 2000)
            .to_ascii_lowercase()
            .contains("password")
        {
            saw_password = true;
            break;
        }
        let _ = guest.serial_write("alice\n");
    }
    assert!(
        saw_password,
        "Appliance CLI must prompt for the admin password, serial:\n{last}"
    );
    guest
        .serial_write("secret12\n")
        .expect("admin password on Appliance CLI");
    let mut logged_in = false;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        let tail = serial_tail(&last, 3000);
        if tail.contains("fwos>") || tail.contains("fwos-box") {
            logged_in = true;
            break;
        }
    }
    assert!(
        logged_in,
        "admin must authenticate into the Appliance CLI, serial:\n{last}"
    );

    guest
        .serial_write("status\n")
        .expect("status on Appliance CLI");
    let mut status_cli = String::new();
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        status_cli = guest.serial();
        if serial_tail(&status_cli, 3000).contains("fwos-box") {
            break;
        }
    }
    let st_tail = serial_tail(&status_cli, 4000);
    assert!(
        st_tail.contains("fwos-box"),
        "Appliance CLI status must show the hostname, serial:\n{status_cli}"
    );
    assert!(
        !serial_tail(&status_cli, 2000).contains("FWOS Bootstrap console"),
        "status must not be the Bootstrap console, serial:\n{status_cli}"
    );

    guest
        .serial_write("echo SHELL_RAN\n")
        .expect("probe Host shell");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let after_shell = guest.serial();
    let shell_tail = serial_tail(&after_shell, 2000);
    assert!(
        shell_tail.contains("unknown command"),
        "Appliance CLI must reject a shell command, serial:\n{after_shell}"
    );
    assert!(
        !shell_tail.lines().any(|l| l.trim() == "SHELL_RAN"),
        "serial must not be a Host shell, serial:\n{after_shell}"
    );
    guest
        .serial_write(&format!("static {mgmt_nic} 192.168.9.9/24\n"))
        .expect("probe ephemeral addressing");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let after_static = guest.serial();
    let static_tail = serial_tail(&after_static, 2000);
    assert!(
        static_tail.contains("unknown command"),
        "admin CLI must not offer first-boot ephemeral addressing, serial:\n{after_static}"
    );
    assert!(
        static_tail.contains("fwos>") && !static_tail.contains("FWOS Bootstrap console"),
        "rejected ephemeral static must stay in the Appliance CLI, serial:\n{after_static}"
    );

    assert_no_ssh(&guest, "after Bootstrap");
}

#[test]
fn published_serial_cli_applies_full_desired_state() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let (mgmt_nic, traffic_nic) = published_mgmt_and_traffic(&serial);
    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{mgmt_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    );
    https_bootstrap(&guest, &payload);
    serial_login_admin(&guest, "alice", "secret12");

    let full = format!(
        r#"{{"hostname":"fwos-box","interfaces":[{{"name":"{mgmt_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200","wireguard":[{{"name":"wg0","private_key":"{WG_PRIVATE}","listen_port":51820,"addresses":["10.13.13.1/24"]}}],"routes":[{{"to":"198.51.100.0/24","via":"192.0.2.254"}}],"nft_extra":["ip saddr 203.0.113.50 drop"],"qdiscs":[{{"dev":"{traffic_nic}","kind":"fq_codel"}}]}}"#
    );
    let after_apply = serial_cmd(&guest, &format!("apply {full}\n"), 90, |t| {
        t.contains("\"ok\": true") || t.contains("\"ok\":true")
    });
    assert!(
        after_apply.contains("\"ok\": true") || after_apply.contains("\"ok\":true"),
        "Appliance CLI on serial must apply full Desired state via netd, serial:\n{after_apply}"
    );

    let shown = serial_cmd(&guest, "show\n", 20, |t| {
        t.contains("name = \"wg0\"")
            && t.contains("198.51.100.0/24")
            && t.contains("203.0.113.50")
            && t.contains("fq_codel")
    });
    assert!(
        shown.contains("name = \"wg0\"")
            && shown.contains("198.51.100.0/24")
            && shown.contains("203.0.113.50")
            && shown.contains("fq_codel"),
        "show must round-trip TOML on /var (WG, extra nft, static routes), serial:\n{shown}"
    );

    let after_toml = serial_cmd(&guest, "apply /var/lib/fwos/desired.toml\n", 90, |t| {
        t.contains("\"ok\": true") || t.contains("\"ok\":true")
    });
    assert!(
        after_toml.contains("\"ok\": true") || after_toml.contains("\"ok\":true"),
        "Appliance CLI must apply break-glass TOML from /var, serial:\n{after_toml}"
    );

    let after_update = serial_cmd(&guest, "update\n", 15, |t| t.contains("update.sock"));
    assert!(
        after_update.contains("update.sock"),
        "CLI must be a client of the Host update unix socket and error if it is missing, serial:\n{after_update}"
    );
    assert!(
        !after_update.to_ascii_lowercase().contains("reboot")
            && !after_update.to_ascii_lowercase().contains("staged"),
        "stage/reboot land in later tickets; missing socket must not stage, serial:\n{after_update}"
    );

    guest
        .serial_write("echo SHELL_RAN\n")
        .expect("probe Host shell");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let after_shell = guest.serial();
    let shell_tail = serial_tail(&after_shell, 2000);
    assert!(
        shell_tail.contains("unknown command"),
        "serial must stay the admin Appliance CLI, serial:\n{after_shell}"
    );
    assert!(
        !shell_tail.lines().any(|l| l.trim() == "SHELL_RAN"),
        "serial must not be a Host shell, serial:\n{after_shell}"
    );
    assert_no_ssh(&guest, "after serial apply");
}

fn https_bootstrap(guest: &Guest, payload: &str) {
    let mut page = String::new();
    let mut err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                page = body;
                if page.to_ascii_lowercase().contains("hostname")
                    && page.to_ascii_lowercase().contains("admin")
                {
                    break;
                }
            }
            Err(e) => err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        page.to_ascii_lowercase().contains("hostname"),
        "Workstation must reach the HTTPS wizard, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );

    let mut post = String::from("(no POST)");
    let mut post_ok = false;
    for _ in 0..90 {
        match guest.https_exchange("POST", "/api/bootstrap", Some(payload), 90) {
            Ok((200, body)) => {
                post = body;
                if post.contains("\"ok\"") {
                    post_ok = true;
                    break;
                }
            }
            Ok((409, body)) => {
                post = body;
                post_ok = true;
                break;
            }
            Ok((code, body)) => post = format!("http_code={code} {body}"),
            Err(e) => post = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        post_ok,
        "HTTPS wizard POST must complete Bootstrap, last={post}; serial:\n{}",
        guest.serial()
    );

    let mut after = String::new();
    for _ in 0..180 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                after = body;
                if after.contains("\"bootstrapped\"") && after.contains("true") {
                    break;
                }
            }
            Err(e) => after = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        after.contains("\"bootstrapped\"") && after.contains("true"),
        "after Bootstrap, UI status must report bootstrapped; got:\n{after}; serial:\n{}",
        guest.serial()
    );
}

fn serial_login_admin(guest: &Guest, user: &str, password: &str) {
    let mut last = guest.serial();
    for _ in 0..60 {
        let _ = guest.serial_write("\n");
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if last.contains("FWOS Appliance CLI") {
            break;
        }
    }
    assert!(
        last.contains("FWOS Appliance CLI"),
        "after Bootstrap, serial must be the admin Appliance CLI; serial:\n{last}"
    );
    guest
        .serial_write(&format!("{user}\n"))
        .expect("admin name on Appliance CLI");
    let mut saw_password = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if serial_tail(&last, 2000)
            .to_ascii_lowercase()
            .contains("password")
        {
            saw_password = true;
            break;
        }
        let _ = guest.serial_write(&format!("{user}\n"));
    }
    assert!(
        saw_password,
        "Appliance CLI must prompt for the admin password, serial:\n{last}"
    );
    guest
        .serial_write(&format!("{password}\n"))
        .expect("admin password on Appliance CLI");
    let mut logged_in = false;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        let tail = serial_tail(&last, 3000);
        if tail.contains("fwos>") {
            logged_in = true;
            break;
        }
    }
    assert!(
        logged_in,
        "admin must authenticate into the Appliance CLI, serial:\n{last}"
    );
}

fn serial_cmd(guest: &Guest, cmd: &str, secs: u64, pred: impl Fn(&str) -> bool) -> String {
    let from = guest.serial().len();
    guest
        .serial_write(cmd)
        .unwrap_or_else(|e| panic!("serial {cmd:?}: {e}"));
    let mut last = guest.serial();
    for _ in 0..secs {
        last = guest.serial();
        let new = if last.len() > from { &last[from..] } else { "" };
        if pred(new) {
            return new.to_string();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if last.len() > from {
        last[from..].to_string()
    } else {
        last
    }
}

fn assert_no_ssh(guest: &Guest, when: &str) {
    let mut banner = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(ident) = guest.ssh_ident() {
            banner = Some(ident);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if let Some(ident) = banner {
        panic!(
            "{when}: port 22 must not answer SSH, got banner {ident}; serial:\n{}",
            guest.serial()
        );
    }
}

fn serial_tail(serial: &str, keep: usize) -> &str {
    if serial.len() <= keep {
        serial
    } else {
        &serial[serial.len() - keep..]
    }
}

fn console_nics(serial: &str) -> Vec<(String, String)> {
    let chunk = serial
        .rsplit("FWOS Bootstrap console")
        .next()
        .unwrap_or(serial);
    let mut nics = Vec::new();
    let mut in_nics = false;
    for line in chunk.lines() {
        let t = line.trim();
        if t.starts_with("NICs:") {
            in_nics = true;
            continue;
        }
        if !in_nics {
            continue;
        }
        if t.starts_with("Reach the UI") || t == ">" || t.starts_with("> ") {
            break;
        }
        let mut parts = t.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        if !is_ethernet_name(name) {
            continue;
        }
        nics.push((name.to_string(), parts.collect::<Vec<_>>().join(" ")));
    }
    nics
}

fn is_ethernet_name(name: &str) -> bool {
    let nic = name.starts_with("enp")
        || name.starts_with("ens")
        || name.starts_with("eno")
        || name.starts_with("eth");
    nic && name.chars().any(|c| c.is_ascii_digit())
}

fn published_mgmt_and_traffic(serial: &str) -> (String, String) {
    let nics = console_nics(serial);
    assert!(
        nics.len() >= 2,
        "published two-NIC guest must list two Host-netns NICs on the Bootstrap console, serial:\n{serial}"
    );
    let mgmt = nics
        .iter()
        .find(|(_, addrs)| addrs.contains("10.0.2."))
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| nics[0].0.clone());
    let traffic = nics
        .iter()
        .find(|(n, _)| n != &mgmt)
        .map(|(n, _)| n.clone())
        .expect("Traffic NIC");
    (mgmt, traffic)
}

fn serial_ethernet_name(serial: &str) -> Option<String> {
    serial
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .find(|tok| {
            let nic = tok.starts_with("enp")
                || tok.starts_with("ens")
                || tok.starts_with("eno")
                || tok.starts_with("eth");
            nic && tok.chars().any(|c| c.is_ascii_digit())
        })
        .map(str::to_string)
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

const APPLIANCE_CLI: &str = "/usr/bin/fwos";
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
        present.contains("HOST"),
        "Appliance CLI must be a Host program at /usr/bin/fwos, got:\n{present}"
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

    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{ssh_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24","2001:db8::1/64"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200","wan_pd":"2001:db8:1::/48"}}"#
    );
    let mut post = String::from("(no POST)");
    for _ in 0..30 {
        match guest.https_post("/api/bootstrap", &payload) {
            Ok(body) => {
                post = body;
                break;
            }
            Err(e) => post = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    wait_until_mgmt(&guest, &ssh_nic, &format!("ui-bootstrap:{post}"));
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
    let mut after = String::new();
    for _ in 0..60 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                after = body;
                if after.contains("\"bootstrapped\"") && after.contains("true") {
                    break;
                }
            }
            Err(e) => after = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        after.contains("\"bootstrapped\"") && after.contains("true"),
        "after Bootstrap, status JSON must report bootstrapped; got:\n{after}"
    );
    assert!(
        after.contains("fwos-box") && after.contains("192.168.1.0/24"),
        "status JSON must show hostname and LAN prefix, got:\n{after}"
    );
    let after_l = after.to_ascii_lowercase();
    assert!(
        !after_l.contains("password")
            && !after_l.contains("wireguard")
            && !after_l.contains("qdisc")
            && !after_l.contains("private_key"),
        "v1 status must not expose a rule editor, WG, qdisc, or secrets, got:\n{after}"
    );
    guest.ssh("true").expect("injected-key SSH after wizard");
}

fn fwd_comms(guest: &Guest) -> String {
    guest
        .ssh(
            r#"
while read -r pid; do
  [ -n "$pid" ] || continue
  tr -d '\0' < /proc/$pid/comm
  echo
done <<EOF
$(sudo -n ip netns pids fwd)
EOF
"#,
        )
        .unwrap_or_default()
}

fn wait_kea_in_fwd(guest: &Guest) {
    let mut last = String::from("(no probe)");
    for _ in 0..60 {
        last = fwd_comms(guest);
        if last.contains("kea-dhcp4") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let diag = guest
        .ssh(
            r#"
echo '--- files ---'
ls -l /var/lib/fwos/kea /var/lib/fwos/unbound 2>&1 || true
echo '--- units ---'
systemctl is-active fwos-kea-dhcp4.service fwos-kea-dhcp6.service fwos-unbound.service fwos-lan-services-wait.service 2>&1 || true
systemctl status fwos-kea-dhcp4.service --no-pager -l 2>&1 | tail -40 || true
journalctl -u fwos-kea-dhcp4.service --no-pager -n 40 2>&1 || true
systemctl status fwos-unbound.service --no-pager -l 2>&1 | tail -20 || true
echo '--- lan ---'
sudo -n ip netns exec fwd ip -o addr show 2>&1 || true
echo '--- toml ---'
grep -E 'dhcp|lan_prefix|wan_pd' /var/lib/fwos/desired.toml 2>&1 || true
"#,
        )
        .unwrap_or_else(|e| format!("diag ssh: {e}"));
    panic!("Kea not running in fwd within 60s after DHCP pool set, comms:\n{last}\n{diag}");
}

#[test]
fn lan_dhcp_pool_starts_kea_and_unbound() {
    let _guard = guest_lock();
    let guest =
        Guest::boot_host_image_two_nics().expect("two-NIC host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    let route = guest
        .ssh("ip -o route show default")
        .expect("default route (SSH NIC)");
    let ssh_nic = nics
        .iter()
        .find(|n| route.contains(*n as &str))
        .cloned()
        .unwrap_or_else(|| panic!("SSH NIC from default route, got {route} {nics:?}"));
    let traffic_nic = nics
        .iter()
        .find(|n| *n != &ssh_nic)
        .cloned()
        .expect("Traffic NIC");

    let json = format!(
        r#"{{"interfaces":[{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{ssh_nic}","placement":"mgmt"}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200","wan_pd":"2001:db8:1::/48"}}"#
    );
    let apply_status = apply_desired_result(&guest, &json);
    wait_until_mgmt(&guest, &ssh_nic, &format!("{apply_status:?}"));
    wait_kea_in_fwd(&guest);

    let comms = fwd_comms(&guest);
    assert!(
        comms.contains("kea-dhcp4"),
        "kea-dhcp4 must run in fwd, got:\n{comms}"
    );
    assert!(
        comms.contains("kea-dhcp6"),
        "kea-dhcp6 must run in fwd, got:\n{comms}"
    );
    assert!(
        comms.contains("unbound"),
        "Unbound must run in fwd, got:\n{comms}"
    );
    assert!(
        !comms.contains("radvd"),
        "IPv6 RA must not be a radvd product, got:\n{comms}"
    );

    let mgmt_comms = guest
        .ssh(
            r#"
while read -r pid; do
  [ -n "$pid" ] || continue
  tr -d '\0' < /proc/$pid/comm
  echo
done <<EOF
$(sudo -n ip netns pids mgmt)
EOF
"#,
        )
        .unwrap_or_default();
    assert!(
        !mgmt_comms.contains("kea-dhcp") && !mgmt_comms.contains("unbound"),
        "Kea/Unbound must not run in mgmt, got:\n{mgmt_comms}"
    );
    let host_comms = guest
        .ssh(
            r#"
host=$(readlink /proc/1/ns/net)
for p in /proc/[0-9]*; do
  [ -r "$p/ns/net" ] || continue
  ns=$(readlink "$p/ns/net" 2>/dev/null) || continue
  [ "$ns" = "$host" ] || continue
  tr -d '\0' < "$p/comm"
  echo
done
"#,
        )
        .unwrap_or_default();
    assert!(
        !host_comms.contains("kea-dhcp") && !host_comms.contains("unbound"),
        "Kea/Unbound must not run in the Host netns, got:\n{host_comms}"
    );

    let kea4 = guest
        .ssh("cat /var/lib/fwos/kea/kea-dhcp4.conf")
        .expect("generated Kea DHCPv4 config");
    assert!(
        kea4.contains("192.168.1.100") && kea4.contains("192.168.1.200"),
        "Kea DHCPv4 config must match the pool, got:\n{kea4}"
    );
    let kea6 = guest
        .ssh("cat /var/lib/fwos/kea/kea-dhcp6.conf")
        .expect("generated Kea DHCPv6 config");
    assert!(
        kea6.contains("2001:db8:1::100") && kea6.contains("2001:db8:1::1ff"),
        "Kea DHCPv6 config must match the PD pool, got:\n{kea6}"
    );
    let unbound = guest
        .ssh("cat /var/lib/fwos/unbound/unbound.conf")
        .expect("generated Unbound config");
    assert!(
        unbound.to_ascii_lowercase().contains("interface") && unbound.contains("192.168.1."),
        "Unbound config must serve the LAN, got:\n{unbound}"
    );
    assert!(
        !kea4.to_ascii_lowercase().contains("http-host")
            && !unbound.to_ascii_lowercase().contains("control-interface"),
        "Kea/Unbound must have no public operator API"
    );

    let lan = guest
        .ssh("sudo -n ip netns exec fwd ip -o addr show")
        .expect("fwd addrs");
    assert!(
        lan.contains("192.168.1.1"),
        "LAN prefix must be programmed in fwd, got:\n{lan}"
    );
    assert!(
        lan.contains("2001:db8:1::") || lan.to_ascii_lowercase().contains("2001:db8"),
        "IPv6 prefix from PD must be on the LAN in fwd (netd RA path), got:\n{lan}"
    );
}

fn wait_until_sshd_in_mgmt(guest: &Guest, apply_status: &str) {
    let mut last = String::from("(no probe)");
    for _ in 0..180 {
        let session = match guest.ssh("readlink /proc/self/ns/net") {
            Ok(s) => s,
            Err(e) => {
                last = format!("ssh: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        let host_ns = guest
            .ssh(&host_cmd("readlink /proc/self/ns/net"))
            .unwrap_or_default();
        let mgmt_ns = guest
            .ssh("sudo -n ip netns exec mgmt readlink /proc/self/ns/net")
            .unwrap_or_default();
        let fwd_ns = guest
            .ssh("sudo -n ip netns exec fwd readlink /proc/self/ns/net")
            .unwrap_or_default();
        last = format!("session={session:?} host={host_ns:?} mgmt={mgmt_ns:?} fwd={fwd_ns:?}");
        if !session.is_empty()
            && !mgmt_ns.is_empty()
            && session.trim() == mgmt_ns.trim()
            && session.trim() != host_ns.trim()
            && session.trim() != fwd_ns.trim()
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!(
        "sshd not in mgmt within 180s on stick; apply={apply_status}; last={last}; {}",
        apply_diag(guest)
    );
}

fn assert_stick(guest: &Guest, parent: &str) {
    let wan = format!("{parent}.10");
    let lan = format!("{parent}.20");
    let fwd = guest
        .ssh("sudo -n ip netns exec fwd ip -o link show")
        .expect("fwd links");
    assert!(
        ethernet_names(&fwd).iter().any(|n| n == parent),
        "stick parent {parent} must be in fwd, got:\n{fwd}"
    );
    assert!(
        fwd.contains(&wan) && fwd.contains(&lan),
        "WAN/LAN VLANs must exist in fwd, got:\n{fwd}"
    );
    let details = guest
        .ssh("sudo -n ip netns exec fwd ip -d link show")
        .expect("fwd link details");
    assert!(
        details.contains("802.1Q") && details.contains("id 10") && details.contains("id 20"),
        "WAN/LAN must be 802.1Q on the parent, got:\n{details}"
    );
    let mgmt = guest
        .ssh("sudo -n ip netns exec mgmt ip -o link show")
        .expect("mgmt links");
    assert!(
        !ethernet_names(&mgmt).iter().any(|n| n == parent),
        "stick parent must not move to mgmt, got:\n{mgmt}"
    );
    assert!(
        mgmt.contains("veth") || mgmt.contains("m1mgmt") || mgmt.contains("m0mgmt"),
        "mgmt must have a veth from the stick exception, got:\n{mgmt}"
    );
    let host = guest
        .ssh(&host_cmd("ip -o link show"))
        .expect("Host netns links");
    assert!(
        !ethernet_names(&host).iter().any(|n| n == parent),
        "Host netns must not keep the stick parent, got:\n{host}"
    );
    assert!(
        host.contains("veth") || host.contains("h0mgmt"),
        "Host netns must have a veth to mgmt, got:\n{host}"
    );
    let nft = guest
        .ssh("sudo -n ip netns exec fwd nft list ruleset")
        .expect("nft in fwd");
    let nft_l = nft.to_ascii_lowercase();
    assert!(
        nft_l.contains("dnat"),
        "stick mgmt ports must be DNATed to mgmt, got:\n{nft}"
    );
    assert!(
        nft.contains(" 22") || nft.contains("22,") || nft_l.contains("dport 22"),
        "DNAT must include ssh, got:\n{nft}"
    );
    assert!(
        nft_l.contains("masquerade"),
        "NAT44 masquerade missing in fwd nft, got:\n{nft}"
    );
    assert!(
        nft_l.contains("drop"),
        "WAN inbound drop missing in fwd nft, got:\n{nft}"
    );
    assert!(
        nft.contains(&wan),
        "LAN↔WAN policy must name WAN VLAN {wan} in fwd nft, got:\n{nft}"
    );
    assert!(
        !nft_l.contains("oifname \"f0mgmt\" masquerade")
            && !nft_l.contains("oifname \"m1mgmt\" masquerade"),
        "LAN↔WAN must not masquerade via the mgmt path, got:\n{nft}"
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
    assert_ne!(
        session_ns.trim(),
        fwd_ns.trim(),
        "sshd must not run in fwd on the stick"
    );
}

#[test]
fn stick_exception_keeps_sshd_out_of_fwd() {
    let _guard = guest_lock();
    let mut guest =
        Guest::boot_host_image().expect("one-virtio-net host image guest must boot under QEMU");
    let host = guest.ssh("ip -o link show").expect("Host netns links");
    let nics = ethernet_names(&host);
    assert_eq!(
        nics.len(),
        1,
        "expected one virtio-net NIC in the Host netns, got:\n{host}"
    );
    let parent = nics[0].clone();

    let json = format!(
        r#"{{"interfaces":[{{"name":"{parent}","placement":"fwd","role":"stick"}},{{"name":"{parent}.10","placement":"fwd","role":"wan","parent":"{parent}","vlan":10,"addresses":["192.0.2.1/24"]}},{{"name":"{parent}.20","placement":"fwd","role":"lan","parent":"{parent}","vlan":20,"addresses":["192.168.1.1/24"]}}]}}"#
    );
    let apply_status = apply_desired_result(&guest, &json);
    wait_until_sshd_in_mgmt(&guest, &format!("{apply_status:?}"));
    assert_stick(&guest, &parent);

    guest.reboot().expect("guest must come back after reboot");
    wait_until_sshd_in_mgmt(&guest, "reboot");
    assert_stick(&guest, &parent);
    guest
        .ssh("true")
        .expect("injected-key SSH after stick reboot");
}
