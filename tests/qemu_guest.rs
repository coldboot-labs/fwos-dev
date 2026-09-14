use std::sync::Mutex;

use fwos_dev::{Guest, LocalRegistry};

// WireGuard test vector (docs.wireguard.com).
const WG_PRIVATE: &str = "yAnz5TF+lXXJte14tji3dzMe2arW8mOcy4V+1RU4hQE=";

static GUEST_LOCK: Mutex<()> = Mutex::new(());

fn guest_lock() -> std::sync::MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    assert_no_ssh(&guest, "before Bootstrap");
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

    let nics = wait_console_nics(&guest);
    for (name, addrs) in &nics {
        assert!(
            !addrs.contains("10.0.2."),
            "un-opted NICs must not run DHCP or SLAAC/RA; {name} has {addrs}; serial:\n{}",
            guest.serial()
        );
    }
    https_must_not_answer(&guest, 15, "before a console opt");
    opt_user_net(&guest);

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

    assert_no_ssh(&guest, "published guest serial and HTTPS");
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
    let nic = wait_console_nics(&guest)
        .into_iter()
        .next()
        .map(|(n, _)| n)
        .unwrap_or_else(|| {
            panic!(
                "Bootstrap console must list Traffic NICs, serial:\n{}",
                guest.serial()
            )
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

    assert_no_ssh(&guest, "after Bootstrap console addressing");
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

    let mgmt_nic = opt_user_net(&guest);
    let traffic_nic = other_console_nic(&guest, &mgmt_nic);
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
    let after_switch = last.rsplit("Bootstrap complete.").next().unwrap_or(&last);
    let tail = serial_tail(after_switch, 4000).to_ascii_lowercase();
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
    let after_login = status_cli.rsplit("password:").next().unwrap_or(&status_cli);
    assert!(
        !after_login.contains("FWOS Bootstrap console"),
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
    let static_tail = after_static
        .rsplit("password:")
        .next()
        .unwrap_or(&after_static);
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
    let (mgmt_nic, traffic_nic) = published_mgmt_and_traffic_after_opt(&guest);
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

    let after_update = serial_cmd(&guest, "update\n", 15, |t| t.contains("usage: update"));
    assert!(
        after_update.contains("usage: update"),
        "Appliance CLI update without a Host image must print usage, serial:\n{after_update}"
    );
    assert!(
        !after_update.to_ascii_lowercase().contains("reboot")
            && !after_update.to_ascii_lowercase().contains("staged"),
        "update without an image must not stage, serial:\n{after_update}"
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

#[test]
fn published_serial_stages_host_update_then_reboot_applies() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_next_release()
        .expect("Workstation-local registry must serve a newer Release");
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let (mgmt_nic, traffic_nic) = published_mgmt_and_traffic_after_opt(&guest);
    let image = registry.guest_image();

    let refused = serial_cmd(&guest, &format!("update {image}\n"), 30, |t| {
        let l = t.to_ascii_lowercase();
        l.contains("admin") || l.contains("refus")
    });
    let refused_l = refused.to_ascii_lowercase();
    assert!(
        refused_l.contains("admin") || refused_l.contains("refus"),
        "Host update must be refused until an admin exists, serial:\n{refused}"
    );
    assert!(
        !refused.contains("\"ok\": true") && !refused.contains("\"ok\":true"),
        "Host update must not be accepted before an admin exists, serial:\n{refused}"
    );

    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{mgmt_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    );
    https_bootstrap(&guest, &payload);
    serial_login_admin(&guest, "alice", "secret12");

    let mut ui_update = String::from("(no POST)");
    let mut ui_code = 0u16;
    for _ in 0..30 {
        match guest.https_exchange(
            "POST",
            "/api/update",
            Some(&format!(r#"{{"image":"{image}"}}"#)),
            15,
        ) {
            Ok((code, body)) => {
                ui_code = code;
                ui_update = body;
                break;
            }
            Err(e) => ui_update = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(
        ui_code, 404,
        "v1 UI must not be a client of the Host update socket, got http_code={ui_code} {ui_update}; serial:\n{}",
        guest.serial()
    );
    let js = guest.https_get("/app.js").unwrap_or_default();
    assert!(
        !js.contains("update.sock") && !js.contains("/api/update"),
        "UI JS must not call the Host update program, js:\n{js}"
    );

    let before_len = guest.serial().len();
    let staged = serial_cmd(&guest, &format!("update {image}\n"), 1200, |t| {
        (t.contains("\"ok\": true") || t.contains("\"ok\":true"))
            && t.to_ascii_lowercase().contains("reboot_required")
    });
    assert!(
        staged.contains("\"ok\": true") || staged.contains("\"ok\":true"),
        "Appliance CLI on serial must stage a Host update from the Workstation-local registry, serial:\n{staged}"
    );
    assert!(
        staged.to_ascii_lowercase().contains("reboot_required") && staged.contains("true"),
        "staging must report that a reboot is required, serial:\n{staged}"
    );
    assert!(
        staged.contains("fwos:next") || staged.contains(&image),
        "a Release is one tag; staged image must be the Workstation-local Release, serial:\n{staged}"
    );

    let after = guest.serial();
    let new = if after.len() > before_len {
        &after[before_len..]
    } else {
        after.as_str()
    };
    let new_l = new.to_ascii_lowercase();
    assert!(
        !new_l.contains("linux version") && !new.contains("FWOS Bootstrap console"),
        "Host update must not reboot by itself, serial:\n{new}"
    );

    let still = serial_cmd(&guest, "status\n", 20, |t| {
        t.contains("fwos-box") && t.contains("fwos>")
    });
    assert!(
        still.contains("fwos-box") && still.contains("fwos>"),
        "running bootc deployment is unchanged; Appliance CLI session must survive staging, serial:\n{still}"
    );

    let mut ui_status = String::new();
    for _ in 0..30 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                ui_status = body;
                if ui_status.contains("\"bootstrapped\"") && ui_status.contains("true") {
                    break;
                }
            }
            Err(e) => ui_status = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        ui_status.contains("\"bootstrapped\"") && ui_status.contains("true"),
        "Forwarding must keep running after staging; UI status:\n{ui_status}; serial:\n{}",
        guest.serial()
    );
    assert!(
        ui_status.contains("\"fwd\"") && ui_status.contains("192.0.2.1"),
        "Traffic NIC placement in fwd must still be applied after staging, status:\n{ui_status}"
    );
    assert_no_ssh(&guest, "after Host update stage");

    let previous = json_string_field(&staged, "booted");
    let next_image = json_string_field(&staged, "staged")
        .filter(|s| s.contains("fwos:next") || s.contains(&image))
        .unwrap_or_else(|| image.clone());
    let from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("explicit Appliance CLI reboot after stage");
    let rebooted = serial_wait(&guest, from, 300, |t| {
        t.to_ascii_lowercase().contains("fwos appliance cli")
    });
    assert!(
        rebooted.to_ascii_lowercase().contains("fwos appliance cli"),
        "operator reboot on serial must restart the guest onto the staged bootc deployment, serial:\n{rebooted}"
    );
    assert!(
        !serial_tail(&rebooted, 4000).contains("unknown command"),
        "Appliance CLI reboot must be a command, not a Host shell, serial:\n{rebooted}"
    );

    serial_login_admin_from(&guest, "alice", "secret12", from);
    let deployed = serial_cmd(&guest, "status\n", 30, |t| {
        t.contains("fwos-box")
            && t.contains("fwd: yes")
            && t.contains("mgmt: yes")
            && t.contains("netd: running")
            && (t.contains("fwos:next") || t.contains(&image) || t.contains(&next_image))
    });
    assert!(
        deployed.contains("fwos-box"),
        "/var is shared across bootc deployments; hostname must survive reboot, serial:\n{deployed}"
    );
    assert!(
        deployed.contains("bootstrapped"),
        "/var is shared; Bootstrap stamp must survive reboot, serial:\n{deployed}"
    );
    assert!(
        deployed.contains("fwos:next")
            || deployed.contains(&image)
            || deployed.contains(&next_image),
        "guest must come up on the new bootc deployment, serial:\n{deployed}"
    );
    let booted = json_status_image(&deployed, "booted").unwrap_or_default();
    let rollback = json_status_image(&deployed, "rollback").unwrap_or_default();
    let staged_after = json_status_image(&deployed, "staged").unwrap_or_default();
    assert!(
        booted.contains("fwos:next") || booted.contains(&image) || booted.contains(&next_image),
        "booted bootc deployment must be the new Host image, serial:\n{deployed}"
    );
    assert!(
        staged_after.is_empty()
            || (!staged_after.contains("fwos:next") && !staged_after.contains(&image)),
        "reboot must consume the staged deployment, serial:\n{deployed}"
    );
    assert!(
        deployed.contains("rollback:") && !rollback.contains("fwos:next"),
        "previous bootc deployment remains the rollback target, serial:\n{deployed}"
    );
    if let Some(prev) = previous.as_deref() {
        if !prev.is_empty() && !prev.contains("fwos:next") {
            assert!(
                rollback.contains(prev) || deployed.contains(prev),
                "rollback target must be the previously booted image {prev}, serial:\n{deployed}"
            );
        }
    }
    assert!(
        deployed.contains("fwd: yes") && deployed.contains("mgmt: yes"),
        "fwd and mgmt must exist after the Host-update reboot, serial:\n{deployed}"
    );
    assert!(
        deployed.contains("netd: running"),
        "netd must be running after the Host-update reboot, serial:\n{deployed}"
    );

    let mut ui_after = String::new();
    for _ in 0..180 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                ui_after = body;
                if ui_after.contains("\"bootstrapped\"") && ui_after.contains("true") {
                    break;
                }
            }
            Err(e) => ui_after = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        ui_after.contains("\"bootstrapped\"") && ui_after.contains("true"),
        "after reboot, HTTPS UI in mgmt must still serve status; got:\n{ui_after}; serial:\n{}",
        guest.serial()
    );
    assert!(
        ui_after.contains("fwos-box")
            && ui_after.contains("\"fwd\"")
            && ui_after.contains("\"mgmt\""),
        "HTTPS status must show hostname and NIC placement from shared /var, status:\n{ui_after}"
    );

    let bad = serial_cmd(&guest, "apply this-is-not-desired-state\n", 20, |t| {
        let l = t.to_ascii_lowercase();
        l.contains("error")
            || l.contains("parse")
            || l.contains("\"ok\": false")
            || l.contains("\"ok\":false")
    });
    assert!(
        !bad.contains("\"ok\": true") && !bad.contains("\"ok\":true"),
        "invalid Desired state must not apply, serial:\n{bad}"
    );
    let still_next = serial_cmd(&guest, "status\n", 20, |t| {
        t.contains("fwos-box")
            && (t.contains("fwos:next") || t.contains(&image) || t.contains(&next_image))
    });
    let still_booted = json_status_image(&still_next, "booted").unwrap_or_default();
    assert!(
        still_booted.contains("fwos:next")
            || still_booted.contains(&image)
            || still_booted.contains(&next_image)
            || still_next.contains("fwos:next"),
        "Desired state that fails to apply must not roll back the Host image, serial:\n{still_next}"
    );

    let help = serial_cmd(&guest, "help\n", 10, |t| t.contains("rollback"));
    assert!(
        help.contains("rollback"),
        "manual rollback via Appliance CLI must remain, serial:\n{help}"
    );
    let rolled = serial_cmd(&guest, "rollback\n", 60, |t| {
        (t.contains("\"ok\": true") || t.contains("\"ok\":true"))
            && t.to_ascii_lowercase().contains("reboot_required")
    });
    assert!(
        rolled.contains("\"ok\": true") || rolled.contains("\"ok\":true"),
        "Appliance CLI rollback must queue the previous bootc deployment, serial:\n{rolled}"
    );
    assert!(
        !serial_tail(&rolled, 4000).contains("unknown command"),
        "rollback must be an Appliance CLI command, serial:\n{rolled}"
    );

    let from_rb = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("explicit reboot after manual rollback");
    let rb_boot = serial_wait(&guest, from_rb, 300, |t| {
        t.to_ascii_lowercase().contains("fwos appliance cli")
    });
    assert!(
        rb_boot.to_ascii_lowercase().contains("fwos appliance cli"),
        "manual rollback reboot must restart the guest, serial:\n{rb_boot}"
    );
    serial_login_admin_from(&guest, "alice", "secret12", from_rb);
    let back = serial_cmd(&guest, "status\n", 30, |t| {
        t.contains("fwos-box")
            && t.contains("fwd: yes")
            && t.contains("netd: running")
            && t.contains("booted:")
    });
    let back_booted = json_status_image(&back, "booted").unwrap_or_default();
    assert!(
        back.contains("booted:") && !back_booted.contains("fwos:next"),
        "manual rollback must return the previous bootc deployment, serial:\n{back}"
    );
    if let Some(prev) = previous.as_deref() {
        if !prev.is_empty() && !prev.contains("fwos:next") {
            assert!(
                back_booted.contains(prev) || back.contains(prev),
                "manual rollback must boot {prev}, serial:\n{back}"
            );
        }
    }
    assert!(
        back.contains("netd: running"),
        "netd must be running after manual rollback, serial:\n{back}"
    );
    assert_no_ssh(&guest, "after Host update reboot");
}

#[test]
fn published_serial_rolls_back_host_update_when_netd_is_dead() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_dead_netd_release()
        .expect("Workstation-local registry must serve a Release with dead netd");
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let (mgmt_nic, traffic_nic) = published_mgmt_and_traffic_after_opt(&guest);
    let image = registry.guest_image();

    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{mgmt_nic}","placement":"mgmt"}},{{"name":"{traffic_nic}","placement":"fwd","role":"wan","addresses":["192.0.2.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    );
    https_bootstrap(&guest, &payload);
    serial_login_admin(&guest, "alice", "secret12");

    let prior = serial_cmd(&guest, "status\n", 20, |t| {
        t.contains("fwos-box") && t.contains("netd: running")
    });
    let previous = json_status_image(&prior, "booted").unwrap_or_default();

    let staged = serial_cmd(&guest, &format!("update {image}\n"), 1200, |t| {
        (t.contains("\"ok\": true") || t.contains("\"ok\":true"))
            && t.to_ascii_lowercase().contains("reboot_required")
    });
    assert!(
        staged.contains("\"ok\": true") || staged.contains("\"ok\":true"),
        "Appliance CLI must stage the dead-netd Release, serial:\n{staged}"
    );

    let from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("explicit Appliance CLI reboot onto the dead-netd deployment");
    let rolled = serial_wait(&guest, from, 600, |t| {
        t.to_ascii_lowercase().matches("fwos appliance cli").count() >= 2
    });
    assert!(
        rolled.to_ascii_lowercase().matches("fwos appliance cli").count() >= 2,
        "failed appliance health (dead netd) must reboot into the previous bootc deployment, serial:\n{rolled}"
    );

    let serial_now = guest.serial();
    let login_from = serial_now
        .to_ascii_lowercase()
        .rfind("fwos appliance cli")
        .unwrap_or(from);
    serial_login_admin_from(&guest, "alice", "secret12", login_from);
    let deployed = serial_cmd(&guest, "status\n", 30, |t| {
        t.contains("fwos-box")
            && t.contains("fwd: yes")
            && t.contains("mgmt: yes")
            && t.contains("netd: running")
    });
    let booted = json_status_image(&deployed, "booted").unwrap_or_default();
    assert!(
        deployed.contains("booted:") && !booted.contains("fwos:next"),
        "auto rollback must leave the previous bootc deployment booted, not the dead-netd Release, serial:\n{deployed}"
    );
    if !previous.is_empty() && !previous.contains("fwos:next") {
        assert!(
            booted.contains(&previous) || deployed.contains(&previous),
            "rollback target must be the previously booted image {previous}, serial:\n{deployed}"
        );
    }
    assert!(
        deployed.contains("fwd: yes") && deployed.contains("mgmt: yes"),
        "fwd and mgmt must exist after automatic rollback, serial:\n{deployed}"
    );
    assert!(
        deployed.contains("netd: running"),
        "netd must be running after automatic rollback, serial:\n{deployed}"
    );

    let mut ui_after = String::new();
    for _ in 0..180 {
        match guest.https_get("/api/status") {
            Ok(body) => {
                ui_after = body;
                if ui_after.contains("\"bootstrapped\"") && ui_after.contains("true") {
                    break;
                }
            }
            Err(e) => ui_after = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        ui_after.contains("\"bootstrapped\"") && ui_after.contains("true"),
        "after automatic rollback, HTTPS UI must still serve status; got:\n{ui_after}; serial:\n{}",
        guest.serial()
    );
    assert_no_ssh(&guest, "after automatic rollback");
}

fn https_bootstrap(guest: &Guest, payload: &str) {
    opt_user_net(guest);
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
    serial_login_admin_from(guest, user, password, 0);
}

fn serial_login_admin_from(guest: &Guest, user: &str, password: &str, from: usize) {
    let mut last = String::new();
    for _ in 0..90 {
        last = guest.serial();
        let new = if last.len() > from {
            &last[from..]
        } else {
            last.as_str()
        };
        if new.contains("FWOS Appliance CLI") || new.contains("admin:") {
            break;
        }
        let _ = guest.serial_write("\n");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let new = if last.len() > from {
        &last[from..]
    } else {
        last.as_str()
    };
    assert!(
        new.contains("FWOS Appliance CLI") || last.contains("FWOS Appliance CLI"),
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
    serial_wait(guest, from, secs, pred)
}

fn serial_wait(guest: &Guest, from: usize, secs: u64, pred: impl Fn(&str) -> bool) -> String {
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

fn json_string_field(blob: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let rest = blob.split(&pat).nth(1)?;
    let rest = rest.trim_start().trim_start_matches(':').trim_start();
    if rest.starts_with("null") {
        return None;
    }
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let s = &rest[..end];
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn json_status_image(status: &str, which: &str) -> Option<String> {
    json_string_field(status, which).or_else(|| {
        for line in status.lines() {
            let t = line.trim();
            let prefix = format!("{which}:");
            if let Some(rest) = t.strip_prefix(&prefix) {
                let s = rest.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        None
    })
}

fn assert_no_ssh(guest: &Guest, when: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if guest.port_22_reachable() {
            panic!(
                "{when}: port 22 must not answer; serial:\n{}",
                guest.serial()
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
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
        "published two-NIC guest must list two Traffic NICs on the Bootstrap console, serial:\n{serial}"
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

fn published_mgmt_and_traffic_after_opt(guest: &Guest) -> (String, String) {
    opt_user_net(guest);
    published_mgmt_and_traffic(&guest.serial())
}

fn wait_console_nics(guest: &Guest) -> Vec<(String, String)> {
    let mut last = String::new();
    for _ in 0..90 {
        last = guest.serial();
        let nics = console_nics(&last);
        if !nics.is_empty() {
            return nics;
        }
        let _ = guest.serial_write("status\n");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("Bootstrap console must list Traffic NICs, serial:\n{last}");
}

fn other_console_nic(guest: &Guest, used: &str) -> String {
    wait_console_nics(guest)
        .into_iter()
        .find(|(n, _)| n != used)
        .map(|(n, _)| n)
        .unwrap_or_else(|| {
            panic!(
                "published two-NIC guest must list another Traffic NIC besides {used}, serial:\n{}",
                guest.serial()
            )
        })
}

fn console_opt_static(guest: &Guest, nic: &str, cidr: &str) {
    let ip = cidr.split('/').next().unwrap_or(cidr);
    guest
        .serial_write(&format!("static {nic} {cidr}\n"))
        .expect("set ephemeral addressing on serial");
    let mut last = String::new();
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
        if last.contains(ip) {
            return;
        }
    }
    panic!("console static {nic} {cidr} did not take, serial:\n{last}");
}

fn https_must_not_answer(guest: &Guest, secs: u64, when: &str) {
    for _ in 0..secs {
        match guest.https_exchange("GET", "/", None, 3) {
            Ok((code, body)) if code != 0 => panic!(
                "{when}: HTTPS must not answer (http_code={code}); body:\n{body}; serial:\n{}",
                guest.serial()
            ),
            _ => {}
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn https_up(guest: &Guest) -> bool {
    matches!(guest.https_exchange("GET", "/", None, 3), Ok((code, _)) if code != 0)
}

fn opt_user_net(guest: &Guest) -> String {
    let nics = wait_console_nics(guest);
    if https_up(guest) {
        if let Some((name, _)) = nics.iter().find(|(_, a)| a.contains("10.0.2.")) {
            return name.clone();
        }
        return nics[0].0.clone();
    }
    for (name, _) in &nics {
        console_opt_static(guest, name, "10.0.2.15/24");
        for _ in 0..20 {
            if https_up(guest) {
                return name.clone();
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    panic!(
        "console static 10.0.2.15/24 on a Traffic NIC must make the HTTPS wizard reachable; serial:\n{}",
        guest.serial()
    );
}

#[allow(dead_code)]
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

#[test]
fn published_console_opt_survives_reboot_before_bootstrap() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published Disk image guest must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    opt_user_net(&guest);
    let mut page = String::new();
    for _ in 0..30 {
        if let Ok(body) = guest.https_get("/") {
            page = body;
            if page.to_ascii_lowercase().contains("hostname") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        page.to_ascii_lowercase().contains("hostname"),
        "HTTPS wizard must answer after the console opt; serial:\n{}",
        guest.serial()
    );

    std::thread::sleep(std::time::Duration::from_secs(3));
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("QEMU must reset the published guest");
    let mut last = String::new();
    for _ in 0..240 {
        last = guest.serial();
        let new = if last.len() > from { &last[from..] } else { "" };
        if new.contains("FWOS Bootstrap console") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let new = if last.len() > from { &last[from..] } else { last.as_str() };
    assert!(
        new.contains("FWOS Bootstrap console"),
        "reboot before Bootstrap must return to the Bootstrap console; serial:\n{last}"
    );
    assert!(
        !serial_tail(new, 4000).contains("FWOS Appliance CLI")
            || serial_tail(new, 4000).contains("FWOS Bootstrap console"),
        "reboot before Bootstrap is not the admin Appliance CLI; serial:\n{last}"
    );

    let mut after = String::new();
    let mut err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                after = body;
                if after.to_ascii_lowercase().contains("hostname") {
                    break;
                }
            }
            Err(e) => err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        after.to_ascii_lowercase().contains("hostname"),
        "console opt must persist across reboot until Bootstrap, last={err}; body:\n{after}; serial:\n{}",
        guest.serial()
    );
}

#[test]
fn published_console_can_replace_opt() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let user = opt_user_net(&guest);
    let extra = other_console_nic(&guest, &user);
    let mut page = String::new();
    for _ in 0..30 {
        if let Ok(body) = guest.https_get("/") {
            page = body;
            if page.to_ascii_lowercase().contains("html") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        page.to_ascii_lowercase().contains("html") || page.to_ascii_lowercase().contains("hostname"),
        "HTTPS must answer on the opted user-net NIC; serial:\n{}",
        guest.serial()
    );

    console_opt_static(&guest, &extra, "10.0.3.15/24");
    https_must_not_answer(
        &guest,
        20,
        "after replacing the opt, the old user-net overlay must be gone",
    );
}

#[test]
fn published_stick_serial_and_https_without_ssh() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published one-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    assert_no_ssh(&guest, "before stick Bootstrap");
    let nic = opt_user_net(&guest);
    let payload = format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{nic}","placement":"fwd","role":"stick"}},{{"name":"{nic}.10","placement":"fwd","role":"wan","parent":"{nic}","vlan":10,"addresses":["192.0.2.1/24"]}},{{"name":"{nic}.20","placement":"fwd","role":"lan","parent":"{nic}","vlan":20,"addresses":["192.168.1.1/24"]}}],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    );
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
        "Workstation must reach the HTTPS wizard before stick placement, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );
    let mut post = String::from("(no POST)");
    for _ in 0..30 {
        match guest.https_exchange("POST", "/api/bootstrap", Some(&payload), 90) {
            Ok((200, body)) | Ok((409, body)) => {
                post = body;
                break;
            }
            Ok((code, body)) => post = format!("http_code={code} {body}"),
            Err(e) => post = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    // Stick moves the only NIC into fwd; the Host-netns UI drops and curl may
    // lose the POST. Serial is how the published guest is observed after that.
    let mut last = guest.serial();
    for _ in 0..120 {
        if last.contains("Bootstrap complete") || last.contains("FWOS Appliance CLI") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
    }
    assert!(
        last.contains("Bootstrap complete") || last.contains("FWOS Appliance CLI"),
        "HTTPS wizard must apply stick Desired state (serial after POST={post}); serial:\n{last}"
    );
    serial_login_admin(&guest, "alice", "secret12");
    let shown = serial_cmd(&guest, "show\n", 20, |t| {
        t.contains("stick") && t.contains(".10") && t.contains(".20")
    });
    assert!(
        shown.contains("stick") && shown.contains(".10") && shown.contains(".20"),
        "stick WAN/LAN VLANs must be Desired state, serial:\n{shown}"
    );
    assert_no_ssh(&guest, "after stick Bootstrap");
}

#[test]
fn installer_writes_host_image_onto_empty_disk() {
    let _guard = guest_lock();
    let guest = Guest::install_from_iso()
        .expect("Installer must write the Host image onto an empty virt disk");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "installed guest is observed on serial as a published Disk image guest; serial:\n{serial}"
    );
    let lower = serial.to_ascii_lowercase();
    assert!(
        !lower.contains("login:"),
        "Appliance CLI owns serial after First install; serial:\n{serial}"
    );

    https_must_not_answer(&guest, 10, "after First install, before a console opt");
    opt_user_net(&guest);

    let mut page = String::new();
    let mut err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                page = body;
                if page.to_ascii_lowercase().contains("hostname") {
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
        "Workstation must reach the UI over HTTPS after First install, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );
    assert_no_ssh(&guest, "after Installer First install");
}

#[test]
fn installer_one_disk_without_yes_never_reaches_bootstrap() {
    let _guard = guest_lock();
    let guest = Guest::boot_installer_one_disk()
        .expect("Installer with one writable disk must start under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("The entire disk will be erased and replaced with the Host disk layout"),
        "one writable disk: name the target and explain the wipe before any write; serial:\n{serial}"
    );
    assert!(
        serial.contains("FWOS Installer: /dev/") && serial.contains("("),
        "one writable disk: serial must name the target device and size; serial:\n{serial}"
    );
    assert!(
        !serial.contains("FWOS Bootstrap console"),
        "without yes, the one-disk Installer must not finish First install; serial:\n{serial}"
    );

    let yes_prompts = serial.matches("Type yes to wipe").count();
    guest
        .serial_write("y\n")
        .expect("y on the Installer serial must be a decline");
    let mut after_y = serial;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        after_y = guest.serial();
        if after_y.matches("Type yes to wipe").count() > yes_prompts {
            break;
        }
    }
    assert!(
        after_y.matches("Type yes to wipe").count() > yes_prompts,
        "y must not wipe; the operator stays on the approval prompt; serial:\n{after_y}"
    );
    assert!(
        !after_y.contains("FWOS Bootstrap console"),
        "y must not complete First install; serial:\n{after_y}"
    );

    let yes_prompts = after_y.matches("Type yes to wipe").count();
    guest
        .serial_write("\n")
        .expect("empty Enter on the Installer serial must be a decline");
    let mut after_enter = after_y;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        after_enter = guest.serial();
        if after_enter.matches("Type yes to wipe").count() > yes_prompts {
            break;
        }
    }
    assert!(
        after_enter.matches("Type yes to wipe").count() > yes_prompts,
        "empty Enter must not wipe; the operator stays on the approval prompt; serial:\n{after_enter}"
    );
    assert!(
        !after_enter.contains("FWOS Bootstrap console"),
        "without yes, QEMU one-disk Installer never reaches the Bootstrap console; serial:\n{after_enter}"
    );
}

#[test]
fn installer_asks_which_disk_when_more_than_one() {
    let _guard = guest_lock();
    let guest = Guest::boot_installer_two_disks()
        .expect("Installer with two writable disks must start under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Installer: pick a disk to wipe"),
        "more than one writable disk: only disk pick; serial:\n{serial}"
    );
    assert!(
        !serial.contains("FWOS Bootstrap console"),
        "Installer must not finish First install until a disk is chosen; serial:\n{serial}"
    );
}
