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
fn published_local_identity_protects_https_management() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));

    let (code, body) = guest
        .https_exchange("GET", "/api/status", None, 15)
        .expect("anonymous HTTPS response after Bootstrap");
    assert_eq!(code, 401, "management status requires login: {body}");
    assert!(!body.contains("192.168.1.0/24"));
    let (code, _) = guest
        .https_exchange(
            "POST",
            "/api/login",
            Some(r#"{"source":"local","username":"alice","password":"incorrect"}"#),
            15,
        )
        .expect("incorrect-password login response");
    assert_eq!(
        code, 401,
        "an incorrect password cannot authorize management"
    );
    let (code, _) = guest
        .https_exchange(
            "POST",
            "/api/login",
            Some(r#"{"source":"os","username":"alice","password":"secret12"}"#),
            15,
        )
        .expect("unknown Authentication source response");
    assert_eq!(
        code, 401,
        "another source must not fall back to a local account"
    );
    let session = guest
        .https_login(r#"{"source":"local","username":"alice","password":"secret12"}"#)
        .expect("the Bootstrap-created FWOS-local administrator signs in over HTTPS");
    let status = session
        .get("/api/status")
        .expect("authenticated management status");
    assert!(status.contains("192.168.1.0/24"));
    assert_eq!(
        json_string_field(&status, "source").as_deref(),
        Some("local")
    );
    assert_eq!(
        json_string_field(&status, "username").as_deref(),
        Some("alice")
    );
    assert!(json_string_field(&status, "subject").is_some());
    assert!(
        !status.contains("secret12")
            && !status.contains("password_hash")
            && !status.contains("$y$")
    );
    let replay = session.clone();
    let (code, _) = session
        .exchange("POST", "/api/logout", Some("{}"), 15)
        .expect("authenticated logout response");
    assert_eq!(code, 200);
    let (code, _) = replay
        .exchange("GET", "/api/status", None, 15)
        .expect("revoked-cookie replay response");
    assert_eq!(
        code, 401,
        "logout revokes the server-side session, not just the browser cookie"
    );
    let admin_ready = serial_wait(&guest, 0, 90, |text| {
        text.contains("FWOS Appliance CLI")
            && text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        admin_ready.contains("FWOS Appliance CLI")
            && admin_ready.lines().any(|line| line.trim() == "admin:"),
        "Bootstrap must hand serial input to the administrator prompt before login; serial tail:\n{}",
        serial_tail(&admin_ready, 4000)
            .replace("secret12", "<REDACTED>")
            .replace("incorrect-console-password", "<REDACTED>")
    );
    let password_prompt = serial_cmd(&guest, "alice\n", 15, |text| text.contains("password:"));
    assert!(
        password_prompt.contains("password:"),
        "the ready administrator prompt must request a password after a username; serial tail:\n{}",
        serial_tail(&guest.serial(), 4000)
            .replace("secret12", "<REDACTED>")
            .replace("incorrect-console-password", "<REDACTED>")
    );
    let denied = serial_cmd(&guest, "incorrect-console-password\n", 15, |text| {
        text.contains("login failed")
    });
    assert!(
        denied.contains("login failed"),
        "incorrect console credentials must fail"
    );
    serial_login_admin(&guest, "alice", "secret12");
    let serial = guest.serial();
    assert!(
        !serial.contains("incorrect-console-password") && !serial.contains("secret12"),
        "the Appliance console must not echo passwords into serial output"
    );
    let before_reboot = https_login_admin(&guest, "alice", "secret12");
    assert!(before_reboot.get("/api/status").is_ok());
    let reboot_from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("authenticated console reboot");
    let rebooted = serial_wait(&guest, reboot_from, 300, |text| {
        text.contains("FWOS Appliance CLI")
    });
    assert!(
        rebooted.contains("FWOS Appliance CLI"),
        "authenticated console must return after reboot"
    );
    assert!(
        !rebooted.contains("FWOS Bootstrap console"),
        "reboot must not reopen Bootstrap"
    );
    serial_login_admin_from(&guest, "alice", "secret12", reboot_from);
    let current = https_login_admin(&guest, "alice", "secret12");
    let restored = current
        .get("/api/status")
        .expect("persistent local Identity authenticates after reboot");
    assert_eq!(
        json_string_field(&restored, "subject"),
        json_string_field(&status, "subject")
    );
    let (code, _) = before_reboot
        .exchange("GET", "/api/status", None, 15)
        .expect("old-session request after reboot");
    assert_eq!(code, 401, "reboot must invalidate prior HTTPS sessions");
    let browser = guest
        .browser_login("alice", "secret12")
        .expect("rendered UI must sign in, show useful authenticated status, and sign out");
    println!("real rendered local-identity scenario passed on Firefox {browser}");
    assert_no_ssh(&guest, "after authenticated Bootstrap");
}

#[test]
fn published_bootstrap_credentials_work_on_https_and_console() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    opt_user_net(&guest);
    let mut payload = serde_json::json!({
        "hostname": "fwos-box",
        "admin": "alice",
        "password": "",
        "interfaces": [
            {"name": lan_nic, "role": "lan"},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [lan_nic],
        "lan_prefix": "192.168.1.0/24",
        "dhcp_pool": "192.168.1.100-192.168.1.200"
    });
    let too_long = "x".repeat(512);
    for (kind, password) in [
        ("CR", "line\rbreak"),
        ("LF", "line\nbreak"),
        ("Ctrl-D", "terminal\u{0004}control"),
        ("Ctrl-S", "terminal\u{0013}control"),
        ("DEL", "terminal\u{007f}control"),
        ("unsupported-length", too_long.as_str()),
    ] {
        payload["password"] = password.into();
        let (code, body) = guest
            .https_exchange("POST", "/api/bootstrap", Some(&payload.to_string()), 90)
            .expect("Bootstrap must respond to an unsupported password");
        assert_eq!(
            code, 400,
            "Bootstrap must reject a {kind} password before establishing ownership"
        );
        assert!(
            !body.contains(password),
            "credential validation must not disclose the submitted password"
        );
        let (code, status) = guest
            .https_exchange("GET", "/api/status", None, 15)
            .expect("Bootstrap remains reachable after credential validation fails");
        assert_eq!(code, 200, "invalid credentials must not complete Bootstrap");
        let status: serde_json::Value =
            serde_json::from_str(&status).expect("Bootstrap status must be JSON");
        assert_eq!(
            status["bootstrapped"], false,
            "invalid credentials must leave the appliance unowned"
        );
    }

    let password = "  boundary-passphrase  ";
    payload["password"] = password.into();
    https_bootstrap(&guest, &payload.to_string());
    let session = https_login_admin(&guest, "alice", password);
    let status = session
        .get("/api/status")
        .expect("HTTPS must accept the exact password including surrounding spaces");
    assert_eq!(json_string_field(&status, "username").as_deref(), Some("alice"));
    let trimmed = serde_json::json!({
        "source": "local", "username": "alice", "password": password.trim()
    });
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&trimmed.to_string()), 15)
        .expect("HTTPS must respond to a password with its surrounding spaces removed");
    assert_eq!(code, 401, "password spaces must remain part of the credential");
    serial_login_admin(&guest, "alice", password);
    assert!(
        !guest.serial().contains(password.trim()),
        "the Appliance console must not echo the space-preserving password"
    );
}

fn https_login_admin<'a>(
    guest: &'a Guest,
    username: &str,
    password: &str,
) -> fwos_dev::HttpsSession<'a> {
    let credentials =
        serde_json::json!({"source": "local", "username": username, "password": password})
            .to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        match guest.https_login(&credentials) {
            Ok(session) => return session,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "HTTPS administrator login unavailable: {error}"
                );
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

fn https_authenticated_status(guest: &Guest) -> Result<String, fwos_dev::Error> {
    guest
        .https_login(r#"{"source":"local","username":"alice","password":"secret12"}"#)?
        .get("/api/status")
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
    for needle in [
        "wan",
        "lan",
        "vlan",
        "dhcp",
        "static",
        "pool",
        "pd",
        "exposure",
        "management",
    ] {
        assert!(
            lower.contains(needle),
            "wizard HTML must collect {needle} (roles, VLAN IDs, UI exposure, static/DHCP, LAN prefix, DHCP pool, WAN v6/PD), body:\n{page}"
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

    let lan_nic = opt_user_net(&guest);
    let wan_nic = other_console_nic(&guest, &lan_nic);
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

    let payload = wan_lan_bootstrap_json(&lan_nic, &wan_nic);
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
        match https_authenticated_status(&guest) {
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
        after.contains("\"lan\"") && after.contains("\"wan\""),
        "status JSON must show interface roles, got:\n{after}"
    );
    assert!(
        after.contains("ui_exposure") && after.contains(&lan_nic),
        "status JSON must show UI exposure on the LAN, got:\n{after}"
    );
    assert!(
        !after.contains("\"placement\"") && !after.contains("placement=mgmt"),
        "Desired state must not classify a NIC into the Management netns, got:\n{after}"
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
        .serial_write(&format!("static {lan_nic} 192.168.9.9/24\n"))
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
fn published_two_nic_user_net_wan_stops_https_after_apply() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published two-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let (wan_nic, lan_nic) = published_user_net_and_extra(&guest);
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
    assert!(
        page.to_ascii_lowercase().contains("hostname"),
        "Workstation must reach the HTTPS wizard on the user-net NIC, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );

    let payload = wan_lan_bootstrap_json(&lan_nic, &wan_nic);
    post_bootstrap_observe_serial(&guest, &payload);

    let mut https_down = false;
    for _ in 0..60 {
        match guest.https_exchange("GET", "/", None, 3) {
            Ok((code, _)) if code != 0 => {}
            _ => {
                https_down = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        https_down,
        "HTTPS on the user-net NIC must stop after apply when that NIC is WAN; serial:\n{}",
        guest.serial()
    );
    https_must_not_answer(
        &guest,
        10,
        "HTTPS on the user-net NIC must stay down after apply when that NIC is WAN",
    );

    serial_login_admin(&guest, "alice", "secret12");
    let shown = serial_cmd(&guest, "show\n", 20, |t| {
        t.contains("wan") && t.contains("lan") && t.contains(&wan_nic) && t.contains(&lan_nic)
    });
    assert!(
        shown.contains(&wan_nic) && shown.contains(&lan_nic),
        "serial must still work and show WAN+LAN Desired state, serial:\n{shown}"
    );
}

#[test]
fn published_three_nic_mgmt_https_after_bootstrap() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_three_nics()
        .expect("published three-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );

    let mgmt_nic = opt_user_net(&guest);
    let extras: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| n != &mgmt_nic)
        .collect();
    assert_eq!(
        extras.len(),
        2,
        "three-NIC guest must list WAN and LAN extras besides the user-net Management NIC, serial:\n{}",
        guest.serial()
    );
    let lan_nic = extras[0].clone();
    let wan_nic = extras[1].clone();

    let mut page = String::new();
    let mut page_err = String::from("(no GET)");
    for _ in 0..90 {
        match guest.https_get("/") {
            Ok(body) => {
                page = body;
                if page.to_ascii_lowercase().contains("management") {
                    break;
                }
            }
            Err(e) => page_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        page.to_ascii_lowercase().contains("management"),
        "wizard HTML must collect an optional Management NIC, last={page_err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );

    let mut js = String::new();
    let mut js_err = String::from("(no GET)");
    for _ in 0..30 {
        match guest.https_get("/app.js") {
            Ok(body) => {
                js = body;
                if js.contains("mgmt_nic") && js.contains("mgmt_prefix") {
                    break;
                }
            }
            Err(e) => js_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        js.contains("mgmt_nic")
            && js.contains("mgmt_prefix")
            && js.contains("on-link prefix")
            && js.contains("none"),
        "wizard must offer an optional Management NIC and on-link static prefix (no gateway), last={js_err}; js:\n{js}"
    );
    assert!(
        js.contains("expose_lan") && js.contains("lan_req") && js.contains("(optional)"),
        "LAN UI exposure must be optional when a Management NIC is selected, js:\n{js}"
    );

    let payload = wan_lan_mgmt_bootstrap_json(&lan_nic, &wan_nic, &mgmt_nic);
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
        match https_authenticated_status(&guest) {
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
        "workstation HTTPS status after Bootstrap must answer on the Management NIC (user-net); got:\n{after}; serial:\n{}",
        guest.serial()
    );
    assert!(
        after.contains("\"mgmt\"") && after.contains(&mgmt_nic) && after.contains("10.0.2.15"),
        "status JSON must show the Management NIC role and on-link prefix, got:\n{after}"
    );
    assert!(
        after.contains("ui_exposure") && after.contains(&mgmt_nic),
        "Management NIC is always in UI exposure, got:\n{after}"
    );
    assert!(
        after.contains(&wan_nic)
            && after.contains("\"wan\"")
            && after.contains(&lan_nic)
            && after.contains("\"lan\""),
        "v1 still applies WAN and LAN; WAN is an extra NIC, got:\n{after}"
    );
    assert!(
        !after.contains("\"placement\"") && !after.contains("placement=mgmt"),
        "Management NIC stays in fwd; it is not placement=mgmt, got:\n{after}"
    );

    serial_login_admin(&guest, "alice", "secret12");
    let shown = serial_cmd(&guest, "show\n", 20, |t| {
        t.contains("role = \"mgmt\"")
            && t.contains(&mgmt_nic)
            && t.contains(&wan_nic)
            && t.contains(&lan_nic)
    });
    assert!(
        shown.contains("role = \"mgmt\"") && shown.contains(&mgmt_nic),
        "Appliance CLI show must list the Management NIC in fwd, serial:\n{shown}"
    );
    assert!(
        shown.contains("ui_exposure") && shown.contains(&format!("\"{mgmt_nic}\"")),
        "UI exposure after apply includes the Management NIC, serial:\n{shown}"
    );
    assert!(
        !shown.contains("placement =") && !shown.contains("placement=mgmt"),
        "Desired state must not move the Management NIC into the Management netns, serial:\n{shown}"
    );
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
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    let payload = wan_lan_bootstrap_json(&lan_nic, &wan_nic);
    https_bootstrap(&guest, &payload);
    serial_login_admin(&guest, "alice", "secret12");

    let full = format!(
        r#"{{"hostname":"fwos-box","interfaces":[{{"name":"{lan_nic}","role":"lan"}},{{"name":"{wan_nic}","role":"wan","addresses":["192.0.2.1/24"]}}],"ui_exposure":["{lan_nic}"],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200","wireguard":[{{"name":"wg0","private_key":"{WG_PRIVATE}","listen_port":51820,"addresses":["10.13.13.1/24"]}}],"routes":[{{"to":"198.51.100.0/24","via":"192.0.2.254"}}],"nft_extra":["ip saddr 203.0.113.50 drop"],"qdiscs":[{{"dev":"{wan_nic}","kind":"fq_codel"}}]}}"#
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
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
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

    let payload = wan_lan_bootstrap_json(&lan_nic, &wan_nic);
    https_bootstrap(&guest, &payload);
    serial_login_admin(&guest, "alice", "secret12");

    let mut ui_update = String::from("(no POST)");
    let mut ui_code = 0u16;
    let ui_session = https_login_admin(&guest, "alice", "secret12");
    for _ in 0..30 {
        match ui_session.exchange(
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
        match https_authenticated_status(&guest) {
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
        ui_status.contains("\"wan\"") && ui_status.contains("192.0.2.1"),
        "WAN role must still be applied after staging, status:\n{ui_status}"
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
        match https_authenticated_status(&guest) {
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
            && ui_after.contains("\"wan\"")
            && ui_after.contains("\"lan\""),
        "HTTPS status must show hostname and interface roles from shared /var, status:\n{ui_after}"
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
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    let image = registry.guest_image();

    let payload = wan_lan_bootstrap_json(&lan_nic, &wan_nic);
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
        match https_authenticated_status(&guest) {
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
        match guest.https_exchange("GET", "/api/status", None, 15) {
            Ok((200 | 401, body)) => {
                after = body;
                if after.contains("\"bootstrapped\"") && after.contains("true") {
                    break;
                }
            }
            Ok((code, body)) => after = format!("http_code={code} {body}"),
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
        "admin must authenticate into the Appliance CLI, serial:\n{}",
        last.replace(password, "[redacted]")
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

fn post_bootstrap_observe_serial(guest: &Guest, payload: &str) {
    let post = match guest.https_exchange("POST", "/api/bootstrap", Some(payload), 45) {
        Ok((200, body)) | Ok((409, body)) => body,
        Ok((code, body)) => format!("http_code={code} {body}"),
        Err(e) => e.to_string(),
    };
    let mut last = guest.serial();
    for _ in 0..120 {
        if last.contains("Bootstrap complete") || last.contains("FWOS Appliance CLI") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        last = guest.serial();
    }
    panic!("HTTPS wizard apply must complete (serial after POST={post}); serial:\n{last}");
}

fn wan_lan_bootstrap_json(lan: &str, wan: &str) -> String {
    format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{lan}","role":"lan"}},{{"name":"{wan}","role":"wan","addresses":["192.0.2.1/24"]}}],"ui_exposure":["{lan}"],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    )
}

fn wan_lan_mgmt_bootstrap_json(lan: &str, wan: &str, mgmt: &str) -> String {
    format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{lan}","role":"lan"}},{{"name":"{wan}","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{mgmt}","role":"mgmt","addresses":["10.0.2.15/24"]}}],"ui_exposure":["{mgmt}"],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    )
}

fn one_nic_untagged_wan_json(nic: &str, lan_vid: u16) -> String {
    format!(
        r#"{{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{{"name":"{nic}","role":"wan","addresses":["192.0.2.1/24"]}},{{"name":"{nic}.{lan_vid}","role":"lan","parent":"{nic}","vlan":{lan_vid},"addresses":["192.168.1.1/24"]}}],"ui_exposure":["{nic}.{lan_vid}"],"lan_prefix":"192.168.1.0/24","dhcp_pool":"192.168.1.100-192.168.1.200"}}"#
    )
}

fn published_user_net_and_extra(guest: &Guest) -> (String, String) {
    let user = opt_user_net(guest);
    let extra = other_console_nic(guest, &user);
    (user, extra)
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
    let new = if last.len() > from {
        &last[from..]
    } else {
        last.as_str()
    };
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
        page.to_ascii_lowercase().contains("html")
            || page.to_ascii_lowercase().contains("hostname"),
        "HTTPS must answer on the opted user-net NIC; serial:\n{}",
        guest.serial()
    );

    console_opt_static(&guest, &extra, "10.0.3.15/24");
    https_must_not_answer(
        &guest,
        20,
        "after replacing the opt, the old user-net overlay must be gone",
    );
    let mut extra_page = String::new();
    let mut extra_err = String::from("(no GET)");
    for _ in 0..30 {
        match guest.https_get_extra("/") {
            Ok(body) => {
                extra_page = body;
                if extra_page.to_ascii_lowercase().contains("hostname")
                    || extra_page.to_ascii_lowercase().contains("html")
                {
                    break;
                }
            }
            Err(e) => extra_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        extra_page.to_ascii_lowercase().contains("hostname")
            || extra_page.to_ascii_lowercase().contains("html"),
        "after replacing the opt, the extra NIC must answer HTTPS, last={extra_err}; body:\n{extra_page}; serial:\n{}",
        guest.serial()
    );
}

#[test]
fn published_one_nic_untagged_wan_stops_https_after_apply() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image()
        .expect("published one-NIC Disk image must boot under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Bootstrap console"),
        "published first-boot serial must be the Bootstrap console, serial:\n{serial}"
    );
    let nic = opt_user_net(&guest);
    let lan = format!("{nic}.42");
    let payload = one_nic_untagged_wan_json(&nic, 42);
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
        "Workstation must reach the HTTPS wizard on untagged first-boot, last={err}; body:\n{page}; serial:\n{}",
        guest.serial()
    );
    let mut wizard = String::new();
    let mut wizard_err = String::from("(no GET)");
    for _ in 0..30 {
        match guest.https_get("/app.js") {
            Ok(body) => {
                wizard = body;
                if wizard.contains("Apply still proceeds") {
                    break;
                }
            }
            Err(e) => wizard_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        wizard.contains("Untagged first-boot HTTPS will vanish")
            && wizard.contains("Apply still proceeds"),
        "one-NIC wizard must warn that untagged first-boot HTTPS leaves when untagged is not in post-apply UI exposure; last={wizard_err}; body:\n{wizard}"
    );

    // Untagged becomes WAN; workstation HTTPS on 10.0.2.15 leaves with it.
    post_bootstrap_observe_serial(&guest, &payload);

    let mut https_down = false;
    for _ in 0..60 {
        match guest.https_exchange("GET", "/", None, 3) {
            Ok((code, _)) if code != 0 => {}
            _ => {
                https_down = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        https_down,
        "HTTPS on 10.0.2.15 must stop after apply when untagged became WAN; serial:\n{}",
        guest.serial()
    );
    https_must_not_answer(
        &guest,
        10,
        "HTTPS on 10.0.2.15 must stay down after untagged became WAN",
    );

    serial_login_admin(&guest, "alice", "secret12");
    let shown = serial_cmd(&guest, "show\n", 20, |t| {
        t.contains("role = \"wan\"")
            && t.contains("role = \"lan\"")
            && t.contains(&lan)
            && t.contains("vlan = 42")
    });
    assert!(
        shown.contains("role = \"wan\"") && shown.contains("role = \"lan\""),
        "Appliance CLI show must list WAN and LAN L2s, serial:\n{shown}"
    );
    assert!(
        shown.contains(&lan) && shown.contains("vlan = 42"),
        "operator-chosen LAN VID must be Desired state, serial:\n{shown}"
    );
    assert!(
        shown.contains("ui_exposure") && shown.contains(&format!("\"{lan}\"")),
        "UI exposure after apply is the LAN L2, serial:\n{shown}"
    );
    assert!(
        !shown.contains(&format!("ui_exposure = [\"{nic}\"]")),
        "UI exposure must not be the WAN parent, serial:\n{shown}"
    );
    assert!(
        !shown.contains("stick"),
        "one-NIC WAN+LAN Desired state has no stick role, serial:\n{shown}"
    );
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
        !serial.contains("These partitions will be overwritten"),
        "empty disk path is unchanged: no fake partition list; serial:\n{serial}"
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
        "several eligible disks: serial still asks which disk to wipe before the yes prompt; serial:\n{serial}"
    );
    assert!(
        !serial.contains("Type yes to wipe"),
        "picking a number is not the wipe; yes comes after a valid disk number; serial:\n{serial}"
    );
    assert!(
        !serial.contains("FWOS Bootstrap console"),
        "two empty disks, no number entered: still no Bootstrap console; serial:\n{serial}"
    );
}

#[test]
fn installer_two_disks_pick_then_yes_decline_returns_to_pick() {
    let _guard = guest_lock();
    let guest = Guest::boot_installer_two_disks()
        .expect("Installer with two writable disks must start under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Installer: pick a disk to wipe"),
        "several eligible disks: serial asks which disk before yes; serial:\n{serial}"
    );
    assert!(
        !serial.contains("Type yes to wipe"),
        "yes must not appear before a valid disk number; serial:\n{serial}"
    );

    let after_bad = installer_serial_cmd(&guest, "nope\r\n", 30, |t| t.contains("Disk number:"));
    assert!(
        !after_bad.contains("Type yes to wipe") && !after_bad.contains("FWOS Bootstrap console"),
        "non-numeric input does not select a disk or write; serial:\n{after_bad}"
    );

    let after_range = installer_serial_cmd(&guest, "9\r\n", 30, |t| t.contains("Disk number:"));
    assert!(
        !after_range.contains("Type yes to wipe")
            && !after_range.contains("FWOS Bootstrap console"),
        "out-of-range input does not select a disk or write; serial:\n{after_range}"
    );

    let after_pick = installer_serial_cmd(&guest, "1\r\n", 30, |t| t.contains("Type yes to wipe"));
    assert!(
        after_pick.contains("Type yes to wipe")
            && after_pick.contains("FWOS Installer: /dev/")
            && after_pick.contains(
                "The entire disk will be erased and replaced with the Host disk layout"
            ),
        "after a valid disk number, serial shows that disk and waits for typed yes; serial:\n{after_pick}"
    );
    assert!(
        !after_pick.contains("FWOS Bootstrap console"),
        "typed yes is required after pick; serial:\n{after_pick}"
    );

    guest
        .serial_write("n\r\n")
        .expect("decline on the Installer serial must be written");
    let mut after_decline = guest.serial();
    for _ in 0..30 {
        after_decline = guest.serial();
        if pick_prompt_after_yes(&after_decline) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        pick_prompt_after_yes(&after_decline),
        "decline after a pick returns to the disk flow so the operator can pick again; serial:\n{after_decline}"
    );
    assert!(
        !after_decline.contains("FWOS Bootstrap console"),
        "decline after a pick writes nothing; serial:\n{after_decline}"
    );

    let after_repick =
        installer_serial_cmd(&guest, "2\r\n", 30, |t| t.contains("Type yes to wipe"));
    assert!(
        after_repick.contains("Type yes to wipe") && after_repick.contains("FWOS Installer: /dev/"),
        "after decline the operator can pick again and still waits for typed yes; serial:\n{after_repick}"
    );
    assert!(
        !after_repick.contains("FWOS Bootstrap console"),
        "a second pick is still not the wipe; serial:\n{after_repick}"
    );
}

#[test]
fn installer_approval_lists_existing_partitions() {
    let _guard = guest_lock();
    let guest = Guest::boot_installer_one_partitioned_disk()
        .expect("Installer with one partitioned disk must start under QEMU");
    let serial = guest.serial();
    assert!(
        serial.contains("FWOS Installer: /dev/") && serial.contains("("),
        "partitioned disk still names the target; serial:\n{serial}"
    );
    assert!(
        serial.contains("vda1") && serial.contains("vda2"),
        "if the target has partitions and they can be listed, they appear on the approval screen; serial:\n{serial}"
    );
    let list_at = serial.find("vda1");
    let overwrite_at =
        serial.find("These partitions will be overwritten with the Host disk layout.");
    assert!(
        list_at.is_some()
            && overwrite_at.is_some()
            && overwrite_at.unwrap() > list_at.unwrap(),
        "that listing is followed by a sentence that they will be overwritten with the Host disk layout; serial:\n{serial}"
    );
    assert!(
        serial
            .lines()
            .any(|line| line.contains("vda1") && line.contains("ext4")),
        "filesystem is shown on the partition listing when known; serial:\n{serial}"
    );
    assert!(
        serial.contains("The entire disk will be erased and replaced with the Host disk layout"),
        "approval still states the whole disk is erased; serial:\n{serial}"
    );
    assert!(
        serial.contains("Type yes to wipe"),
        "approval still requires typed yes; serial:\n{serial}"
    );
    assert!(
        !serial.contains("FWOS Bootstrap console"),
        "without yes, a partitioned disk is not written; serial:\n{serial}"
    );
}

fn pick_prompt_after_yes(serial: &str) -> bool {
    match (
        serial.rfind("Type yes to wipe"),
        serial.rfind("FWOS Installer: pick a disk to wipe"),
    ) {
        (Some(yes_at), Some(pick_at)) => pick_at > yes_at,
        _ => false,
    }
}

fn installer_serial_cmd(
    guest: &Guest,
    data: &str,
    secs: u64,
    pred: impl Fn(&str) -> bool,
) -> String {
    let from = guest.serial().len();
    guest
        .serial_write(data)
        .unwrap_or_else(|e| panic!("Installer serial {data:?}: {e}"));
    serial_wait(guest, from, secs, pred)
}
