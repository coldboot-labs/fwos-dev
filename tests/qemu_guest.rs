use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use fwos_dev::{Guest, Ipv6Upstream, LocalRegistry, NetworkPeer};

// WireGuard test vector (docs.wireguard.com).
const WG_PRIVATE: &str = "yAnz5TF+lXXJte14tji3dzMe2arW8mOcy4V+1RU4hQE=";

static GUEST_LOCK: Mutex<()> = Mutex::new(());

fn boot_apply_confirmation_route_guest() -> (Guest, NetworkPeer, NetworkPeer, String) {
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("198.51.100.0/24", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("198.51.100.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    let (lan_nic, wan_nic) = (&peers[0], &peers[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic], "lan_prefix": "10.56.0.0/24"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    (guest, lan_peer, wan_peer, wan_nic.clone())
}

#[test]
fn apply_confirmation_is_off_by_default_and_route_apply_is_immediately_accepted() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    let alice = https_login_admin(&guest, "alice", "secret12");
    let setting: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(setting["enabled"], false);
    guest
        .browser_add_static_route(
            "alice",
            "secret12",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("administrator applies a route through rendered UI");
    let routes: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(routes["status"], "accepted");
    assert_eq!(routes["revision"], 2);
    let setting: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(setting["pending"].is_null());
}

#[test]
fn another_administrator_reviews_and_confirms_pending_apply_while_drafts_continue() {
    let _guard = guest_lock();
    let (guest, lan_peer, _wan_peer, wan_nic) = boot_apply_confirmation_route_guest();
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Alice creates Bob through the rendered UI");
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Alice enables Apply confirmation through the rendered UI");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let setting: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(setting["enabled"], true);
    assert_eq!(setting["accepted_revision"], 2);
    assert!(!lan_peer.ping("198.51.100.2").unwrap());
    guest
        .browser_static_route_action(
            "add-pending",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice applies a route with post-Apply confirmation pending");
    assert!(
        lan_peer.ping("198.51.100.2").unwrap(),
        "pending route is live"
    );
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 2);
    assert_eq!(accepted["routes"], serde_json::json!([]));
    let pending: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(pending["pending"]["revision"], 3);
    assert_eq!(pending["pending"]["applying"]["username"], "alice");
    assert_eq!(pending["pending"]["applying"]["source"], "local");
    assert!(pending["pending"]["applying"]["subject"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    let (overlap_status, _) = alice
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(r#"{"base_revision":2,"routes":[]}"#),
            15,
        )
        .unwrap();
    assert_eq!(overlap_status, 409, "another Apply must wait");
    guest
        .browser_static_route_action(
            "save",
            "bob",
            "bob-secret",
            "",
            "203.0.113.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Bob can keep editing his private draft during confirmation");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let draft: serde_json::Value = serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(draft["status"], "pending");
    assert_eq!(draft["base_revision"], 2);
    let draft_reference = serde_json::json!({
        "base_revision": 2, "version": draft["version"]
    });
    let (draft_overlap_status, _) = bob
        .exchange(
            "POST",
            "/api/draft/apply",
            Some(&draft_reference.to_string()),
            15,
        )
        .unwrap();
    assert_eq!(draft_overlap_status, 409, "draft Apply must also wait");
    guest
        .browser_apply_confirmation_action("confirm", "bob", "bob-secret")
        .expect("Bob reviews and confirms the exact pending revision through rendered UI");
    let accepted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 3);
    assert_eq!(accepted["routes"][0]["to"], "198.51.100.0/24");
    let setting: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(setting["pending"].is_null());
    assert_eq!(setting["last_accepted"]["revision"], 3);
    assert_eq!(setting["last_accepted"]["applying"]["username"], "alice");
    assert_eq!(setting["last_accepted"]["confirming"]["username"], "bob");
    assert_ne!(
        setting["last_accepted"]["applying"]["subject"],
        setting["last_accepted"]["confirming"]["subject"]
    );
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    let (setting_shortcut_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/configure",
            Some(r#"{"base_revision":3,"enabled":false}"#),
            15,
        )
        .unwrap();
    assert_eq!(
        setting_shortcut_status, 409,
        "Bob's private pending draft excludes the standalone setting Apply shortcut"
    );
    guest
        .browser_apply_confirmation_action("disable", "alice", "secret12")
        .expect("disabling an enabled safeguard itself waits for confirmation");
    let pending_off: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(
        pending_off["enabled"], true,
        "Accepted setting stays on until confirmation"
    );
    assert_eq!(pending_off["pending"]["revision"], 4);
    assert_eq!(
        pending_off["pending"]["proposed_review"]["apply_confirmation"],
        false
    );
    let wrong_revision = serde_json::json!({
        "revision": 3,
        "confirmation_id": pending_off["pending"]["confirmation_id"],
    });
    let (wrong_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&wrong_revision.to_string()),
            15,
        )
        .unwrap();
    assert_eq!(
        wrong_status, 409,
        "old revision cannot confirm pending revision 4"
    );
    let still_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(still_pending["pending"]["revision"], 4);
    guest
        .browser_apply_confirmation_action("confirm-setting", "bob", "bob-secret")
        .expect("Bob reviews and confirms disabling the safeguard");
    let disabled: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["accepted_revision"], 4);
    assert!(disabled["pending"].is_null());
    let next_route = serde_json::json!({
        "base_revision": 4,
        "routes": [
            {"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic},
            {"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic}
        ]
    });
    let (next_status, next_body) = alice
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(&next_route.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(next_status, 200);
    let next: serde_json::Value = serde_json::from_str(&next_body).unwrap();
    assert_eq!(next["outcome"], "accepted");
    assert_eq!(next["revision"], 5);
    let after: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(after["pending"].is_null());
}

#[test]
fn pending_apply_expires_after_two_minutes_and_restores_accepted_network_without_losing_identity_or_draft(
) {
    let _guard = guest_lock();
    let (guest, lan_peer, _wan_peer, wan_nic) = boot_apply_confirmation_route_guest();
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Alice enables Apply confirmation");
    guest
        .browser_static_route_action(
            "save",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice saves a private draft");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let draft_before: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    guest
        .browser_static_route_action(
            "apply-draft-pending",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "",
            &wan_nic,
        )
        .expect("Alice reviews and applies her draft, leaving it private until acceptance");
    assert!(
        lan_peer.ping("198.51.100.2").unwrap(),
        "pending route forwards"
    );
    let pending: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(pending["pending"]["revision"], 3);
    let started = std::time::Instant::now();
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Identity changes continue while network confirmation is pending");
    let deadline = started + std::time::Duration::from_secs(170);
    loop {
        let status: serde_json::Value =
            serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
        if status["pending"].is_null() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pending Apply did not expire"
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(105),
        "Apply expired too early"
    );
    assert!(
        !lan_peer.ping("198.51.100.2").unwrap(),
        "timeout restores previous forwarding"
    );
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 2);
    assert_eq!(accepted["routes"], serde_json::json!([]));
    let (late_status, _) = alice
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(
                &serde_json::json!({
                    "revision": 3,
                    "confirmation_id": pending["pending"]["confirmation_id"],
                })
                .to_string(),
            ),
            15,
        )
        .unwrap();
    assert_eq!(late_status, 409, "expired revision cannot be confirmed");
    let draft_after: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(draft_after["status"], "pending");
    assert_eq!(draft_after["version"], draft_before["version"]);
    assert_eq!(draft_after["routes"], draft_before["routes"]);
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let identity_status: serde_json::Value =
        serde_json::from_str(&bob.get("/api/status").unwrap()).unwrap();
    assert_eq!(identity_status["principal"]["username"], "bob");
    let setting: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(setting["last_accepted"]["revision"], 2);
    let apply_reference = serde_json::json!({
        "base_revision": draft_after["base_revision"],
        "version": draft_after["version"],
    });
    let (reapply_status, reapply_body) = alice
        .exchange(
            "POST",
            "/api/draft/apply",
            Some(&apply_reference.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(reapply_status, 200);
    let reapplied: serde_json::Value = serde_json::from_str(&reapply_body).unwrap();
    assert_eq!(reapplied["outcome"], "pending_confirmation");
    guest
        .browser_apply_confirmation_action("confirm", "bob", "bob-secret")
        .expect("Bob confirms Alice's recovered draft after her UI session ends");
    let accepted_draft: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(
        accepted_draft["status"], "none",
        "an unchanged applied draft is no longer pending once Accepted"
    );
    guest
        .browser_static_route_action(
            "save",
            "alice",
            "secret12",
            "",
            "203.0.113.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice saves another private proposal");
    let next_draft: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(next_draft["base_revision"], 3);
    let next_reference = serde_json::json!({
        "base_revision": 3,
        "version": next_draft["version"],
    });
    let (next_apply_status, next_apply_body) = alice
        .exchange(
            "POST",
            "/api/draft/apply",
            Some(&next_reference.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(next_apply_status, 200);
    let next_apply: serde_json::Value = serde_json::from_str(&next_apply_body).unwrap();
    assert_eq!(next_apply["outcome"], "pending_confirmation");
    assert_eq!(next_apply["revision"], 4);
    let edited_routes = serde_json::json!([
        next_draft["routes"][0],
        {"to": "203.0.114.0/24", "via": "192.0.2.2", "dev": wan_nic},
    ]);
    let edit = serde_json::json!({
        "base_revision": 3,
        "version": next_draft["version"],
        "routes": edited_routes,
    });
    let (edit_status, _) = alice
        .exchange("POST", "/api/draft/save", Some(&edit.to_string()), 15)
        .unwrap();
    assert_eq!(
        edit_status, 200,
        "private editing continues while Apply is pending"
    );
    let edited: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_ne!(edited["version"], next_draft["version"]);
    let edit_back = serde_json::json!({
        "base_revision": 3,
        "version": edited["version"],
        "routes": next_draft["routes"],
    });
    let (edit_back_status, _) = alice
        .exchange("POST", "/api/draft/save", Some(&edit_back.to_string()), 15)
        .unwrap();
    assert_eq!(edit_back_status, 200);
    let edited_back: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_ne!(edited_back["version"], edited["version"]);
    assert_eq!(edited_back["routes"], next_draft["routes"]);
    let pending_next: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    let confirmation = serde_json::json!({
        "revision": 4,
        "confirmation_id": pending_next["pending"]["confirmation_id"],
    });
    let (confirm_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&confirmation.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(confirm_status, 200);
    let preserved: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(preserved["status"], "pending");
    assert_eq!(preserved["version"], edited_back["version"]);
    assert_eq!(preserved["routes"], next_draft["routes"]);
    assert_eq!(preserved["stale"], true);
    let accepted_status: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(accepted_status["last_accepted"]
        .get("draft_version")
        .is_none());
}

#[test]
fn external_reset_during_pending_apply_restores_accepted_network_and_current_identity() {
    let _guard = guest_lock();
    let (guest, lan_peer, _wan_peer, wan_nic) = boot_apply_confirmation_route_guest();
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Alice enables Apply confirmation");
    guest
        .browser_static_route_action(
            "add-pending",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice applies the tentative route");
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Bob is created after the network Apply starts");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let before: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(before["pending"]["revision"], 3);
    let old_confirmation_id = before["pending"]["confirmation_id"]
        .as_str()
        .expect("pending Apply exposes an operation-specific confirmation ID")
        .to_owned();
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("external power reset during pending confirmation");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.lines().any(|line| line.trim() == "admin:"),
        "owned appliance must reach authenticated console: {rebooted}"
    );
    let recovery_deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        if !lan_peer.ping("198.51.100.2").unwrap() {
            break;
        }
        assert!(
            std::time::Instant::now() < recovery_deadline,
            "tentative forwarding continued after external restart"
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let accepted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 2);
    assert_eq!(accepted["routes"], serde_json::json!([]));
    let setting: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(setting["enabled"], true);
    assert!(setting["pending"].is_null());
    assert_eq!(setting["last_accepted"]["revision"], 2);
    assert_eq!(setting["last_accepted"]["applying"]["username"], "alice");
    let status: serde_json::Value = serde_json::from_str(&bob.get("/api/status").unwrap()).unwrap();
    assert_eq!(status["principal"]["username"], "bob");
    guest
        .browser_static_route_action(
            "add-pending",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("a new pending Apply may reuse the rolled-back revision number");
    let new_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(new_pending["pending"]["revision"], 3);
    let new_confirmation_id = new_pending["pending"]["confirmation_id"]
        .as_str()
        .expect("new pending Apply exposes its own confirmation ID");
    assert_ne!(new_confirmation_id, old_confirmation_id);
    let stale = serde_json::json!({
        "revision": 3,
        "confirmation_id": old_confirmation_id,
    });
    let (stale_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&stale.to_string()),
            15,
        )
        .unwrap();
    assert_eq!(
        stale_status, 409,
        "old confirmation must not accept new Apply"
    );
    let still_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(
        still_pending["pending"]["confirmation_id"],
        new_confirmation_id
    );
    guest
        .browser_apply_confirmation_action("confirm", "bob", "bob-secret")
        .expect("Bob reviews and confirms the new Apply through the rendered UI");
    let accepted_new: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(accepted_new["accepted_revision"], 3);
    assert!(accepted_new["pending"].is_null());
}

#[test]
fn authenticated_console_can_restore_previous_network_with_apply_confirmation_enabled() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Apply confirmation is Accepted in revision 2");
    serial_login_admin(&guest, "alice", "secret12");
    let restored = serial_cmd(&guest, "restore-previous\n", 120, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        restored.contains("\"outcome\":\"accepted\"")
            || restored.contains("\"outcome\": \"accepted\""),
        "authenticated console restoration must be accepted without UI reachability: {restored}"
    );
    let status = serial_cmd(&guest, "status\n", 15, |text| {
        text.contains("Previous accepted network revision:")
    });
    assert!(
        status.contains("Previous accepted network revision: 2"),
        "restoration retains the displaced Accepted revision: {status}"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let setting: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(setting["accepted_revision"], 3);
    assert_eq!(setting["enabled"], false, "restored previous Desired state");
    assert!(setting["pending"].is_null());
    assert_eq!(setting["last_accepted"]["revision"], 3);
    assert_eq!(setting["last_accepted"]["applying"]["username"], "alice");
    assert_eq!(setting["last_accepted"]["applying"]["source"], "local");
}

#[test]
fn legacy_full_apply_remains_callable_but_needs_ui_confirmation_when_enabled() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Apply confirmation is Accepted in revision 2");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let status: serde_json::Value =
        serde_json::from_str(&alice.get("/api/status").unwrap()).unwrap();
    let proposed = serde_json::json!({
        "revision": 2,
        "hostname": status["hostname"],
        "interfaces": status["interfaces"],
        "ui_exposure": status["ui_exposure"],
        "lan_prefix": status["lan_prefix"],
        "dhcp_pool": status["dhcp_pool"],
        "wan_pd": status["wan_pd"],
        "apply_confirmation": true,
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic}]
    });
    serial_login_admin(&guest, "alice", "secret12");
    let applied = serial_cmd(&guest, &format!("apply {proposed}\n"), 120, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        applied.contains("\"outcome\":\"pending_confirmation\"")
            || applied.contains("\"outcome\": \"pending_confirmation\""),
        "legacy Apply remains callable and awaits UI confirmation: {applied}"
    );
    let pending: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(pending["pending"]["revision"], 3);
    assert!(
        pending["pending"]["applying"].is_null(),
        "do not invent a legacy actor"
    );
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(r#"{"revision":3}"#),
            120,
        )
        .unwrap();
    assert_eq!(code, 200, "authenticated UI acknowledgement: {body}");
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(accepted["accepted_revision"], 3);
    assert!(accepted["last_accepted"]["applying"].is_null());
    assert_eq!(accepted["last_accepted"]["confirming"]["username"], "alice");
}

#[test]
fn interrupted_apply_restores_accepted_route_after_external_reset() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("198.51.100.0/24", "10.56.0.1").unwrap();
    lan_peer.add_route("203.0.113.0/24", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("198.51.100.2/24").unwrap();
    wan_peer.add_address("203.0.113.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peer_nics: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    let (lan_nic, wan_nic) = (&peer_nics[0], &peer_nics[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic], "lan_prefix": "10.56.0.0/24"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    guest
        .browser_add_static_route("alice", "secret12", "198.51.100.0/24", "192.0.2.2", wan_nic)
        .expect("accept A through rendered UI");
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    assert!(!lan_peer.ping("203.0.113.2").unwrap());
    serial_login_admin(&guest, "alice", "secret12");
    let replacement = serde_json::json!({
        "revision": 2, "hostname": "fwos-box", "interfaces": bootstrap["interfaces"],
        // Preflight accepts this; Kea Host activation rejects it after the
        // replacement route is live, holding the operation short of Accepted.
        "ui_exposure": [ui_nic], "lan_prefix": "10.56.0.0/24", "dhcp_pool": "",
        "routes": [{"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic}]
    });
    let from = guest.serial().len();
    guest
        .serial_write(&format!("apply {replacement}\n"))
        .expect("send complete Desired state over authenticated serial console");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !lan_peer
        .ping("203.0.113.2")
        .expect("external replacement probe")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "replacement never forwarded before cut; serial: {}",
            guest.serial()
        );
    }
    guest
        .qemu_system_reset()
        .expect("externally cut power during mutation and Host service reconciliation");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.lines().any(|line| line.trim() == "admin:"),
        "owned appliance must reach authenticated console: {rebooted}"
    );
    assert!(
        !rebooted.contains("\"outcome\""),
        "the interrupted apply returned an outcome before the external cut: {rebooted}"
    );
    // The serial login prompt can precede netd's recovery and Host ACK.
    let recovery_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !lan_peer.ping("198.51.100.2").unwrap() {
        assert!(
            std::time::Instant::now() < recovery_deadline,
            "previous Accepted route did not resume after restart; serial: {}",
            guest.serial()
        );
    }
    assert!(
        !lan_peer.ping("203.0.113.2").unwrap(),
        "tentative route must not forward after restart"
    );
    let current = https_login_admin(&guest, "alice", "secret12");
    let routes: serde_json::Value =
        serde_json::from_str(&current.get("/api/routes").unwrap()).unwrap();
    assert_eq!(
        routes["revision"], 2,
        "interrupted replacement must not become Accepted"
    );
    serial_login_admin(&guest, "alice", "secret12");
    let status = serial_cmd(&guest, "status\n", 15, |text| {
        text.contains("Previous accepted network revision:")
    });
    assert!(
        status.contains("Previous accepted network revision: 1"),
        "interrupted B must retain A's manual predecessor P: {status}"
    );
}

#[test]
fn failed_interrupted_restoration_blocks_forwarding_and_keeps_authenticated_console() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("192.0.2.0/24", "10.56.0.1").unwrap();
    lan_peer.add_route("198.51.100.0/24", "10.56.0.1").unwrap();
    lan_peer.add_route("203.0.113.0/24", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("198.51.100.2/24").unwrap();
    wan_peer.add_address("203.0.113.2/24").unwrap();
    let guest =
        Guest::boot_published_host_image_with_user_net_peers_and_extra_nic(&[&lan_peer, &wan_peer])
            .expect("published Disk image with independent LAN, WAN and removable required NIC");
    let ui_nic = opt_user_net(&guest);
    let discovered = wait_console_nics(&guest);
    let extra_nics: Vec<String> = discovered
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(extra_nics.len(), 3, "two peers plus removable required NIC");
    let (lan_nic, wan_nic, required_nic) = (&extra_nics[0], &extra_nics[1], &extra_nics[2]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]},
            {"name": required_nic, "role": "mgmt", "addresses": ["10.0.3.15/24"]}
        ],
        "ui_exposure": [ui_nic, required_nic], "lan_prefix": "10.56.0.0/24"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    guest
        .browser_add_static_route("alice", "secret12", "198.51.100.0/24", "192.0.2.2", wan_nic)
        .expect("accept A through rendered UI");
    assert!(
        lan_peer.ping("192.0.2.2").unwrap(),
        "intact LAN to WAN path forwards before cut"
    );
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    assert!(
        !wan_peer.ping("192.0.2.1").unwrap(),
        "Accepted firewall blocks unsolicited WAN input before recovery"
    );
    guest
        .browser_change_own_administrator_password("alice", "secret12", "new-secret12")
        .expect("current Identity changes after A is accepted");
    serial_login_admin(&guest, "alice", "new-secret12");
    let replacement = serde_json::json!({
        "revision": 2, "hostname": "fwos-box", "interfaces": bootstrap["interfaces"],
        // The invalid pool delays acceptance until Kea rejects activation;
        // the B route is externally visible before that Host acknowledgement.
        "ui_exposure": [ui_nic, required_nic], "lan_prefix": "10.56.0.0/24", "dhcp_pool": "",
        "routes": [{"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic}]
    });
    let from = guest.serial().len();
    guest
        .serial_write(&format!("apply {replacement}\n"))
        .expect("submit replacement from authenticated console");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !lan_peer
        .ping("203.0.113.2")
        .expect("replacement traffic from external LAN")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "replacement never forwarded; serial: {}",
            guest.serial()
        );
    }
    guest
        .qemu_unplug_extra_nic()
        .expect("externally remove only the required spare NIC before restart");
    guest
        .qemu_system_reset()
        .expect("externally cut VM power during replacement");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.lines().any(|line| line.trim() == "admin:"),
        "authenticated console after failed restoration: {rebooted}"
    );
    assert!(
        !rebooted.contains("\"outcome\""),
        "the interrupted apply returned an outcome before the external cut: {rebooted}"
    );
    let lan_local = lan_peer.ping("10.56.0.1").unwrap();
    let wan_local = wan_peer.resolve_neighbor("192.0.2.1").unwrap();
    let forwarded = lan_peer.ping("192.0.2.2").unwrap();
    assert!(lan_local, "LAN link and appliance address remain present");
    assert!(
        wan_local,
        "WAN peer must resolve the appliance address on its intact link"
    );
    assert!(
        !wan_peer.ping("192.0.2.1").unwrap(),
        "WAN input must remain blocked while restoration is incomplete"
    );
    assert!(
        !forwarded,
        "forwarding must be blocked even though LAN and WAN remain connected"
    );
    let wrong = serial_cmd(&guest, "alice\n", 15, |text| text.contains("password:"));
    assert!(
        wrong.contains("password:"),
        "current administrator is prompted: {wrong}"
    );
    let denied_from = guest.serial().len();
    guest.serial_write("secret12\n").unwrap();
    let denied = serial_wait(&guest, denied_from, 15, |text| {
        text.contains("login failed")
    });
    assert!(
        denied.contains("login failed"),
        "obsolete password cannot access recovery: {denied}"
    );
    serial_login_admin(&guest, "alice", "new-secret12");
    let status = serial_cmd(&guest, "status\n", 15, |text| {
        text.contains("Recovery required")
    });
    assert!(
        status.contains("Recovery required"),
        "console must name in-flight recovery: {status}"
    );
    let excluded = serial_cmd(&guest, &format!("apply {replacement}\n"), 15, |text| {
        text.contains("\"restoration\"")
    });
    assert!(
        excluded.contains("\"required\""),
        "another apply must be excluded throughout recovery: {excluded}"
    );
    let retry = serial_cmd(&guest, "restore-previous\n", 30, |text| {
        text.contains("\"restoration\"")
    });
    assert!(
        retry.contains("\"required\""),
        "retry stays blocked while required NIC is absent: {retry}"
    );
    assert!(
        !lan_peer.ping("192.0.2.2").unwrap(),
        "failed retry remains fail closed"
    );
    guest
        .qemu_replug_extra_nic()
        .expect("externally repair the required NIC");
    let repaired_from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("reboot so network startup moves repaired NIC into fwd");
    let repaired = serial_wait(&guest, repaired_from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        repaired.lines().any(|line| line.trim() == "admin:"),
        "repaired appliance console: {repaired}"
    );
    assert!(
        lan_peer.ping("192.0.2.2").unwrap(),
        "forwarding resumes only after successful recovery"
    );
    assert!(
        lan_peer.ping("198.51.100.2").unwrap(),
        "A restored after repair"
    );
    assert!(
        !lan_peer.ping("203.0.113.2").unwrap(),
        "B never became Accepted"
    );
    let current = https_login_admin(&guest, "alice", "new-secret12");
    let routes: serde_json::Value =
        serde_json::from_str(&current.get("/api/routes").unwrap()).unwrap();
    assert_eq!(routes["revision"], 2);
    let old = serde_json::json!({"source":"local", "username":"alice", "password":"secret12"});
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&old.to_string()), 15)
        .unwrap();
    assert_eq!(code, 401, "network recovery must preserve current Identity");
    guest
        .browser_add_static_route(
            "alice",
            "new-secret12",
            "203.0.113.0/24",
            "192.0.2.2",
            wan_nic,
        )
        .expect("new apply is allowed only after successful recovery");
    assert!(
        lan_peer.ping("203.0.113.2").unwrap(),
        "normal forwarding resumes with newly accepted B"
    );
}

#[test]
fn authenticated_console_restores_previous_network_after_ui_reply_path_is_lost() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    for destination in ["198.51.100.0/24", "203.0.113.0/24"] {
        lan_peer
            .add_route(destination, "10.56.0.1")
            .expect("LAN route through appliance");
    }
    wan_peer.add_address("192.0.2.2/24").expect("WAN next hop");
    wan_peer
        .add_address("198.51.100.2/24")
        .expect("A destination");
    wan_peer
        .add_address("203.0.113.2/24")
        .expect("B destination");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peer_nics: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peer_nics.len(), 2);
    let (lan_nic, wan_nic) = (&peer_nics[0], &peer_nics[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic]
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    guest
        .browser_add_static_route("alice", "secret12", "198.51.100.0/24", "192.0.2.2", wan_nic)
        .expect("administrator accepts reachable network A through rendered UI");
    assert!(lan_peer.ping("198.51.100.2").expect("A traffic"));
    assert!(!lan_peer.ping("203.0.113.2").expect("no B route yet"));

    // Identity changes after A is accepted are outside the network predecessor.
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("create current administrator through rendered UI");
    guest
        .browser_change_administrator_password("alice", "secret12", "bob", "new-bob-secret")
        .expect("change password after accepting A");
    guest
        .browser_remove_administrator("bob", "new-bob-secret", "alice")
        .expect("remove former administrator after accepting A");
    let bob = https_login_admin(&guest, "bob", "new-bob-secret");
    let bad_routes = serde_json::json!({
        "base_revision": 2,
        "routes": [
            {"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic},
            // More specific than the connected QEMU user-net route: valid,
            // but HTTPS replies to the Workstation now leave by the WAN.
            {"to": "10.0.2.2/32", "via": "192.0.2.2", "dev": wan_nic}
        ]
    });
    let _ = bob.exchange(
        "POST",
        "/api/routes/apply",
        Some(&bad_routes.to_string()),
        15,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while !lan_peer.ping("203.0.113.2").expect("B traffic") {
        assert!(
            std::time::Instant::now() < deadline,
            "unsuitable network B never became live; serial:\n{}",
            guest.serial()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(!lan_peer.ping("198.51.100.2").expect("A route removed"));
    https_must_not_answer(&guest, 3, "after accepted route hijacks UI reply path");

    // Neither obsolete identity can reach the recovery operation.
    for (user, password) in [("alice", "secret12"), ("bob", "bob-secret")] {
        let prompt = serial_cmd(&guest, &format!("{user}\n"), 15, |text| {
            text.contains("password:")
        });
        assert!(
            prompt.contains("password:"),
            "console login prompt: {prompt}"
        );
        let from = guest.serial().len();
        guest
            .serial_write(&format!("{password}\n"))
            .expect("submit obsolete console password");
        let denied = serial_wait(&guest, from, 15, |text| text.contains("login failed"));
        assert!(
            denied.contains("login failed"),
            "obsolete identity denied: {denied}"
        );
    }
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("failed auth cannot restore A"));
    serial_login_admin(&guest, "bob", "new-bob-secret");
    let help = serial_cmd(&guest, "help\n", 15, |text| {
        text.contains("restore-previous")
    });
    assert!(help.contains("restore-previous"), "recovery menu: {help}");
    assert!(!help.contains("apply <"), "v1 menu is limited: {help}");
    let restored = serial_cmd(&guest, "restore-previous\n", 120, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        restored.contains("\"outcome\":\"accepted\"")
            || restored.contains("\"outcome\": \"accepted\""),
        "console restoration outcome: {restored}"
    );
    assert!(lan_peer.ping("198.51.100.2").expect("A traffic restored"));
    assert!(!lan_peer.ping("203.0.113.2").expect("B route removed"));
    let current = https_login_admin(&guest, "bob", "new-bob-secret");
    let status: serde_json::Value =
        serde_json::from_str(&current.get("/api/status").unwrap()).unwrap();
    assert_eq!(
        status["bootstrapped"], true,
        "recovery cannot reopen Bootstrap"
    );
    let routes: serde_json::Value =
        serde_json::from_str(&current.get("/api/routes").unwrap()).unwrap();
    assert_eq!(
        routes["revision"], 4,
        "restoration is a new Accepted revision"
    );
    assert_eq!(routes["routes"][0]["to"], "198.51.100.0/24");
    for (user, password) in [("alice", "secret12"), ("bob", "bob-secret")] {
        let credentials =
            serde_json::json!({"source": "local", "username": user, "password": password});
        let (code, _) = guest
            .https_exchange("POST", "/api/login", Some(&credentials.to_string()), 15)
            .expect("obsolete identity response after restoration");
        assert_eq!(code, 401, "network recovery must preserve current Identity");
    }
}

fn guest_lock() -> std::sync::MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_dhcp_offer(peer: &NetworkPeer) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut packet_trace = String::new();
    while std::time::Instant::now() < deadline {
        let (address, trace) = peer
            .dhcp_offer_with_trace()
            .expect("external LAN DHCP offer");
        packet_trace.push_str(&trace);
        if let Some(address) = address {
            return address;
        }
    }
    panic!("accepted Kea config must offer an address; external packets: {packet_trace}");
}

fn offer_octet(address: &str) -> u8 {
    address
        .strip_prefix("10.56.0.")
        .unwrap_or_else(|| panic!("unexpected DHCP offer subnet: {address}"))
        .parse()
        .expect("DHCP offer last octet")
}

#[test]
fn accepted_removal_of_lan_prefix_and_pool_stops_dhcp_on_external_lan() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    wan_peer
        .add_address("192.0.2.2/24")
        .expect("WAN peer address");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peer_nics: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peer_nics.len(), 2);
    let (lan_nic, wan_nic) = (&peer_nics[0], &peer_nics[1]);
    let initial = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.56.0.0/24"
    });
    https_bootstrap(&guest, &initial.to_string());
    serial_login_admin(&guest, "alice", "secret12");
    let enabled = serde_json::json!({
        "revision": 1, "hostname": "fwos-box",
        "interfaces": initial["interfaces"],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.56.0.0/24", "dhcp_pool": "10.56.0.170-10.56.0.199"
    });
    let enabled_result = serial_cmd(&guest, &format!("apply {enabled}\n"), 90, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        enabled_result.contains("\"outcome\":\"accepted\"")
            || enabled_result.contains("\"outcome\": \"accepted\""),
        "valid DHCP enablement must be Accepted after Host activation: {enabled_result}"
    );
    let offer = wait_dhcp_offer(&lan_peer);
    assert!(
        (170..=199).contains(&offer_octet(&offer)),
        "initial pool offer: {offer}"
    );

    let disabled = serde_json::json!({
        "revision": 2, "hostname": "fwos-box",
        "interfaces": initial["interfaces"],
        "ui_exposure": [ui_nic],
        "lan_prefix": null, "dhcp_pool": null
    });
    let result = serial_cmd(&guest, &format!("apply {disabled}\n"), 90, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        result.contains("\"outcome\":\"accepted\"") || result.contains("\"outcome\": \"accepted\""),
        "valid complete-state DHCP disablement must be accepted: {result}"
    );
    let unexpected_offer = lan_peer
        .dhcp_offer()
        .expect("DHCP after accepted disablement");
    assert!(
        unexpected_offer.is_none(),
        "accepted removal must stop DHCP; external peer still received {unexpected_offer:?}"
    );
}

#[test]
fn published_administrator_reviews_and_applies_static_route_in_rendered_ui() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    let session = https_login_admin(&guest, "alice", "secret12");
    let initial = session
        .get("/api/routes")
        .expect("authenticated route view");
    assert!(
        initial.contains("\"revision\":1"),
        "initial route view: {initial}"
    );
    guest
        .browser_add_static_route(
            "alice",
            "secret12",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("rendered administrator reviews and applies a static route");
    let session = https_login_admin(&guest, "alice", "secret12");
    let desired: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").expect("accepted route view"))
            .expect("route view JSON");
    assert_eq!(desired["routes"][0]["to"], "198.51.100.0/24");
    assert_eq!(desired["status"], "accepted");
}

#[test]
fn standalone_route_shortcut_uses_reviewed_apply_lifecycle_without_other_drafts() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Alice creates Bob in rendered UI");
    guest
        .browser_add_static_route(
            "alice",
            "secret12",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("normal reviewed route Apply");
    guest
        .browser_static_route_action(
            "quick-add",
            "alice",
            "secret12",
            "",
            "203.0.113.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("one-action route Apply");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 3);
    assert_eq!(accepted["routes"].as_array().unwrap().len(), 2);
    assert_eq!(accepted["routes"][0]["to"], "198.51.100.0/24");
    assert_eq!(accepted["routes"][1]["to"], "203.0.113.0/24");
    let apply: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(apply["accepted_revision"], 3);
    assert!(apply["pending"].is_null());
    guest
        .browser_static_route_action(
            "quick-switch-dirty-unavailable",
            "alice",
            "secret12",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("a second route cannot replace an unfinished edit until it is canceled");
    guest
        .browser_static_route_action(
            "quick-remove-dirty",
            "alice",
            "secret12",
            "203.0.113.0/24",
            "192.0.2.128/25",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("removal shortcut is unavailable with another unfinished route edit");

    guest
        .browser_static_route_action(
            "save",
            "bob",
            "bob-secret",
            "",
            "192.0.2.0/25",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Bob saves private draft");
    guest
        .browser_static_route_action(
            "quick-unavailable",
            "bob",
            "bob-secret",
            "",
            "192.0.2.128/25",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("shortcut is unavailable to Bob while his draft is pending");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let shortcut = serde_json::json!({
        "base_revision": 3, "action": "add",
        "route": {"to": "192.0.2.128/25", "via": "192.0.2.2", "dev": wan_nic}
    });
    let (blocked, _) = bob
        .exchange(
            "POST",
            "/api/routes/save-and-apply",
            Some(&shortcut.to_string()),
            15,
        )
        .unwrap();
    assert_eq!(
        blocked, 409,
        "another client cannot bypass Bob's pending draft"
    );
    let (smuggled, _) = alice.exchange(
        "POST", "/api/routes/save-and-apply",
        Some(&serde_json::json!({"base_revision": 3, "action": "add", "route": shortcut["route"],
            "routes": [{"to": "0.0.0.0/0", "via": "192.0.2.2", "dev": wan_nic}]}).to_string()), 15,
    ).unwrap();
    assert_eq!(smuggled, 400, "shortcut accepts only one route change");
    let (stale, _) = alice.exchange(
        "POST", "/api/routes/save-and-apply",
        Some(&serde_json::json!({"base_revision": 1, "action": "add", "route": shortcut["route"]}).to_string()), 15,
    ).unwrap();
    assert_eq!(stale, 409);
    let draft: serde_json::Value = serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(draft["status"], "pending");
    assert_eq!(draft["routes"].as_array().unwrap().len(), 3);
    guest
        .browser_static_route_action(
            "quick-change",
            "alice",
            "secret12",
            "198.51.100.0/24",
            "198.51.101.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice changes only her selected Accepted route while Bob has a private draft");
    let changed: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(changed["revision"], 4);
    assert_eq!(changed["routes"].as_array().unwrap().len(), 2);
    assert_eq!(changed["routes"][0]["to"], "198.51.101.0/24");
    assert_eq!(changed["routes"][1]["to"], "203.0.113.0/24");
    let bob_after: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(bob_after["version"], draft["version"]);
    assert_eq!(bob_after["routes"], draft["routes"]);
    assert_eq!(bob_after["stale"], true);
    guest
        .browser_static_route_action(
            "quick-remove",
            "alice",
            "secret12",
            "203.0.113.0/24",
            "",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice removes one Accepted route through the shortcut");
    let after: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(after["revision"], 5);
    assert_eq!(after["routes"].as_array().unwrap().len(), 1);
    assert_eq!(after["routes"][0]["to"], "198.51.101.0/24");
    guest
        .browser_static_route_action(
            "quick-change-stale",
            "alice",
            "secret12",
            "198.51.101.0/24",
            "198.51.102.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("shortcut rejects a route edit prepared before a newer Accepted revision");
    let after_stale: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(after_stale["revision"], 6);
    assert_eq!(after_stale["routes"].as_array().unwrap().len(), 1);
    assert_eq!(after_stale["routes"][0]["to"], "198.51.101.0/24");
}

#[test]
fn standalone_route_shortcut_recovers_failed_apply_and_uses_shared_confirmation() {
    let _guard = guest_lock();
    let (guest, lan_peer, wan_peer, wan_nic) = boot_apply_confirmation_route_guest();
    lan_peer.add_route("203.0.113.0/24", "10.56.0.1").unwrap();
    wan_peer.add_address("203.0.113.2/24").unwrap();
    guest
        .browser_add_static_route(
            "alice",
            "secret12",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("normal reviewed route Apply establishes Accepted forwarding");
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    assert!(!lan_peer.ping("203.0.113.2").unwrap());
    let alice = https_login_admin(&guest, "alice", "secret12");
    let before_validation: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    let invalid_route = serde_json::json!({
        "to": "not-a-network", "via": "192.0.2.2", "dev": wan_nic
    });
    let normal_invalid = serde_json::json!({
        "base_revision": 2,
        "routes": [before_validation["routes"][0], invalid_route]
    });
    let (normal_code, normal_body) = alice
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(&normal_invalid.to_string()),
            15,
        )
        .expect("normal Apply validation response");
    let shortcut_invalid = serde_json::json!({
        "base_revision": 2, "action": "add", "route": invalid_route
    });
    let (shortcut_code, shortcut_body) = alice
        .exchange(
            "POST",
            "/api/routes/save-and-apply",
            Some(&shortcut_invalid.to_string()),
            15,
        )
        .expect("shortcut Apply validation response");
    assert_eq!(
        normal_code, 400,
        "normal validation response: {normal_body}"
    );
    assert_eq!(
        shortcut_code, normal_code,
        "shortcut validation response: {shortcut_body}"
    );
    let normal_rejected: serde_json::Value = serde_json::from_str(&normal_body).unwrap();
    let shortcut_rejected: serde_json::Value = serde_json::from_str(&shortcut_body).unwrap();
    assert_eq!(normal_rejected["outcome"], "rejected");
    assert_eq!(shortcut_rejected["outcome"], normal_rejected["outcome"]);
    assert_eq!(shortcut_rejected["error"], normal_rejected["error"]);
    assert_eq!(shortcut_rejected["revision"], normal_rejected["revision"]);
    let after_validation: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(after_validation["revision"], 2);
    assert_eq!(after_validation["routes"], before_validation["routes"]);
    assert!(lan_peer.ping("198.51.100.2").unwrap());
    assert!(!lan_peer.ping("203.0.113.2").unwrap());
    guest
        .browser_static_route_action(
            "quick-failed",
            "alice",
            "secret12",
            "",
            "203.0.113.0/24",
            "192.0.2.255",
            &wan_nic,
        )
        .expect("shortcut reports recovery after runtime route failure");
    let restored: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(restored["revision"], 2);
    assert_eq!(restored["routes"].as_array().unwrap().len(), 1);
    assert_eq!(restored["routes"][0]["to"], "198.51.100.0/24");
    assert!(
        lan_peer.ping("198.51.100.2").unwrap(),
        "Accepted forwarding survived shortcut rollback"
    );
    assert!(
        !lan_peer.ping("203.0.113.2").unwrap(),
        "failed shortcut did not leave route live"
    );

    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("enable optional Apply confirmation");
    guest
        .browser_static_route_action(
            "quick-add-pending",
            "alice",
            "secret12",
            "",
            "203.0.113.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("shortcut returns shared pending confirmation status");
    assert!(
        lan_peer.ping("203.0.113.2").unwrap(),
        "pending shortcut route is live"
    );
    let before: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(before["revision"], 3);
    assert_eq!(before["routes"].as_array().unwrap().len(), 1);
    let status: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(status["pending"]["revision"], 4);
    assert_eq!(status["pending"]["applying"]["username"], "alice");
    let overlap = serde_json::json!({
        "base_revision": 3, "action": "add",
        "route": {"to": "192.0.2.0/25", "via": "192.0.2.2", "dev": wan_nic}
    });
    let (busy, _) = alice
        .exchange(
            "POST",
            "/api/routes/save-and-apply",
            Some(&overlap.to_string()),
            15,
        )
        .unwrap();
    assert_eq!(busy, 409, "shortcut waits for the in-flight Apply");
    guest
        .browser_apply_confirmation_action("confirm-route-change", "alice", "secret12")
        .expect("review and confirm shortcut revision in the common UI");
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 4);
    assert_eq!(accepted["routes"].as_array().unwrap().len(), 2);
    let after: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(after["pending"].is_null());
    assert_eq!(after["last_accepted"]["revision"], 4);
}

#[test]
fn failed_runtime_route_apply_restores_accepted_forwarding_and_reports_recovery() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    for destination in ["198.51.100.0/24", "203.0.113.0/24"] {
        lan_peer
            .add_route(destination, "10.56.0.1")
            .expect("LAN peer route through appliance");
    }
    wan_peer.add_address("192.0.2.2/24").expect("WAN next hop");
    wan_peer
        .add_address("198.51.100.2/24")
        .expect("Accepted destination behind WAN peer");
    wan_peer
        .add_address("203.0.113.2/24")
        .expect("tentative destination behind WAN peer");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peer_nics: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peer_nics.len(), 2);
    let (lan_nic, wan_nic) = (&peer_nics[0], &peer_nics[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.56.0.0/24"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    assert!(lan_peer
        .dhcp_offer()
        .expect("no DHCP service before enablement")
        .is_none());
    guest
        .browser_add_static_route("alice", "secret12", "198.51.100.0/24", "192.0.2.2", wan_nic)
        .expect("administrator accepts the initial route in rendered UI");
    assert!(lan_peer
        .ping("198.51.100.2")
        .expect("Accepted peer traffic"));
    assert!(!lan_peer
        .ping("203.0.113.2")
        .expect("no tentative peer route"));

    let session = https_login_admin(&guest, "alice", "secret12");
    let accepted_before: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted_before["revision"], 2);
    let proposal = serde_json::json!({
        "base_revision": 2,
        "routes": [
            {"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic},
            {"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic},
            // The WAN subnet's directed-broadcast address is syntactically
            // on-link, but Linux rejects it as a route next hop at runtime.
            {"to": "203.0.114.0/24", "via": "192.0.2.255", "dev": wan_nic}
        ]
    });
    let (code, body) = session
        .exchange("POST", "/api/routes/apply", Some(&proposal.to_string()), 90)
        .expect("authenticated apply reports its outcome");
    assert_eq!(
        code, 502,
        "runtime apply must fail after validation: {body}"
    );
    let outcome: serde_json::Value = serde_json::from_str(&body).expect("apply outcome JSON");
    assert_eq!(
        outcome["outcome"], "failed",
        "not a validation rejection: {body}"
    );
    assert_eq!(
        outcome["restoration"], "restored",
        "operator-visible recovery: {body}"
    );
    assert_eq!(outcome["revision"], 2, "Accepted revision remains current");
    assert!(lan_peer
        .ping("198.51.100.2")
        .expect("prior traffic after recovery"));
    assert!(!lan_peer
        .ping("203.0.113.2")
        .expect("tentative traffic after recovery"));
    let accepted_after: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted_after["revision"], accepted_before["revision"]);
    assert_eq!(accepted_after["routes"], accepted_before["routes"]);
    let status: serde_json::Value =
        serde_json::from_str(&session.get("/api/status").unwrap()).unwrap();
    assert_eq!(
        status["bootstrapped"], true,
        "recovery never reopens Bootstrap"
    );
    let fresh = https_login_admin(&guest, "alice", "secret12");
    assert!(
        fresh.get("/api/routes").is_ok(),
        "current Identity still authenticates"
    );

    let draft_change = serde_json::json!({
        "base_revision": 2,
        "routes": proposal["routes"]
    });
    let (draft_code, draft_body) = session
        .exchange(
            "POST",
            "/api/draft/save",
            Some(&draft_change.to_string()),
            15,
        )
        .expect("save a private reviewable failed-apply draft");
    assert_eq!(draft_code, 200, "save failed-apply draft: {draft_body}");
    guest
        .browser_static_route_action(
            "apply-failed-draft",
            "alice",
            "secret12",
            "",
            "203.0.114.0/24",
            "",
            wan_nic,
        )
        .expect("rendered UI reports previous Accepted network restored");
    let retained: serde_json::Value =
        serde_json::from_str(&session.get("/api/draft").unwrap()).unwrap();
    assert_eq!(retained["status"], "pending", "failed draft stays private");

    // A complete-state caller can change more than routes. Add a WAN alias,
    // then induce a later WireGuard runtime failure by targeting the real WAN
    // NIC as though it were a WireGuard link. Recovery must remove the alias.
    serial_login_admin(&guest, "alice", "secret12");
    let invalid_runtime = serde_json::json!({
        "revision": 2,
        "hostname": "fwos-box",
        "interfaces": [
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": ui_nic, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24", "192.0.2.3/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.56.0.0/24", "dhcp_pool": "10.56.0.100-10.56.0.129",
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic}],
        "wireguard": [{"name": wan_nic, "private_key": WG_PRIVATE, "addresses": ["10.13.13.1/24"]}]
    });
    let failed = serial_cmd(&guest, &format!("apply {invalid_runtime}\n"), 90, |text| {
        text.contains("\"restoration\"") || text.contains("\"outcome\"")
    });
    assert!(
        failed.contains("\"outcome\":\"failed\"") || failed.contains("\"outcome\": \"failed\""),
        "complete-state apply must fail at runtime: {failed}"
    );
    assert!(
        failed.contains("\"restoration\":\"restored\"")
            || failed.contains("\"restoration\": \"restored\""),
        "complete-state apply must report restoration: {failed}"
    );
    wan_peer
        .ping("192.0.2.3")
        .expect("probe tentative WAN alias");
    assert!(
        !wan_peer
            .neighbor_resolved("192.0.2.3")
            .expect("observe WAN alias externally"),
        "failed complete-state apply left a tentative address active: {failed}"
    );
    assert!(lan_peer
        .ping("198.51.100.2")
        .expect("Accepted traffic after WAN alias recovery"));
    assert!(
        lan_peer
            .dhcp_offer()
            .expect("DHCP after failed enablement")
            .is_none(),
        "tentative Kea config must not launch a DHCP service"
    );

    let mut enable_dhcp = invalid_runtime.clone();
    enable_dhcp["interfaces"][2]["addresses"] = serde_json::json!(["192.0.2.1/24"]);
    enable_dhcp["wireguard"] = serde_json::json!([]);
    let accepted = serial_cmd(&guest, &format!("apply {enable_dhcp}\n"), 90, |text| {
        text.contains("\"outcome\":\"accepted\"") || text.contains("\"outcome\": \"accepted\"")
    });
    assert!(
        accepted.contains("\"outcome\":\"accepted\"")
            || accepted.contains("\"outcome\": \"accepted\""),
        "accepted DHCP enablement: {accepted}"
    );
    let offer_a = wait_dhcp_offer(&lan_peer);
    assert!(
        (100..=129).contains(&offer_octet(&offer_a)),
        "pool A offer: {offer_a}"
    );

    let mut edit_dhcp = enable_dhcp.clone();
    edit_dhcp["revision"] = serde_json::json!(3);
    edit_dhcp["dhcp_pool"] = serde_json::json!("10.56.0.170-10.56.0.199");
    let edited = serial_cmd(&guest, &format!("apply {edit_dhcp}\n"), 90, |text| {
        text.contains("\"outcome\":\"accepted\"") || text.contains("\"outcome\": \"accepted\"")
    });
    assert!(
        edited.contains("\"outcome\":\"accepted\"") || edited.contains("\"outcome\": \"accepted\""),
        "accepted DHCP pool edit: {edited}"
    );
    let offer_b = lan_peer
        .dhcp_offer()
        .expect("DHCP immediately after accepted B")
        .expect("Host acknowledgement must follow working DHCP service B");
    assert!(
        (170..=199).contains(&offer_octet(&offer_b)),
        "pool B offer after accepted edit: {offer_b}"
    );

    // Empty pool currently passes preflight but Kea rejects its generated
    // config. Host activation must fail before netd can accept this revision,
    // and both the former service process and Accepted B must be restored.
    let mut invalid_host_config = edit_dhcp.clone();
    invalid_host_config["revision"] = serde_json::json!(4);
    invalid_host_config["dhcp_pool"] = serde_json::json!("");
    let host_failure = serial_cmd(
        &guest,
        &format!("apply {invalid_host_config}\n"),
        90,
        |text| text.contains("\"restoration\"") || text.contains("\"outcome\""),
    );
    assert!(
        host_failure.contains("\"restoration\":\"restored\"")
            || host_failure.contains("\"restoration\": \"restored\""),
        "Host activation failure must restore B: {host_failure}"
    );
    let offer_after_host_failure = wait_dhcp_offer(&lan_peer);
    assert!(
        (170..=199).contains(&offer_octet(&offer_after_host_failure)),
        "pool B offer after rejected Kea config: {offer_after_host_failure}"
    );

    let mut failed_pool = edit_dhcp.clone();
    failed_pool["revision"] = serde_json::json!(4);
    failed_pool["dhcp_pool"] = serde_json::json!("10.56.0.130-10.56.0.159");
    failed_pool["wireguard"] = invalid_runtime["wireguard"].clone();
    let failed = serial_cmd(&guest, &format!("apply {failed_pool}\n"), 90, |text| {
        text.contains("\"restoration\"") || text.contains("\"outcome\"")
    });
    assert!(
        failed.contains("\"restoration\":\"restored\"")
            || failed.contains("\"restoration\": \"restored\""),
        "failed DHCP pool edit must restore B: {failed}"
    );
    let offer_after_failure = wait_dhcp_offer(&lan_peer);
    assert!(
        (170..=199).contains(&offer_octet(&offer_after_failure)),
        "pool B offer after failed C edit: {offer_after_failure}"
    );

    let reboot_from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("appliance console reboot");
    let rebooted = serial_wait(&guest, reboot_from, 300, |text| {
        text.contains("FWOS Appliance CLI")
    });
    assert!(
        rebooted.contains("FWOS Appliance CLI") && !rebooted.contains("FWOS Bootstrap console"),
        "Accepted B must boot as an owned appliance: {rebooted}"
    );
    let session = https_login_admin(&guest, "alice", "secret12");
    let after_reboot: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(after_reboot["revision"], 4, "Accepted B survives reboot");
    let reboot_offer = wait_dhcp_offer(&lan_peer);
    assert!(
        (170..=199).contains(&offer_octet(&reboot_offer)),
        "Host worker must reactivate Accepted B after reboot: {reboot_offer}"
    );
    serial_login_admin_from(&guest, "alice", "secret12", reboot_from);

    let mut disable_dhcp = edit_dhcp.clone();
    disable_dhcp["revision"] = serde_json::json!(4);
    disable_dhcp["lan_prefix"] = serde_json::Value::Null;
    disable_dhcp["dhcp_pool"] = serde_json::Value::Null;
    let disabled = serial_cmd(&guest, &format!("apply {disable_dhcp}\n"), 90, |text| {
        text.contains("\"outcome\":\"accepted\"") || text.contains("\"outcome\": \"accepted\"")
    });
    assert!(
        disabled.contains("\"outcome\":\"accepted\"")
            || disabled.contains("\"outcome\": \"accepted\""),
        "accepted DHCP disablement: {disabled}"
    );
    assert!(
        lan_peer
            .dhcp_offer()
            .expect("DHCP after accepted disablement")
            .is_none(),
        "accepted removal must stop the former DHCP service"
    );
}

#[test]
fn saved_private_draft_does_not_activate_or_change_accepted_desired() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    lan_peer
        .add_route("198.51.100.0/24", "10.56.0.1")
        .expect("peer route through appliance");
    wan_peer.add_address("192.0.2.2/24").expect("WAN next hop");
    wan_peer
        .add_address("198.51.100.2/24")
        .expect("destination behind WAN next hop");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peers.len(), 2);
    let (lan_nic, wan_nic) = (&peers[0], &peers[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.0.2.0/24", "dhcp_pool": "10.0.2.100-10.0.2.200"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    assert!(!lan_peer
        .ping("198.51.100.2")
        .expect("peer probe before draft"));
    guest
        .browser_static_route_action(
            "save",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("rendered administrator saves a draft");
    let session = https_login_admin(&guest, "alice", "secret12");
    let accepted: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 1);
    assert_eq!(accepted["routes"], serde_json::json!([]));
    assert!(!lan_peer
        .ping("198.51.100.2")
        .expect("peer probe after draft"));
    let draft: serde_json::Value =
        serde_json::from_str(&session.get("/api/draft").unwrap()).unwrap();
    assert_eq!(draft["status"], "pending");
    assert_eq!(draft["base_revision"], 1);
    assert_eq!(draft["routes"][0]["to"], "198.51.100.0/24");
    assert!(!session.get("/api/draft").unwrap().contains("private_key"));
    let (logout_status, _) = session
        .exchange("POST", "/api/logout", Some("{}"), 15)
        .expect("explicit logout");
    assert_eq!(logout_status, 200);
    let fresh_session = https_login_admin(&guest, "alice", "secret12");
    let after_logout: serde_json::Value =
        serde_json::from_str(&fresh_session.get("/api/draft").unwrap()).unwrap();
    assert_eq!(after_logout["version"], draft["version"]);
    assert_eq!(after_logout["routes"], draft["routes"]);
    assert!(!lan_peer
        .ping("198.51.100.2")
        .expect("peer probe after logout"));
}

#[test]
fn identical_network_change_by_another_administrator_does_not_accept_private_draft() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Alice creates Bob through the rendered UI");
    guest
        .browser_static_route_action(
            "save",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice saves a private route draft");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let before: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(before["status"], "pending");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let apply = serde_json::json!({
        "base_revision": 1,
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic}],
    });
    let (code, body) = bob
        .exchange("POST", "/api/routes/apply", Some(&apply.to_string()), 120)
        .unwrap();
    assert_eq!(code, 200);
    let result: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(result["outcome"], "accepted");
    assert_eq!(result["revision"], 2);
    let after: serde_json::Value = serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(
        after["status"], "pending",
        "Bob did not apply Alice's draft"
    );
    assert_eq!(after["base_revision"], 1);
    assert_eq!(after["accepted_revision"], 2);
    assert_eq!(after["stale"], true);
    assert_eq!(after["version"], before["version"]);
}

#[test]
fn confirmed_private_draft_cleans_up_after_another_unrelated_accepted_apply() {
    let _guard = guest_lock();
    let (guest, _lan_peer, _wan_peer, wan_nic) = boot_apply_confirmation_route_guest();
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("Alice creates Bob through the rendered UI");
    guest
        .browser_apply_confirmation_action("enable", "alice", "secret12")
        .expect("Apply confirmation is enabled in Accepted revision 2");
    guest
        .browser_static_route_action(
            "save",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "192.0.2.2",
            &wan_nic,
        )
        .expect("Alice saves a private route draft");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let saved: serde_json::Value = serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(saved["status"], "pending");
    guest
        .browser_static_route_action(
            "apply-draft-pending",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "",
            &wan_nic,
        )
        .expect("Alice reviews and applies the private draft");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let first_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(first_pending["pending"]["revision"], 3);
    let first_confirmation = serde_json::json!({
        "revision": 3,
        "confirmation_id": first_pending["pending"]["confirmation_id"],
    });
    let (first_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&first_confirmation.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(first_status, 200);
    let later = serde_json::json!({
        "base_revision": 3,
        "routes": [
            {"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic},
            {"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic},
        ],
    });
    let (later_status, later_body) = bob
        .exchange("POST", "/api/routes/apply", Some(&later.to_string()), 120)
        .unwrap();
    assert_eq!(later_status, 200);
    let later_reply: serde_json::Value = serde_json::from_str(&later_body).unwrap();
    assert_eq!(later_reply["outcome"], "pending_confirmation");
    assert_eq!(later_reply["revision"], 4);
    let later_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    let later_confirmation = serde_json::json!({
        "revision": 4,
        "confirmation_id": later_pending["pending"]["confirmation_id"],
    });
    let (confirm_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&later_confirmation.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(confirm_status, 200);
    let accepted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 4);
    assert_eq!(accepted["routes"][1]["to"], "203.0.113.0/24");
    let (disable_status, disable_body) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/configure",
            Some(r#"{"base_revision":4,"enabled":false}"#),
            120,
        )
        .unwrap();
    assert_eq!(disable_status, 200);
    let disabling: serde_json::Value = serde_json::from_str(&disable_body).unwrap();
    assert_eq!(disabling["outcome"], "pending_confirmation");
    let setting_pending: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    let setting_confirmation = serde_json::json!({
        "revision": 5,
        "confirmation_id": setting_pending["pending"]["confirmation_id"],
    });
    let (setting_status, _) = bob
        .exchange(
            "POST",
            "/api/apply-confirmation/confirm",
            Some(&setting_confirmation.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(setting_status, 200);
    let immediate = serde_json::json!({
        "base_revision": 5,
        "routes": [
            {"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic},
            {"to": "203.0.113.0/24", "via": "192.0.2.2", "dev": wan_nic},
            {"to": "203.0.114.0/24", "via": "192.0.2.2", "dev": wan_nic},
        ],
    });
    let (immediate_status, immediate_body) = bob
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(&immediate.to_string()),
            120,
        )
        .unwrap();
    assert_eq!(immediate_status, 200);
    let immediate_reply: serde_json::Value = serde_json::from_str(&immediate_body).unwrap();
    assert_eq!(immediate_reply["outcome"], "accepted");
    assert_eq!(immediate_reply["revision"], 6);
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("external restart before the draft owner checks her accepted proposal");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.lines().any(|line| line.trim() == "admin:"),
        "owned appliance must return to the authenticated console: {rebooted}"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let after: serde_json::Value = serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_eq!(
        after["status"], "none",
        "Alice's accepted draft must not reappear after Bob's later Apply"
    );
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let status: serde_json::Value =
        serde_json::from_str(&bob.get("/api/apply-confirmation").unwrap()).unwrap();
    assert!(status["last_accepted"].get("draft_receipts").is_none());
    assert!(status["last_accepted"].get("draft_version").is_none());
}

#[test]
fn two_administrators_reconcile_private_drafts_after_accepted_revision_changes() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image boots without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("first administrator creates a second administrator");
    for (username, password, destination) in [
        ("alice", "secret12", "198.51.100.0/24"),
        ("bob", "bob-secret", "203.0.113.0/24"),
    ] {
        guest
            .browser_static_route_action(
                "save",
                username,
                password,
                "",
                destination,
                "192.0.2.2",
                &wan_nic,
            )
            .expect("each administrator saves a private route draft");
    }
    let alice = https_login_admin(&guest, "alice", "secret12");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let alice_draft: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    let bob_draft: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(alice_draft["routes"][0]["to"], "198.51.100.0/24");
    assert_eq!(bob_draft["routes"][0]["to"], "203.0.113.0/24");
    assert!(!bob.get("/api/draft").unwrap().contains("198.51.100.0/24"));
    let owner_hint: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft?owner=alice").unwrap()).unwrap();
    assert_eq!(owner_hint["routes"][0]["to"], "203.0.113.0/24");
    let stolen_reference = serde_json::json!({
        "base_revision": 1, "version": alice_draft["version"]
    });
    let (stolen_code, _) = bob
        .exchange(
            "POST",
            "/api/draft/apply",
            Some(&stolen_reference.to_string()),
            15,
        )
        .expect("Bob cannot apply Alice's draft using her version");
    assert_eq!(stolen_code, 409);
    let refreshed_alice = serde_json::json!({
        "base_revision": 1,
        "version": alice_draft["version"],
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan_nic}]
    });
    let (refresh_code, _) = alice
        .exchange(
            "POST",
            "/api/draft/save",
            Some(&refreshed_alice.to_string()),
            15,
        )
        .expect("Alice saves a newer version of her own draft");
    assert_eq!(refresh_code, 200);
    let old_tab_save = serde_json::json!({
        "base_revision": 1,
        "version": alice_draft["version"],
        "routes": [{"to": "198.51.101.0/24", "via": "192.0.2.2", "dev": wan_nic}]
    });
    let (old_tab_save_code, _) = alice
        .exchange(
            "POST",
            "/api/draft/save",
            Some(&old_tab_save.to_string()),
            15,
        )
        .expect("old tab save response");
    assert_eq!(
        old_tab_save_code, 409,
        "old tab cannot overwrite newer draft"
    );
    let (old_tab_code, _) = alice
        .exchange(
            "POST",
            "/api/draft/apply",
            Some(&stolen_reference.to_string()),
            15,
        )
        .expect("stale tab apply response");
    assert_eq!(
        old_tab_code, 409,
        "old review cannot apply a newer private draft"
    );
    let current_alice: serde_json::Value =
        serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
    assert_ne!(current_alice["version"], alice_draft["version"]);
    assert_eq!(current_alice["routes"][0]["to"], "198.51.100.0/24");
    let accepted: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 1);
    assert_eq!(accepted["routes"], serde_json::json!([]));
    let (quick_code, _) = bob
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(r#"{"base_revision":1,"routes":[]}"#),
            15,
        )
        .expect("pending work restricts quick apply");
    assert_eq!(
        quick_code, 409,
        "Bob's quick apply must not bundle his draft"
    );

    guest
        .browser_static_route_action(
            "apply-draft",
            "alice",
            "secret12",
            "",
            "198.51.100.0/24",
            "",
            &wan_nic,
        )
        .expect("Alice reviews and applies only her own draft");
    let accepted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 2);
    assert_eq!(accepted["routes"][0]["to"], "198.51.100.0/24");
    guest
        .browser_static_route_action(
            "apply-stale-draft",
            "bob",
            "bob-secret",
            "",
            "203.0.113.0/24",
            "",
            &wan_nic,
        )
        .expect("Bob's stale apply is rejected after explicit review");
    let retained: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(retained["base_revision"], 1);
    assert_eq!(retained["accepted_revision"], 2);
    assert_eq!(retained["stale"], true);
    assert_eq!(retained["routes"][0]["to"], "203.0.113.0/24");
    assert_eq!(retained["version"], bob_draft["version"]);

    serial_login_admin(&guest, "alice", "secret12");
    let reboot_from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("Appliance console reboot");
    let rebooted = serial_wait(&guest, reboot_from, 300, |text| {
        text.contains("FWOS Appliance CLI")
    });
    assert!(rebooted.contains("FWOS Appliance CLI"));
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let after_reboot: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(after_reboot["revision"], 2);
    assert_eq!(after_reboot["routes"][0]["to"], "198.51.100.0/24");
    let persisted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(persisted["base_revision"], 1);
    assert_eq!(persisted["routes"][0]["to"], "203.0.113.0/24");
    assert_eq!(persisted["version"], retained["version"]);

    guest
        .browser_static_route_action(
            "reconcile-draft",
            "bob",
            "bob-secret",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "",
            &wan_nic,
        )
        .expect("Bob explicitly reviews reconciliation against new Accepted state");
    let reconciled: serde_json::Value =
        serde_json::from_str(&bob.get("/api/draft").unwrap()).unwrap();
    assert_eq!(reconciled["base_revision"], 2);
    assert_eq!(reconciled["routes"][0]["to"], "203.0.113.0/24");
    assert_ne!(reconciled["version"], persisted["version"]);
    let not_yet_applied: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(not_yet_applied["revision"], 2);
    assert_eq!(not_yet_applied["routes"][0]["to"], "198.51.100.0/24");
    guest
        .browser_static_route_action(
            "apply-draft",
            "bob",
            "bob-secret",
            "",
            "203.0.113.0/24",
            "",
            &wan_nic,
        )
        .expect("Bob reviews the reconciled draft and applies it");
    let accepted: serde_json::Value =
        serde_json::from_str(&bob.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 3);
    assert_eq!(accepted["routes"][0]["to"], "203.0.113.0/24");
}

#[test]
fn published_graphical_static_route_changes_external_peer_forwarding() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    lan_peer
        .add_route("198.51.100.0/24", "10.56.0.1")
        .expect("LAN test route");
    lan_peer
        .add_route("203.0.113.0/24", "10.56.0.1")
        .expect("second LAN test route");
    wan_peer.add_address("192.0.2.2/24").expect("WAN next hop");
    wan_peer
        .add_address("198.51.100.2/24")
        .expect("destination behind WAN next hop");
    wan_peer
        .add_address("203.0.113.2/24")
        .expect("replacement destination behind WAN next hop");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peers.len(), 2);
    let (lan_nic, wan_nic) = (&peers[0], &peers[1]);
    let payload = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.0.2.0/24", "dhcp_pool": "10.0.2.100-10.0.2.200"
    });
    https_bootstrap(&guest, &payload.to_string());
    let initial_session = https_login_admin(&guest, "alice", "secret12");
    let initial_status: serde_json::Value =
        serde_json::from_str(&initial_session.get("/api/status").unwrap()).unwrap();
    assert!(!lan_peer
        .ping("198.51.100.2")
        .expect("peer probe before route"));
    guest
        .browser_add_static_route("alice", "secret12", "198.51.100.0/24", "192.0.2.2", wan_nic)
        .expect("graphical review and apply of forwarding route");
    assert!(lan_peer
        .ping("198.51.100.2")
        .expect("peer probe after route"));
    assert!(!lan_peer
        .ping("203.0.113.2")
        .expect("peer probe before replacement route"));

    guest
        .browser_static_route_action(
            "change",
            "alice",
            "secret12",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "192.0.2.2",
            wan_nic,
        )
        .expect("graphical review and apply of replacement route");
    assert!(!lan_peer
        .ping("198.51.100.2")
        .expect("old route removed after change"));
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("new route forwards after change"));
    let session = https_login_admin(&guest, "alice", "secret12");
    let accepted: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(accepted["revision"], 3);
    assert_eq!(accepted["routes"][0]["to"], "203.0.113.0/24");
    let after_route_status: serde_json::Value =
        serde_json::from_str(&session.get("/api/status").unwrap()).unwrap();
    for field in [
        "hostname",
        "lan_prefix",
        "dhcp_pool",
        "ui_exposure",
        "interfaces",
    ] {
        assert_eq!(
            after_route_status[field], initial_status[field],
            "route editor preserves {field}"
        );
    }

    serial_login_admin(&guest, "alice", "secret12");
    let malformed = serial_cmd(
        &guest,
        "apply {\"interfaces\":[],\"ui_exposure\":[],\"routes\":[]}\n",
        20,
        |text| text.contains("rejected"),
    );
    assert!(
        malformed.contains("rejected"),
        "malformed complete Desired state must be rejected: {malformed}"
    );
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("legacy rejected apply leaves forwarding intact"));
    let reboot_from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("normal Appliance console reboot");
    let rebooted = serial_wait(&guest, reboot_from, 300, |text| {
        text.contains("FWOS Appliance CLI")
    });
    assert!(
        rebooted.contains("FWOS Appliance CLI"),
        "Accepted Desired state reboot: {rebooted}"
    );
    let session = https_login_admin(&guest, "alice", "secret12");
    let after_reboot: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(
        after_reboot["revision"], 3,
        "Accepted revision survives reboot"
    );
    assert_eq!(after_reboot["routes"][0]["to"], "203.0.113.0/24");
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("Accepted route forwards after reboot"));

    guest
        .browser_static_route_action(
            "reject",
            "alice",
            "secret12",
            "",
            "not-a-cidr",
            "192.0.2.2",
            wan_nic,
        )
        .expect("graphical invalid-route review receives rejection");
    let after_rejection: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(
        after_rejection["revision"], 3,
        "invalid route does not advance Accepted revision"
    );
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("accepted route still forwards after rejection"));

    let (stale_code, stale_body) = session
        .exchange(
            "POST",
            "/api/routes/apply",
            Some(r#"{"base_revision":1,"routes":[]}"#),
            15,
        )
        .expect("stale route apply response");
    assert_eq!(stale_code, 409, "stale base must be rejected: {stale_body}");
    assert!(lan_peer
        .ping("203.0.113.2")
        .expect("stale apply leaves forwarding intact"));

    guest
        .browser_static_route_action(
            "remove",
            "alice",
            "secret12",
            "203.0.113.0/24",
            "",
            "192.0.2.2",
            wan_nic,
        )
        .expect("graphical review and apply of route removal");
    assert!(!lan_peer
        .ping("203.0.113.2")
        .expect("peer probe after route removal"));
    let removed: serde_json::Value =
        serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    assert_eq!(removed["revision"], 4);
    assert_eq!(removed["routes"], serde_json::json!([]));
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
        text.contains("FWOS Appliance CLI") && text.lines().any(|line| line.trim() == "admin:")
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
fn published_administrator_creates_distinct_local_login_in_rendered_ui() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    let alice = https_login_admin(&guest, "alice", "secret12");
    let initial_status: serde_json::Value =
        serde_json::from_str(&alice.get("/api/status").expect("initial network status"))
            .expect("status JSON");

    let (anonymous_code, _) = guest
        .https_exchange("GET", "/api/administrators", None, 15)
        .expect("anonymous account-list response");
    assert_eq!(anonymous_code, 401, "account list requires sign in");
    let (anonymous_change, _) = guest
        .https_exchange(
            "POST",
            "/api/administrators",
            Some(r#"{"username":"mallory","password":"nope"}"#),
            15,
        )
        .expect("anonymous account-create response");
    assert_eq!(anonymous_change, 401, "account creation requires sign in");

    guest
        .browser_create_administrator("alice", "secret12", "bob", "bob-secret")
        .expect("rendered UI creates a distinct administrator");
    let bob = https_login_admin(&guest, "bob", "bob-secret");
    let status = bob
        .get("/api/status")
        .expect("new administrator has management access");
    assert_eq!(
        json_string_field(&status, "username").as_deref(),
        Some("bob")
    );
    assert!(
        status.contains("192.168.1.0/24"),
        "administrator can see management status"
    );

    guest
        .browser_change_administrator_password("alice", "secret12", "bob", "new-bob-secret")
        .expect("rendered UI changes another administrator's password");
    let (stale_code, _) = bob
        .exchange("GET", "/api/status", None, 15)
        .expect("prior session response after password change");
    assert_eq!(
        stale_code, 401,
        "changing credentials revokes the prior session"
    );
    let (old_code, _) = guest
        .https_exchange(
            "POST",
            "/api/login",
            Some(r#"{"source":"local","username":"bob","password":"bob-secret"}"#),
            15,
        )
        .expect("obsolete-password login response");
    assert_eq!(old_code, 401, "obsolete password must fail");
    let changed = https_login_admin(&guest, "bob", "new-bob-secret");
    assert!(
        changed.get("/api/status").is_ok(),
        "replacement password must authenticate"
    );

    guest
        .browser_remove_administrator("bob", "new-bob-secret", "alice")
        .expect("a second administrator can remove the Bootstrap administrator");
    let (removed_session_code, _) = alice
        .exchange("GET", "/api/status", None, 15)
        .expect("removed administrator's prior session response");
    assert_eq!(
        removed_session_code, 401,
        "removal revokes existing sessions"
    );
    let (removed_login_code, _) = guest
        .https_exchange(
            "POST",
            "/api/login",
            Some(r#"{"source":"local","username":"alice","password":"secret12"}"#),
            15,
        )
        .expect("removed administrator login response");
    assert_eq!(
        removed_login_code, 401,
        "removed administrator cannot sign in"
    );
    let final_status = changed
        .get("/api/status")
        .expect("remaining administrator retains access");
    let final_status_json: serde_json::Value =
        serde_json::from_str(&final_status).expect("status JSON");
    for field in [
        "interfaces",
        "ui_exposure",
        "lan_prefix",
        "dhcp_pool",
        "wan_pd",
    ] {
        assert_eq!(
            initial_status[field], final_status_json[field],
            "account changes must not change public network {field}"
        );
    }
    let account_list = changed
        .get("/api/administrators")
        .expect("remaining administrator lists accounts");
    let account_list_json: serde_json::Value =
        serde_json::from_str(&account_list).expect("account-list JSON");
    assert_eq!(
        account_list_json["administrators"],
        serde_json::json!(["bob"])
    );
    for ordinary_response in [&final_status, &account_list] {
        assert!(
            !ordinary_response.contains("$y$")
                && !ordinary_response.contains("password_hash")
                && !ordinary_response.contains("new-bob-secret")
                && !ordinary_response.contains("secret12"),
            "routine responses must never disclose a password or hash"
        );
    }
    let (last_code, _) = changed
        .exchange(
            "POST",
            "/api/administrators/remove",
            Some(r#"{"username":"bob"}"#),
            15,
        )
        .expect("last-administrator removal response");
    assert_eq!(last_code, 409, "final administrator must not be removable");
    assert!(
        changed.get("/api/status").is_ok(),
        "rejected removal leaves administrator access intact"
    );

    let admin_ready = serial_wait(&guest, 0, 90, |text| {
        text.contains("FWOS Appliance CLI") && text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        admin_ready.contains("FWOS Appliance CLI"),
        "Appliance console must offer administrator login"
    );
    let password_prompt = serial_cmd(&guest, "alice\n", 15, |text| text.contains("password:"));
    assert!(
        password_prompt.contains("password:"),
        "removed administrator attempt reaches password prompt"
    );
    let before_denial = guest.serial().len();
    guest
        .serial_write("secret12\n")
        .expect("submit removed administrator's prior password");
    let denied = serial_wait(&guest, before_denial, 15, |text| {
        text.contains("login failed")
    });
    assert!(
        denied.contains("login failed"),
        "removed account must fail Appliance console login"
    );
    serial_login_admin(&guest, "bob", "new-bob-secret");
    assert!(
        !guest.serial().contains("new-bob-secret"),
        "Appliance console must not echo the changed password"
    );
    guest
        .browser_login("bob", "new-bob-secret")
        .expect("remaining administrator's replacement password signs in through rendered UI");
}

#[test]
fn published_administrator_changing_own_password_returns_to_sign_in() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (lan_nic, wan_nic) = published_user_net_and_extra(&guest);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan_nic, &wan_nic));
    let old_session = https_login_admin(&guest, "alice", "secret12");

    guest
        .browser_change_own_administrator_password("alice", "secret12", "alice-new-secret")
        .expect("changing one's own password immediately shows rendered sign-in");
    let (old_cookie_code, _) = old_session
        .exchange("GET", "/api/status", None, 15)
        .expect("old session response after self password change");
    assert_eq!(old_cookie_code, 401, "old session must be revoked");
    let (old_password_code, _) = guest
        .https_exchange(
            "POST",
            "/api/login",
            Some(r#"{"source":"local","username":"alice","password":"secret12"}"#),
            15,
        )
        .expect("old-password login response");
    assert_eq!(old_password_code, 401, "old password must be rejected");
    let current = https_login_admin(&guest, "alice", "alice-new-secret");
    assert!(
        current.get("/api/status").is_ok(),
        "replacement password must sign in"
    );
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

    // 505 ASCII bytes + two-byte Unicode character + four surrounding spaces.
    let password = format!("  {}é  ", "x".repeat(505));
    payload["password"] = password.as_str().into();
    https_bootstrap(&guest, &payload.to_string());
    let session = https_login_admin(&guest, "alice", &password);
    let status = session
        .get("/api/status")
        .expect("HTTPS must accept a 511-byte password including Unicode and surrounding spaces");
    assert_eq!(
        json_string_field(&status, "username").as_deref(),
        Some("alice")
    );
    let trimmed = serde_json::json!({
        "source": "local", "username": "alice", "password": password.trim()
    });
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&trimmed.to_string()), 15)
        .expect("HTTPS must respond to a password with its surrounding spaces removed");
    assert_eq!(
        code, 401,
        "password spaces must remain part of the credential"
    );
    serial_login_admin(&guest, "alice", &password);
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

    // The UI Host update flow is covered by
    // published_ui_stages_host_update_keeps_forwarding_and_reboots_offline;
    // this legacy serial adapter stays callable until its retirement.
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

    let help = serial_cmd(&guest, "help\n", 10, |t| t.contains("logout"));
    assert!(
        help.contains("status")
            && help.contains("restore-previous")
            && help.contains("reboot")
            && help.contains("rollback-image")
            && !help.lines().any(|l| l.trim() == "rollback")
            && !help.contains("apply <"),
        "v1 recovery help must stay limited while legacy commands remain callable, serial:\n{help}"
    );
    // The old full-CLI adapter stays callable until its separate retirement.
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

fn host_update_status(guest: &Guest) -> serde_json::Value {
    host_update_status_as(guest, "secret12")
}

fn host_update_status_as(guest: &Guest, password: &str) -> serde_json::Value {
    let session = https_login_admin(guest, "alice", password);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let (_, body) = session
            .exchange("GET", "/api/host-update", None, 30)
            .expect("authenticated Host update status");
        let status: serde_json::Value = serde_json::from_str(&body).expect("Host update status JSON");
        if status["ok"] == true || std::time::Instant::now() >= deadline {
            assert_eq!(status["ok"], true, "Host update status: {status}");
            return status;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Forwarded probes sent while a Host update stage ran.
struct StagingProbes {
    sent: u32,
    lost: u32,
    longest_gap: u32,
}

impl StagingProbes {
    /// Staging must not stop forwarding. A single lost 2s probe while the
    /// guest decompresses layers is load, not an outage; a run of them is not.
    fn assert_forwarding_continued(&self, when: &str) {
        eprintln!(
            "{when}: {} of {} forwarded probes lost, longest gap {}",
            self.lost, self.sent, self.longest_gap
        );
        assert!(
            self.sent > 0 && self.longest_gap <= 1 && self.lost * 20 <= self.sent,
            "{when}: forwarding stopped ({} of {} probes lost, longest gap {})",
            self.lost,
            self.sent,
            self.longest_gap
        );
    }
}

/// Poll Host update status until staging ends, pinging through the appliance
/// about once a second.
fn wait_staging_done(
    guest: &Guest,
    peer: &NetworkPeer,
    target: &str,
) -> (serde_json::Value, StagingProbes) {
    let session = https_login_admin(guest, "alice", "secret12");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1200);
    let mut probes = StagingProbes {
        sent: 0,
        lost: 0,
        longest_gap: 0,
    };
    let mut gap = 0;
    loop {
        probes.sent += 1;
        if peer.ping(target).expect("forwarded peer probe during staging") {
            gap = 0;
        } else {
            probes.lost += 1;
            gap += 1;
            probes.longest_gap = probes.longest_gap.max(gap);
        }
        let (_, body) = session
            .exchange("GET", "/api/host-update", None, 30)
            .expect("Host update status during staging");
        let status: serde_json::Value = serde_json::from_str(&body).expect("Host update status JSON");
        if status["ok"] == true && status["operation"]["state"] != "staging" {
            return (status, probes);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Host update staging did not finish: {status}"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn wait_ui_reboot(guest: &Guest, from: usize) {
    let rebooted = serial_wait(guest, from, 600, |text| text.contains("FWOS Appliance CLI"));
    assert!(
        rebooted.contains("FWOS Appliance CLI") && !rebooted.contains("FWOS Bootstrap console"),
        "UI reboot must restart the owned appliance: {rebooted}"
    );
}

#[test]
fn published_ui_stages_host_update_keeps_forwarding_and_reboots_offline() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_next_release()
        .expect("Workstation-local registry must serve a newer Release");
    let image = registry.guest_image();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    lan_peer
        .add_route("192.0.2.0/24", "10.56.0.1")
        .expect("LAN peer route to the WAN");
    wan_peer.add_address("192.0.2.2/24").expect("WAN peer address");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);

    // No administrator exists yet: the UI offers no Host update to anyone.
    for (method, path) in [
        ("GET", "/api/host-update"),
        ("POST", "/api/host-update/stage"),
        ("POST", "/api/host-update/reboot"),
    ] {
        let body = (method == "POST").then(|| format!(r#"{{"image":"{image}"}}"#));
        let (code, reply) = guest
            .https_exchange(method, path, body.as_deref(), 15)
            .expect("pre-Bootstrap Host update request");
        assert_eq!(code, 401, "{method} {path} before Bootstrap: {reply}");
    }

    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peers.len(), 2);
    let (lan_nic, wan_nic) = (&peers[0], &peers[1]);
    let payload = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": ui_nic, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.0.2.0/24", "dhcp_pool": "10.0.2.100-10.0.2.200"
    });
    https_bootstrap(&guest, &payload.to_string());
    assert!(lan_peer
        .ping("192.0.2.2")
        .expect("forwarded probe after Bootstrap"));
    let session = https_login_admin(&guest, "alice", "secret12");
    let revision = accepted_revision(&session);
    let initial = host_update_status(&guest);
    let previous = initial["booted"].as_str().unwrap_or_default().to_string();
    assert!(!previous.is_empty(), "active Release is reported: {initial}");
    assert!(!previous.contains("fwos:next"), "{initial}");
    assert_eq!(initial["staged"], "", "{initial}");
    assert_eq!(initial["reboot_required"], false, "{initial}");
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered Host update status");
    assert!(
        rendered["status"].as_str().unwrap().contains(&previous)
            && rendered["status"].as_str().unwrap().contains("No Release is staged"),
        "{rendered}"
    );

    // Stage the Release while peers keep forwarding through the appliance.
    let from = guest.serial().len();
    let started = guest
        .browser_host_update("stage", "alice", "secret12", &image)
        .expect("rendered stage request");
    assert!(
        started["result"].as_str().unwrap().contains("started"),
        "{started}"
    );
    let (staged, probes) = wait_staging_done(&guest, &lan_peer, "192.0.2.2");
    probes.assert_forwarding_continued("staging");
    assert_eq!(staged["operation"]["state"], "idle", "{staged}");
    assert!(
        staged["staged"].as_str().unwrap().contains("fwos:next"),
        "{staged}"
    );
    assert_eq!(staged["booted"], previous.as_str(), "{staged}");
    assert_eq!(staged["reboot_required"], true, "{staged}");
    let new = &guest.serial()[from..];
    assert!(
        !new.contains("FWOS Appliance CLI"),
        "staging must not reboot: {new}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered staged Release");
    assert!(
        rendered["status"].as_str().unwrap().contains("fwos:next")
            && rendered["status"].as_str().unwrap().contains("Reboot required"),
        "{rendered}"
    );
    let session = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&session), revision);

    // Offline activation: the staged deployment boots without the registry.
    registry.pause().expect("registry outage before reboot");
    let from = guest.serial().len();
    let rendered = guest
        .browser_host_update("reboot", "alice", "secret12", "")
        .expect("rendered reboot onto the staged Release");
    assert!(
        rendered["result"].as_str().unwrap().starts_with("Rebooting"),
        "{rendered}"
    );
    assert!(
        rendered["confirmation"].as_str().unwrap().contains("fwos:next"),
        "reboot confirmation names the staged Release: {rendered}"
    );
    wait_ui_reboot(&guest, from);
    let activated = host_update_status(&guest);
    let next = activated["booted"].as_str().unwrap_or_default().to_string();
    assert!(next.contains("fwos:next"), "{activated}");
    assert_eq!(activated["rollback"], previous.as_str(), "{activated}");
    assert_eq!(activated["staged"], "", "{activated}");
    assert_eq!(activated["reboot_required"], false, "{activated}");
    let session = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&session), revision);
    assert!(lan_peer
        .ping("192.0.2.2")
        .expect("forwarded probe on the new Release"));

    // Registry still down: a later update fails without touching the running
    // Release, the Accepted network, or forwarding.
    let later = image.replace("fwos:next", "fwos:later");
    let requested = guest
        .browser_host_update("stage", "alice", "secret12", &later)
        .expect("rendered stage request during registry outage");
    assert!(
        requested["result"].as_str().unwrap().contains("started"),
        "{requested}"
    );
    let (failed, probes) = wait_staging_done(&guest, &lan_peer, "192.0.2.2");
    probes.assert_forwarding_continued("failed staging");
    assert_eq!(failed["operation"]["state"], "failed", "{failed}");
    assert_eq!(failed["booted"], next.as_str(), "{failed}");
    assert_eq!(failed["staged"], "", "{failed}");
    assert_eq!(failed["reboot_required"], false, "{failed}");
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered failed staging");
    assert!(
        rendered["operation"].as_str().unwrap().contains("failed")
            && rendered["operation"].as_str().unwrap().contains("unchanged"),
        "{rendered}"
    );
    let session = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&session), revision, "Accepted network unchanged");

    // A failed download is not a Host update boot: the running Release stays
    // booted and keeps its rollback target.
    let from = guest.serial().len();
    let rendered = guest
        .browser_host_update("reboot", "alice", "secret12", "")
        .expect("rendered reboot with nothing staged");
    assert!(
        rendered["result"].as_str().unwrap().starts_with("Rebooting"),
        "{rendered}"
    );
    wait_ui_reboot(&guest, from);
    let after_failure = host_update_status(&guest);
    assert_eq!(after_failure["booted"], next.as_str(), "{after_failure}");
    assert_eq!(after_failure["rollback"], previous.as_str(), "{after_failure}");
    let session = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&session), revision);
    assert!(lan_peer
        .ping("192.0.2.2")
        .expect("forwarded probe after reboot with nothing staged"));
    assert_no_ssh(&guest, "after UI Host update");
}

#[test]
fn published_ui_stages_host_update_over_ipv6_only_wan_without_delegation() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_next_release()
        .expect("Workstation-local registry must serve a newer Release");
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let mut wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.enable_slaac().unwrap();
    // The IPv6-only upstream: RAs for SLAAC that name an ISP resolver (RDNSS),
    // no delegated prefix, and the Release's blob storage, which is reachable
    // only over this WAN and only by name.
    wan_peer.add_address("2001:db8:ff::1/64").unwrap();
    wan_peer
        .serve_dns("registry.fwos.test", "2001:db8:ff::1")
        .expect("WAN resolver");
    wan_peer
        .start_ipv6_upstream_with(Ipv6Upstream {
            ra_prefix: "2001:db8:ff::",
            delegate: None,
            dns_server: Some("2001:db8:ff::1"),
        })
        .expect("external IPv6 upstream without prefix delegation");
    let peer_registry = registry
        .serve_on_peer(&wan_peer, "2001:db8:ff::1")
        .expect("registry on the IPv6-only WAN");
    // Plain HTTP stays limited to IP-literal registries, and a reference cannot
    // hold an IPv6 literal. So the guest names the Workstation registry by IPv4
    // literal for manifests, and every blob download redirects to the WAN
    // registry by name, as public registries redirect to storage hosts.
    let front = registry
        .redirect_blobs_to(&peer_registry.url("registry.fwos.test"))
        .expect("registry front that redirects blobs");
    let image = front.guest_image();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan, "role": "wan", "addresses": []}
        ],
        "ui_exposure": [mgmt]
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    let session = https_login_admin(&guest, "alice", "secret12");
    let initial = host_update_status(&guest);
    let previous = initial["booted"].as_str().unwrap_or_default().to_string();
    assert!(!previous.is_empty() && !previous.contains("fwos:next"), "{initial}");

    // Before any WAN has IPv6, no WAN supplied a resolver: a registry name is
    // refused with that reason, not a generic download failure.
    let named = "registry.fwos.test:5000/fwos:next";
    let requested = guest
        .browser_host_update("stage", "alice", "secret12", named)
        .expect("rendered stage request without a WAN resolver");
    assert!(requested["result"].as_str().unwrap().contains("started"), "{requested}");
    let (unresolvable, _) = wait_staging_done(&guest, &lan_peer, "10.56.0.1");
    assert_eq!(unresolvable["operation"]["state"], "failed", "{unresolvable}");
    assert!(
        unresolvable["operation"]["error"]
            .as_str()
            .unwrap()
            .contains("no DNS resolver learned from any WAN"),
        "{unresolvable}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered failure without a WAN resolver");
    assert!(
        rendered["operation"].as_str().unwrap().contains("no DNS resolver learned from any WAN"),
        "{rendered}"
    );

    // The WAN goes IPv6-only by SLAAC: its RAs give an address, a default
    // route, and a resolver; no prefix is delegated or routed behind it.
    let live = guest
        .browser_configure_ipv6("apply", "alice", "secret12", &wan, "slaac", false, "; IPv6 default route")
        .expect("IPv6-only WAN autoconfigures with an RA default route");
    assert!(live.contains("LAN prefix (none): none"), "{live}");
    assert!(live.contains("There is no NAT66, NPTv6, or NAT64"), "{live}");
    let wan_cidr = live
        .split_whitespace()
        .map(|word| word.trim_end_matches([';', ',']))
        .find(|word| word.starts_with("2001:db8:ff:") && word.ends_with("/64"))
        .unwrap_or_else(|| panic!("WAN SLAAC address in live IPv6: {live}"))
        .to_owned();
    let wan_address: std::net::IpAddr = wan_cidr.split('/').next().unwrap().parse().unwrap();
    let revision = accepted_revision(&session);

    // Stage from the UI. The controller stays in the Host netns, which has no
    // route to this WAN; only its fwd worker can resolve and reach it.
    let started = guest
        .browser_host_update("stage", "alice", "secret12", &image)
        .expect("rendered stage request over the IPv6-only WAN");
    assert!(started["result"].as_str().unwrap().contains("started"), "{started}");
    let (staged, probes) = wait_staging_done(&guest, &lan_peer, "10.56.0.1");
    probes.assert_forwarding_continued("IPv6-only staging");
    let queries = wan_peer.dns_queries().expect("WAN resolver log");
    eprintln!("WAN resolver queries: {queries:#?}");
    eprintln!("worker placement: {}", staged["worker_network"]);
    assert_eq!(staged["operation"]["state"], "idle", "{staged}");
    assert_eq!(staged["staged"], image.as_str(), "{staged}");
    assert_eq!(staged["booted"], previous.as_str(), "{staged}");
    assert_eq!(staged["reboot_required"], true, "{staged}");
    assert_eq!(accepted_revision(&https_login_admin(&guest, "alice", "secret12")), revision);

    // Evidence. In the guest, the controller reports that it ran in the Host
    // netns and its download worker in fwd. Outside it, the WAN resolver saw
    // the name looked up from the appliance's own SLAAC address, and every
    // blob came from that address by name (no delegated prefix, no NAT66).
    assert_eq!(
        staged["worker_network"],
        serde_json::json!({"controller": "host", "worker": "fwd"}),
        "{staged}"
    );
    assert!(
        queries
            .iter()
            .any(|q| q.contains("registry.fwos.test") && q.ends_with(&format!("from {wan_address}"))),
        "the worker resolves the registry name through the RDNSS resolver: {queries:?}"
    );
    let requests = peer_registry.requests().expect("registry request log");
    let blobs: Vec<_> = requests.iter().filter(|r| r.is_blob()).collect();
    eprintln!(
        "WAN registry: {} requests, {} blob fetches, clients {:?}, agents {:?}",
        requests.len(),
        blobs.len(),
        requests.iter().map(|r| r.client).collect::<std::collections::BTreeSet<_>>(),
        requests.iter().map(|r| r.user_agent.as_str()).collect::<std::collections::BTreeSet<_>>(),
    );
    assert!(!blobs.is_empty(), "the Release layers were downloaded over the WAN: {requests:?}");
    assert!(
        requests
            .iter()
            .all(|r| r.client == wan_address && r.host == "registry.fwos.test:5000"),
        "every WAN registry request comes from the WAN address, by name: {requests:?}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered staged Release");
    assert!(
        rendered["status"].as_str().unwrap().contains("fwos:next")
            && rendered["status"].as_str().unwrap().contains("Reboot required"),
        "{rendered}"
    );
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        lan_peer.global_ipv6().unwrap().is_empty() && lan_peer.ipv6_default_router().unwrap().is_none(),
        "the LAN still gets no IPv6 rather than translation"
    );

    // The staged deployment activates on the explicit reboot.
    let from = guest.serial().len();
    let rendered = guest
        .browser_host_update("reboot", "alice", "secret12", "")
        .expect("rendered reboot onto the staged Release");
    assert!(rendered["result"].as_str().unwrap().starts_with("Rebooting"), "{rendered}");
    wait_ui_reboot(&guest, from);
    let activated = host_update_status(&guest);
    assert_eq!(activated["booted"], image.as_str(), "{activated}");
    assert_eq!(activated["rollback"], previous.as_str(), "{activated}");
    assert_eq!(activated["reboot_required"], false, "{activated}");

    // Registry outage: a later download fails, and that is neither a staged
    // Release nor a network change.
    peer_registry.stop();
    let later = image.replace("fwos:next", "fwos:later");
    let requested = guest
        .browser_host_update("stage", "alice", "secret12", &later)
        .expect("rendered stage request during the registry outage");
    assert!(requested["result"].as_str().unwrap().contains("started"), "{requested}");
    let (failed, probes) = wait_staging_done(&guest, &lan_peer, "10.56.0.1");
    probes.assert_forwarding_continued("failed IPv6-only staging");
    assert_eq!(failed["operation"]["state"], "failed", "{failed}");
    assert_eq!(failed["booted"], image.as_str(), "{failed}");
    assert_eq!(failed["staged"], "", "{failed}");
    assert_eq!(failed["reboot_required"], false, "{failed}");
    let session = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&session), revision, "Accepted network unchanged");
    let live = guest
        .browser_configure_ipv6("observe", "alice", "secret12", &wan, "slaac", false, &wan_cidr)
        .expect("WAN IPv6 unchanged after the failed download");
    assert!(live.contains(&wan_cidr), "{live}");
    assert_no_ssh(&guest, "after IPv6-only Host update");
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
    let status = host_update_status(&guest);
    assert_eq!(status["last_update"]["outcome"], "rolled_back", "{status}");
    assert_eq!(status["last_update"]["reason"], "netd not running", "{status}");
    assert_no_ssh(&guest, "after automatic rollback");
}

/// UI on the user-net NIC, and a LAN peer that the Accepted Desired state
/// serves with Kea DHCPv4 and routes to a WAN peer.
fn boot_host_update_guest(lan_peer: &NetworkPeer, wan_peer: &NetworkPeer) -> Guest {
    lan_peer
        .add_address("10.56.0.2/24")
        .expect("LAN peer address");
    lan_peer
        .add_route("192.0.2.0/24", "10.56.0.1")
        .expect("LAN peer route to the WAN");
    wan_peer.add_address("192.0.2.2/24").expect("WAN peer address");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[lan_peer, wan_peer])
        .expect("published Disk image with external peers");
    let ui_nic = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &ui_nic)
        .collect();
    assert_eq!(peers.len(), 2);
    let (lan_nic, wan_nic) = (&peers[0], &peers[1]);
    let payload = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": lan_nic, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": ui_nic, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": wan_nic, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [ui_nic],
        "lan_prefix": "10.56.0.0/24", "dhcp_pool": "10.56.0.100-10.56.0.140"
    });
    https_bootstrap(&guest, &payload.to_string());
    guest
}

/// Accepted interface Desired state, without live NIC observations.
fn accepted_interfaces(session: &fwos_dev::HttpsSession<'_>) -> serde_json::Value {
    let body: serde_json::Value =
        serde_json::from_str(&session.get("/api/interfaces").expect("Accepted interfaces"))
            .expect("interfaces JSON");
    serde_json::json!([body["interfaces"], body["ui_exposure"], body["lan_prefix"]])
}

/// The LAN peer gets a lease from the appliance and reaches the WAN peer.
fn assert_lan_services_and_forwarding(lan_peer: &NetworkPeer, when: &str) {
    let offered = wait_dhcp_offer(lan_peer);
    assert!(
        (100..=140).contains(&offer_octet(&offered)),
        "{when}: Accepted DHCP pool lease: {offered}"
    );
    assert!(
        wait_ping(lan_peer, "192.0.2.2"),
        "{when}: LAN peer must forward to the WAN"
    );
}

/// Stage `image` from the rendered UI, run `before_reboot`, and reboot onto
/// it; returns the previously active Release and the serial offset of the reboot.
fn stage_and_reboot_from_ui(
    guest: &Guest,
    lan_peer: &NetworkPeer,
    image: &str,
    before_reboot: impl FnOnce(),
) -> (String, usize) {
    let previous = host_update_status(guest)["booted"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!previous.is_empty() && !previous.contains("fwos:next"));
    let started = guest
        .browser_host_update("stage", "alice", "secret12", image)
        .expect("rendered stage request");
    assert!(
        started["result"].as_str().unwrap().contains("started"),
        "{started}"
    );
    let (staged, _) = wait_staging_done(guest, lan_peer, "192.0.2.2");
    assert_eq!(staged["operation"]["state"], "idle", "{staged}");
    assert!(
        staged["staged"].as_str().unwrap().contains("fwos:next"),
        "{staged}"
    );
    before_reboot();
    let from = guest.serial().len();
    let rendered = guest
        .browser_host_update("reboot", "alice", "secret12", "")
        .expect("rendered reboot onto the staged Release");
    assert!(
        rendered["result"].as_str().unwrap().starts_with("Rebooting"),
        "{rendered}"
    );
    (previous, from)
}

#[test]
fn published_host_update_rolls_back_when_lan_services_are_not_restored_and_keeps_current_identity(
) {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_broken_lan_services_release()
        .expect("Workstation-local registry must serve a Release whose Kea cannot start");
    let image = registry.guest_image();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    let guest = boot_host_update_guest(&lan_peer, &wan_peer);
    assert_lan_services_and_forwarding(&lan_peer, "before the update");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/administrators",
            Some(r#"{"username":"bob","password":"secret34"}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let revision = accepted_revision(&alice);
    let accepted_network = accepted_interfaces(&alice);

    let (previous, from) = stage_and_reboot_from_ui(&guest, &lan_peer, &image, || ());
    wait_ui_reboot(&guest, from);

    // The broken Release is live: netd runs and serves the UI, but the
    // Accepted LAN services are not restored.
    let failed = host_update_status(&guest);
    assert!(
        failed["booted"].as_str().unwrap().contains("fwos:next"),
        "{failed}"
    );
    assert_eq!(failed["rollback"], previous.as_str(), "{failed}");
    // Identity changes made on the failed Release are current and must
    // survive the rollback: bob is removed and alice changes her password.
    let alice = https_login_admin(&guest, "alice", "secret12");
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/administrators/remove",
            Some(r#"{"username":"bob"}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/administrators/password",
            Some(r#"{"username":"alice","password":"secret56"}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        lan_peer.dhcp_offer().expect("LAN DHCP probe on the failed Release"),
        None,
        "the fixture Release must not serve DHCP"
    );
    let still_failed = host_update_status_as(&guest, "secret56");
    assert!(
        still_failed["booted"].as_str().unwrap().contains("fwos:next"),
        "identity changes must be made on the failed Release: {still_failed}"
    );

    // No operator action: appliance health reboots into the previous Release.
    let rolled = serial_wait(&guest, from, 600, |text| {
        text.matches("FWOS Appliance CLI").count() >= 2
    });
    assert!(
        rolled.matches("FWOS Appliance CLI").count() >= 2,
        "failed appliance health must reboot into the previous bootc deployment: {rolled}"
    );
    let status = host_update_status_as(&guest, "secret56");
    assert_eq!(status["booted"], previous.as_str(), "{status}");
    assert!(
        status["rollback"].as_str().unwrap().contains("fwos:next"),
        "{status}"
    );
    assert_eq!(status["reboot_required"], false, "{status}");
    assert_eq!(status["last_update"]["outcome"], "rolled_back", "{status}");
    let reason = status["last_update"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("Desired state not restored") && reason.contains("fwos-kea-dhcp4"),
        "a running netd is not a restored network: {status}"
    );
    assert_eq!(
        status["last_update"]["network"],
        serde_json::json!({"outcome": "unchanged", "revision": revision}),
        "the failed Release did not change the network: {status}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret56", "")
        .expect("rendered automatic rollback");
    assert!(
        rendered["health"]
            .as_str()
            .unwrap()
            .contains("automatically returned to the previous Release"),
        "{rendered}"
    );

    // The previous Release restores the pre-update network and its services.
    let alice = https_login_admin(&guest, "alice", "secret56");
    assert_eq!(accepted_revision(&alice), revision, "pre-update revision");
    assert_eq!(accepted_interfaces(&alice), accepted_network);
    assert_lan_services_and_forwarding(&lan_peer, "after automatic rollback");

    // Current Identity configuration, not an older snapshot, stays in effect.
    for (username, password) in [("alice", "secret12"), ("bob", "secret34")] {
        let credentials = serde_json::json!({"source": "local", "username": username, "password": password})
            .to_string();
        match guest.https_login(&credentials) {
            Ok(_) => panic!("{username}'s obsolete credential must not return after rollback"),
            Err(error) => assert!(error.to_string().contains("401"), "{error}"),
        }
    }
    let login_from = guest.serial().rfind("FWOS Appliance CLI").unwrap_or(from);
    serial_login_admin_from(&guest, "alice", "secret56", login_from);
    assert_no_ssh(&guest, "after automatic rollback of broken LAN services");
}

/// Wait until the previous Release's netd reports the pre-update network.
fn wait_network_restoration(guest: &Guest, password: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let status = host_update_status_as(guest, password);
        if !status["last_update"]["network"].is_null() {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "netd must report the pre-update network after the rollback: {status}"
        );
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[test]
fn published_host_update_rollback_restores_the_pre_update_network_as_a_new_revision() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_stalled_boot_release()
        .expect("Workstation-local registry must serve a Release that never finishes booting");
    let image = registry.guest_image();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    let guest = boot_host_update_guest(&lan_peer, &wan_peer);
    assert_lan_services_and_forwarding(&lan_peer, "before the update");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let revision = accepted_revision(&alice);
    let accepted_network = accepted_interfaces(&alice);
    let accepted_services = alice.get("/api/lan-services").expect("Accepted LAN services");

    let (previous, from) = stage_and_reboot_from_ui(&guest, &lan_peer, &image, || ());
    wait_ui_reboot(&guest, from);

    // The failed Release serves the UI and applies network changes, but never
    // reaches its default target. An administrator changes the DHCP pool and
    // her password on it before appliance health decides.
    let failed = host_update_status(&guest);
    assert!(
        failed["booted"].as_str().unwrap().contains("fwos:next"),
        "{failed}"
    );
    guest
        .browser_configure_lan_services(
            "apply",
            "alice",
            "secret12",
            "10.56.0.0/24",
            "10.56.0.150-10.56.0.160",
            "",
        )
        .expect("the failed Release applies a DHCP pool change");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision + 1, "change Accepted on the failed Release");
    let leased = wait_dhcp_offer(&lan_peer);
    assert!(
        (150..=160).contains(&offer_octet(&leased)),
        "the failed Release serves its own pool: {leased}"
    );
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/administrators/password",
            Some(r#"{"username":"alice","password":"secret56"}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let still_failed = host_update_status_as(&guest, "secret56");
    assert!(
        still_failed["booted"].as_str().unwrap().contains("fwos:next"),
        "changes must be made on the failed Release: {still_failed}"
    );

    // No operator action: appliance health reboots into the previous Release,
    // which restores the pre-update network as a new Accepted revision.
    let rolled = serial_wait(&guest, from, 600, |text| {
        text.matches("FWOS Appliance CLI").count() >= 2
    });
    assert!(
        rolled.matches("FWOS Appliance CLI").count() >= 2,
        "failed appliance health must reboot into the previous bootc deployment: {rolled}"
    );
    let status = wait_network_restoration(&guest, "secret56");
    assert_eq!(status["booted"], previous.as_str(), "{status}");
    assert_eq!(status["last_update"]["outcome"], "rolled_back", "{status}");
    assert_eq!(
        status["last_update"]["reason"], "default target not reached",
        "{status}"
    );
    assert_eq!(
        status["last_update"]["network"],
        serde_json::json!({"outcome": "restored", "revision": revision + 2}),
        "{status}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret56", "")
        .expect("rendered automatic rollback");
    assert!(
        rendered["health"]
            .as_str()
            .unwrap()
            .contains(&format!("restored as Accepted revision {}", revision + 2)),
        "{rendered}"
    );
    let alice = https_login_admin(&guest, "alice", "secret56");
    assert_eq!(accepted_revision(&alice), revision + 2);
    assert_eq!(accepted_interfaces(&alice), accepted_network);
    let services = alice.get("/api/lan-services").expect("Accepted LAN services");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&services).unwrap()["dhcp_pool"],
        serde_json::from_str::<serde_json::Value>(&accepted_services).unwrap()["dhcp_pool"],
        "pre-update pool is Accepted again: {services}"
    );
    // Effective prior networking: leases from the pre-update pool, forwarding.
    assert_lan_services_and_forwarding(&lan_peer, "after the network restoration");

    // Identity configuration is current, not reverted with the network.
    let old = serde_json::json!({"source": "local", "username": "alice", "password": "secret12"});
    match guest.https_login(&old.to_string()) {
        Ok(_) => panic!("the obsolete password must not return with the network"),
        Err(error) => assert!(error.to_string().contains("401"), "{error}"),
    }
    assert_no_ssh(&guest, "after restoring the pre-update network");
}

#[test]
fn published_host_update_is_accepted_with_the_wan_unplugged_and_no_acknowledgement() {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_next_release()
        .expect("Workstation-local registry must serve a newer Release");
    let image = registry.guest_image();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    let guest = boot_host_update_guest(&lan_peer, &wan_peer);
    assert_lan_services_and_forwarding(&lan_peer, "before the update");
    // Apply confirmation is a network safeguard, not Host update health.
    let alice = https_login_admin(&guest, "alice", "secret12");
    let base = accepted_revision(&alice);
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/apply-confirmation/configure",
            Some(&format!(r#"{{"base_revision":{base},"enabled":true}}"#)),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let revision = accepted_revision(&alice);

    let (previous, from) = stage_and_reboot_from_ui(&guest, &lan_peer, &image, || {
        // Unplug the WAN and lose every upstream, including the registry,
        // before the update boot and through its health check.
        guest
            .qemu_set_peer_link(1, false)
            .expect("pull the WAN cable");
        registry.pause().expect("upstream registry outage");
        assert!(!lan_peer.ping("192.0.2.2").unwrap(), "WAN is unplugged");
    });
    wait_ui_reboot(&guest, from);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let status = loop {
        let status = host_update_status(&guest);
        if !status["last_update"].is_null() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "appliance health must decide the update boot: {status}"
        );
        std::thread::sleep(std::time::Duration::from_secs(5));
    };
    assert_eq!(status["last_update"]["outcome"], "accepted", "{status}");
    assert!(
        status["booted"].as_str().unwrap().contains("fwos:next"),
        "an unplugged WAN is not a failed Release: {status}"
    );
    assert_eq!(status["rollback"], previous.as_str(), "{status}");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision, "Accepted network unchanged");
    let confirmation: serde_json::Value =
        serde_json::from_str(&alice.get("/api/apply-confirmation").unwrap()).unwrap();
    assert_eq!(confirmation["enabled"], true, "{confirmation}");
    assert!(
        confirmation["pending"].is_null(),
        "Host update health asks for no Apply confirmation: {confirmation}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret12", "")
        .expect("rendered accepted update");
    assert!(
        rendered["health"].as_str().unwrap().contains("passed appliance health"),
        "{rendered}"
    );

    let offered = wait_dhcp_offer(&lan_peer);
    assert!((100..=140).contains(&offer_octet(&offered)), "{offered}");
    guest
        .qemu_set_peer_link(1, true)
        .expect("plug the WAN cable back in");
    assert!(
        wait_ping(&lan_peer, "192.0.2.2"),
        "forwarding resumes when the WAN returns"
    );
    assert_no_ssh(&guest, "after an update boot with the WAN unplugged");
}

/// Poll `probe` every `every` until it yields a value; after `secs`, fail
/// with `what` and the probe's last observation.
fn wait_until<T>(
    secs: u64,
    every: std::time::Duration,
    what: &str,
    mut probe: impl FnMut() -> Result<T, String>,
) -> T {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        match probe() {
            Ok(value) => return value,
            Err(last) => assert!(
                std::time::Instant::now() < deadline,
                "{what}; last observed: {last}"
            ),
        }
        std::thread::sleep(every);
    }
}

/// Wait until appliance health has accepted the update boot.
fn wait_update_accepted(guest: &Guest) -> serde_json::Value {
    wait_until(
        300,
        std::time::Duration::from_secs(5),
        "appliance health must accept the working Release",
        || {
            let status = host_update_status(guest);
            if status["last_update"]["outcome"] == "accepted" {
                Ok(status)
            } else {
                Err(status.to_string())
            }
        },
    )
}

/// At the console's `admin:` prompt, obsolete identities are refused.
fn assert_serial_logins_refused(guest: &Guest, from: usize, obsolete: &[(&str, &str)]) {
    let prompt = serial_wait(guest, from, 600, |text| text.contains("admin:"));
    assert!(
        prompt.contains("admin:") && !prompt.contains("FWOS Bootstrap console"),
        "authenticated console, not Bootstrap: {prompt}"
    );
    for (user, password) in obsolete {
        let asked = serial_cmd(guest, &format!("{user}\n"), 15, |text| {
            text.contains("password:")
        });
        assert!(asked.contains("password:"), "console login prompt: {asked}");
        let sent = guest.serial().len();
        guest
            .serial_write(&format!("{password}\n"))
            .expect("submit obsolete console password");
        let denied = serial_wait(guest, sent, 15, |text| text.contains("login failed"));
        assert!(
            denied.contains("login failed"),
            "{user}'s obsolete credential must be refused: {denied}"
        );
    }
}

/// The LAN peer leases from `pool` (last octets) and forwards to the WAN.
fn assert_lease_in_pool_and_forwarding(
    lan_peer: &NetworkPeer,
    pool: std::ops::RangeInclusive<u8>,
    when: &str,
) {
    wait_until(
        120,
        std::time::Duration::from_secs(2),
        &format!("{when}: the lease must come from {pool:?}"),
        || {
            let offered = wait_dhcp_offer(lan_peer);
            if pool.contains(&offer_octet(&offered)) {
                Ok(())
            } else {
                Err(offered)
            }
        },
    );
    assert!(
        wait_ping(lan_peer, "192.0.2.2"),
        "{when}: LAN peer must forward to the WAN"
    );
}

#[test]
fn published_serial_image_rollback_without_the_ui_keeps_the_network_revision_and_current_identity(
) {
    let _guard = guest_lock();
    let registry = LocalRegistry::publish_next_release()
        .expect("Workstation-local registry must serve a newer Release");
    let image = registry.guest_image();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    let guest = boot_host_update_guest(&lan_peer, &wan_peer);
    assert_lan_services_and_forwarding(&lan_peer, "before the update");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/administrators",
            Some(r#"{"username":"bob","password":"secret34"}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let revision = accepted_revision(&alice);
    let accepted_network = accepted_interfaces(&alice);

    let (previous, from) = stage_and_reboot_from_ui(&guest, &lan_peer, &image, || ());
    wait_ui_reboot(&guest, from);
    let accepted = wait_update_accepted(&guest);
    assert!(
        accepted["booted"].as_str().unwrap().contains("fwos:next"),
        "{accepted}"
    );
    assert_eq!(accepted["rollback"], previous.as_str(), "{accepted}");
    let next = accepted["booted"].as_str().unwrap().to_string();

    // On the accepted newer Release: a network change, and Identity changes
    // that the image rollback must not revert.
    guest
        .browser_configure_lan_services(
            "apply",
            "alice",
            "secret12",
            "10.56.0.0/24",
            "10.56.0.150-10.56.0.160",
            "",
        )
        .expect("the newer Release applies a DHCP pool change");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision + 1);
    for (path, body) in [
        ("/api/administrators/remove", r#"{"username":"bob"}"#),
        (
            "/api/administrators/password",
            r#"{"username":"alice","password":"secret56"}"#,
        ),
    ] {
        let (code, reply) = alice.exchange("POST", path, Some(body), 15).unwrap();
        assert_eq!(code, 200, "{path}: {reply}");
    }
    assert_lease_in_pool_and_forwarding(&lan_peer, 150..=160, "on the newer Release");

    // The UI path is lost: its NIC's cable is pulled.
    guest
        .qemu_set_user_net_link(false)
        .expect("pull the UI NIC cable");
    https_must_not_answer(&guest, 5, "with the UI NIC unplugged");

    let console_from = guest.serial().rfind("FWOS Appliance CLI").unwrap_or(from);
    assert_serial_logins_refused(
        &guest,
        console_from,
        &[("alice", "secret12"), ("bob", "secret34")],
    );
    serial_login_admin_from(&guest, "alice", "secret56", guest.serial().len());
    let help = serial_cmd(&guest, "help\n", 15, |text| text.contains("logout"));
    assert!(
        help.contains("rollback-image")
            && help.contains("the Accepted Desired state is unchanged")
            && help.contains("cancels the queued rollback")
            && help.contains("restore-previous")
            && help.contains("the Host image is unchanged")
            && !help.contains("apply <"),
        "the recovery menu distinguishes image rollback from network restoration: {help}"
    );
    let status = serial_cmd(&guest, "status\n", 30, |text| {
        text.contains("Previous Host image") && text.contains("fwos>")
    });
    assert!(
        status.contains(&format!(
            "Previous Host image available for rollback-image: {previous}"
        )) && json_status_image(&status, "booted")
            .unwrap_or_default()
            .contains("fwos:next"),
        "console status names the rollback target: {status}"
    );
    assert!(
        status.contains("fwos:next accepted"),
        "console status reports the accepted update: {status}"
    );

    let queued = serial_cmd(&guest, "rollback-image\n", 60, |text| {
        text.contains("Host image rollback") && text.contains("fwos>")
    });
    assert!(
        queued.contains(&format!(
            "Host image rollback queued: the next boot runs the previous Host image {previous}"
        )),
        "manual image rollback outcome: {queued}"
    );
    assert!(
        queued.contains("Reboot required: enter reboot")
            && queued.contains("The Accepted Desired state is unchanged")
            && !queued.contains("unknown command"),
        "the outcome names the explicit reboot and keeps the network: {queued}"
    );
    // Queued, not activated: the newer Release keeps running until reboot.
    let still = serial_cmd(&guest, "status\n", 30, |text| {
        text.contains("Host image rollback queued") && text.contains("fwos>")
    });
    assert!(
        still.contains(&format!(
            "Host image rollback queued: the next boot runs {previous}"
        )) && still.contains("Reboot required")
            && json_status_image(&still, "booted")
                .unwrap_or_default()
                .contains("fwos:next"),
        "rollback waits for the explicit reboot: {still}"
    );
    assert!(wait_ping(&lan_peer, "192.0.2.2"), "forwarding continues");

    let from_rb = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("explicit console reboot into the previous Host image");
    assert_serial_logins_refused(
        &guest,
        from_rb,
        &[("alice", "secret12"), ("bob", "secret34")],
    );
    let serial = guest.serial();
    let rebooted = &serial[from_rb..];
    assert!(
        rebooted.contains("FWOS Appliance CLI") && !rebooted.contains("FWOS Bootstrap console"),
        "the image rollback reboot must not reopen Bootstrap: {rebooted}"
    );
    serial_login_admin_from(&guest, "alice", "secret56", guest.serial().len());
    let back = serial_cmd(&guest, "status\n", 60, |text| {
        text.contains("netd: running") && text.contains("Previous Host image")
    });
    assert_eq!(
        json_status_image(&back, "booted").unwrap_or_default(),
        previous,
        "the previous Host image is booted: {back}"
    );
    assert!(
        json_status_image(&back, "rollback")
            .unwrap_or_default()
            .contains("fwos:next")
            && !back.contains("rollback queued")
            && !back.contains("Reboot required")
            && back.contains(&format!("Accepted network revision: {}", revision + 1))
            && back.contains("bootstrapped"),
        "image rollback keeps the Accepted network revision: {back}"
    );
    assert!(
        back.contains(&format!(
            "Last Host image change: manually rolled back from {next} to {previous}"
        )),
        "the booted previous Release reports the manual rollback: {back}"
    );
    // Prior Release, current network, with the UI still unreachable.
    assert_lease_in_pool_and_forwarding(&lan_peer, 150..=160, "after the image rollback");

    guest
        .qemu_set_user_net_link(true)
        .expect("restore the UI NIC cable");
    wait_until(
        120,
        std::time::Duration::from_secs(2),
        "the UI must answer again on the previous Release",
        || {
            https_up(&guest)
                .then_some(())
                .ok_or_else(|| serial_tail(&guest.serial(), 4000).to_string())
        },
    );
    let status = host_update_status_as(&guest, "secret56");
    assert_eq!(status["booted"], previous.as_str(), "{status}");
    assert_eq!(status["reboot_required"], false, "{status}");
    assert_eq!(status["rollback_queued"], false, "{status}");
    assert_eq!(
        status["last_update"],
        serde_json::json!({"release": next, "outcome": "rolled_back",
            "reason": "manual rollback",
            "manual": {"to": previous, "pre_update_network": false},
            "network": null}),
        "{status}"
    );
    let rendered = guest
        .browser_host_update("status", "alice", "secret56", "")
        .expect("rendered manual rollback outcome");
    assert_eq!(
        rendered["health"].as_str().unwrap(),
        format!(
            "The Host image was manually rolled back from {next} to {previous}. The Accepted network was kept."
        ),
        "{rendered}"
    );
    for (username, password) in [("alice", "secret12"), ("bob", "secret34")] {
        let credentials =
            serde_json::json!({"source": "local", "username": username, "password": password});
        let (code, _) = guest
            .https_exchange("POST", "/api/login", Some(&credentials.to_string()), 15)
            .expect("obsolete identity response after image rollback");
        assert_eq!(code, 401, "{username}'s obsolete credential must stay refused");
    }
    let alice = https_login_admin(&guest, "alice", "secret56");
    let ui_status: serde_json::Value =
        serde_json::from_str(&alice.get("/api/status").unwrap()).unwrap();
    assert_eq!(ui_status["bootstrapped"], true, "rollback cannot reopen Bootstrap");
    assert_eq!(accepted_revision(&alice), revision + 1);

    // Restoring the previous network revision is the separate operation, and
    // leaves the Host image alone.
    let restored = serial_cmd(&guest, "restore-previous\n", 120, |text| {
        text.contains("\"outcome\"")
    });
    assert!(
        restored.contains("\"outcome\":\"accepted\"")
            || restored.contains("\"outcome\": \"accepted\""),
        "console network restoration outcome: {restored}"
    );
    let alice = https_login_admin(&guest, "alice", "secret56");
    assert_eq!(accepted_revision(&alice), revision + 2);
    assert_eq!(accepted_interfaces(&alice), accepted_network);
    assert_lease_in_pool_and_forwarding(&lan_peer, 100..=140, "after network restoration");
    let status = host_update_status_as(&guest, "secret56");
    assert_eq!(status["booted"], previous.as_str(), "{status}");
    assert_eq!(status["reboot_required"], false, "{status}");
    assert_no_ssh(&guest, "after manual Host image rollback");
}

fn peer_https_stays_down(peer: &NetworkPeer, address: &str) {
    for _ in 0..5 {
        match peer.https_response(address) {
            Ok(None) => {}
            Ok(Some(code)) => panic!("HTTPS answered {code} at {address}"),
            Err(error) => panic!("peer HTTPS probe failed: {error}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn wait_peer_https(peer: &NetworkPeer, address: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last = String::from("no response");
    while std::time::Instant::now() < deadline {
        match peer.https_response(address) {
            Ok(Some(code)) if (200..500).contains(&code) => return,
            Ok(Some(code)) => last = format!("http {code}"),
            Ok(None) => last = "unreachable".into(),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("peer HTTPS to {address} did not come up: {last}");
}

#[test]
fn published_two_nic_interface_editor_accepts_global_wan_and_rejects_topology() {
    let _guard = guest_lock();
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("203.0.113.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&wan_peer])
        .expect("published two-NIC Disk image");
    let lan = opt_user_net(&guest);
    let wan = other_console_nic(&guest, &lan);
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&lan, &wan));
    peer_https_stays_down(&wan_peer, "192.0.2.1");

    guest
        .browser_configure_interfaces(
            "apply",
            "alice",
            "secret12",
            &serde_json::json!([{
                "op": "set", "name": wan, "addresses": "203.0.113.1/24"
            }]),
            "",
        )
        .expect("administrator applies a global WAN address through the rendered editor");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let interfaces = alice.get("/api/interfaces").expect("accepted interfaces");
    assert!(
        interfaces.contains("203.0.113.1/24"),
        "steady-state WAN addressing is not limited to Bootstrap's RFC1918 policy: {interfaces}"
    );
    assert!(
        interfaces.contains(&format!("\"{lan}\"")),
        "LAN remains in UI exposure: {interfaces}"
    );
    peer_https_stays_down(&wan_peer, "203.0.113.1");
    assert!(
        alice.get("/api/status").unwrap().contains("bootstrapped"),
        "LAN UI exposure remains reachable from the workstation"
    );

    let routes: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    let revision = routes["revision"].as_u64().unwrap();
    let draft = serde_json::json!({
        "base_revision": revision,
        "routes": [{"to": "198.51.100.0/24", "via": "203.0.113.2", "dev": wan}],
    });
    let (code, body) = alice
        .exchange("POST", "/api/draft/save", Some(&draft.to_string()), 20)
        .unwrap();
    assert_eq!(code, 200, "route draft failed: {body}");
    guest
        .browser_configure_interfaces(
            "save-draft",
            "alice",
            "secret12",
            &serde_json::json!([{
                "op": "set", "name": lan, "appendAddress": "192.168.1.2/24", "expose": true
            }]),
            "",
        )
        .expect("interface edit joins the private route draft");
    guest
        .browser_configure_interfaces(
            "apply-draft",
            "alice",
            "secret12",
            &serde_json::json!([]),
            "198.51.100.0/24",
        )
        .expect("reviewed draft applies routes and interfaces together");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let routes = alice.get("/api/routes").unwrap();
    let interfaces = alice.get("/api/interfaces").unwrap();
    assert!(routes.contains("198.51.100.0/24"), "{routes}");
    assert!(interfaces.contains("192.168.1.2/24"), "{interfaces}");
    assert!(interfaces.contains("203.0.113.1/24"), "{interfaces}");
    let revision = serde_json::from_str::<serde_json::Value>(&alice.get("/api/interfaces").unwrap())
        .unwrap()["revision"]
        .as_u64()
        .unwrap();

    guest
        .browser_configure_interfaces(
            "reject",
            "alice",
            "secret12",
            &serde_json::json!([{"op": "set", "name": lan, "expose": false}]),
            "",
        )
        .expect("empty UI exposure is rejected in the editor");
    guest
        .browser_configure_interfaces(
            "reject",
            "alice",
            "secret12",
            &serde_json::json!([{"op": "set", "name": wan, "role": "unused"}]),
            "",
        )
        .expect("a missing WAN role is rejected before mutation");
    guest
        .browser_configure_interfaces(
            "reject",
            "alice",
            "secret12",
            &serde_json::json!([
                {"op": "add-vlan", "name": format!("{lan}.10"), "parent": lan, "vlan": 10, "role": "wan", "addresses": "192.0.2.10/24", "expose": false},
                {"op": "add-vlan", "name": format!("{lan}.10b"), "parent": lan, "vlan": 10, "role": "lan", "addresses": "192.168.10.1/24", "expose": true}
            ]),
            "",
        )
        .expect("shared parent and tag is rejected before apply");
    let after = alice.get("/api/interfaces").unwrap();
    let after_revision = serde_json::from_str::<serde_json::Value>(&after).unwrap()["revision"]
        .as_u64()
        .unwrap();
    assert_eq!(after_revision, revision, "rejected topology must not change Accepted state: {after}");
    assert!(after.contains("192.168.1.2/24"), "{after}");
    peer_https_stays_down(&wan_peer, "203.0.113.1");
}

#[test]
fn published_vlan_on_one_nic_exposure_is_reachable_from_peer() {
    let _guard = guest_lock();
    let peer = NetworkPeer::new().expect("isolated one-NIC peer");
    peer.add_address("10.70.0.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_peers(&[&peer])
        .expect("published one-NIC Disk image");
    let nics = wait_console_nics(&guest);
    assert_eq!(nics.len(), 1, "VLAN-on-one-NIC guest has one Traffic NIC: {nics:?}");
    let nic = nics[0].0.clone();
    let before = guest.serial().len();
    guest
        .serial_write(&format!("static {nic} 10.70.0.1/24\n"))
        .expect("opt the only Traffic NIC");
    let opt_deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        let tail = guest.serial().get(before..).unwrap_or("").to_string();
        if tail.contains("Reach the UI:") && tail.contains("10.70.0.1") {
            break;
        }
        assert!(
            std::time::Instant::now() < opt_deadline,
            "console static selection did not finish: {tail}"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let https_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if peer.https_response("10.70.0.1").ok().flatten().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < https_deadline,
            "peer cannot reach Bootstrap HTTPS at 10.70.0.1; serial:\n{}",
            guest.serial()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let lan = format!("{nic}.20");
    let payload = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": nic, "role": "wan", "addresses": ["192.0.2.1/24"]},
            {"name": lan, "role": "lan", "parent": nic, "vlan": 20, "addresses": ["192.168.20.1/24"]}
        ],
        "ui_exposure": [lan],
        "lan_prefix": "192.168.20.0/24",
        "dhcp_pool": "192.168.20.100-192.168.20.200"
    });
    let _ = peer.https_exchange(
        "POST",
        "10.70.0.1",
        "/api/bootstrap",
        Some(&payload.to_string()),
        None,
        20,
    );
    let ready = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if guest.serial().contains("Bootstrap complete") {
            break;
        }
        assert!(
            std::time::Instant::now() < ready,
            "one-NIC Bootstrap did not finish; serial:\n{}",
            guest.serial()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    peer.add_address("192.0.2.2/24").unwrap();
    peer.add_vlan(20, "192.168.20.2/24").unwrap();
    wait_peer_https(&peer, "192.168.20.1");
    peer_https_stays_down(&peer, "192.0.2.1");

    let extra = format!("{nic}.30");
    peer.browser_configure_interfaces(
        "https://192.168.20.1/",
        "apply",
        "alice",
        "secret12",
        &serde_json::json!([{
            "op": "add-vlan", "name": extra, "parent": nic, "vlan": 30, "role": "lan",
            "addresses": "192.168.30.1/24", "expose": true
        }]),
        "",
    )
    .expect("rendered editor adds a LAN VLAN and exposes it");
    peer.add_vlan(30, "192.168.30.2/24").unwrap();
    wait_peer_https(&peer, "192.168.30.1");
    peer_https_stays_down(&peer, "192.0.2.1");

    peer.browser_configure_interfaces(
        "https://192.168.30.1/",
        "reject",
        "alice",
        "secret12",
        &serde_json::json!([{
            "op": "set", "name": nic, "role": "wan", "parent": nic, "vlan": 20, "expose": false
        }]),
        "",
    )
    .expect("WAN and LAN cannot share one parent and tag");
    wait_peer_https(&peer, "192.168.30.1");
    peer_https_stays_down(&peer, "192.0.2.1");
}

#[test]
fn published_management_nic_exposure_moves_with_peer_traffic() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("192.0.2.2/32", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Management NIC Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    assert_eq!(peers.len(), 2, "management topology needs LAN and WAN peers");
    let (lan, wan) = (&peers[0], &peers[1]);
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [mgmt],
        "lan_prefix": "10.56.0.0/24",
        "dhcp_pool": "10.56.0.100-10.56.0.200"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    peer_https_stays_down(&lan_peer, "10.56.0.1");
    peer_https_stays_down(&wan_peer, "192.0.2.1");
    assert!(
        https_login_admin(&guest, "alice", "secret12")
            .get("/api/status")
            .unwrap()
            .contains(&mgmt),
        "Management NIC stays reachable"
    );

    guest
        .browser_configure_interfaces(
            "apply",
            "alice",
            "secret12",
            &serde_json::json!([{"op": "set", "name": lan, "expose": true}]),
            "",
        )
        .expect("administrator exposes the LAN");
    wait_peer_https(&lan_peer, "10.56.0.1");
    peer_https_stays_down(&wan_peer, "192.0.2.1");
    assert!(
        lan_peer.ping("192.0.2.2").expect("LAN peer ICMP"),
        "LAN traffic still forwards to WAN"
    );
    let offer = wait_dhcp_offer(&lan_peer);
    assert!(
        offer.starts_with("10.56.0."),
        "LAN services stay on the LAN, not the Management NIC: {offer}"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let revision = serde_json::from_str::<serde_json::Value>(&alice.get("/api/routes").unwrap())
        .unwrap()["revision"]
        .as_u64()
        .unwrap();
    let gateway = serde_json::json!({
        "base_revision": revision,
        "routes": [{"to": "198.51.100.0/24", "via": "10.0.2.2", "dev": mgmt}],
    });
    let (code, body) = alice
        .exchange("POST", "/api/routes/apply", Some(&gateway.to_string()), 30)
        .unwrap();
    assert_eq!(code, 400, "Management NIC gateway must be rejected: {body}");
    assert!(body.contains("no gateway"), "{body}");

    guest
        .browser_configure_interfaces(
            "apply",
            "alice",
            "secret12",
            &serde_json::json!([{"op": "set", "name": lan, "expose": false}]),
            "",
        )
        .expect("administrator removes LAN UI exposure");
    peer_https_stays_down(&lan_peer, "10.56.0.1");
    peer_https_stays_down(&wan_peer, "192.0.2.1");
    assert!(
        https_login_admin(&guest, "alice", "secret12")
            .get("/api/interfaces")
            .unwrap()
            .contains(&format!("\"{mgmt}\"")),
        "Management NIC remains in UI exposure"
    );

    let before = https_login_admin(&guest, "alice", "secret12")
        .get("/api/interfaces")
        .unwrap();
    let revision = serde_json::from_str::<serde_json::Value>(&before).unwrap()["revision"]
        .as_u64()
        .unwrap();
    guest
        .browser_configure_interfaces(
            "reject",
            "alice",
            "secret12",
            &serde_json::json!([{
                "op": "add-vlan", "name": format!("{mgmt}.20"), "parent": mgmt, "vlan": 20,
                "role": "lan", "addresses": "192.168.9.1/24", "expose": false
            }]),
            "",
        )
        .expect("a Management NIC owns its whole parent");
    let after = https_login_admin(&guest, "alice", "secret12")
        .get("/api/interfaces")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&after).unwrap()["revision"].as_u64(),
        Some(revision),
        "rejected Management NIC topology must not apply: {after}"
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("LAN peer ICMP after rejection"),
        "rejected topology leaves LAN-to-WAN forwarding in place"
    );
}

fn wait_dns(peer: &NetworkPeer, server: &str, source: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if peer
            .dns_resolves(server, "localhost", source)
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

fn wait_vlan_offer(peer: &NetworkPeer, device: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(address)) = peer.dhcp_offer_on(device) {
            return address;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("VLAN DHCP did not offer an address on {device}");
}

#[test]
fn published_lan_services_move_dhcp_and_dns_with_a_vlan_draft() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [mgmt],
        "lan_prefix": "10.56.0.0/24",
        "dhcp_pool": "10.56.0.100-10.56.0.140"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    let initial = wait_dhcp_offer(&lan_peer);
    assert!(
        (100..=140).contains(&offer_octet(&initial)),
        "initial lease: {initial}"
    );
    lan_peer
        .add_address_on("eth0", &format!("{initial}/24"))
        .expect("use the leased LAN address");
    assert!(
        wait_dns(&lan_peer, "10.56.0.1", &initial),
        "leased client must resolve localhost through the LAN DNS"
    );

    guest
        .browser_configure_lan_services(
            "reject",
            "alice",
            "secret12",
            "10.56.0.0/24",
            "192.168.9.10-192.168.9.20",
            "",
        )
        .expect("a pool outside the LAN prefix is rejected");
    let unchanged = wait_dhcp_offer(&lan_peer);
    assert!(
        (100..=140).contains(&offer_octet(&unchanged)),
        "rejected pool must not change leases: {unchanged}"
    );

    let vlan = format!("{lan}.20");
    guest
        .browser_configure_interfaces(
            "save-draft",
            "alice",
            "secret12",
            &serde_json::json!([
                {"op": "set", "name": lan, "role": "unused"},
                {"op": "add-vlan", "name": vlan, "parent": lan, "vlan": 20, "role": "lan", "addresses": "192.168.20.1/24", "expose": false}
            ]),
            "",
        )
        .expect("VLAN interface joins the private draft");
    guest
        .browser_configure_lan_services(
            "save-draft",
            "alice",
            "secret12",
            "192.168.20.0/24",
            "192.168.20.50-192.168.20.80",
            "",
        )
        .expect("LAN services join the VLAN draft");
    guest
        .browser_configure_lan_services(
            "apply-draft",
            "alice",
            "secret12",
            "192.168.20.0/24",
            "192.168.20.50-192.168.20.80",
            "",
        )
        .expect("reviewed draft applies the VLAN and its services together");

    lan_peer.add_vlan(20, "192.168.20.2/24").unwrap();
    let moved = wait_vlan_offer(&lan_peer, "eth0.20");
    let last = moved.split('.').next_back().unwrap_or("0").parse::<u8>().unwrap_or(0);
    assert!(
        (50..=80).contains(&last),
        "VLAN lease: {moved}"
    );
    lan_peer
        .add_address_on("eth0.20", &format!("{moved}/24"))
        .expect("use the leased VLAN address");
    assert!(
        wait_dns(&lan_peer, "192.168.20.1", &moved),
        "leased VLAN client must resolve localhost through the moved DNS"
    );
    assert!(
        !lan_peer
            .dns_resolves("10.56.0.1", "localhost", "10.56.0.2")
            .unwrap_or(true),
        "the previous LAN resolver must stop"
    );
    assert!(
        lan_peer.dhcp_offer().unwrap().is_none(),
        "the previous LAN must stop leasing"
    );
}

#[test]
fn published_firewall_policy_blocks_lan_input_and_keeps_forwarding() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("192.0.2.2/32", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [mgmt],
        "lan_prefix": "10.56.0.0/24",
        "dhcp_pool": "10.56.0.100-10.56.0.140"
    });
    https_bootstrap(&guest, &bootstrap.to_string());
    assert!(
        lan_peer.ping("10.56.0.1").expect("LAN input probe"),
        "LAN input starts permitted"
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("forwarded probe"),
        "LAN-to-WAN forwarding starts permitted"
    );
    peer_https_stays_down(&wan_peer, "192.0.2.1");

    let alice = https_login_admin(&guest, "alice", "secret12");
    let routes: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    let draft = serde_json::json!({
        "base_revision": routes["revision"].as_u64().unwrap(),
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan}],
    });
    let (code, body) = alice
        .exchange("POST", "/api/draft/save", Some(&draft.to_string()), 20)
        .unwrap();
    assert_eq!(code, 200, "route draft failed: {body}");
    guest
        .browser_configure_policy(
            "save-draft",
            "alice",
            "secret12",
            &lan,
            "10.56.0.2",
            "icmp",
            "drop",
            "",
        )
        .expect("firewall rule joins the private route draft");
    guest
        .browser_configure_policy(
            "apply-draft",
            "alice",
            "secret12",
            "",
            "",
            "any",
            "drop",
            "10.56.0.2",
        )
        .expect("reviewed draft applies the route and firewall policy together");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let applied = alice.get("/api/routes").unwrap();
    assert!(applied.contains("198.51.100.0/24"), "{applied}");
    assert!(
        !lan_peer.ping("10.56.0.1").expect("blocked LAN input"),
        "the firewall rule must drop the LAN peer echo"
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("forwarded probe after policy"),
        "forwarded LAN-to-WAN traffic stays permitted"
    );
    peer_https_stays_down(&wan_peer, "192.0.2.1");

    guest
        .browser_configure_policy(
            "reject",
            "alice",
            "secret12",
            &wan,
            "",
            "any",
            "accept",
            "",
        )
        .expect("WAN input accept is rejected");
    assert!(
        !lan_peer.ping("10.56.0.1").unwrap(),
        "rejected policy must leave the drop in place"
    );
    assert!(lan_peer.ping("192.0.2.2").unwrap(), "forwarding stays in place");
    peer_https_stays_down(&wan_peer, "192.0.2.1");

    guest
        .browser_remove_policy_rule(
            "alice",
            "secret12",
            &format!("iifname \"{lan}\" ip saddr 10.56.0.2 icmp type echo-request drop"),
        )
        .expect("the rendered page removes the drop rule");
    assert!(
        lan_peer.ping("10.56.0.1").expect("permitted LAN input"),
        "removing the rule must permit the LAN peer echo again"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let policy = alice.get("/api/firewall").unwrap();
    assert!(!policy.contains("echo-request"), "{policy}");
    assert!(lan_peer.ping("192.0.2.2").unwrap(), "forwarding stays in place");
    peer_https_stays_down(&wan_peer, "192.0.2.1");
}

fn wait_udp(peer: &NetworkPeer, address: &str, port: u16) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if peer.udp_port_listening(address, port).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

fn assert_wireguard_key_hidden(body: &str) {
    assert!(
        !body.contains(WG_PRIVATE),
        "ordinary status must omit the WireGuard private key: {body}"
    );
}

#[test]
fn published_wireguard_ui_listens_and_hides_the_private_key() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    https_bootstrap(
        &guest,
        &serde_json::json!({
            "hostname": "fwos-box", "admin": "alice", "password": "secret12",
            "interfaces": [
                {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
                {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
                {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
            ],
            "ui_exposure": [mgmt],
            "lan_prefix": "10.56.0.0/24",
            "dhcp_pool": "10.56.0.100-10.56.0.140"
        })
        .to_string(),
    );
    guest
        .browser_configure_wireguard(
            "save-draft",
            "alice",
            "secret12",
            "wg0",
            WG_PRIVATE,
            "51820",
            "10.13.13.1/24",
            "198.51.100.0/24",
            "10.13.13.2",
        )
        .expect("WireGuard draft is saved from the rendered editor");
    let alice = https_login_admin(&guest, "alice", "secret12");
    let draft = alice.get("/api/draft").unwrap();
    let status = alice.get("/api/status").unwrap();
    let tunnels = alice.get("/api/wireguard").unwrap();
    assert_wireguard_key_hidden(&draft);
    assert_wireguard_key_hidden(&status);
    assert_wireguard_key_hidden(&tunnels);
    assert!(
        draft.contains("\"private_key_set\":true") && draft.contains("wg0"),
        "private draft keeps the key without revealing it: {draft}"
    );
    guest
        .browser_configure_wireguard(
            "apply-draft",
            "alice",
            "secret12",
            "wg0",
            "",
            "",
            "",
            "",
            "",
        )
        .expect("reviewed WireGuard draft applies");
    assert!(
        wait_udp(&lan_peer, "10.56.0.1", 51820),
        "accepted WireGuard listen port must take effect"
    );
    let routes = https_login_admin(&guest, "alice", "secret12")
        .get("/api/routes")
        .unwrap();
    assert!(routes.contains("198.51.100.0/24"), "{routes}");
    assert!(routes.contains("wg0"), "{routes}");
    lan_peer
        .add_route("10.13.13.1/32", "10.56.0.1")
        .expect("route toward the tunnel address");
    assert!(
        lan_peer.ping("10.13.13.1").expect("tunnel address probe"),
        "the accepted WireGuard address must answer"
    );
    guest
        .browser_configure_wireguard(
            "apply",
            "alice",
            "secret12",
            "wg0",
            "",
            "51821",
            "10.13.13.1/24",
            "",
            "",
        )
        .expect("listen port changes without retyping the private key");
    assert!(
        wait_udp(&lan_peer, "10.56.0.1", 51821),
        "new listen port must take effect"
    );
    assert!(
        !lan_peer.udp_port_listening("10.56.0.1", 51820).unwrap_or(true),
        "old listen port must close"
    );
    let tunnels = https_login_admin(&guest, "alice", "secret12")
        .get("/api/wireguard")
        .unwrap();
    assert_wireguard_key_hidden(&tunnels);
    assert!(tunnels.contains("\"private_key_set\":true"), "{tunnels}");
    guest
        .browser_configure_wireguard(
            "reject",
            "alice",
            "secret12",
            "wg0",
            "not-a-key",
            "51821",
            "10.13.13.1/24",
            "",
            "",
        )
        .expect("invalid private key is rejected");
    guest
        .browser_configure_wireguard(
            "failed",
            "alice",
            "secret12",
            &lan,
            WG_PRIVATE,
            "51822",
            "10.13.14.1/24",
            "",
            "",
        )
        .expect("a tunnel that cannot be created restores the previous network");
    assert!(
        wait_udp(&lan_peer, "10.56.0.1", 51821),
        "restoration must keep the accepted tunnel"
    );
    let tunnels = https_login_admin(&guest, "alice", "secret12")
        .get("/api/wireguard")
        .unwrap();
    assert_wireguard_key_hidden(&tunnels);
    assert!(tunnels.contains("51821"), "{tunnels}");
}

fn accepted_revision(session: &fwos_dev::HttpsSession<'_>) -> u64 {
    let routes: serde_json::Value = serde_json::from_str(&session.get("/api/routes").unwrap()).unwrap();
    routes["revision"].as_u64().expect("Accepted revision")
}

#[test]
fn published_network_export_and_import_round_trip_through_the_ui() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("198.51.100.0/24", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("198.51.100.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    https_bootstrap(
        &guest,
        &serde_json::json!({
            "hostname": "fwos-box", "admin": "alice", "password": "secret12",
            "interfaces": [
                {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
                {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
                {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
            ],
            "ui_exposure": [mgmt],
            "lan_prefix": "10.56.0.0/24",
            "dhcp_pool": "10.56.0.100-10.56.0.140"
        })
        .to_string(),
    );
    guest
        .browser_configure_wireguard(
            "apply", "alice", "secret12", "wg0", WG_PRIVATE, "51820", "10.13.13.1/24", "", "",
        )
        .expect("secret-bearing WireGuard configuration is accepted");
    assert!(wait_udp(&lan_peer, "10.56.0.1", 51820));

    // Export is never an unauthenticated download path.
    for path in ["/api/desired-state/export", "/api/desired-state/import"] {
        let (code, body) = guest
            .https_exchange("POST", path, Some(r#"{"acknowledge_sensitive":true}"#), 15)
            .expect("anonymous transfer response");
        assert_eq!(code, 401, "{path} must require sign-in: {body}");
        assert_wireguard_key_hidden(&body);
    }
    let alice = https_login_admin(&guest, "alice", "secret12");
    let (code, body) = alice
        .exchange("POST", "/api/desired-state/export", Some(r#"{"acknowledge_sensitive":false}"#), 15)
        .unwrap();
    assert_eq!(code, 400, "export needs the sensitive-file acknowledgement: {body}");
    assert_wireguard_key_hidden(&body);
    for path in ["/api/status", "/api/wireguard", "/api/draft", "/api/apply-confirmation", "/api/routes"] {
        assert_wireguard_key_hidden(&alice.get(path).unwrap());
    }
    let revision = accepted_revision(&alice);

    // The exported file holds a network secret; remove it even if the test fails.
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = std::env::temp_dir().join(format!("fwos-transfer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let exported_path = dir.join("exported.toml");
    guest
        .browser_transfer_desired_state("export", "alice", "secret12", &exported_path, WG_PRIVATE, "")
        .expect("rendered export downloads the network file");
    let exported = std::fs::read_to_string(&exported_path).unwrap();
    assert!(exported.starts_with("# SENSITIVE"), "{exported}");
    assert!(exported.contains(WG_PRIVATE), "export must restore the WireGuard key");
    assert!(exported.contains("fwos-network-desired-state"));
    assert!(!exported.contains("secret12") && !exported.contains("alice"), "no Identity configuration");

    // Identity configuration changed after the export must survive the import.
    let (code, body) = alice
        .exchange("POST", "/api/administrators", Some(r#"{"username":"bob","password":"secret34"}"#), 15)
        .unwrap();
    assert_eq!(code, 200, "{body}");

    let write = |name: &str, content: &str| {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    let malformed = write("malformed.toml", "this is not a network export [");
    guest
        .browser_transfer_desired_state("reject", "alice", "secret12", &malformed, WG_PRIVATE, "")
        .expect("malformed file is rejected in the page");
    let invalid = write("invalid.toml", &exported.replace(WG_PRIVATE, "not-a-key"));
    guest
        .browser_transfer_desired_state("reject", "alice", "secret12", &invalid, WG_PRIVATE, "")
        .expect("invalid network is rejected in the page");
    let identity = serde_json::json!({
        "base_revision": revision,
        "content": format!("administrators = [\"mallory\"]\n{exported}"),
    });
    let (code, body) = alice
        .exchange("POST", "/api/desired-state/import", Some(&identity.to_string()), 30)
        .unwrap();
    assert_eq!(code, 400, "a network import cannot carry Identity configuration: {body}");
    assert_eq!(accepted_revision(&alice), revision, "rejected imports leave Accepted state");
    assert!(alice.get("/api/draft").unwrap().contains("\"status\":\"none\""));
    assert!(!lan_peer.ping("198.51.100.2").unwrap());

    assert!(exported.contains("routes = []") && exported.contains("listen_port = 51820"), "{exported}");
    let edited = exported
        .replace(
            "routes = []",
            "routes = [{ to = \"198.51.100.0/24\", via = \"192.0.2.2\" }]",
        )
        .replace("listen_port = 51820", "listen_port = 51821");
    let edited_path = write("edited.toml", &edited);
    guest
        .browser_transfer_desired_state("import", "alice", "secret12", &edited_path, WG_PRIVATE, "")
        .expect("valid file becomes the private draft");
    assert_eq!(accepted_revision(&alice), revision, "import does not apply");
    assert!(!lan_peer.ping("198.51.100.2").unwrap(), "import does not change forwarding");
    assert!(wait_udp(&lan_peer, "10.56.0.1", 51820), "import keeps the live tunnel");
    let draft = alice.get("/api/draft").unwrap();
    assert_wireguard_key_hidden(&draft);
    assert!(draft.contains("\"sections\":[\"import\"]"), "{draft}");
    assert!(draft.contains("198.51.100.0/24") && draft.contains("\"private_key_set\":true"), "{draft}");
    let again = serde_json::json!({"base_revision": revision, "content": edited});
    let (code, body) = alice
        .exchange("POST", "/api/desired-state/import", Some(&again.to_string()), 30)
        .unwrap();
    assert_eq!(code, 409, "an import cannot replace a pending draft: {body}");
    let (code, _) = alice
        .exchange("POST", "/api/routes/save-and-apply", Some(&serde_json::json!({
            "base_revision": revision, "action": "add",
            "route": {"to": "203.0.113.0/24", "via": "192.0.2.2"},
        }).to_string()), 30)
        .unwrap();
    assert_eq!(code, 409, "quick apply still refuses while the imported draft is pending");

    guest
        .browser_transfer_desired_state("apply-draft", "alice", "secret12", &edited_path, WG_PRIVATE, "")
        .expect("reviewed imported draft applies through the shared engine");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision + 1);
    assert!(lan_peer.ping("198.51.100.2").unwrap(), "imported route forwards");
    assert!(wait_udp(&lan_peer, "10.56.0.1", 51821), "imported listen port takes effect");
    assert!(!lan_peer.udp_port_listening("10.56.0.1", 51820).unwrap_or(true));
    let bob = https_login_admin(&guest, "bob", "secret34");
    assert!(bob.get("/api/administrators").unwrap().contains("bob"));
    for path in ["/api/status", "/api/wireguard", "/api/draft", "/api/apply-confirmation"] {
        assert_wireguard_key_hidden(&alice.get(path).unwrap());
    }
    let (code, reexport) = alice
        .exchange("POST", "/api/desired-state/export", Some(r#"{"acknowledge_sensitive":true}"#), 15)
        .unwrap();
    assert_eq!(code, 200);
    assert!(reexport.contains(WG_PRIVATE) && reexport.contains("listen_port = 51821"));
}

const EXPORT_PASSPHRASE: &str = "correct horse battery staple";

fn age_decrypt(armored: &str, passphrase: &str) -> String {
    let identity = age::scrypt::Identity::new(passphrase.to_owned().into());
    String::from_utf8(age::decrypt(&identity, armored.as_bytes()).expect("decrypt export")).unwrap()
}

fn age_encrypt(plaintext: &str, passphrase: &str) -> String {
    let mut recipient = age::scrypt::Recipient::new(passphrase.to_owned().into());
    recipient.set_work_factor(18);
    age::encrypt_and_armor(&recipient, plaintext.as_bytes()).expect("encrypt export")
}

#[test]
fn published_encrypted_network_export_round_trips_and_rejects_bad_passphrases_through_the_ui() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.57.0.2/24").unwrap();
    lan_peer.add_route("198.51.100.0/24", "10.57.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("198.51.100.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    https_bootstrap(
        &guest,
        &serde_json::json!({
            "hostname": "fwos-box", "admin": "alice", "password": "secret12",
            "interfaces": [
                {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
                {"name": lan, "role": "lan", "addresses": ["10.57.0.1/24"]},
                {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
            ],
            "ui_exposure": [mgmt],
            "lan_prefix": "10.57.0.0/24",
            "dhcp_pool": "10.57.0.100-10.57.0.140"
        })
        .to_string(),
    );
    guest
        .browser_configure_wireguard(
            "apply", "alice", "secret12", "wg0", WG_PRIVATE, "51820", "10.13.13.1/24", "", "",
        )
        .expect("secret-bearing WireGuard configuration is accepted");
    assert!(wait_udp(&lan_peer, "10.57.0.1", 51820));
    let alice = https_login_admin(&guest, "alice", "secret12");
    let revision = accepted_revision(&alice);

    // Exported files hold network secrets; remove them even if the test fails.
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = std::env::temp_dir().join(format!("fwos-encrypted-transfer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let transfer = |action: &str, file: &std::path::Path, passphrase: &str| {
        guest.browser_transfer_desired_state(action, "alice", "secret12", file, WG_PRIVATE, passphrase)
    };

    // Encrypted export is an established age file that only the passphrase opens.
    let encrypted_path = dir.join("exported.toml.age");
    transfer("export", &encrypted_path, EXPORT_PASSPHRASE).expect("rendered encrypted export downloads");
    let encrypted = std::fs::read_to_string(&encrypted_path).unwrap();
    assert!(encrypted.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"), "{encrypted}");
    assert!(!encrypted.contains(WG_PRIVATE) && !encrypted.contains("fwos-network-desired-state"));
    let decrypted = age_decrypt(&encrypted, EXPORT_PASSPHRASE);
    assert!(decrypted.starts_with("# SENSITIVE") && decrypted.contains(WG_PRIVATE));
    assert!(!decrypted.contains("secret12") && !decrypted.contains("alice"), "no Identity configuration");

    // The explicitly sensitive plaintext export stays available.
    let plaintext_path = dir.join("exported.toml");
    transfer("export", &plaintext_path, "").expect("rendered plaintext export downloads");
    let plaintext = std::fs::read_to_string(&plaintext_path).unwrap();
    assert!(plaintext.starts_with("# SENSITIVE") && plaintext.contains(WG_PRIVATE));
    let (code, body) = alice
        .exchange(
            "POST",
            "/api/desired-state/export",
            Some(r#"{"acknowledge_sensitive":true,"passphrase":""}"#),
            15,
        )
        .unwrap();
    assert_eq!(code, 400, "an empty passphrase is not encryption: {body}");
    assert_wireguard_key_hidden(&body);

    // FWOS keeps no passphrase: ordinary views never show it.
    for path in ["/api/status", "/api/wireguard", "/api/draft", "/api/apply-confirmation", "/api/routes"] {
        let body = alice.get(path).unwrap();
        assert!(!body.contains(EXPORT_PASSPHRASE), "{path} exposes the passphrase");
        assert_wireguard_key_hidden(&body);
    }

    // Identity configuration changed after the export must survive every import.
    let (code, body) = alice
        .exchange("POST", "/api/administrators", Some(r#"{"username":"bob","password":"secret34"}"#), 15)
        .unwrap();
    assert_eq!(code, 200, "{body}");

    let write = |name: &str, content: &str| {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    assert!(decrypted.contains("routes = []") && decrypted.contains("listen_port = 51820"));
    let edited = decrypted
        .replace("routes = []", "routes = [{ to = \"198.51.100.0/24\", via = \"192.0.2.2\" }]")
        .replace("listen_port = 51820", "listen_port = 51821");
    let edited_path = write("edited.toml.age", &age_encrypt(&edited, EXPORT_PASSPHRASE));
    let mut damaged = encrypted.lines().map(str::to_owned).collect::<Vec<_>>();
    let middle = damaged.len() / 2;
    let replacement = if damaged[middle].starts_with('A') { "B" } else { "A" };
    damaged[middle].replace_range(..1, replacement);
    let damaged_path = write("damaged.toml.age", &(damaged.join("\n") + "\n"));
    let invalid_path = write(
        "invalid.toml.age",
        &age_encrypt(&decrypted.replace(WG_PRIVATE, "not-a-key"), EXPORT_PASSPHRASE),
    );
    let identity_path = write(
        "identity.toml.age",
        &age_encrypt(&format!("administrators = [\"mallory\"]\n{decrypted}"), EXPORT_PASSPHRASE),
    );
    for (file, passphrase, case) in [
        (&edited_path, "wrong horse battery staple", "wrong passphrase"),
        (&edited_path, "", "missing passphrase"),
        (&damaged_path, EXPORT_PASSPHRASE, "damaged file"),
        (&invalid_path, EXPORT_PASSPHRASE, "invalid decrypted network"),
        (&identity_path, EXPORT_PASSPHRASE, "decrypted Identity configuration"),
    ] {
        transfer("reject", file, passphrase).unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(accepted_revision(&alice), revision, "{case} leaves Accepted state");
        assert!(alice.get("/api/draft").unwrap().contains("\"status\":\"none\""), "{case} makes no draft");
    }
    assert!(!lan_peer.ping("198.51.100.2").unwrap(), "rejections do not change forwarding");
    assert!(wait_udp(&lan_peer, "10.57.0.1", 51820), "rejections keep the live tunnel");
    https_login_admin(&guest, "bob", "secret34");

    // The UI's own encrypted file restores with its passphrase into the same
    // reviewed private draft as the plaintext export of that revision.
    let proposed = |alice: &fwos_dev::HttpsSession<'_>| {
        let mut draft: serde_json::Value = serde_json::from_str(&alice.get("/api/draft").unwrap()).unwrap();
        assert_eq!(draft["status"], "pending");
        assert_eq!(draft["sections"], serde_json::json!(["import"]));
        for revisioned in ["base_revision", "accepted_revision", "version", "stale"] {
            draft.as_object_mut().unwrap().remove(revisioned);
        }
        draft
    };
    transfer("import", &encrypted_path, EXPORT_PASSPHRASE).expect("UI-encrypted export imports unchanged");
    assert_eq!(accepted_revision(&alice), revision, "import does not apply");
    let draft = alice.get("/api/draft").unwrap();
    assert_wireguard_key_hidden(&draft);
    assert!(!draft.contains(EXPORT_PASSPHRASE), "the draft exposes the passphrase");
    let from_encrypted = proposed(&alice);
    transfer("apply-draft", &encrypted_path, "").expect("reviewed encrypted import applies");
    let alice = https_login_admin(&guest, "alice", "secret12");
    transfer("import", &plaintext_path, "").expect("plaintext export imports unchanged");
    assert_eq!(proposed(&alice), from_encrypted, "encrypted and plaintext imports propose the same draft");
    transfer("apply-draft", &plaintext_path, "").expect("reviewed plaintext import applies");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision + 2);
    assert!(wait_udp(&lan_peer, "10.57.0.1", 51820), "restoring the export keeps the tunnel");

    // An operator-edited encrypted file imports and applies only on review.
    transfer("import", &edited_path, EXPORT_PASSPHRASE).expect("encrypted file becomes the private draft");
    assert_eq!(accepted_revision(&alice), revision + 2, "import does not apply");
    assert!(!lan_peer.ping("198.51.100.2").unwrap(), "import does not change forwarding");
    let draft = alice.get("/api/draft").unwrap();
    assert!(draft.contains("198.51.100.0/24"), "the draft proposes the edited route");
    transfer("apply-draft", &edited_path, "").expect("reviewed imported draft applies");
    let alice = https_login_admin(&guest, "alice", "secret12");
    assert_eq!(accepted_revision(&alice), revision + 3);
    assert!(lan_peer.ping("198.51.100.2").unwrap(), "imported route forwards");
    assert!(wait_udp(&lan_peer, "10.57.0.1", 51821), "imported listen port takes effect");
    let bob = https_login_admin(&guest, "bob", "secret34");
    assert!(bob.get("/api/administrators").unwrap().contains("bob"));
}

#[test]
fn published_qdisc_ui_keeps_forwarding_and_rejects_unknown_kinds() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("192.0.2.2/32", "10.56.0.1").unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    https_bootstrap(
        &guest,
        &serde_json::json!({
            "hostname": "fwos-box", "admin": "alice", "password": "secret12",
            "interfaces": [
                {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
                {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
                {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
            ],
            "ui_exposure": [mgmt],
            "lan_prefix": "10.56.0.0/24",
            "dhcp_pool": "10.56.0.100-10.56.0.140"
        })
        .to_string(),
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("forwarded probe"),
        "LAN-to-WAN forwarding starts permitted"
    );
    // fq_codel is commonly the kernel default, so first move the WAN root to
    // pfifo; the later fq_codel line then proves the reviewed draft changed it.
    let live = guest
        .browser_configure_qdisc("save-and-apply", "alice", "secret12", &wan, "pfifo")
        .expect("rendered shortcut installs pfifo");
    assert_eq!(
        root_qdisc_kind(&live, &wan).as_deref(),
        Some("pfifo"),
        "rendered live qdisc show must report pfifo at the WAN root: {live}"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let routes: serde_json::Value =
        serde_json::from_str(&alice.get("/api/routes").unwrap()).unwrap();
    let draft = serde_json::json!({
        "base_revision": routes["revision"].as_u64().unwrap(),
        "routes": [{"to": "198.51.100.0/24", "via": "192.0.2.2", "dev": wan}],
    });
    let (code, body) = alice
        .exchange("POST", "/api/draft/save", Some(&draft.to_string()), 20)
        .unwrap();
    assert_eq!(code, 200, "route draft failed: {body}");
    guest
        .browser_configure_qdisc("save-draft", "alice", "secret12", &wan, "fq_codel")
        .expect("qdisc joins the private route draft");
    let live = guest
        .browser_configure_qdisc("apply-draft", "alice", "secret12", &wan, "fq_codel")
        .expect("reviewed draft applies the route and qdisc together");
    assert_eq!(
        root_qdisc_kind(&live, &wan).as_deref(),
        Some("fq_codel"),
        "rendered live qdisc show must report fq_codel at the WAN root: {live}"
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("forwarded probe after fq_codel"),
        "traffic still forwards across the shaped WAN"
    );
    let alice = https_login_admin(&guest, "alice", "secret12");
    let applied = alice.get("/api/qdiscs").unwrap();
    let routes = alice.get("/api/routes").unwrap();
    assert!(applied.contains("fq_codel") && applied.contains(&wan), "{applied}");
    assert!(routes.contains("198.51.100.0/24"), "{routes}");
    let revision = serde_json::from_str::<serde_json::Value>(&applied).unwrap()["revision"]
        .as_u64()
        .unwrap();
    let rejected = serde_json::json!({
        "base_revision": revision,
        "qdiscs": [{"dev": wan, "kind": "tbf"}],
    });
    let (code, body) = alice
        .exchange("POST", "/api/qdiscs/apply", Some(&rejected.to_string()), 20)
        .unwrap();
    assert_eq!(code, 400, "unsupported qdisc must be rejected: {body}");
    assert!(body.contains("unsupported qdisc"), "{body}");
    let after = alice.get("/api/qdiscs").unwrap();
    assert!(after.contains("fq_codel"), "{after}");
    let effective = serde_json::from_str::<serde_json::Value>(&after).unwrap()["effective"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        root_qdisc_kind(&effective, &wan).as_deref(),
        Some("fq_codel"),
        "rejected kind must leave the live fq_codel queue: {effective}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&after).unwrap()["revision"].as_u64(),
        Some(revision)
    );
    assert!(
        lan_peer.ping("192.0.2.2").expect("forwarded probe after rejection"),
        "rejected qdisc must leave forwarding in place"
    );
}

/// The root qdisc kind `tc qdisc show` reports for one device.
fn root_qdisc_kind(show: &str, dev: &str) -> Option<String> {
    show.lines().find_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let on_dev = words.windows(2).any(|pair| pair == ["dev", dev]);
        (words.first() == Some(&"qdisc") && on_dev && words.contains(&"root"))
            .then(|| words.get(1).map(|kind| kind.to_string()))
            .flatten()
    })
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
fn invalid_bootstrap_values_preserve_console_selection_and_allow_new_owner() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without an injected credential");
    let selected = opt_user_net(&guest);
    let wan = other_console_nic(&guest, &selected);
    let invalid_vlan = serde_json::json!({
        "hostname": "abandoned-box",
        "admin": "abandoned",
        "password": "abandoned-passphrase",
        "interfaces": [
            {"name": format!("{selected}.4095"), "role": "lan", "parent": selected, "vlan": 4095},
            {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [format!("{selected}.4095")],
        "lan_prefix": "192.168.1.0/24"
    });
    let mut invalid_prefix = invalid_vlan.clone();
    invalid_prefix["interfaces"][0] = serde_json::json!({"name": selected, "role": "lan"});
    invalid_prefix["ui_exposure"] = serde_json::json!([selected]);
    invalid_prefix["lan_prefix"] = "invalid-prefix".into();
    for (label, payload) in [("VLAN 4095", invalid_vlan), ("LAN prefix", invalid_prefix)] {
        let (code, body) = guest
            .https_exchange("POST", "/api/bootstrap", Some(&payload.to_string()), 15)
            .expect("invalid Bootstrap input must receive an HTTP response");
        assert_eq!(code, 400, "{label} must be rejected before apply: {body}");
        let (code, body) = guest
            .https_exchange("GET", "/api/status", None, 15)
            .expect("selected temporary HTTPS must remain available");
        assert_eq!(code, 200, "{label} must preserve selected HTTPS: {body}");
        let status: serde_json::Value = serde_json::from_str(&body).expect("valid status JSON");
        assert_eq!(status["bootstrapped"], false, "{label}");
        assert_eq!(status["interfaces"], serde_json::json!([]), "{label}");
        assert_eq!(status["ui_exposure"], serde_json::json!([]), "{label}");
        assert_ne!(status["hostname"], "abandoned-box", "{label}");
    }
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("externally reset rejected Bootstrap input");
    let after = serial_wait(&guest, from, 240, |text| {
        text.contains("FWOS Bootstrap console")
    });
    assert!(
        after.contains("FWOS Bootstrap console"),
        "invalid attempts must leave the Bootstrap console available: {after}"
    );

    let mut status = String::new();
    for _ in 0..90 {
        if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 5) {
            status = body;
            if status.contains("\"bootstrapped\":false")
                || status.contains("\"bootstrapped\": false")
            {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let status: serde_json::Value = serde_json::from_str(&status)
        .expect("console-selected HTTPS and status must survive invalid attempts");
    assert_eq!(status["bootstrapped"], false);
    assert_eq!(status["interfaces"], serde_json::json!([]));
    assert_eq!(status["ui_exposure"], serde_json::json!([]));
    assert_ne!(status["hostname"], "abandoned-box");

    let retry = wan_lan_bootstrap_json(&selected, &wan);
    https_bootstrap(&guest, &retry);
    let session = https_login_admin(&guest, "alice", "secret12");
    assert!(session.get("/api/status").is_ok());
    let abandoned_login = serde_json::json!({
        "source": "local", "username": "abandoned", "password": "abandoned-passphrase"
    });
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&abandoned_login.to_string()), 15)
        .expect("abandoned administrator login must get a response");
    assert_eq!(code, 401, "retry must not reuse tentative credentials");
}

fn post_bootstrap_in_flight(guest: &Guest, payload: &str) -> Child {
    start_bootstrap_sender(guest, payload, false).0
}

fn start_bootstrap_sender(
    guest: &Guest,
    payload: &str,
    report_response: bool,
) -> (Child, std::io::BufReader<std::process::ChildStdout>) {
    let mut child = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/browser/bootstrap-in-flight.mjs"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start external HTTPS Bootstrap sender");
    let input = serde_json::json!({
        "port": guest.https_port(), "payload": payload, "reportResponse": report_response
    });
    child
        .stdin
        .take()
        .expect("sender stdin")
        .write_all(input.to_string().as_bytes())
        .expect("send Bootstrap payload to external TLS client");
    let mut line = String::new();
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("sender stdout"));
    reader.read_line(&mut line).expect("sender progress line");
    assert_eq!(
        line.trim(),
        "sent",
        "external TLS client must send Bootstrap before reset"
    );
    (child, reader)
}

#[test]
fn external_reset_before_desired_persist_restores_clean_bootstrap_retry() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (selected, wan) = published_user_net_and_extra(&guest);
    let mut first: serde_json::Value =
        serde_json::from_str(&wan_lan_bootstrap_json(&selected, &wan))
            .expect("valid first Bootstrap payload");
    first["hostname"] = "interrupted-early".into();
    first["admin"] = "abandoned".into();
    first["password"] = "abandoned-passphrase".into();
    let mut sender = post_bootstrap_in_flight(&guest, &first.to_string());

    // Status reads Desired after its netd NIC request. An empty Desired in a
    // response that already shows the tentative hostname is an externally
    // visible pre-persist transition, not merely bytes sent by our client.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut observed = false;
    while std::time::Instant::now() < deadline {
        if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 1) {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&body) {
                observed = status["hostname"] == "interrupted-early"
                    && status["bootstrapped"] == false
                    && status["interfaces"] == serde_json::json!([])
                    && status["ui_exposure"] == serde_json::json!([]);
                if observed {
                    break;
                }
            }
        }
    }
    if !observed {
        let _ = sender.kill();
        let _ = sender.wait();
        panic!("public status must show tentative hostname but no persisted Desired before reset");
    }
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("externally interrupt Bootstrap before Desired persistence");
    let _ = sender
        .wait()
        .expect("external TLS sender exits after reset");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.contains("FWOS Bootstrap console") || text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.contains("FWOS Bootstrap console")
            && !rebooted.lines().any(|line| line.trim() == "admin:"),
        "pre-persist interruption must return to Bootstrap, not durable owner: {rebooted}"
    );

    let mut status = serde_json::Value::Null;
    for _ in 0..90 {
        if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 5) {
            if let Ok(current) = serde_json::from_str::<serde_json::Value>(&body) {
                if current["bootstrapped"] == false {
                    status = current;
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(status["bootstrapped"], false, "selected HTTPS must return");
    assert_eq!(status["interfaces"], serde_json::json!([]));
    assert_eq!(status["ui_exposure"], serde_json::json!([]));
    assert_ne!(status["hostname"], "interrupted-early");

    let abandoned = serde_json::json!({
        "source": "local", "username": "abandoned", "password": "abandoned-passphrase"
    });
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&abandoned.to_string()), 15)
        .expect("tentative administrator login must receive a response");
    assert_eq!(code, 401, "interrupted Identity must not survive");
    https_bootstrap(&guest, &wan_lan_bootstrap_json(&selected, &wan));
    assert!(https_login_admin(&guest, "alice", "secret12")
        .get("/api/status")
        .is_ok());
}

#[test]
fn externally_removed_wan_during_bootstrap_restores_clean_retry_after_reset() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (selected, wan) = published_user_net_and_extra(&guest);
    let first = serde_json::json!({
        "hostname": "interrupted-network",
        "admin": "abandoned",
        "password": "abandoned-passphrase",
        "interfaces": [
            {"name": selected, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": format!("{wan}.42"), "role": "wan", "parent": wan, "vlan": 42, "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [selected],
        "lan_prefix": "10.0.2.0/24",
        "dhcp_pool": "10.0.2.100-10.0.2.200"
    });
    let (mut sender, mut response) = start_bootstrap_sender(&guest, &first.to_string(), true);
    guest
        .qemu_unplug_extra_nic()
        .expect("externally remove physical WAN parent after valid Bootstrap request was sent");
    let mut line = String::new();
    response
        .read_line(&mut line)
        .expect("Bootstrap response code");
    sender
        .wait()
        .expect("external HTTPS Bootstrap sender exits");
    let raw = line
        .trim()
        .strip_prefix("response:502:")
        .unwrap_or_else(|| {
            panic!("missing tagged WAN parent must fail after apply begins: {line}")
        });
    let failure: serde_json::Value = serde_json::from_str(raw).expect("late apply error JSON");
    assert!(
        failure["error"]
            .as_str()
            .is_some_and(|error| error.contains(&format!("ip link add link {wan}"))),
        "late failure must identify tagged WAN link creation, after journal and opt teardown: {failure}"
    );
    let (code, body) = guest
        .https_exchange("GET", "/api/status", None, 15)
        .expect("selected temporary HTTPS must be restored after failed apply");
    assert_eq!(code, 200);
    let failed_status: serde_json::Value = serde_json::from_str(&body).expect("status JSON");
    assert_eq!(failed_status["bootstrapped"], false);
    assert_eq!(failed_status["interfaces"], serde_json::json!([]));
    assert_eq!(failed_status["ui_exposure"], serde_json::json!([]));
    let abandoned = serde_json::json!({
        "source": "local", "username": "abandoned", "password": "abandoned-passphrase"
    });
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&abandoned.to_string()), 15)
        .expect("same-boot failed administrator login must receive a response");
    assert_eq!(
        code, 401,
        "failed apply must discard tentative Identity immediately"
    );
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("externally reset after failed network apply");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.contains("FWOS Bootstrap console") || text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.contains("FWOS Bootstrap console")
            && !rebooted.lines().any(|line| line.trim() == "admin:"),
        "interrupted network apply must not commit ownership: {rebooted}"
    );

    let mut status = serde_json::Value::Null;
    for _ in 0..90 {
        if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 5) {
            if let Ok(current) = serde_json::from_str::<serde_json::Value>(&body) {
                if current["bootstrapped"] == false {
                    status = current;
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(status["bootstrapped"], false, "selected HTTPS must return");
    assert_eq!(status["interfaces"], serde_json::json!([]));
    assert_eq!(status["ui_exposure"], serde_json::json!([]));
    assert_ne!(status["hostname"], "interrupted-network");
    let (code, _) = guest
        .https_exchange("POST", "/api/login", Some(&abandoned.to_string()), 15)
        .expect("tentative administrator login must receive a response");
    assert_eq!(code, 401, "tentative Identity must be discarded");
    let retry = serde_json::json!({
        "hostname": "new-owner",
        "admin": "alice",
        "password": "secret12",
        "interfaces": [
            {"name": selected, "role": "lan", "addresses": ["10.0.2.15/24"]},
            {"name": format!("{selected}.10"), "role": "wan", "parent": selected, "vlan": 10, "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [selected],
        "lan_prefix": "10.0.2.0/24",
        "dhcp_pool": "10.0.2.100-10.0.2.200"
    });
    https_bootstrap(&guest, &retry.to_string());
    assert!(https_login_admin(&guest, "alice", "secret12")
        .get("/api/status")
        .is_ok());
}

#[test]
fn external_reset_during_bootstrap_yields_either_clean_retry_or_completed_owner() {
    let _guard = guest_lock();
    let guest = Guest::boot_published_host_image_two_nics()
        .expect("published Disk image must boot without injected credentials");
    let (selected, lan) = published_user_net_and_extra(&guest);
    let first = serde_json::json!({
        "hostname": "interrupted-box",
        "admin": "first_owner",
        "password": "first-passphrase",
        "interfaces": [
            {"name": selected, "role": "wan", "addresses": ["192.0.2.1/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.0.3.15/24"]}
        ],
        "ui_exposure": [lan],
        "lan_prefix": "10.0.3.0/24",
        "dhcp_pool": "10.0.3.100-10.0.3.200"
    });
    assert!(
        https_up(&guest),
        "console-selected temporary HTTPS starts available"
    );
    let mut sender = post_bootstrap_in_flight(&guest, &first.to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut lost_selected_https = false;
    let mut failed_probes = 0;
    while std::time::Instant::now() < deadline {
        if guest.https_exchange("GET", "/", None, 1).is_err() {
            failed_probes += 1;
            if failed_probes >= 2 {
                lost_selected_https = true;
                break;
            }
        } else {
            failed_probes = 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !lost_selected_https {
        let _ = sender.kill();
        let _ = sender.wait();
        panic!("the external workstation must observe selected temporary HTTPS disappear when that NIC becomes WAN before cutting power");
    }
    let from = guest.serial().len();
    guest
        .qemu_system_reset()
        .expect("externally cut power during HTTPS Bootstrap request");
    let _ = sender
        .wait()
        .expect("external TLS sender exits after reset");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.contains("FWOS Bootstrap console") || text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.contains("FWOS Bootstrap console")
            || rebooted.lines().any(|line| line.trim() == "admin:"),
        "reboot after interrupted request must reach a console mode: {rebooted}"
    );
    if rebooted.lines().any(|line| line.trim() == "admin:") {
        println!("external Bootstrap reset observed durable ownership after reboot");
        assert!(
            !rebooted.contains("FWOS Bootstrap console"),
            "durable ownership must not reopen Bootstrap"
        );
        serial_login_admin_from(&guest, "first_owner", "first-passphrase", from);
        assert!(
            guest.https_get_extra("/").is_ok(),
            "configured LAN UI must be reachable"
        );
        let (code, _) = guest
            .https_exchange_extra("POST", "/api/bootstrap", Some(&first.to_string()), 15)
            .expect("completed appliance must reject unauthenticated Bootstrap");
        assert_eq!(code, 409);
    } else {
        println!("external Bootstrap reset observed clean incomplete retry after reboot");
        let mut recovered = false;
        for _ in 0..90 {
            if let Ok((200, body)) = guest.https_exchange("GET", "/api/status", None, 5) {
                if let Ok(status) = serde_json::from_str::<serde_json::Value>(&body) {
                    recovered = status["bootstrapped"] == false
                        && status["interfaces"] == serde_json::json!([])
                        && status["ui_exposure"] == serde_json::json!([]);
                    if recovered {
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        assert!(
            recovered,
            "interrupted attempt must restore temporary HTTPS and empty Desired state"
        );
        let abandoned = serde_json::json!({
            "source": "local", "username": "first_owner", "password": "first-passphrase"
        });
        let (code, _) = guest
            .https_exchange("POST", "/api/login", Some(&abandoned.to_string()), 15)
            .expect("tentative credentials must be rejected");
        assert_eq!(code, 401);
        https_bootstrap(&guest, &wan_lan_bootstrap_json(&selected, &lan));
        assert!(https_login_admin(&guest, "alice", "secret12")
            .get("/api/status")
            .is_ok());
    }
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
    guest
        .browser_one_nic_bootstrap_warning()
        .expect("rendered wizard warning follows the untagged WAN choice");

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
    let from = guest.serial().len();
    guest
        .serial_write("reboot\n")
        .expect("authenticated console reboot after losing untagged HTTPS");
    let rebooted = serial_wait(&guest, from, 300, |text| {
        text.lines().any(|line| line.trim() == "admin:")
    });
    assert!(
        rebooted.lines().any(|line| line.trim() == "admin:")
            && !rebooted.contains("FWOS Bootstrap console"),
        "durable one-NIC ownership must survive reboot without unauthenticated Bootstrap: {rebooted}"
    );
    https_must_not_answer(
        &guest,
        5,
        "reboot must not re-expose temporary HTTPS on the untagged WAN",
    );
    serial_login_admin_from(&guest, "alice", "secret12", from);
    let after = serial_cmd(&guest, "show\n", 20, |text| {
        text.contains("role = \"wan\"") && text.contains("role = \"lan\"")
    });
    assert!(after.contains(&lan) && after.contains("ui_exposure"));
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

fn wait_global_ipv6(peer: &NetworkPeer, prefix: &str) -> Option<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while std::time::Instant::now() < deadline {
        if let Some(address) = peer
            .global_ipv6()
            .unwrap_or_default()
            .into_iter()
            .find(|address| address.starts_with(prefix))
        {
            return Some(address);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    None
}

fn wait_ping(peer: &NetworkPeer, address: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if peer.ping(address).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

/// The routed LAN source reaches the WAN peer; the appliance's own WAN
/// address never stands in for it (no NAT66/NPTv6).
fn assert_routed_ipv6(lan_peer: &NetworkPeer, wan_peer: &NetworkPeer, lan_source: &str, target: &str) {
    assert!(wait_ping(lan_peer, target), "LAN-to-WAN IPv6 must forward to {target}");
    let sources = wan_peer
        .echo_request_sources(|| {
            let _ = lan_peer.ping(target);
        })
        .expect("WAN-side ICMPv6 capture");
    assert!(
        sources.iter().any(|source| source == lan_source),
        "WAN peer must see the LAN host's own address {lan_source}: {sources:?}"
    );
    assert!(
        sources.iter().all(|source| source == lan_source),
        "no translated IPv6 source may reach the WAN: {sources:?}"
    );
}

#[test]
fn published_ipv6_dual_stack_delegates_a_routed_lan_prefix() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let mut wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.add_address("10.56.0.2/24").unwrap();
    lan_peer.add_route("192.0.2.2/32", "10.56.0.1").unwrap();
    lan_peer.enable_slaac().unwrap();
    wan_peer.add_address("192.0.2.2/24").unwrap();
    wan_peer.add_address("2001:db8:ff::1/64").unwrap();
    wan_peer
        .start_ipv6_upstream("2001:db8:ff::", Some("2001:db8:ff00:100::/56"))
        .expect("external IPv6 upstream with prefix delegation");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": ["10.56.0.1/24"]},
            {"name": wan, "role": "wan", "addresses": ["192.0.2.1/24"]}
        ],
        "ui_exposure": [mgmt],
        "lan_prefix": "10.56.0.0/24",
        "dhcp_pool": "10.56.0.100-10.56.0.140"
    });
    https_bootstrap(&guest, &bootstrap.to_string());

    // IPv4-only: NAT44 forwards (the WAN peer has no route to 10.56.0.0/24),
    // and a LAN without a routed IPv6 prefix is not advertised.
    assert!(wait_ping(&lan_peer, "192.0.2.2"), "IPv4-only LAN-to-WAN uses NAT44");
    let live = guest
        .browser_configure_ipv6("observe", "alice", "secret12", &wan, "static", false, "no NAT66")
        .expect("IPv6 page reports the IPv4-only appliance");
    assert!(live.contains("LAN prefix (none): none"), "{live}");
    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(
        lan_peer.global_ipv6().unwrap().is_empty() && lan_peer.ipv6_default_router().unwrap().is_none(),
        "no RA without a delegated or routed prefix"
    );

    let live = guest
        .browser_configure_ipv6(
            "apply",
            "alice",
            "secret12",
            &wan,
            "dhcpv6",
            true,
            "delegated prefix 2001:db8:ff00:100::/56",
        )
        .expect("reviewed IPv6 change acquires an address and a delegated prefix");
    assert!(live.contains("2001:db8:ff::1000/128"), "DHCPv6 WAN address: {live}");
    assert!(live.contains("; IPv6 default route"), "RA default route: {live}");
    assert!(
        live.contains("LAN prefix (delegated): 2001:db8:ff00:100::/64 on"),
        "{live}"
    );
    let events = wan_peer.ipv6_upstream_events().unwrap();
    assert!(
        events.iter().any(|event| event["event"] == "delegated"),
        "upstream delegated the prefix: {events:?}"
    );

    let lan_address = wait_global_ipv6(&lan_peer, "2001:db8:ff00:100:")
        .expect("LAN host autoconfigures from the delegated prefix");
    let router = lan_peer
        .ipv6_default_router()
        .unwrap()
        .expect("LAN host learns FWOS as its IPv6 router");
    assert!(router.starts_with("fe80:"), "RA comes from the LAN link-local address: {router}");
    assert_routed_ipv6(&lan_peer, &wan_peer, &lan_address, "2001:db8:ff::1");
    assert!(wait_ping(&lan_peer, "192.0.2.2"), "dual-stack keeps NAT44 for IPv4");
    assert_eq!(
        lan_peer
            .https_response(&format!("{router}%eth0"))
            .expect("link-local HTTPS probe"),
        None,
        "neighbor discovery and RA work without link-local UI access"
    );
}

#[test]
fn published_ipv6_only_wan_reports_missing_delegation_and_routes_a_static_prefix() {
    let _guard = guest_lock();
    let lan_peer = NetworkPeer::new().expect("isolated LAN peer");
    let mut wan_peer = NetworkPeer::new().expect("isolated WAN peer");
    lan_peer.enable_slaac().unwrap();
    wan_peer.add_address("2001:db8:ff::1/64").unwrap();
    wan_peer
        .start_ipv6_upstream("2001:db8:ff::", None)
        .expect("external IPv6 upstream without prefix delegation");
    let guest = Guest::boot_published_host_image_with_user_net_and_peers(&[&lan_peer, &wan_peer])
        .expect("published Disk image");
    let mgmt = opt_user_net(&guest);
    let peers: Vec<String> = wait_console_nics(&guest)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name != &mgmt)
        .collect();
    let (lan, wan) = (peers[0].clone(), peers[1].clone());
    let bootstrap = serde_json::json!({
        "hostname": "fwos-box", "admin": "alice", "password": "secret12",
        "interfaces": [
            {"name": mgmt, "role": "mgmt", "addresses": ["10.0.2.15/24"]},
            {"name": lan, "role": "lan", "addresses": []},
            {"name": wan, "role": "wan", "addresses": []}
        ],
        "ui_exposure": [mgmt]
    });
    https_bootstrap(&guest, &bootstrap.to_string());

    let live = guest
        .browser_configure_ipv6(
            "save-and-apply",
            "alice",
            "secret12",
            &wan,
            "slaac",
            true,
            &format!("{wan}: 2001:db8:ff:"),
        )
        .expect("IPv6-only WAN autoconfigures with a prefix request");
    assert!(live.contains("delegated prefix none received"), "{live}");
    assert!(live.contains("LAN prefix (none): none"), "{live}");
    assert!(live.contains("There is no NAT66, NPTv6, or NAT64"), "{live}");
    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(
        lan_peer.global_ipv6().unwrap().is_empty() && lan_peer.ipv6_default_router().unwrap().is_none(),
        "without a delegated prefix the LAN gets no IPv6 rather than translation"
    );
    let wan_address = live
        .split_whitespace()
        .find(|word| word.starts_with("2001:db8:ff:"))
        .and_then(|cidr| cidr.split('/').next())
        .expect("WAN SLAAC address in live IPv6")
        .to_owned();

    guest
        .browser_configure_lan_services("reject", "alice", "secret12", "", "", "2001:db8:56::/48")
        .expect("a static prefix and prefix delegation together are rejected");
    guest
        .browser_configure_ipv6("apply", "alice", "secret12", &wan, "slaac", false, "")
        .expect("stop requesting prefix delegation");
    guest
        .browser_configure_lan_services("apply", "alice", "secret12", "", "", "2001:db8:56::/48")
        .expect("statically routed LAN prefix applies on an IPv6-only LAN");
    // The ISP routes the static prefix to the appliance's WAN address.
    wan_peer.add_route("2001:db8:56::/48", &wan_address).unwrap();

    let lan_address = wait_global_ipv6(&lan_peer, "2001:db8:56:")
        .expect("IPv6-only LAN host autoconfigures from the routed prefix");
    assert_routed_ipv6(&lan_peer, &wan_peer, &lan_address, "2001:db8:ff::1");
    let live = guest
        .browser_configure_ipv6("observe", "alice", "secret12", &wan, "slaac", false, "LAN prefix (static)")
        .expect("IPv6 page reports the static routed prefix");
    assert!(live.contains("2001:db8:56::/64"), "{live}");
}
