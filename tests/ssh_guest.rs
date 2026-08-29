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

    let ssh_ok = guest.ssh("true").expect("SSH into Host netns after netd is up");
    assert_eq!(ssh_ok, "");
}
