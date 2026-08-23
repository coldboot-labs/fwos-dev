use fwos_dev::Guest;

#[test]
fn ssh_into_booted_fedora_bootc_guest() {
    let guest = Guest::boot_fedora_bootc().expect("guest must boot under QEMU");
    let out = guest
        .ssh("uname -s")
        .expect("SSH into the guest Host netns");
    assert_eq!(out.trim(), "Linux");
}
