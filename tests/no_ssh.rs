//! Contract: cargo test does not SSH, Workstation tooling does not inject a
//! key, sshd is not a v1 product, and a guest must not answer on port 22.
//! Needles are assembled at runtime so this file does not match itself.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn host_image_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FWOS_IMAGE_DIR") {
        return PathBuf::from(dir);
    }
    crate_root().join("..").join("fwos-image")
}

fn src_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FWOS_SRC_DIR") {
        return PathBuf::from(dir);
    }
    crate_root().join("..").join("fwos-src")
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn rust_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(dir, &mut files);
    files
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect()
}

fn hits(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

fn ssh_method() -> String {
    format!("fn {}(", "ssh")
}

fn ssh_call() -> String {
    format!(".{}(", "ssh")
}

fn ssh_path() -> String {
    format!("::{}(", "ssh")
}

fn ssh_client() -> String {
    format!("{}(\"{}\")", "new", "ssh")
}

fn ssh_keygen() -> String {
    format!("\"{}\"", "ssh-keygen")
}

fn sshd_stamp() -> String {
    format!("{}_{}", "write", "sshd_stamp")
}

fn dnat_22() -> String {
    format!("{{{{ {}, 443", "22")
}

fn dport_22() -> String {
    format!("{} {}", "dport", "22")
}

#[test]
fn guest_api_has_no_ssh() {
    let lib = read(&crate_root().join("src/lib.rs"));
    let needle = ssh_method();
    assert!(
        !hits(&lib, &needle),
        "Guest::ssh still exists; cargo test must not SSH into a guest"
    );
    assert!(
        !hits(&lib, &ssh_client()),
        "Workstation tooling still invokes the ssh client"
    );
}

#[test]
fn cargo_test_does_not_ssh() {
    let tests = crate_root().join("tests");
    let needle = ssh_call();
    let path_call = ssh_path();
    let client = ssh_client();
    let mut offenders = Vec::new();
    for path in rust_under(&tests) {
        if path.file_name().and_then(|n| n.to_str()) == Some("no_ssh.rs") {
            continue;
        }
        let src = read(&path);
        if hits(&src, &needle) || hits(&src, &path_call) || hits(&src, &client) {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "cargo test still SSHes into a guest: {}",
        offenders.join(", ")
    );
}

#[test]
fn workstation_does_not_inject_an_ssh_key() {
    let mut src = read(&crate_root().join("src/lib.rs"));
    src.push_str(&read(&crate_root().join("src/main.rs")));
    assert!(
        !hits(&src, &ssh_keygen()),
        "Workstation tooling still generates an injected SSH key"
    );
    let user_key = format!("customizations.{}]]", "user");
    assert!(
        !hits(&src, &user_key),
        "Workstation tooling still injects a user SSH key into a Disk image"
    );
}

#[test]
fn sshd_is_not_a_v1_product() {
    let image = host_image_dir();
    assert!(
        image.join("Containerfile").is_file(),
        "host-image checkout not found at {}",
        image.display()
    );
    let overlay = image.join("overlay");
    let mut files = Vec::new();
    collect_files(&overlay, &mut files);
    files.push(image.join("Containerfile"));
    let mut offenders = Vec::new();
    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let rel = path.display().to_string();
        if name.contains("fwos-sshd") || rel.contains("sshd.service.d") {
            offenders.push(rel);
            continue;
        }
        let text = read(path);
        if text.contains("fwos-sshd") || text.contains("/usr/sbin/sshd") {
            offenders.push(rel);
        }
    }
    assert!(
        offenders.is_empty(),
        "sshd is still a v1 product (Host netns or mgmt): {}",
        offenders.join(", ")
    );

    let src = src_dir();
    let netd = read(&src.join("src/netd.rs"));
    assert!(
        !hits(&netd, &sshd_stamp()),
        "netd still writes an sshd-mgmt stamp"
    );
    assert!(
        !hits(&netd, &dnat_22()) && !hits(&netd, &dport_22()),
        "stick DNAT of port 22 is still programmed"
    );
}
