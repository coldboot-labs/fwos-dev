use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => match args.next().as_deref() {
            None => match fwos_dev::build_host_image_disk() {
                Ok(path) => {
                    println!("{}", path.display());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("fwos-dev build: {err}");
                    ExitCode::FAILURE
                }
            },
            Some("published") => match fwos_dev::build_published_host_image_disk() {
                Ok(path) => {
                    println!("{}", path.display());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("fwos-dev build: {err}");
                    ExitCode::FAILURE
                }
            },
            Some(other) => {
                eprintln!(
                    "fwos-dev build: unknown target {other:?}. Try fwos-dev build or fwos-dev build published"
                );
                ExitCode::FAILURE
            }
        },
        Some("run") => match fwos_dev::Guest::boot_host_image() {
            Ok(guest) => match fwos_dev::cached_ssh_key() {
                Ok(key) => {
                    println!("guest is up. SSH into the Host netns:");
                    println!(
                        "  ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {} fwos@127.0.0.1",
                        key.display(),
                        guest.ssh_port()
                    );
                    println!("leave this process running; Ctrl-C stops the guest.");
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                Err(err) => {
                    eprintln!("fwos-dev run: {err}");
                    ExitCode::FAILURE
                }
            },
            Err(err) => {
                eprintln!("fwos-dev run: {err}");
                ExitCode::FAILURE
            }
        },
        Some("help") | Some("--help") | Some("-h") | None => {
            eprintln!("Workstation tooling (not installed on the appliance).\n");
            eprintln!("Usage: fwos-dev <build|build published|run>");
            eprintln!("  build            Injected-key Disk image (test seam, cached)");
            eprintln!("  build published  Disk image with no SSH key and no password");
            eprintln!("  run              Boot the injected-key Disk image under QEMU");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("fwos-dev: unknown command {other:?}. Try fwos-dev help");
            ExitCode::FAILURE
        }
    }
}
