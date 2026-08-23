use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => match fwos_dev::build_fedora_bootc_disk() {
            Ok(path) => {
                println!("{}", path.display());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("fwos-dev build: {err}");
                ExitCode::FAILURE
            }
        },
        Some("run") => match fwos_dev::Guest::boot_fedora_bootc() {
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
            eprintln!("Usage: fwos-dev <build|run>");
            eprintln!("  build  Convert Fedora bootc to a qcow2 (cached)");
            eprintln!("  run    Boot that qcow2 under QEMU and wait until SSH works");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("fwos-dev: unknown command {other:?}. Try fwos-dev help");
            ExitCode::FAILURE
        }
    }
}
