use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => match args.next().as_deref() {
            None | Some("published") => match fwos_dev::build_published_host_image_disk() {
                Ok(path) => {
                    println!("{}", path.display());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("fwos-dev build: {err}");
                    ExitCode::FAILURE
                }
            },
            Some("installer") => match fwos_dev::build_installer_iso() {
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
                    "fwos-dev build: unknown target {other:?}. Try fwos-dev build, fwos-dev build published, or fwos-dev build installer"
                );
                ExitCode::FAILURE
            }
        },
        Some("run") => match fwos_dev::Guest::boot_published_host_image() {
            Ok(guest) => {
                println!("guest is up. Observe serial (Appliance CLI) and HTTPS (UI).");
                println!(
                    "  UI: https://127.0.0.1:{}/ (self-signed)",
                    guest.https_port()
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
        Some("help") | Some("--help") | Some("-h") | None => {
            eprintln!("Workstation tooling (not installed on the appliance).\n");
            eprintln!("Usage: fwos-dev <build|build published|build installer|run>");
            eprintln!("  build            Disk image with no SSH key and no password");
            eprintln!("  build published  Disk image with no SSH key and no password");
            eprintln!("  build installer  Anaconda Installer ISO from the same Host image");
            eprintln!("  run              Boot the Disk image under QEMU; serial + HTTPS");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("fwos-dev: unknown command {other:?}. Try fwos-dev help");
            ExitCode::FAILURE
        }
    }
}
