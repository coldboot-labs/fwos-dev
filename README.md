# fwos-dev

Workstation tooling: build the host image into a qcow2 and run a QEMU guest. It is never installed on the appliance.

Requires a Fedora Workstation with rootful Podman, KVM, QEMU, and OVMF. Check out `fwos-image`, `fwos-src`, and `fwos-builtin-addons` next to this repo (`../fwos-image`, `../fwos-src`, `../fwos-builtin-addons`), or set `FWOS_IMAGE_DIR`, `FWOS_SRC_DIR`, and `FWOS_ADDONS_DIR`.

```
fwos-dev build            # Disk image with no SSH key and no password (cached)
fwos-dev build published  # same Disk image
fwos-dev build installer  # Anaconda Installer ISO from the same Host image (UEFI, self-contained)
fwos-dev run              # boot the Disk image under QEMU; observe serial and HTTPS
cargo test                # QEMU guests on serial (Appliance CLI) and HTTPS (UI); never SSH
```

The Disk image has no injected key and no default password. Observe it on the Bootstrap console over serial and the UI over HTTPS. Disks are cached under `$XDG_CACHE_HOME/fwos-dev/fwos-host/` (or `~/.cache/fwos-dev/fwos-host/`). `build` and `cargo test` run `sudo podman`; the first image build can take several minutes.
