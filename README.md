# fwos-dev

Workstation tooling: build the host image into a qcow2 and run a QEMU guest. It is never installed on the appliance.

Requires a Fedora Workstation with rootful Podman, KVM, QEMU, and OVMF. Check out `fwos-image`, `fwos-src`, and `fwos-builtin-addons` next to this repo (`../fwos-image`, `../fwos-src`, `../fwos-builtin-addons`), or set `FWOS_IMAGE_DIR`, `FWOS_SRC_DIR`, and `FWOS_ADDONS_DIR`.

```
fwos-dev build            # injected-key Disk image (test seam, cached)
fwos-dev build published  # Disk image with no SSH key and no password
fwos-dev run              # boot the injected-key Disk image under QEMU; SSH when the guest is up
cargo test                # QEMU guests (injected-key SSH, and published serial)
```

SSH user on the injected-key disk is `fwos`. The published Disk image has no injected key and no default password; observe it on serial, not Host-netns SSH. Disks are cached under `$XDG_CACHE_HOME/fwos-dev/fwos-host/` (or `~/.cache/fwos-dev/fwos-host/`). `build` and `cargo test` run `sudo podman`; the first image build can take several minutes.
