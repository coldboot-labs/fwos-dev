# fwos-dev

Workstation tooling: build the host image into a qcow2 and run a QEMU guest. It is never installed on the appliance.

Requires a Fedora Workstation with rootful Podman, KVM, QEMU, and OVMF. Check out `fwos-image`, `fwos-src`, and `fwos-builtin-addons` next to this repo (`../fwos-image`, `../fwos-src`, `../fwos-builtin-addons`), or set `FWOS_IMAGE_DIR`, `FWOS_SRC_DIR`, and `FWOS_ADDONS_DIR`.

```
fwos-dev build   # qcow2 from the host image (cached)
fwos-dev run     # boot that disk under QEMU; SSH when the guest is up
cargo test       # SSH into a booted guest (the test seam)
```

SSH user is `fwos`. The host-image key and qcow2 are cached under `$XDG_CACHE_HOME/fwos-dev/fwos-host/` (or `~/.cache/fwos-dev/fwos-host/`). `build` and `cargo test` run `sudo podman`; the first image build can take several minutes.
