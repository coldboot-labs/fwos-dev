# fwos-dev

Workstation tooling: build a Fedora bootc qcow2 and run a QEMU guest. It is never installed on the appliance.

Requires a Fedora Workstation with rootful Podman, KVM, QEMU, and OVMF.

```
fwos-dev build   # qcow2 from quay.io/fedora/fedora-bootc:44 (cached)
fwos-dev run     # boot that disk under QEMU; SSH when the guest is up
cargo test       # SSH into a booted guest (the test seam)
```

SSH user is `fwos`. The private key and qcow2 are cached under `$XDG_CACHE_HOME/fwos-dev/fedora-bootc-44/` (or `~/.cache/fwos-dev/fedora-bootc-44/`). `build` and `cargo test` run `sudo podman`; the first image build can take several minutes.
