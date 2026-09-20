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

## Browser acceptance checks

The existing Rust appliance tests also drive the rendered UI with an isolated,
headless Firefox. Install Node.js 20 or newer and Firefox, then run `npm ci` in
this repo before `cargo test`. The driver uses the pinned `playwright-core`
dependency and Firefox's WebDriver BiDi support; it does not download a separate
browser or use a personal browser profile. The validated combination is Node.js
24.18.0, npm 11.16.0, Playwright Core 1.63.0, and Firefox 154.0. Firefox defaults
to `/usr/bin/firefox`; set `FWOS_FIREFOX_PATH` if it is installed elsewhere.

`tests/browser/login.mjs` is a driver invoked by `Guest`, not another test runner.
The Rust test owns the real QEMU appliance and creates its first administrator
through Bootstrap. It passes the guest's forwarded HTTPS URL and those test
credentials to the driver as JSON on stdin (`url`, `username`, `password`). The
driver uses real rendered controls to check rejection of a wrong password,
successful sign-in, useful status, session survival across reload, and sign-out.
The test fixture's hostname is `fwos-box`. Only loopback HTTPS targets are
accepted, with self-signed certificate validation disabled for the test guest.

The driver emits one redacted JSON result and exits nonzero on failure. Failure
output identifies the scenario stage; it never prints credentials, page content,
or raw browser errors. The scenario has a two-minute deadline and up to five
seconds to close an unresponsive browser. Browser debug logging is disabled to
keep form values out of test output. No SSH, guest shell, authentication shortcuts, or mocked appliance
internals are involved.
