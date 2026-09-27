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

`tests/browser/administrators.mjs` uses the same isolated Firefox and stdin-only
credential handoff to create, change, and remove local administrators through
rendered controls. The Rust guest test checks each account's HTTPS login and
session behavior, then verifies removed and changed credentials on serial.
The driver reports only a fixed stage name and browser version, never form values.

`tests/browser/qdiscs.mjs` drives the existing qdisc controls. A peer still
forwards through the shaped interface, and an unsupported kind is rejected
before the live queue changes.

`tests/browser/wireguard.mjs` drives the supported WireGuard settings and a
route through that tunnel. Ordinary status and review text omit the private
key, and a peer checks that the accepted listen port is bound.

`tests/browser/transfer.mjs` drives network Desired state export and import.
Export needs the sensitive-file acknowledgement and saves the downloaded file.
Import sends a file into the private draft, and the driver then reviews and
applies it. The QEMU guest round-trips a WireGuard key and an edited route and
listen port. It checks that anonymous export and import get 401 and that
ordinary views omit the key. Malformed, invalid, and identity-bearing files are
rejected with the Accepted network unchanged. An administrator created after
the export survives the import. Peers see the imported route and port only
after the explicit apply.

`tests/browser/policy.mjs` drives firewall policy through the same private draft
and apply controls. Peers prove which packets the appliance forwards and which
it drops, while the UI stays off the WAN.

`tests/browser/services.mjs` drives post-bootstrap LAN DHCP and DNS settings
through the same draft and apply controls, including a VLAN and its services
in one revision. Peers check address leases and DNS answers before and after.

`tests/browser/ipv6.mjs` drives the WAN IPv6 mode (static, SLAAC, or DHCPv6)
and the prefix-delegation request through the same draft and apply controls,
and reads the page's live IPv6 state. `tests/peer/ipv6-upstream.py` is the
external IPv6 upstream on a WAN peer: it sends Router Advertisements, answers
DHCPv6 with an address and optionally a delegated prefix, and routes that
prefix to the appliance like an ISP. QEMU guests check IPv4-only NAT44,
dual-stack prefix delegation, and an IPv6-only WAN without delegation, with a
LAN peer autoconfiguring from the appliance's RA and its own address seen on
the WAN (no NAT66).

`tests/browser/interfaces.mjs` drives post-bootstrap interface, VLAN, role, and UI
exposure edits through the same private draft, review, and apply controls.
QEMU guests check two-NIC, VLAN-on-one-NIC, and Management NIC topologies with
external peers, including rejected topology changes that leave the accepted
network in place.

`tests/browser/routes.mjs` also drives private Draft Desired state through the
rendered route controls. The QEMU guest tests use two separately authenticated
administrators to verify private draft ownership, stale-base rejection,
reconciliation, logout/reboot persistence without activation, and fresh review
before applying. An external LAN/WAN peer checks that saving a draft does not
change forwarding. The browser receives route/revision projections only; the
complete Desired state (including network secrets) stays on the appliance.

## External network acceptance checks

`cargo test --test bootstrap_reachability -- --test-threads=1` drives the same
published QEMU appliance over its serial console and real Ethernet peers. In
addition to the image prerequisites, install `iproute`, `curl`, `dnsmasq`,
`tcpdump`, `coreutils` (`timeout`), Node.js, and Python 3. Non-interactive `sudo` is required
for task-owned TAP/bridge/veth links, peer network namespaces, and the DHCP/RA
and packet-capture helpers running inside those namespaces. QEMU itself runs as
the current user; no SSH, guest shell, injected credentials, or local HTTPS
relay is used.

Each peer has unique link/namespace names and its own temporary files. Only those
resources are cleaned up. The fixture does not change existing interfaces,
Workstation addresses/routes, default IPv6 settings, or system services. IPv6
is disabled individually on its owned host-facing links, and peer-only settings
prevent advertisements from configuring the Workstation. DHCP/RA ignores system
configuration and binds only the peer interface. Capture starts before guest
boot and observes incoming guest discovery packets; later real DHCP and IPv6
traffic provide positive controls. HTTP error responses count as exposed HTTPS,
while failed fixture commands fail the test.

Serialize appliance test runs across checkouts: the normal image builder uses
shared local Podman image tags even when `XDG_CACHE_HOME` is different.
