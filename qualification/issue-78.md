# Issue #78: v1 Release qualification

Qualification date: 2026-10-12. This report records commands and observed results from the existing `fwos-dev` Workstation tooling and its real-appliance tests. The tests use serial, HTTPS with rendered Firefox controls, and isolated external network peers; they do not inject credentials or use SSH or a guest Host shell.

## Inputs and environment

The sibling checkout versions used to build the Release were:

| Repository | Commit |
| --- | --- |
| `fwos-src` | `fd6bb25b425cc1778de957a2ea4c4d9c4b89cb03` |
| `fwos-image` | `7cbc0cbfbdcf37682eb5e30347925e865535093b` |
| `fwos-builtin-addons` | `6ef7bab9663b8db4825a401b15c60db18753245a` |
| `fwos-dev` build tooling | `ac6d25a0a30c6a6f58939e829b4c923041df815a` (qualification test added by this change) |

Workstation: Fedora 44, Linux `7.1.9-200.fc44.x86_64`, x86_64 Intel Core i7-8700K (8 logical CPUs), 11 GiB RAM, KVM and TAP available, QEMU 10.2.2, Podman 5.8.4, Rust 1.97.1, Node 24.18.0, Firefox 154.0. Tests used non-interactive `sudo`, `iproute`, `dnsmasq`, `tcpdump`, `curl`, and Python 3. The filesystem had roughly 9–13 GiB free during artifact construction after old Rust build outputs were cleaned; update fixtures later reduced headroom to about 4 GiB, so only old rebuildable caches were cleared. The local `quay.io/centos-bootc/bootc-image-builder:latest` image ID was `ba9dec3a9a314dad88bfcdd2299a8d2b441ced1a833b5cc4a335f5ee315a3922`; the `quay.io/fedora/fedora-bootc:44` base image ID was `225f2079aef8dd334c23bd5bf3c3df8795f598c38f89787059cc3bfc47e72342`. These IDs identify the images actually used even if their tags later move.

## Artifacts

From the `fwos-dev` checkout, with the three sibling checkouts above:

```sh
npm ci
cargo check --all-targets
cargo run -- build published
cargo run -- build installer
sha256sum ~/.cache/fwos-dev/fwos-host/published.qcow2 ~/.cache/fwos-dev/fwos-host/installer.iso
```

The published Disk image and self-contained Installer built successfully from Host image `sha256:da5683ff098bd484f8a7b577f255e55c245fbde59a312f488cd2cb4a2bf4514b` (`localhost/fwos:dev`). The Disk image is 1,373,579,776 bytes, SHA-256 `7061d4f9a6f9234305c3a5f61b93f108014c5138d5bcfd29962d6439b32f61e1`. The Installer ISO is 2,421,323,776 bytes, SHA-256 `7810e087ccc762a2c3417ec3ef6dc4b6d1d6b52a80703eab954f0ed516eaa761`.

## Test results

Run appliance tests serially across checkouts because the image builder uses shared local Podman tags. The existing test fixtures own and clean up their TAP links, peer namespaces, QEMU disks, and registry processes.

| Command / case | Result | Boundary observed |
| --- | --- | --- |
| `cargo check --all-targets` in `fwos-dev` and `fwos-src` | Pass | Both Rust source trees typecheck. |
| `cargo test -- --test-threads=1` in `fwos-src` | Pass: 162 tests, 0 failures | First-party Host, netd, console, UI, and update source tests. |
| `cargo test --test no_ssh -- --test-threads=1` | Pass: 4 tests | No test SSH adapter, injected key, or shipped SSH service in source and image definitions. |
| `cargo test -- --test-threads=1` in `fwos-dev` before the Installer review fix | Pass: 75 tests, 0 failures (7 Bootstrap reachability, 4 no-SSH, 63 QEMU guest, 1 startup network) | Full serial, HTTPS/browser, and external-peer regression suite before the test-fixture-only Installer change. |
| `cargo test --test qemu_guest published_vlan_services_and_firewall_apply_as_one_reviewed_revision -- --exact --nocapture --test-threads=1` | Pass: 1 test after correcting the test topology | The rendered UI saves VLAN, LAN services, and firewall changes in one private draft, then applies one reviewed revision; external peers observe the VLAN DHCP/DNS and firewall effect. |
| `cargo test --test qemu_guest installer_two_disks_yes_writes_only_selected_disk -- --exact --nocapture --test-threads=1` | Pass: 1 test in 164.72 s with the final serial protocol | In a two-disk boot, selecting disk 1 and separately typing `yes` completed installation and requested reboot; a stopped-guest virtual-content comparison found disk 1 changed and disk 2 unchanged. |
| `cargo test --test qemu_guest installer_ -- --test-threads=1 --nocapture` after the review fix | Pass: 6 tests, 0 failures in 652.45 s | Existing-partition warning, single- and multi-disk approval, declined inputs with byte-level virtual-content comparisons, and an offline Installer write followed by serial and HTTPS first boot. |

The first run of the new combined test failed because the test left the original interface as the first LAN while moving the service prefix to the VLAN. The fixture was corrected to make the original interface unused and to match the firewall rule by VLAN subnet. The rerun passed. This was a test topology error, not an accepted product failure.

The positive two-disk test initially used CRLF input in separate serial writes; terminal handling could consume the extra newline as a decline before `yes` arrived. Sending `1\n` and `yes\n` as two lines in one serial write made the intended two-step approval deterministic. Its focused rerun passed. Every decline case now compares the stopped virtual disk with a copy made before Installer boot, including the existing-partition case; the comparison checks virtual contents, rather than relying only on absence of the Bootstrap console.

The full run passed the representative one-, two-, and three-NIC topology cases; IPv4-only, dual-stack with prefix delegation, and IPv6-only without delegation; Management NIC and WAN UI exposure checks; multi-administrator drafts and confirmation/recovery; plaintext and encrypted import/export; and UI-driven Host update including rollback. The cases named in `tests/qemu_guest.rs` provide the individual reproduction filters. No integration failure remained in this run.

## Forwarding evidence

The combined test proves a peer can reach the initial LAN and forward to the WAN before draft save, and that saving three pages leaves the Accepted revision and live LAN input unchanged. After Apply, a VLAN peer receives a DHCP address in the requested pool, resolves DNS through the VLAN gateway, and is blocked by the accepted ICMP input rule. The WAN peer remains unable to reach the UI. Other existing tests cover routed IPv4/IPv6 forwarding, Management NIC isolation, qdisc behavior, and forwarding throughout update staging. This qualification records reachability and continuity; it sets no universal throughput target.

For a reproducible forwarding continuity measurement, rerun the existing update case with visible output:

```sh
cargo test --test qemu_guest published_ui_stages_host_update_keeps_forwarding_and_reboots_offline -- --exact --nocapture --test-threads=1
```

That rerun passed in 239.88 s. Its external LAN-to-WAN ICMP probe reported **0 lost of 52 sent during successful staging**, longest loss gap 0, and **0 lost of 1 sent during the deliberately failed staging attempt**, longest gap 0. The failure path finished quickly, so its single probe only establishes that no loss was observed in that short window. The same test also checks that staging leaves forwarding running, reports a separate reboot requirement, and can boot the staged Release after the registry goes offline. The test asserts no more than one consecutive lost probe and at most 5% loss; these are continuity regression checks on this KVM host, not a universal throughput SLA. No 10G throughput measurement was made.
