use super::NetworkPeer;
use crate::{temp_work_dir, Error};
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// Packets emitted by the appliance, observed at the external Ethernet peer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryPackets {
    pub dhcp_v4: usize,
    pub dhcp_v6: usize,
    pub router_discovery: usize,
    pub neighbor_discovery: usize,
}

pub(super) struct Discovery {
    directory: PathBuf,
    children: Vec<Child>,
}

impl Discovery {
    pub(super) fn start(
        peer: &NetworkPeer,
        lease: &str,
        netmask: &str,
        prefix: &str,
    ) -> Result<Self, Error> {
        let mut service = Self {
            directory: temp_work_dir("fwos-dev-peer", "creating peer service directory")?,
            children: Vec::new(),
        };
        let pcap = service.file("traffic.pcap")?;
        let capture_log = service.file("capture.log")?;
        service.children.push(
            peer.command("timeout")
                .args([
                    "600",
                    "tcpdump",
                    "-i",
                    "eth0",
                    "-Q",
                    "in",
                    "-U",
                    "-s",
                    "128",
                    "-w",
                    "-",
                    "udp port 67 or udp port 68 or udp port 546 or udp port 547 or icmp6",
                ])
                .stdin(Stdio::null())
                .stdout(pcap)
                .stderr(capture_log)
                .spawn()
                .map_err(|e| Error::from_io("starting peer packet capture", e))?,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            service.ensure_alive()?;
            if fs::metadata(service.directory.join("traffic.pcap"))
                .is_ok_and(|meta| meta.len() >= 24)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::from_message(
                    "peer packet capture did not become ready",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let server_log = service.file("dnsmasq.log")?;
        service.children.push(
            peer.command("timeout")
                .args([
                    "600",
                    "dnsmasq",
                    "--conf-file=/dev/null",
                    "--no-resolv",
                    "--no-hosts",
                    "--port=0",
                    "--interface=eth0",
                    "--bind-interfaces",
                    "--keep-in-foreground",
                    "--user=root",
                    "--dhcp-authoritative",
                    "--enable-ra",
                    "--ra-param=eth0,3,0",
                    "--log-dhcp",
                    "--log-facility=-",
                ])
                .arg(format!("--dhcp-range={lease},{lease},{netmask},2m"))
                .arg(format!("--dhcp-range={prefix},ra-only,64,2m"))
                .arg(format!(
                    "--dhcp-leasefile={}",
                    service.directory.join("leases").display()
                ))
                .arg(format!(
                    "--pid-file={}",
                    service.directory.join("dnsmasq.pid").display()
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(server_log)
                .spawn()
                .map_err(|e| Error::from_io("starting peer DHCP/RA service", e))?,
        );
        std::thread::sleep(Duration::from_millis(200));
        service.ensure_alive()?;
        Ok(service)
    }

    fn file(&self, name: &str) -> Result<File, Error> {
        File::create(self.directory.join(name))
            .map_err(|e| Error::from_io("creating peer service output", e))
    }

    fn ensure_alive(&mut self) -> Result<(), Error> {
        for child in &mut self.children {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| Error::from_io("checking peer service", e))?
            {
                let logs = ["capture.log", "dnsmasq.log"]
                    .iter()
                    .map(|name| fs::read_to_string(self.directory.join(name)).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(Error::from_message(format!(
                    "peer service exited {status}: {logs}"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn packets(&mut self) -> Result<DiscoveryPackets, Error> {
        self.ensure_alive()?;
        let bytes = fs::read(self.directory.join("traffic.pcap"))
            .map_err(|e| Error::from_io("reading external packet capture", e))?;
        let little = match bytes.get(..4) {
            Some([0xd4, 0xc3, 0xb2, 0xa1]) => true,
            Some([0xa1, 0xb2, 0xc3, 0xd4]) => false,
            _ => return Err(Error::from_message("invalid peer pcap header")),
        };
        let number = |at: usize| {
            let word: [u8; 4] = bytes[at..at + 4].try_into().expect("checked pcap word");
            if little {
                u32::from_le_bytes(word)
            } else {
                u32::from_be_bytes(word)
            }
        };
        if bytes.len() < 24 || number(20) != 1 {
            return Err(Error::from_message("peer capture is not Ethernet"));
        }
        let mut counts = DiscoveryPackets::default();
        let mut offset = 24;
        while offset + 16 <= bytes.len() {
            let length = number(offset + 8) as usize;
            if length > 128 {
                return Err(Error::from_message("invalid peer capture record length"));
            }
            offset += 16;
            if offset + length > bytes.len() {
                break;
            } // tcpdump may still be writing the last record.
            let packet = &bytes[offset..offset + length];
            offset += length;
            if packet.len() < 14 {
                continue;
            }
            match &packet[12..14] {
                [0x08, 0x00] if packet.len() >= 34 && packet[23] == 17 => {
                    let udp = 14 + usize::from(packet[14] & 15) * 4;
                    if packet.get(udp..udp + 4) == Some(&[0, 68, 0, 67]) {
                        counts.dhcp_v4 += 1;
                    }
                }
                [0x86, 0xdd] if packet.len() >= 58 => match packet[20] {
                    17 if packet[54..58] == [2, 34, 2, 35] => counts.dhcp_v6 += 1,
                    58 => match packet[54] {
                        133 | 134 => counts.router_discovery += 1,
                        135 | 136 => counts.neighbor_discovery += 1,
                        _ => {}
                    },
                    _ => {}
                },
                _ => {}
            }
        }
        Ok(counts)
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        // NetworkPeer signals helpers in its owned namespace before this runs.
        // timeout also bounds their lifetime if construction fails halfway.
        for child in &mut self.children {
            let deadline = Instant::now() + Duration::from_secs(2);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}
