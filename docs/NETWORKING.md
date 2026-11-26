# Networking, 802.11 Wi-Fi, and TLS 1.3

- **Status:** implemented and exercised in host suites and QEMU (`net-service`,
  `wlan-service`, `huesos-tls`, `/bin/curl.elf`); physical multi-NIC/RF
  bare-metal qualification remains open
- **Related:** [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md),
  [SHELL_AND_STD.md](SHELL_AND_STD.md), [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md),
  [STATUS.md](STATUS.md)

HuesOS keeps every network protocol, wireless state machine, and cryptographic
handshake out of Ring 0. The kernel supplies only generic `DeviceLease`, MMIO
`Resource`, `Interrupt`, `Vmo`, `Channel`, and `Port` primitives; PCI enumeration
and BAR/MSI-X/MSI/INTx programming are performed in Ring 3 by `pci-manager` and
delivered through `driver-manager`.

---

## 1. Crate and service map

| Component | Kind | Safety boundary | Responsibility |
|---|---|---|---|
| `crates/huesos-net` | `no_std` library | `#![forbid(unsafe_code)]` | Ethernet II, ARP neighbor cache + pending queue, IPv4, ICMPv4 Echo, UDP, DHCPv4 (`DISCOVER→OFFER→REQUEST→ACK`), RFC 1035 DNS stub resolver (pointer compression + TTL cache), RFC 793/6298 TCP |
| `crates/huesos-ieee80211` | `no_std` library | `#![forbid(unsafe_code)]` | 802.11 MAC header/IE codec, LLC/SNAP framing, Beacon/Probe/Auth/Assoc Station Management Entity (SME) |
| `crates/huesos-wpa` | `no_std` library | `#![forbid(unsafe_code)]` | WPA2-PSK (IEEE 802.11i/RSN): PBKDF2-HMAC-SHA1 (4096 iter), PRF-384 PTK derivation, RFC 3394 AES Key Wrap, 4-Way EAPOL handshake, AES-128-CCMP encryption/MIC + 48-bit PN replay protection |
| `crates/huesos-rtw88` | `no_std` library | `#![forbid(unsafe_code)]` | Realtek `RTL8821CE` (`10ec:c821`) firmware parser (`/firmware/rtw8821c_fw.bin`), power-on sequence, MAC/BB/RF/TXAGC/RFE tables, 3-wire RF SPI, RX filter, and BT-PTA coexistence |
| `crates/huesos-tls` | `no_std` library | `#![forbid(unsafe_code)]` | RFC 8446 TLS 1.3 client (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, X25519 + P-256, `HelloRetryRequest`) + RFC 5280 X.509v3 chain validation |
| `crates/huesos-abi::{net,wlan}` | Wire ABI | `#![forbid(unsafe_code)]` | Fixed-header Channel IPC messages for socket lifecycle, DNS/ICMP/DHCP control, Wi-Fi scan/connect/status, and `wlan-service ↔ net-service` frame bridging |
| `crates/huesos-userspace/net-service` | `/services/net.elf` | Audited VirtIO MMIO/DMA | VirtIO 1.0 Modern (`1af4:1000` / `1af4:1041`) PCIe NIC driver, `huesos-net` TCP/IP stack owner, and dual-uplink bridge with `wlan-service` |
| `crates/huesos-userspace/wlan-service` | `/services/wlan.elf` | Audited PCIe MMIO/DMA | Realtek `RTL8821CE` PCIe Wi-Fi DriverHost + 802.11/WPA2-CCMP STA daemon |

---

## 2. PCI handoff and dual-uplink routing

1. `pci-manager` enumerates PCI/PCIe bridges (configuring Type-1 I/O, MMIO32,
   and 64-bit prefetchable windows) and matches VirtIO network controllers and
   network/wireless functions (`02:00:*`, `02:80:*`).
2. `driver-manager` mints per-device `DeviceLease`, BAR MMIO `Resource`, IRQ
   handles, and bounded `DmaPoolGrant` VMOs, then publishes deterministic
   `DriverBindingPublished` records to `net-service` and `wlan-service`
   (including explicit unbound/settlement notices when no hardware NIC is
   present so boot never stalls).
3. When a wired VirtIO link is up, `net-service` transmits Ethernet frames over
   its VirtIO TX/RX queues. When an 802.11 WPA2 association is active on
   `wlan-service`, `net-service` can route IPv4/ARP/DHCP/DNS/TCP traffic over the
   authenticated `wlan-service` LLC/SNAP ↔ Ethernet uplink channel without
   exposing 802.11 keys or PCIe DMA rings to socket clients.

---

## 3. TLS 1.3 and root certificates

`huesos-tls` implements a pure-Rust client stack without OpenSSL or C
dependencies:

- **Key exchange & cipher suites:** X25519 and NIST P-256 ECDHE (`HelloRetryRequest`
  supported), HKDF-SHA256/SHA384 key schedule, `AES-128-GCM`, `AES-256-GCM`, and
  `ChaCha20-Poly1305` record protection.
- **Certificate verification:** DER X.509v3 chain parsing, validity-window check,
  SAN/CN hostname matching (including RFC 6125 wildcard rules), BasicConstraints /
  KeyUsage checks, and RSA-PKCS#1v1.5 / RSA-PSS / ECDSA P-256/P-384 signature
  verification against the bundled Mozilla CA root store
  (`third_party/certs/ca-certificates.pem`, packaged in BOOTFS as
  `/etc/ssl/certs/ca-certificates.pem`).

---

## 4. Userspace APIs and capability attenuation

- **`huesos-std::net`:** safe `TcpStream`, `UdpSocket`, DNS `resolve`, ICMP
  `ping`, and interface status helpers over `AT_HUESOS_NET_SERVICE`.
- **Win64 `ws2_32.dll`:** maps Winsock2 (`WSAStartup`, `socket`, `connect`,
  `send`, `recv`, `sendto`, `recvfrom`, `getaddrinfo`, `closesocket`) onto the
  same `net-service` capability channel when a `.exe` holds network authority.
- **CLI utilities (`coreutils`):**
  - `netctl` — inspect link/IPv4/DHCP/gateway/DNS state and trigger DHCP renew;
  - `wlanctl` — scan BSSs, connect with WPA2-PSK, disconnect, and read RSSI/state;
  - `ping` — ICMPv4 echo probe with RTT statistics;
  - `curl` — HTTP/1.1 and TLS 1.3 HTTPS client using `huesos-tls`.
- **Shell `@caps` sandboxing:** `hsh` can strip network or Wi-Fi handles per
  command or pipeline (`@caps(net=none) curl ...`, `@caps(wlan=none) wlanctl ...`).
  Because handles are omitted from child `auxv` bootstrap rather than blocked by
  a cooperative userspace check, an attenuated process has no kernel path to
  `net-service` or `wlan-service`.

---

## 5. Current boundaries and non-claims

- **IPv4 client focus:** IPv6, server listen/accept backlog scaling, and kernel
  zero-copy socket rings are not yet implemented.
- **Simulated RF separation:** `VirtualRtw88Medium` in `huesos-rtw88` exists
  strictly behind `#[cfg(any(test, feature = "boot-selftest"))]` for deterministic
  WPA2/802.11 CI verification and is compiled out of production images.
- **Hardware coverage:** VirtIO 1.0 Modern is verified in QEMU; Realtek
  `RTL8821CE` register/firmware/WPA2 bring-up targets initial laptop silicon,
  while broad Ethernet (`e1000e`/`igc`/`r8169`) and Wi-Fi chipset qualification
  and Stage N.2 IOMMU DMA isolation remain open.
