# Sound (`audio-service` / `VirtIO-Sound`) & Plan 9 `/net/btl` Bluetooth Classic

HuesOS implements end-to-end audio playback and Bluetooth Classic wireless transport across isolated Ring-3 capability processes with `#![forbid(unsafe_code)]` protocol/codec cores (`crates/huesos-bt` and `crates/huesos-audio`).

## Architectural Separation & Capability Model

HuesOS strictly separates Bluetooth network transport from media codecs and audio mixing:

1. **`driver-host-xhci` (`/drivers/driver-host-xhci.elf`)** — Owns the xHCI PCIe controller lease (`0x0C/0x03/0x30`), detects USB Wireless Bluetooth HCI interfaces (`0xE0/0x01/0x01` and Realtek `0bda:{c821,b00a,c820,8821,b00c}` combo cards), allocates isolated USB-BT DMA (`0x0020_0000..0x0021_8400`), and exposes the internal `UBTH` H4 bridge (`bt-hci-client`) to `btl-service`.
2. **`btl-service` (`/services/btl.elf`, Plan 9 `/net/btl/*`, `HBTL` v1)** — Pure Bluetooth Classic transport layer:
   - Uploads Realtek `RTL8821CE` Bluetooth firmware (`/lib/firmware/rtl_bt/rtl8821c_fw.bin` + `rtl8821c_config.bin`) from the verified `BOOTFS` VMO via `huesos_bt::btrtl`.
   - Manages HCI reset, local `BD_ADDR`/buffer discovery, ACL credit flow control (`AclCreditTracker` + `AclReassembler`), Inquiry + Extended Inquiry Result (`EIR`) scan, and Secure Simple Pairing (`SSP` Just-Works).
   - Persists 128-bit Bluetooth Link Keys atomically inside `/etc/btl/link_keys.bin` on `HxFS` (with RAM fallback on diskless boots). **Raw Link Keys never leave `btl-service`**; `ListKeys` (`/net/btl/keys`, `btctl keys`) exposes only non-invertible 4-byte SHA-256 fingerprints.
   - Multiplexes connection-oriented `L2CAP` channels (`PSM 0x0001` SDP, `PSM 0x0017` AVCTP/AVRCP, `PSM 0x0019` AVDTP/A2DP, and dynamic client PSMs), serves and queries `SDP`, records `RFC 1761` `btsnoop` v1 HCI H4 captures (`/net/btl/snoop`), and drives 2.4 GHz `RTL8821CE` Wi-Fi/Bluetooth Packet Traffic Arbitration (`PTA`) coexistence (`coex:wlan` -> `wlan-service` `Rtl8821ceHw::set_bt_coex_profile`).
   - Includes a deterministic virtual Bluetooth radio + `"HuesOS AirBuds Pro"` (`52:54:00:B7:A2:D9`) A2DP/AVRCP headset (`btctl power virtual`) for reproducible CI and QEMU testing.
3. **`driver-host-snd` (`/drivers/driver-host-snd.elf`, `HSND` v1)** — Zero-heap, zero-unsafe OASIS VirtIO 1.2 Sound (`1af4:1059` / `1af4:1018`) PCIe driver using an isolated 4 MiB IOMMU-bound DMA slice (`AUDIO_DMA_OFFSET = 76 MiB`). Configures `48 kHz` `S16LE` stereo playback over `controlq` (`queue 0`) and double-buffered `txq` (`queue 2`) periods.
4. **`audio-service` (`/services/audio.elf`, `/dev/audio/*`, `HAUD` v1)** — Multi-stream `48 kHz` audio mixer and A2DP/AVRCP media engine:
   - Allocates per-client `HARB` v1 lock-free Single-Producer / Single-Consumer (`SPSC`) shared-memory `Vmo` ring buffers (`16,384` stereo frames = `64 KiB` + `64`-byte atomic header). Steady-state audio rendering performs zero IPC syscalls per sample frame.
   - Resamples `8..96 kHz` client streams with `Q16.16` fractional linear interpolation, applies per-stream and master `Q8.8` gain, and routes output across `auto`, `virtio`, `btl`, or simultaneous `mirror` sinks with bounded `ring_pop_clock_synced` clock-drift compensation (`±1` sample frame slip/duplication at high/low watermarks).
   - Runs `AVDTP 1.3` Source (`Discover` -> `GetCapabilities` -> `SetConfiguration` -> `Open` -> `Start`), pure-Rust integer `A2DP` Subband Codec (`SBC`, Joint Stereo `48 kHz`, 8 subbands, 16 blocks, adaptive bitpool `24..=53` driven by `/net/btl` ACL credit feedback), `RTP` media framing, and `AVCTP/AVRCP` Absolute Volume + Pass-Through media key handling over `/net/btl` L2CAP channels.

## Capability Attenuation (`@caps`)

Both services have independent 3-tier capability masks in `huesos_abi::auxv::caps_mask` (`AT_HUESOS_BTL_SERVICE = 0x1011`, `AT_HUESOS_AUDIO_SERVICE = 0x1012`) enforced by `ld-huesos`, `hsh`, `driver-manager`, `huesos-std`, `btl-service`, and `audio-service`:

| Domain | `none` | `ro` | `rw` | `admin` |
| :--- | :--- | :--- | :--- | :--- |
| `btl` | Handle withheld | `Status`, `ListPeers`, `ListKeys` (SHA-256 fp), `ReadSnoop` | `ro` + `SdpQuery`, `L2cap*`, `SetCoexHint` | `rw` + `Scan`, `Pair`, `DeleteKey`, `ConnectAcl`, `DisconnectAcl`, `SetPower` |
| `audio` | Handle withheld | `Status` (`/dev/audio/status`) | `ro` + `OpenStream`, `CloseStream`, `PlayTestTone` (`aplay`, `doom`) | `rw` + `SetVolume`, `SetRouteMode`, `ConnectBtlSink`, `DisconnectBtlSink` |

## Plan 9 VFS & User-Space Tools

- **Synthetic VFS (`crates/huesos-userspace/huesos-std/src/vfs_synth.rs`)**:
  - `/net/btl/{ctl,status,peers,keys,snoop,clone}`
  - `/dev/audio/{ctl,status,pcm}`
- **CLI Utilities (`crates/huesos-userspace/coreutils/src/bin/`)**:
  - `btctl` — Controller telemetry, `power <on|off|virtual>`, Inquiry/EIR `scan`, SSP `pair`/`unpair`, `keys`, `sdp`, `snoop`, and `coex`.
  - `audioctl` — Mixer/sink telemetry, `volume`/`mute`/`unmute`, `route <auto|virtio|btl|mirror>`, `bt-connect`/`bt-disconnect`, and `tone`.
  - `aplay` — Zero-copy `HARB` SPSC VMO player for RIFF/WAVE (`8/16-bit`, `1..=2` channels, `8..96 kHz`), raw PCM, and `--synth` / `--gen-wav`.
- **Doom (`crates/huesos-userspace/doom/src/sound.rs`)**:
  - Streams 8-voice stereo-panned `DMX 0x0003` digital sound effects plus pure-Rust Yamaha `YM3812` (`OPL2`) 2-operator FM synthesis driven by Freedoom's `#OPL_II#` `GENMIDI` instrument bank and `MUS` / `MThd` MIDI tracks into `audio-service`.

Related documents: [NETWORKING.md](NETWORKING.md), [USB_XHCI.md](USB_XHCI.md), [DOOM.md](DOOM.md), [SHELL_AND_STD.md](SHELL_AND_STD.md).
