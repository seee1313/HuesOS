//! HuesOS native PE32+ `/lib/ws2_32.dll` (Winsock 2.2 IPv4 TCP & DNS).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;

use huesos_pe::win64_abi::{DEFAULT_PROCESS_HEAP, PeHostApi, TRUE};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __huesos_ntdll_host() -> *const PeHostApi;
    fn RtlGetLastWin32Error() -> u32;
    fn RtlSetLastWin32Error(code: u32);
    fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> usize;
    fn RtlFreeHeap(heap: usize, flags: u32, ptr_val: usize) -> u8;
    fn NtTerminateProcess(process_handle: usize, exit_status: u32) -> !;
}

#[inline]
fn host() -> Option<&'static PeHostApi> {
    // SAFETY: imported via PE32+ IAT from `ntdll.dll`.
    let p = unsafe { __huesos_ntdll_host() };
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` points to `'static` `PE_HOST_API`.
        Some(unsafe { &*p })
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: terminates process on panic.
    unsafe { NtTerminateProcess(usize::MAX, 101) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _DllMainCRTStartup(
    _hinst_dll: usize,
    _fdw_reason: u32,
    _lpv_reserved: usize,
) -> i32 {
    TRUE
}

const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;

const WSAEINVAL: i32 = 10022;
const WSAEAFNOSUPPORT: i32 = 10047;
const WSAHOST_NOT_FOUND: i32 = 11001;

#[repr(C)]
struct WsaData64 {
    w_version: u16,
    w_high_version: u16,
    i_max_sockets: u16,
    i_max_udp_dg: u16,
    lp_vendor_info: usize,
    sz_description: [u8; 257],
    sz_system_status: [u8; 129],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct AddrInfoA {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: *mut u8,
    pub ai_addr: *mut SockAddrIn,
    pub ai_next: *mut AddrInfoA,
}

#[repr(C)]
struct AddrInfoAlloc {
    info: AddrInfoA,
    addr: SockAddrIn,
}

#[unsafe(no_mangle)]
pub extern "win64" fn WSAStartup(version_requested: u16, wsa_data: *mut u8) -> i32 {
    if !wsa_data.is_null() {
        let mut d = WsaData64 {
            w_version: version_requested,
            w_high_version: 0x0202,
            i_max_sockets: 0,
            i_max_udp_dg: 0,
            lp_vendor_info: 0,
            sz_description: [0; 257],
            sz_system_status: [0; 129],
        };
        let desc = b"HuesOS Winsock 2.2";
        d.sz_description[..desc.len()].copy_from_slice(desc);
        let status = b"Running";
        d.sz_system_status[..status.len()].copy_from_slice(status);
        // SAFETY: `wsa_data` points to caller's `WSADATA` struct (408 bytes on Win64).
        unsafe { ptr::write_unaligned(wsa_data.cast::<WsaData64>(), d) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn WSACleanup() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn WSAGetLastError() -> i32 {
    // SAFETY: forwards to `ntdll`.
    unsafe { RtlGetLastWin32Error() as i32 }
}

#[unsafe(no_mangle)]
pub extern "win64" fn WSASetLastError(err: i32) {
    // SAFETY: forwards to `ntdll`.
    unsafe { RtlSetLastWin32Error(err as u32) };
}

#[unsafe(no_mangle)]
pub extern "win64" fn socket(af: i32, sock_type: i32, _protocol: i32) -> usize {
    if af != AF_INET || sock_type != SOCK_STREAM {
        WSASetLastError(WSAEAFNOSUPPORT);
        return INVALID_SOCKET;
    }
    let Some(h) = host() else {
        WSASetLastError(WSAEINVAL);
        return INVALID_SOCKET;
    };
    let s = (h.net_tcp_socket)();
    if s == INVALID_SOCKET {
        WSASetLastError(WSAEINVAL);
    }
    s
}

#[unsafe(no_mangle)]
pub extern "win64" fn WSASocketW(
    af: i32,
    sock_type: i32,
    protocol: i32,
    _protocol_info: usize,
    _group: u32,
    _flags: u32,
) -> usize {
    socket(af, sock_type, protocol)
}

#[unsafe(no_mangle)]
pub extern "win64" fn connect(sock: usize, name: *const SockAddrIn, namelen: i32) -> i32 {
    if name.is_null() || (namelen as usize) < core::mem::size_of::<SockAddrIn>() {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    // SAFETY: `name` validated non-null and large enough for `SockAddrIn`.
    let sin = unsafe { ptr::read_unaligned(name) };
    if i32::from(sin.sin_family) != AF_INET {
        WSASetLastError(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }
    let Some(h) = host() else {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    };
    let port_host = u16::from_be(sin.sin_port);
    let err = (h.net_tcp_connect)(sock, sin.sin_addr, port_host);
    if err != 0 {
        WSASetLastError(err);
        SOCKET_ERROR
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn send(sock: usize, buf: *const u8, len: i32, _flags: i32) -> i32 {
    if len < 0 {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(h) = host() else {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    };
    let rc = (h.net_tcp_send)(sock, buf, len as usize);
    if rc < 0 {
        WSASetLastError((-rc) as i32);
        SOCKET_ERROR
    } else {
        rc as i32
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn recv(sock: usize, buf: *mut u8, len: i32, _flags: i32) -> i32 {
    if len < 0 {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(h) = host() else {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    };
    let rc = (h.net_tcp_recv)(sock, buf, len as usize);
    if rc < 0 {
        WSASetLastError((-rc) as i32);
        SOCKET_ERROR
    } else {
        rc as i32
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn closesocket(sock: usize) -> i32 {
    let Some(h) = host() else {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    };
    let err = (h.net_tcp_close)(sock);
    if err != 0 {
        WSASetLastError(err);
        SOCKET_ERROR
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn shutdown(_sock: usize, _how: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn ioctlsocket(sock: usize, cmd: i32, argp: *mut u32) -> i32 {
    const FIONBIO: i32 = -0x7FFB_9982; // 0x8004667E as signed i32
    if argp.is_null() {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if cmd == FIONBIO {
        let Some(h) = host() else {
            WSASetLastError(WSAEINVAL);
            return SOCKET_ERROR;
        };
        // SAFETY: `argp` checked non-null.
        let nonblock = unsafe { ptr::read_unaligned(argp) };
        let err = (h.net_tcp_set_nonblocking)(sock, nonblock);
        if err != 0 {
            WSASetLastError(err);
            return SOCKET_ERROR;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn setsockopt(
    _sock: usize,
    _level: i32,
    _optname: i32,
    _optval: *const u8,
    _optlen: i32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn getsockopt(
    _sock: usize,
    _level: i32,
    _optname: i32,
    optval: *mut u8,
    optlen: *mut i32,
) -> i32 {
    if !optval.is_null() && !optlen.is_null() {
        // SAFETY: `optlen` checked non-null.
        let n = unsafe { ptr::read_unaligned(optlen) }.max(0) as usize;
        // SAFETY: zeroes `n` bytes in `optval`.
        unsafe { ptr::write_bytes(optval, 0, n) };
    }
    0
}

fn cstr_len(s: *const u8, max: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    while n < max {
        // SAFETY: `s` NUL-terminated.
        if unsafe { *s.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    n
}

fn parse_port_ascii(service: *const u8) -> u16 {
    if service.is_null() {
        return 0;
    }
    let len = cstr_len(service, 32);
    // SAFETY: `service` valid for `len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(service, len) };
    if bytes.eq_ignore_ascii_case(b"http") {
        return 80;
    }
    if bytes.eq_ignore_ascii_case(b"https") {
        return 443;
    }
    let mut acc = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return 0;
        }
        acc = acc.saturating_mul(10).saturating_add(u32::from(b - b'0'));
    }
    acc.min(65_535) as u16
}

#[unsafe(no_mangle)]
pub extern "win64" fn getaddrinfo(
    node_name: *const u8,
    service_name: *const u8,
    _hints: *const AddrInfoA,
    res_out: *mut *mut AddrInfoA,
) -> i32 {
    if res_out.is_null() {
        return WSAEINVAL;
    }
    // SAFETY: `res_out` checked non-null.
    unsafe { ptr::write_unaligned(res_out, ptr::null_mut()) };

    let port = parse_port_ascii(service_name);
    let ip_net: u32 = if node_name.is_null() {
        u32::from_ne_bytes([127, 0, 0, 1])
    } else {
        let len = cstr_len(node_name, 255);
        let Some(h) = host() else {
            return WSAHOST_NOT_FOUND;
        };
        let mut out_ip = 0u32;
        let rc = (h.net_resolve_ipv4)(node_name, len, &raw mut out_ip);
        if rc != 0 {
            WSASetLastError(rc);
            return rc;
        }
        out_ip
    };

    // SAFETY: allocates `AddrInfoAlloc` from process heap (`HEAP_ZERO_MEMORY = 0x08`).
    let raw = unsafe {
        RtlAllocateHeap(
            DEFAULT_PROCESS_HEAP,
            0x08,
            core::mem::size_of::<AddrInfoAlloc>(),
        )
    };
    if raw == 0 {
        return 8; // EAI_MEMORY / ERROR_NOT_ENOUGH_MEMORY
    }
    let alloc_ptr = raw as *mut AddrInfoAlloc;
    // SAFETY: `alloc_ptr` freshly allocated and properly aligned for `AddrInfoAlloc`.
    unsafe {
        let addr_ptr = &raw mut (*alloc_ptr).addr;
        ptr::write(
            addr_ptr,
            SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: ip_net,
                sin_zero: [0; 8],
            },
        );
        ptr::write(
            &raw mut (*alloc_ptr).info,
            AddrInfoA {
                ai_flags: 0,
                ai_family: AF_INET,
                ai_socktype: SOCK_STREAM,
                ai_protocol: IPPROTO_TCP,
                ai_addrlen: core::mem::size_of::<SockAddrIn>(),
                ai_canonname: ptr::null_mut(),
                ai_addr: addr_ptr,
                ai_next: ptr::null_mut(),
            },
        );
        ptr::write_unaligned(res_out, &raw mut (*alloc_ptr).info);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn freeaddrinfo(mut ai: *mut AddrInfoA) {
    while !ai.is_null() {
        // SAFETY: `ai` was allocated by `getaddrinfo` via `RtlAllocateHeap`.
        let next = unsafe { (*ai).ai_next };
        // SAFETY: frees heap block.
        unsafe {
            let _ = RtlFreeHeap(DEFAULT_PROCESS_HEAP, 0, ai as usize);
        }
        ai = next;
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

#[unsafe(no_mangle)]
pub extern "win64" fn ntohs(netshort: u16) -> u16 {
    u16::from_be(netshort)
}

#[unsafe(no_mangle)]
pub extern "win64" fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

#[unsafe(no_mangle)]
pub extern "win64" fn ntohl(netlong: u32) -> u32 {
    u32::from_be(netlong)
}

fn parse_ipv4_cstr(cp: *const u8) -> Option<[u8; 4]> {
    if cp.is_null() {
        return None;
    }
    let len = cstr_len(cp, 32);
    // SAFETY: `cp` valid for `len` bytes.
    let s = core::str::from_utf8(unsafe { core::slice::from_raw_parts(cp, len) }).ok()?;
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut octets {
        let p = parts.next()?;
        *slot = p.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

#[unsafe(no_mangle)]
pub extern "win64" fn inet_addr(cp: *const u8) -> u32 {
    parse_ipv4_cstr(cp).map_or(u32::MAX, u32::from_ne_bytes)
}

#[unsafe(no_mangle)]
pub extern "win64" fn inet_pton(
    family: i32,
    psz_addr_string: *const u8,
    p_addr_buf: *mut u8,
) -> i32 {
    if family != AF_INET || p_addr_buf.is_null() {
        WSASetLastError(WSAEAFNOSUPPORT);
        return -1;
    }
    let Some(octets) = parse_ipv4_cstr(psz_addr_string) else {
        return 0;
    };
    // SAFETY: `p_addr_buf` checked non-null and holds `in_addr` (4 bytes).
    unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), p_addr_buf, 4) };
    1
}

#[unsafe(no_mangle)]
pub extern "win64" fn inet_ntop(
    family: i32,
    p_addr: *const u8,
    p_string_buf: *mut u8,
    string_buf_size: usize,
) -> *const u8 {
    if family != AF_INET || p_addr.is_null() || p_string_buf.is_null() || string_buf_size < 16 {
        return ptr::null();
    }
    // SAFETY: `p_addr` checked non-null (4-byte IPv4).
    let octets = unsafe {
        [
            (*p_addr),
            (*p_addr.add(1)),
            (*p_addr.add(2)),
            (*p_addr.add(3)),
        ]
    };
    let mut tmp = [0u8; 16];
    let mut pos = 0usize;
    for (idx, &o) in octets.iter().enumerate() {
        if idx > 0 {
            tmp[pos] = b'.';
            pos += 1;
        }
        if o >= 100 {
            tmp[pos] = b'0' + (o / 100);
            pos += 1;
        }
        if o >= 10 {
            tmp[pos] = b'0' + ((o / 10) % 10);
            pos += 1;
        }
        tmp[pos] = b'0' + (o % 10);
        pos += 1;
    }
    tmp[pos] = 0;
    // SAFETY: `pos + 1 <= 16 <= string_buf_size`.
    unsafe { ptr::copy_nonoverlapping(tmp.as_ptr(), p_string_buf, pos + 1) };
    p_string_buf
}
