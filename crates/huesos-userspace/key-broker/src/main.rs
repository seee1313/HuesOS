//! Isolated userspace volume-key broker.
//!
//! Init transfers two capabilities during bootstrap: the unique
//! `ResourceKind::VolumeKey` authority and a manager-channel endpoint delegated
//! to DriverManager. The broker atomically takes the master key from the kernel
//! once, then serves at most one reply channel for each monotonically increasing
//! HxFS generation. No ordinary process receives the manager endpoint.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::key_broker::{GrantReply, GrantRequest, GrantStatus, GRANT_REQUEST_BYTES};
use libcanvas::{println, wait_any, Channel, ErrorCode, Handle, Signals, WaitItem};

const AUTHORITY_LABEL: &[u8] = b"key-broker:volume-key-authority";
const MANAGER_LABEL: &[u8] = b"key-broker:manager-channel";
const READY: &[u8] = b"key-broker:ready";
const MISSING_BOOTSTRAP: &[u8] = b"key-broker:missing-bootstrap";
const POLL_BUDGET: u32 = 64;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let bootstrap = libcanvas::channel::bootstrap();
    println!("[key-broker] started");

    let Some((authority, manager)) = receive_bootstrap(&bootstrap) else {
        let _ = bootstrap.write(MISSING_BOOTSTRAP);
        libcanvas::process::exit(-1);
    };

    let key = match libcanvas::system::take_volume_key(&authority) {
        Ok(key) => key,
        Err(error) => {
            println!("[key-broker] key take failed: {}", error.as_str());
            libcanvas::process::exit(-2);
        }
    };
    // A second take with the same capability must never produce a key. This is
    // an on-target regression for the one-shot kernel state transition.
    if key.is_some() {
        match libcanvas::system::take_volume_key(&authority) {
            Ok(None) => println!("[key-broker] one-shot handoff verified"),
            Ok(Some(duplicate)) => {
                drop(duplicate);
                println!("[key-broker] duplicate key handoff rejected by broker");
                libcanvas::process::exit(-4);
            }
            Err(error) => {
                println!("[key-broker] one-shot probe failed: {}", error.as_str());
                libcanvas::process::exit(-5);
            }
        }
    }
    drop(authority);

    println!(
        "[key-broker] kernel key moved; state={}",
        if key.is_some() {
            "available"
        } else {
            "plain-only"
        }
    );
    let _ = bootstrap.write(READY);

    let mut last_generation = 0u64;
    loop {
        if !poll_manager(&manager, key.as_ref(), &mut last_generation) {
            println!("[key-broker] manager channel closed; exiting");
            libcanvas::process::exit(-3);
        }
        libcanvas::process::yield_now();
    }
}

fn receive_bootstrap(bootstrap: &Channel) -> Option<(Handle, Channel)> {
    let mut authority: Option<Handle> = None;
    let mut manager: Option<Channel> = None;
    let mut label = [0u8; 64];
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];

    'outer: loop {
        if authority.is_some() && manager.is_some() {
            return match (authority, manager) {
                (Some(authority), Some(manager)) => Some((authority, manager)),
                _ => None,
            };
        }
        if wait_any(&items, 0).is_err() {
            return None;
        }
        loop {
            match bootstrap.read_optional_handle(&mut label) {
                Ok((n, Some(handle))) if &label[..n] == AUTHORITY_LABEL => {
                    if authority.is_some() {
                        drop(handle);
                        return None;
                    }
                    authority = Some(handle);
                }
                Ok((n, Some(handle))) if &label[..n] == MANAGER_LABEL => {
                    if manager.is_some() {
                        drop(handle);
                        return None;
                    }
                    manager = Some(Channel::from_handle(handle));
                }
                Ok((_n, Some(handle))) => {
                    drop(handle);
                    return None;
                }
                Ok((_n, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => continue 'outer,
                Err(_) => return None,
            }
        }
    }
}

/// Drain a bounded number of generation requests. Returns false when the
/// delegated manager authority is gone.
fn poll_manager(
    manager: &Channel,
    key: Option<&libcanvas::system::VolumeKey>,
    last_generation: &mut u64,
) -> bool {
    let mut request_bytes = [0u8; GRANT_REQUEST_BYTES];
    let mut budget = POLL_BUDGET;
    loop {
        budget = match budget.checked_sub(1) {
            Some(remaining) => remaining,
            None => return true,
        };
        match manager.read_optional_handle(&mut request_bytes) {
            Ok((length, Some(handle))) => {
                let reply_channel = Channel::from_handle(handle);
                let Some(request) = GrantRequest::decode(&request_bytes[..length]) else {
                    send_reply(
                        &reply_channel,
                        GrantReply::without_key(1, GrantStatus::Denied),
                    );
                    continue;
                };
                if request.generation <= *last_generation {
                    send_reply(
                        &reply_channel,
                        GrantReply::without_key(request.generation, GrantStatus::StaleGeneration),
                    );
                    continue;
                }
                *last_generation = request.generation;
                match key {
                    Some(key) => send_reply(
                        &reply_channel,
                        GrantReply::granted(request.generation, *key.as_bytes()),
                    ),
                    None => send_reply(
                        &reply_channel,
                        GrantReply::without_key(request.generation, GrantStatus::NotFound),
                    ),
                }
            }
            Ok((_length, None)) => {
                // Requests without a single-use reply endpoint carry no
                // authority and cannot observe whether a key exists.
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return true,
            Err(ErrorCode::PeerClosed) => return false,
            Err(_) => return true,
        }
    }
}

fn send_reply(channel: &Channel, reply: GrantReply) {
    let mut encoded = reply.encode();
    let _ = channel.write(&encoded);
    clear_secret(&mut encoded);
    drop(reply);
}

fn clear_secret(secret: &mut [u8]) {
    for byte in secret {
        *byte = 0;
        let _ = core::hint::black_box(*byte);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = info;
    libcanvas::debug::write_str("[key-broker] PANIC\n");
    libcanvas::process::exit(-99);
}
