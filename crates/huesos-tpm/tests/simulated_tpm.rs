//! End-to-end seal/unseal against a simulated CRB TPM.
//!
//! The point of these tests is the part that a swtpm run cannot check
//! cheaply on every commit: that the CRB handshake sequence is driven
//! correctly, that a PCR mismatch is reported *as a mismatch*, and
//! that the driver does not hang when the device misbehaves.
//!
//! The simulator is deliberately picky. It refuses a command that
//! arrives without the Ready handshake and it refuses one sent while
//! it is not in the right state, so a driver that "works" only because
//! the device is forgiving fails here. That is the same class of bug
//! the NVMe MockNvme was too lenient to catch earlier in this phase.

use huesos_tpm::crb::{ctrl_req, ctrl_sts, loc_ctrl, loc_sts, reg, CrbError, CrbTransport};
use huesos_tpm::pcr::{PcrSelection, PCR_DIGEST_BYTES, PCR_KERNEL_MEASUREMENT};
use huesos_tpm::seal::{unseal_volume_key, SealError, SealedKey, VolumeKey, VOLUME_KEY_BYTES};
use huesos_tpm::{command, read_u32, response_code, HEADER_BYTES};

/// A minimal TPM 2.0 responder speaking the CRB register protocol.
struct SimTpm {
    granted: bool,
    idle: bool,
    start: u32,
    error: bool,
    command: Vec<u8>,
    response: Vec<u8>,
    /// Current PCR 12 value.
    pcr12: [u8; PCR_DIGEST_BYTES],
    /// PCR 12 value the sealed blob was bound to.
    sealed_against: [u8; PCR_DIGEST_BYTES],
    /// The key inside the sealed blob.
    key: [u8; VOLUME_KEY_BYTES],
    /// Whether the active policy session satisfied its PCR assertion.
    policy_ok: bool,
    /// Transient handles the driver has failed to flush.
    live_handles: usize,
    /// Never clear `start`, to exercise the timeout path.
    wedge: bool,
    /// Commands seen, in order.
    seen: Vec<u32>,
}

impl SimTpm {
    fn new(pcr12: [u8; PCR_DIGEST_BYTES], sealed_against: [u8; PCR_DIGEST_BYTES]) -> Self {
        Self {
            granted: false,
            idle: true,
            start: 0,
            error: false,
            command: Vec::new(),
            response: Vec::new(),
            pcr12,
            sealed_against,
            key: [0x5A; VOLUME_KEY_BYTES],
            policy_ok: false,
            live_handles: 0,
            wedge: false,
            seen: Vec::new(),
        }
    }

    fn header(&mut self, code: u32, body: &[u8]) {
        let size = (HEADER_BYTES + body.len()) as u32;
        self.response.clear();
        self.response.extend_from_slice(&0x8001u16.to_be_bytes());
        self.response.extend_from_slice(&size.to_be_bytes());
        self.response.extend_from_slice(&code.to_be_bytes());
        self.response.extend_from_slice(body);
    }

    /// Execute the buffered command.
    fn run(&mut self) {
        let Some(code) = read_u32(&self.command, 6) else {
            self.error = true;
            return;
        };
        self.seen.push(code);
        match code {
            command::LOAD => {
                self.live_handles += 1;
                let mut body = Vec::new();
                // handle, then parameterSize + name
                body.extend_from_slice(&0x8000_0001u32.to_be_bytes());
                body.extend_from_slice(&0u32.to_be_bytes());
                self.header(response_code::SUCCESS, &body);
            }
            command::START_AUTH_SESSION => {
                self.live_handles += 1;
                let mut body = Vec::new();
                body.extend_from_slice(&0x0300_0000u32.to_be_bytes());
                body.extend_from_slice(&0u16.to_be_bytes());
                self.header(response_code::SUCCESS, &body);
            }
            command::POLICY_PCR => {
                // The assertion succeeds only if the current PCR
                // matches what the blob was sealed against.
                self.policy_ok = self.pcr12 == self.sealed_against;
                if self.policy_ok {
                    self.header(response_code::SUCCESS, &[]);
                } else {
                    self.header(response_code::POLICY_FAIL, &[]);
                }
            }
            command::UNSEAL => {
                if !self.policy_ok {
                    self.header(response_code::POLICY_FAIL, &[]);
                    return;
                }
                let mut body = Vec::new();
                body.extend_from_slice(&(2 + VOLUME_KEY_BYTES as u32).to_be_bytes());
                body.extend_from_slice(&(VOLUME_KEY_BYTES as u16).to_be_bytes());
                body.extend_from_slice(&self.key);
                self.header(response_code::SUCCESS, &body);
            }
            command::FLUSH_CONTEXT => {
                self.live_handles = self.live_handles.saturating_sub(1);
                self.header(response_code::SUCCESS, &[]);
            }
            _ => self.header(response_code::SUCCESS, &[]),
        }
    }
}

impl CrbTransport for SimTpm {
    fn read_reg(&self, offset: usize) -> u32 {
        match offset {
            reg::LOC_STS => {
                if self.granted {
                    loc_sts::GRANTED
                } else {
                    0
                }
            }
            reg::CTRL_STS => {
                let mut value = 0;
                if self.error {
                    value |= ctrl_sts::TPM_STS_ERROR;
                }
                if self.idle {
                    value |= ctrl_sts::TPM_IDLE;
                }
                value
            }
            reg::CTRL_START => self.start,
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: usize, value: u32) {
        match offset {
            reg::LOC_CTRL if value & loc_ctrl::REQUEST_ACCESS != 0 => self.granted = true,
            reg::LOC_CTRL if value & loc_ctrl::RELINQUISH != 0 => self.granted = false,
            reg::CTRL_REQ if value & ctrl_req::COMMAND_READY != 0 => self.idle = false,
            reg::CTRL_REQ if value & ctrl_req::GO_IDLE != 0 => self.idle = true,
            reg::CTRL_START => {
                self.start = value;
                if value != 0 && !self.wedge {
                    self.run();
                    self.start = 0;
                }
            }
            _ => {}
        }
    }

    fn write_command(&mut self, bytes: &[u8]) -> Result<(), CrbError> {
        // A real CRB device only accepts a command in the Ready state.
        if self.idle {
            return Err(CrbError::NotReady);
        }
        self.command = bytes.to_vec();
        Ok(())
    }

    fn read_response(&mut self, out: &mut [u8]) -> Result<usize, CrbError> {
        if out.len() < self.response.len() {
            return Err(CrbError::ResponseTooLarge);
        }
        out[..self.response.len()].copy_from_slice(&self.response);
        Ok(self.response.len())
    }

    fn poll_tick(&mut self) {}
}

fn selection() -> PcrSelection {
    match PcrSelection::single(PCR_KERNEL_MEASUREMENT) {
        Some(selection) => selection,
        None => panic!("PCR 12 must be a valid index"),
    }
}

fn blob() -> SealedKey {
    match SealedKey::new(&[0xAA; 48], &[0xBB; 64]) {
        Ok(sealed) => sealed,
        Err(error) => panic!("small areas must be accepted: {error:?}"),
    }
}

/// The good case: the machine presents the PCR value the key was
/// sealed against, and the key comes back.
#[test]
fn unseal_succeeds_when_pcrs_match() {
    let measurement = [0x11; PCR_DIGEST_BYTES];
    let mut tpm = SimTpm::new(measurement, measurement);
    let key = match unseal_volume_key(&mut tpm, 0x8100_0000, &blob(), &selection()) {
        Ok(key) => key,
        Err(error) => panic!("matching PCRs must unseal: {error:?}"),
    };
    assert_eq!(key.as_bytes(), &[0x5A; VOLUME_KEY_BYTES]);
}

/// The security-relevant case: a different boot chain measured into
/// PCR 12 must NOT get the key, and the failure must be identifiable
/// as a policy mismatch rather than a generic error.
#[test]
fn unseal_fails_when_pcr_changed() {
    let mut tpm = SimTpm::new([0x22; PCR_DIGEST_BYTES], [0x11; PCR_DIGEST_BYTES]);
    // `VolumeKey` intentionally has no `Debug` -- it is key material --
    // so report the error variant rather than the whole result.
    match unseal_volume_key(&mut tpm, 0x8100_0000, &blob(), &selection()) {
        Err(SealError::PolicyMismatch) => {}
        Err(other) => panic!("a changed PCR must report PolicyMismatch, got {other:?}"),
        Ok(_) => panic!("a changed PCR must not yield the key"),
    }
}

/// Transient handles are scarce. Every path -- success and failure --
/// must flush what it created, or the second mount attempt fails for
/// reasons that have nothing to do with the key.
#[test]
fn transient_handles_are_flushed_on_both_paths() {
    let measurement = [0x33; PCR_DIGEST_BYTES];

    let mut ok = SimTpm::new(measurement, measurement);
    let _ = unseal_volume_key(&mut ok, 0x8100_0000, &blob(), &selection());
    assert_eq!(ok.live_handles, 0, "success path leaked a TPM handle");

    let mut bad = SimTpm::new([0x44; PCR_DIGEST_BYTES], measurement);
    let _ = unseal_volume_key(&mut bad, 0x8100_0000, &blob(), &selection());
    assert_eq!(bad.live_handles, 0, "failure path leaked a TPM handle");
}

/// A TPM that never completes a command must time out, not hang. An
/// unbootable machine is bad; a machine that hangs forever in early
/// boot with no message is worse.
#[test]
fn a_wedged_tpm_times_out_instead_of_hanging() {
    let measurement = [0x55; PCR_DIGEST_BYTES];
    let mut tpm = SimTpm::new(measurement, measurement);
    tpm.wedge = true;
    match unseal_volume_key(&mut tpm, 0x8100_0000, &blob(), &selection()) {
        Err(SealError::Command(error)) => {
            assert_eq!(
                error,
                huesos_tpm::TpmCommandError::Transport(CrbError::Timeout)
            );
        }
        Err(other) => panic!("a wedged TPM must time out, got {other:?}"),
        Ok(_) => panic!("a wedged TPM must not yield a key"),
    }
}

/// The driver must perform the Ready handshake before writing a
/// command; the simulator rejects the write otherwise.
#[test]
fn the_ready_handshake_precedes_every_command() {
    let measurement = [0x66; PCR_DIGEST_BYTES];
    let mut tpm = SimTpm::new(measurement, measurement);
    let _ = unseal_volume_key(&mut tpm, 0x8100_0000, &blob(), &selection());
    // Load, StartAuthSession, PolicyPCR, Unseal, and the flushes.
    assert!(tpm.seen.contains(&command::LOAD));
    assert!(tpm.seen.contains(&command::START_AUTH_SESSION));
    assert!(tpm.seen.contains(&command::POLICY_PCR));
    assert!(tpm.seen.contains(&command::UNSEAL));
    assert!(tpm.seen.contains(&command::FLUSH_CONTEXT));
}

/// Unseal must not be attempted after the policy assertion failed.
/// Sending it anyway would be harmless with a correct TPM and a real
/// bug with a permissive one.
#[test]
fn unseal_is_not_attempted_after_a_failed_policy() {
    let mut tpm = SimTpm::new([0x77; PCR_DIGEST_BYTES], [0x88; PCR_DIGEST_BYTES]);
    let _ = unseal_volume_key(&mut tpm, 0x8100_0000, &blob(), &selection());
    assert!(
        !tpm.seen.contains(&command::UNSEAL),
        "unseal was sent despite a failed PCR policy"
    );
}
