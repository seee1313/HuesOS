//! Audited syscall records: all bit patterns are valid; output padding is zero.
//! The exhaustive record patterns make added fields a compile error until reviewed.
//! This private allowlist is a trusted safety boundary for `assume_init`.
//! Neither the sealing module nor the record macro may be exported.
mod sealed {
    pub trait Sealed {}
}
// Trusted implementations stay in this module. All fields must themselves satisfy
// UserRecord; raw pointers are addresses only, validated by the user-copy layer.
// Copy alone is insufficient (bool, enums and references have invalid patterns).
pub(crate) trait UserRecord: sealed::Sealed + Copy {
    fn encode_into(&self, bytes: &mut [u8]);
}
macro_rules! integer {
    ($($ty:ty),*) => {$(
        impl sealed::Sealed for $ty {}
        impl UserRecord for $ty {
            fn encode_into(&self, bytes: &mut [u8]) { bytes.copy_from_slice(&self.to_ne_bytes()); }
        }
    )*};
}
integer!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
impl<T> sealed::Sealed for *const T {}
impl<T> UserRecord for *const T {
    fn encode_into(&self, bytes: &mut [u8]) {
        self.addr().encode_into(bytes);
    }
}
impl<T> sealed::Sealed for *mut T {}
impl<T> UserRecord for *mut T {
    fn encode_into(&self, bytes: &mut [u8]) {
        self.addr().encode_into(bytes);
    }
}
impl<T: UserRecord, const N: usize> sealed::Sealed for [T; N] {}
impl<T: UserRecord, const N: usize> UserRecord for [T; N] {
    fn encode_into(&self, bytes: &mut [u8]) {
        for (value, chunk) in self
            .iter()
            .zip(bytes.chunks_exact_mut(core::mem::size_of::<T>()))
        {
            value.encode_into(chunk);
        }
    }
}
fn encode_field<T: UserRecord>(value: &T, bytes: &mut [u8]) {
    value.encode_into(bytes);
}
macro_rules! record {
    ($ty:path, $size:expr, $align:expr, $($field:ident => $offset:expr),+ $(,)?) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == $size);
            assert!(core::mem::align_of::<$ty>() == $align);
            $(assert!(core::mem::offset_of!($ty, $field) == $offset);)+
        };
        impl sealed::Sealed for $ty {}
        impl UserRecord for $ty {
            fn encode_into(&self, bytes: &mut [u8]) {
                let Self { $($field),+ } = self;
                bytes.fill(0);
                $(
                    let offset = core::mem::offset_of!(Self, $field);
                    encode_field($field, &mut bytes[offset..offset + core::mem::size_of_val($field)]);
                )+
            }
        }
    };
}
record!(huesos_abi::HeapExtendArgs, 24, 8, offset => 0, len => 8, op => 16, reserved => 20);
record!(huesos_abi::FramebufferInfo, 20, 4, width => 0, height => 4, pitch => 8, bpp => 12, red_mask_size => 14, red_mask_shift => 15, green_mask_size => 16, green_mask_shift => 17, blue_mask_size => 18, blue_mask_shift => 19);
record!(huesos_abi::FramebufferBlitArgs, 40, 8, vmo => 0, vmo_offset => 8, src_width => 16, src_height => 20, src_stride => 24, dst_x => 28, dst_y => 32);
record!(huesos_abi::ChannelReadEtcArgs, 56, 8, channel => 0, bytes => 8, bytes_capacity => 16, out_bytes => 24, handles => 32, handles_capacity => 40, out_handles => 48);
record!(huesos_abi::ChannelPeekArgs, 40, 8, channel => 0, out_byte_size => 8, out_handle_count => 16, out_cookie => 24, wait_mode => 32);
record!(huesos_abi::ChannelConsumeArgs, 64, 8, channel => 0, cookie => 8, bytes => 16, bytes_capacity => 24, handles => 32, handles_capacity => 40, out_bytes => 48, out_handles => 56);
record!(huesos_abi::WaitSetItem, 16, 8, handle => 0, awaited_signals => 4, key => 8);
record!(huesos_abi::WaitSetResult, 16, 8, key => 0, active_signals => 8);
record!(huesos_abi::WaitSetWaitArgs, 40, 8, items => 0, item_count => 8, mode => 12, timeout_ticks => 16, out_results => 24, out_count => 32);
record!(huesos_abi::PortPacket, 48, 8, key => 0, packet_type => 8, status => 12, data => 16);
record!(huesos_abi::JobLimitsAbi, 24, 8, max_memory => 0, max_handles => 8, max_cpu_ticks => 16);
record!(huesos_abi::JobCreateArgs, 40, 8, parent => 0, limits => 8, out_job => 32);
record!(huesos_abi::JobSetLimitsArgs, 32, 8, job => 0, limits => 8);
record!(huesos_abi::JobSetNameArgs, 24, 8, job => 0, name => 8, name_len => 16);
record!(huesos_abi::JobBindQuotaPortArgs, 24, 8, job => 0, port => 4, key => 8, flags => 16);
record!(huesos_abi::ProcessCreateInJobArgs, 40, 8, job => 0, name => 8, name_len => 16, out_process => 24, out_root_vmar => 32);
record!(huesos_abi::ProcessBindExitPortArgs, 24, 8, process => 0, port => 4, key => 8, flags => 16);
record!(huesos_abi::VmarCreateChildArgs, 40, 8, parent => 0, addr => 8, len => 16, flags => 24, out_child => 32);
record!(huesos_abi::VmarMapArgs, 40, 8, vmar => 0, vmo => 4, vmo_offset => 8, addr => 16, len => 24, flags => 32);
record!(huesos_abi::VmarOpArgs, 32, 8, vmar => 0, addr => 8, len => 16, flags => 24);
record!(huesos_abi::ResourceMapArgs, 40, 8, resource => 0, resource_offset => 8, addr => 16, len => 24, flags => 32);
record!(huesos_abi::ResourceUnmapArgs, 24, 8, resource => 0, addr => 8, len => 16);
record!(huesos_abi::acpi_broker::Request, 40, 8, version => 0, opcode => 2, width => 4, reserved => 5, request_id => 8, address => 16, value => 24, argument => 32);
record!(huesos_abi::acpi_broker::Response, 24, 8, version => 0, reserved => 2, status => 4, request_id => 8, value => 16);

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Copy)]
    struct Unlisted {
        _value: u32,
    }
    static_assertions::assert_not_impl_any!(bool: UserRecord);
    static_assertions::assert_not_impl_any!(char: UserRecord);
    static_assertions::assert_not_impl_any!(&'static u32: UserRecord);
    static_assertions::assert_not_impl_any!(&'static mut u32: UserRecord);
    static_assertions::assert_not_impl_any!(core::num::NonZeroU32: UserRecord);
    static_assertions::assert_not_impl_any!(huesos_abi::ErrorCode: UserRecord);
    static_assertions::assert_not_impl_any!(Unlisted: UserRecord);
    static_assertions::assert_not_impl_any!([bool; 4]: UserRecord);
    static_assertions::assert_not_impl_any!(*const [u8]: UserRecord);
    static_assertions::assert_not_impl_any!(*const str: UserRecord);
    static_assertions::assert_not_impl_any!(*const dyn core::any::Any: UserRecord);
    static_assertions::assert_not_impl_any!(fn() -> (): UserRecord);
    static_assertions::assert_not_impl_any!(core::ptr::NonNull<u8>: UserRecord);
    static_assertions::assert_impl_all!([huesos_abi::WaitSetResult; 16]: UserRecord);

    #[test]
    fn abi_output_layout_is_unchanged() {
        use core::mem::{align_of, offset_of, size_of};
        use huesos_abi::{FramebufferInfo, PortPacket, WaitSetResult};
        assert_eq!(
            (size_of::<WaitSetResult>(), align_of::<WaitSetResult>()),
            (16, 8)
        );
        assert_eq!(offset_of!(WaitSetResult, active_signals), 8);
        assert_eq!(size_of::<FramebufferInfo>(), 20);
        assert_eq!(size_of::<PortPacket>(), 48);
        assert_eq!(offset_of!(PortPacket, data), 16);
        assert_eq!(size_of::<huesos_abi::acpi_broker::Response>(), 24);
    }

    #[test]
    fn array_encoding_zeros_each_elements_padding() {
        let records = [huesos_abi::WaitSetResult {
            key: 42,
            active_signals: 3,
        }; 16];
        let mut bytes = [0xaa; 256];
        records.encode_into(&mut bytes);
        for chunk in bytes.chunks_exact(16) {
            assert_eq!(&chunk[..8], &42u64.to_ne_bytes());
            assert_eq!(&chunk[8..12], &3u32.to_ne_bytes());
            assert_eq!(&chunk[12..], &[0; 4]);
        }
    }

    #[test]
    fn padded_results_are_encoded_with_zero_tail() {
        let record = huesos_abi::WaitSetResult {
            key: u64::MAX,
            active_signals: u32::MAX,
        };
        let mut bytes = [0xaa; core::mem::size_of::<huesos_abi::WaitSetResult>()];
        record.encode_into(&mut bytes);
        assert_eq!(&bytes[..12], &[0xff; 12]);
        assert!(bytes[12..].iter().all(|byte| *byte == 0));
    }
}
