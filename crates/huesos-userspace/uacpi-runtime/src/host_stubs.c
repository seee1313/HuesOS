#include <uacpi/kernel_api.h>
#include <uacpi/status.h>

/*
 * AP-3 link-completeness boundary. Every host entry point required by the
 * pinned full interpreter is present, but no hardware or process-local runtime
 * authority is active. Later AP stages replace callback families in focused
 * reviews rather than weakening these defaults in place.
 */

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address)
{
    if (out_rsdp_address)
        *out_rsdp_address = 0;
    return UACPI_STATUS_DENIED;
}

void *uacpi_kernel_map(uacpi_phys_addr address, uacpi_size length)
{
    (void)address;
    (void)length;
    return UACPI_MAP_FAILED;
}

void uacpi_kernel_unmap(void *address, uacpi_size length)
{
    (void)address;
    (void)length;
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *message)
{
    (void)level;
    (void)message;
}

uacpi_status uacpi_kernel_pci_device_open(
    uacpi_pci_address address, uacpi_handle *out_handle)
{
    (void)address;
    if (out_handle)
        *out_handle = UACPI_NULL;
    return UACPI_STATUS_DENIED;
}

void uacpi_kernel_pci_device_close(uacpi_handle handle)
{
    (void)handle;
}

uacpi_status uacpi_kernel_pci_read8(
    uacpi_handle handle, uacpi_size offset, uacpi_u8 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_pci_read16(
    uacpi_handle handle, uacpi_size offset, uacpi_u16 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_pci_read32(
    uacpi_handle handle, uacpi_size offset, uacpi_u32 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_pci_write8(
    uacpi_handle handle, uacpi_size offset, uacpi_u8 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_pci_write16(
    uacpi_handle handle, uacpi_size offset, uacpi_u16 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_pci_write32(
    uacpi_handle handle, uacpi_size offset, uacpi_u32 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_map(
    uacpi_io_addr base, uacpi_size length, uacpi_handle *out_handle)
{
    (void)base;
    (void)length;
    if (out_handle)
        *out_handle = UACPI_NULL;
    return UACPI_STATUS_DENIED;
}

void uacpi_kernel_io_unmap(uacpi_handle handle)
{
    (void)handle;
}

uacpi_status uacpi_kernel_io_read8(
    uacpi_handle handle, uacpi_size offset, uacpi_u8 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_read16(
    uacpi_handle handle, uacpi_size offset, uacpi_u16 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_read32(
    uacpi_handle handle, uacpi_size offset, uacpi_u32 *value)
{
    (void)handle;
    (void)offset;
    if (value)
        *value = 0;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_write8(
    uacpi_handle handle, uacpi_size offset, uacpi_u8 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_write16(
    uacpi_handle handle, uacpi_size offset, uacpi_u16 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_write32(
    uacpi_handle handle, uacpi_size offset, uacpi_u32 value)
{
    (void)handle;
    (void)offset;
    (void)value;
    return UACPI_STATUS_DENIED;
}

#ifndef HUESOS_UACPI_RUST_PRIMITIVES
void *uacpi_kernel_alloc(uacpi_size size)
{
    (void)size;
    return UACPI_NULL;
}

void uacpi_kernel_free(void *memory)
{
    (void)memory;
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void)
{
    return 0;
}

void uacpi_kernel_stall(uacpi_u8 microseconds)
{
    (void)microseconds;
}

void uacpi_kernel_sleep(uacpi_u64 milliseconds)
{
    (void)milliseconds;
}

uacpi_handle uacpi_kernel_create_mutex(void)
{
    return UACPI_NULL;
}

void uacpi_kernel_free_mutex(uacpi_handle handle)
{
    (void)handle;
}

uacpi_handle uacpi_kernel_create_event(void)
{
    return UACPI_NULL;
}

void uacpi_kernel_free_event(uacpi_handle handle)
{
    (void)handle;
}

uacpi_thread_id uacpi_kernel_get_thread_id(void)
{
    return UACPI_NULL;
}

uacpi_interrupt_state uacpi_kernel_disable_interrupts(void)
{
    return 0;
}

void uacpi_kernel_restore_interrupts(uacpi_interrupt_state state)
{
    (void)state;
}

uacpi_status uacpi_kernel_acquire_mutex(
    uacpi_handle handle, uacpi_u16 timeout)
{
    (void)handle;
    (void)timeout;
    return UACPI_STATUS_DENIED;
}

void uacpi_kernel_release_mutex(uacpi_handle handle)
{
    (void)handle;
}

uacpi_bool uacpi_kernel_wait_for_event(
    uacpi_handle handle, uacpi_u16 timeout)
{
    (void)handle;
    (void)timeout;
    return UACPI_FALSE;
}

void uacpi_kernel_signal_event(uacpi_handle handle)
{
    (void)handle;
}

void uacpi_kernel_reset_event(uacpi_handle handle)
{
    (void)handle;
}

uacpi_status uacpi_kernel_handle_firmware_request(
    uacpi_firmware_request *request)
{
    (void)request;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle context,
    uacpi_handle *out_irq_handle)
{
    (void)irq;
    (void)handler;
    (void)context;
    if (out_irq_handle)
        *out_irq_handle = UACPI_NULL;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(
    uacpi_interrupt_handler handler, uacpi_handle irq_handle)
{
    (void)handler;
    (void)irq_handle;
    return UACPI_STATUS_DENIED;
}

uacpi_handle uacpi_kernel_create_spinlock(void)
{
    return UACPI_NULL;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle)
{
    (void)handle;
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle)
{
    (void)handle;
    return 0;
}

void uacpi_kernel_unlock_spinlock(
    uacpi_handle handle, uacpi_cpu_flags flags)
{
    (void)handle;
    (void)flags;
}
#endif

uacpi_status uacpi_kernel_schedule_work(
    uacpi_work_type type, uacpi_work_handler handler, uacpi_handle context)
{
    (void)type;
    (void)handler;
    (void)context;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void)
{
    return UACPI_STATUS_DENIED;
}
