#include <stdint.h>
#include <uacpi/kernel_api.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/status.h>

#include "hotplug.h"

/*
 * AP-3 link-completeness boundary. Every host entry point required by the
 * pinned full interpreter is present, but no hardware or process-local runtime
 * authority is active. Later AP stages replace callback families in focused
 * reviews rather than weakening these defaults in place.
 */

#ifndef HUESOS_UACPI_RUST_ARCHIVE
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
#endif

#ifndef HUESOS_UACPI_RUST_LOG
void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *message)
{
    (void)level;
    (void)message;
}
#endif

#ifndef HUESOS_UACPI_RUST_PCI
/* AP-10: the Rust callbacks in src/pci.rs replace this family in the
 * userspace build. The default stays fail-closed for the host smoke. */
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
#endif /* HUESOS_UACPI_RUST_PCI */

#ifndef HUESOS_UACPI_RUST_IO
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
#endif /* HUESOS_UACPI_RUST_IO */

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
#endif

#ifndef HUESOS_UACPI_RUST_WORK
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
#endif

#ifndef HUESOS_UACPI_RUST_PRIMITIVES
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

#ifdef HUESOS_UACPI_RUST_WORK
/*
 * The Rust half owns the capability checks and the kernel Port/Interrupt
 * objects. This C half owns only the opaque uACPI callback pointers: Rust
 * never calls an untyped C function pointer directly. The fixed queue keeps
 * SCI-to-GPE-to-Notify delivery bounded and allocation-free.
 */
extern uacpi_status hues_uacpi_irq_install(
    uacpi_u32 irq, uacpi_handle *out_irq_handle);
extern uacpi_status hues_uacpi_irq_uninstall(uacpi_handle irq_handle);
extern int hues_uacpi_map_hotplug_node(
    uacpi_namespace_node *node, HuesHotplugTarget *out_target);
extern void hues_uacpi_notify_event(
    HuesHotplugTarget target, uacpi_u64 value);

#define HUES_WORK_QUEUE_MAX 64
#define HUES_WORK_DRAIN_MAX 1024

struct hues_work_item {
    uacpi_work_handler handler;
    uacpi_handle context;
};

static struct hues_work_item hues_work_queue[HUES_WORK_QUEUE_MAX];
static uacpi_size hues_work_head;
static uacpi_size hues_work_len;
static uacpi_interrupt_handler hues_sci_handler;
static uacpi_handle hues_sci_context;
static uacpi_handle hues_sci_irq_handle;

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle context,
    uacpi_handle *out_irq_handle)
{
    uacpi_status ret;

    if (handler == UACPI_NULL || out_irq_handle == UACPI_NULL)
        return UACPI_STATUS_INVALID_ARGUMENT;
    ret = hues_uacpi_irq_install(irq, out_irq_handle);
    if (ret != UACPI_STATUS_OK)
        return ret;
    hues_sci_handler = handler;
    hues_sci_context = context;
    hues_sci_irq_handle = *out_irq_handle;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(
    uacpi_interrupt_handler handler, uacpi_handle irq_handle)
{
    uacpi_status ret;

    if (handler == UACPI_NULL || irq_handle == UACPI_NULL)
        return UACPI_STATUS_INVALID_ARGUMENT;
    ret = hues_uacpi_irq_uninstall(irq_handle);
    if (ret != UACPI_STATUS_OK)
        return ret;
    if (handler == hues_sci_handler && irq_handle == hues_sci_irq_handle) {
        hues_sci_handler = UACPI_NULL;
        hues_sci_context = UACPI_NULL;
        hues_sci_irq_handle = UACPI_NULL;
    }
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_schedule_work(
    uacpi_work_type type, uacpi_work_handler handler, uacpi_handle context)
{
    uacpi_size tail;
    (void)type;
    if (handler == UACPI_NULL)
        return UACPI_STATUS_INVALID_ARGUMENT;
    if (hues_work_len >= HUES_WORK_QUEUE_MAX)
        return UACPI_STATUS_OUT_OF_MEMORY;
    tail = (hues_work_head + hues_work_len) % HUES_WORK_QUEUE_MAX;
    hues_work_queue[tail].handler = handler;
    hues_work_queue[tail].context = context;
    hues_work_len++;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void)
{
    uacpi_size steps = 0;
    while (hues_work_len != 0) {
        struct hues_work_item item = hues_work_queue[hues_work_head];
        hues_work_head = (hues_work_head + 1) % HUES_WORK_QUEUE_MAX;
        hues_work_len--;
        if (item.handler != UACPI_NULL)
            item.handler(item.context);
        steps++;
        if (steps >= HUES_WORK_DRAIN_MAX)
            return UACPI_STATUS_TIMEOUT;
    }
    return UACPI_STATUS_OK;
}

/* Called by the Rust Port pump after a real SCI packet was dequeued. */
uacpi_status hues_uacpi_dispatch_sci(void)
{
    uacpi_status ret;
    if (hues_sci_handler == UACPI_NULL)
        return UACPI_STATUS_NOT_FOUND;
    hues_sci_handler(hues_sci_context);
    ret = uacpi_kernel_wait_for_work_completion();
    return ret;
}

/* Root Notify callback: GPE execution remains entirely inside uACPI. */
static uacpi_status hues_hotplug_notify(
    uacpi_handle context, uacpi_namespace_node *node, uacpi_u64 value)
{
    HuesHotplugTarget target;
    int status;
    (void)context;
    status = hues_uacpi_map_hotplug_node(node, &target);
    if (status != 0 || target.valid == 0)
        return UACPI_STATUS_INVALID_ARGUMENT;
    hues_uacpi_notify_event(target, value);
    return UACPI_STATUS_OK;
}

int hues_uacpi_install_hotplug_notify(void)
{
    return (int)uacpi_install_notify_handler(
        uacpi_namespace_root(), hues_hotplug_notify, UACPI_NULL);
}
#endif

#ifndef HUESOS_UACPI_RUST_WORK
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
#endif
