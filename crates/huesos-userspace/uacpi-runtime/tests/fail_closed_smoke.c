#include <uacpi/kernel_api.h>
#include <uacpi/status.h>
#include <uacpi/uacpi.h>

static int expect_denied(uacpi_status status)
{
    return status == UACPI_STATUS_DENIED ? 0 : 1;
}

static void ignored_work(uacpi_handle context)
{
    (void)context;
}

int main(void)
{
    uacpi_phys_addr rsdp = 1;
    uacpi_handle handle = (uacpi_handle)1;
    uacpi_u32 value = 0xFFFFFFFFu;
    uacpi_pci_address address = {0, 0, 0, 0};

    if (expect_denied(uacpi_kernel_get_rsdp(&rsdp)) || rsdp != 0)
        return 1;
    if (uacpi_kernel_map(0x1000, 16) != UACPI_MAP_FAILED)
        return 2;
    if (expect_denied(uacpi_kernel_pci_device_open(address, &handle)) || handle)
        return 3;
    if (expect_denied(uacpi_kernel_pci_read32(handle, 0, &value)) || value != 0)
        return 4;
    if (expect_denied(uacpi_kernel_pci_write32(handle, 0, 1)))
        return 5;
    if (expect_denied(uacpi_kernel_io_map(0x400, 4, &handle)) || handle)
        return 6;
    if (uacpi_kernel_alloc(64) != UACPI_NULL)
        return 7;
    if (uacpi_kernel_create_mutex() != UACPI_NULL)
        return 8;
    if (uacpi_kernel_create_event() != UACPI_NULL)
        return 9;
    if (uacpi_kernel_create_spinlock() != UACPI_NULL)
        return 10;
    if (expect_denied(uacpi_kernel_schedule_work(
            UACPI_WORK_GPE_EXECUTION, ignored_work, UACPI_NULL)))
        return 11;
    if (expect_denied(uacpi_kernel_wait_for_work_completion()))
        return 12;

    /* The complete interpreter is linked, but initialization cannot progress
     * while allocation and RSDP authority remain unavailable. */
    if (uacpi_initialize(UACPI_FLAG_NO_ACPI_MODE) == UACPI_STATUS_OK)
        return 13;
    return 0;
}
