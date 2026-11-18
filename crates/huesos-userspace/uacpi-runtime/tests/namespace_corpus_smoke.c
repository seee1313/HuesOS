#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uacpi/kernel_api.h>
#include <uacpi/namespace.h>
#include <uacpi/status.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

extern int hues_uacpi_load_namespace(
    uacpi_u32 loop_timeout_secs,
    uacpi_u32 max_stack_depth);
extern int hues_uacpi_initialize_namespace(
    uacpi_u32 loop_timeout_secs,
    uacpi_u32 max_stack_depth,
    int *out_pic_status);

typedef struct HuesPciRootDesc {
    uacpi_u16 segment;
    uacpi_u8 start_bus;
    uacpi_u8 end_bus;
    uacpi_u8 has_bus_range;
    uacpi_u8 has_bbn;
    uacpi_u16 aperture_start;
    uacpi_u16 aperture_count;
    uacpi_u16 _pad;
    uacpi_u32 flags;
} HuesPciRootDesc;

typedef struct HuesPciApertureDesc {
    uacpi_u16 root_index;
    uacpi_u8 kind;
    uacpi_u8 _pad;
    uacpi_u32 flags;
    uacpi_u64 pci_base;
    uacpi_u64 cpu_base;
    uacpi_u64 len;
} HuesPciApertureDesc;

typedef struct HuesPciRootsOut {
    uacpi_u16 root_count;
    uacpi_u16 aperture_count;
    uacpi_u32 _pad;
    HuesPciRootDesc roots[16];
    HuesPciApertureDesc apertures[64];
} HuesPciRootsOut;

extern int hues_uacpi_collect_pci_roots(HuesPciRootsOut *out);

/*
 * Host ASan/UBSan test exercising the real uACPI initialization and AML
 * namespace-load path (`hues_uacpi_load_namespace`) against both a valid
 * synthetic ACPI table graph (with SystemMemory and EmbeddedControl OpRegions)
 * and a malformed/truncated AML corpus.
 */

struct test_region {
    uacpi_phys_addr phys;
    const uint8_t *data;
    size_t len;
};

#define MAX_REGIONS 8
static struct test_region g_regions[MAX_REGIONS];
static size_t g_region_count = 0;
static uacpi_phys_addr g_rsdp_phys = 0;
static uint32_t g_mmio_calls = 0;
static uint32_t g_io_calls = 0;
static uint32_t g_pci_calls = 0;
static uint32_t g_pci_reads = 0;
static uint32_t g_pci_writes = 0;
static uint32_t g_error_logs = 0;
static uint32_t g_no_handler_logs = 0;
static uint64_t g_ticks = 1;
static int g_allow_pci_read = 0;

static uint8_t acpi_checksum(const uint8_t *buf, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; ++i)
        sum = (uint8_t)(sum + buf[i]);
    return sum;
}

static void write_u32(uint8_t *dst, uint32_t v)
{
    memcpy(dst, &v, sizeof(v));
}

static void write_u64(uint8_t *dst, uint64_t v)
{
    memcpy(dst, &v, sizeof(v));
}

static void finalize_sdt(uint8_t *buf, size_t len, const char sig[4], uint8_t rev)
{
    memcpy(buf, sig, 4);
    write_u32(buf + 4, (uint32_t)len);
    buf[8] = rev;
    buf[9] = 0;
    memcpy(buf + 10, "HUESOS", 6);
    memcpy(buf + 16, "TESTTBL ", 8);
    write_u32(buf + 24, 1);
    memcpy(buf + 28, "HUES", 4);
    write_u32(buf + 32, 1);
    buf[9] = (uint8_t)(0 - acpi_checksum(buf, len));
}

static void register_region(uacpi_phys_addr phys, const uint8_t *data, size_t len)
{
    if (g_region_count >= MAX_REGIONS)
        abort();
    g_regions[g_region_count++] = (struct test_region){
        .phys = phys,
        .data = data,
        .len = len,
    };
}

int hues_mmio_region_read(uacpi_u64 address, uacpi_u8 width, uacpi_u64 *out_value)
{
    (void)address;
    (void)width;
    (void)out_value;
    g_mmio_calls++;
    return UACPI_STATUS_DENIED;
}

int hues_mmio_region_write(uacpi_u64 address, uacpi_u8 width, uacpi_u64 value)
{
    (void)address;
    (void)width;
    (void)value;
    g_mmio_calls++;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address)
{
    if (out_rsdp_address == NULL || g_rsdp_phys == 0)
        return UACPI_STATUS_INVALID_ARGUMENT;
    *out_rsdp_address = g_rsdp_phys;
    return UACPI_STATUS_OK;
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len)
{
    if (len == 0)
        return UACPI_MAP_FAILED;
    for (size_t i = 0; i < g_region_count; ++i) {
        uacpi_phys_addr start = g_regions[i].phys;
        uacpi_phys_addr end = start + g_regions[i].len;
        if (addr >= start && len <= g_regions[i].len && addr - start <= g_regions[i].len - len) {
            (void)end;
            return (void *)(uintptr_t)(g_regions[i].data + (addr - start));
        }
    }
    return UACPI_MAP_FAILED;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len)
{
    (void)addr;
    (void)len;
}

void *uacpi_kernel_alloc(uacpi_size size)
{
    return malloc(size == 0 ? 1 : size);
}

void *uacpi_kernel_alloc_zeroed(uacpi_size size)
{
    return calloc(1, size == 0 ? 1 : size);
}

void uacpi_kernel_free(void *mem, uacpi_size size_hint)
{
    (void)size_hint;
    free(mem);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *msg)
{
    if (level == UACPI_LOG_ERROR)
        g_error_logs++;
    if (msg != NULL && strstr(msg, "no handler") != NULL)
        g_no_handler_logs++;
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void)
{
    g_ticks += 1;
    return g_ticks * 200000000ULL;
}

void uacpi_kernel_stall(uacpi_u8 usec) { (void)usec; }
void uacpi_kernel_sleep(uacpi_u64 msec) { (void)msec; }

uacpi_handle uacpi_kernel_create_mutex(void)
{
    int *m = (int *)calloc(1, sizeof(int));
    return m;
}
void uacpi_kernel_free_mutex(uacpi_handle h) { free(h); }
uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle h, uacpi_u16 t)
{
    (void)h;
    (void)t;
    return UACPI_STATUS_OK;
}
void uacpi_kernel_release_mutex(uacpi_handle h) { (void)h; }

uacpi_handle uacpi_kernel_create_event(void)
{
    int *e = (int *)calloc(1, sizeof(int));
    return e;
}
void uacpi_kernel_free_event(uacpi_handle h) { free(h); }
uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle h, uacpi_u16 t)
{
    (void)h;
    (void)t;
    return UACPI_FALSE;
}
void uacpi_kernel_signal_event(uacpi_handle h) { (void)h; }
void uacpi_kernel_reset_event(uacpi_handle h) { (void)h; }

uacpi_thread_id uacpi_kernel_get_thread_id(void) { return (uacpi_thread_id)(uintptr_t)1; }

uacpi_cpu_flags uacpi_kernel_disable_interrupts(void) { return 0; }
void uacpi_kernel_restore_interrupts(uacpi_cpu_flags f) { (void)f; }

uacpi_handle uacpi_kernel_create_spinlock(void)
{
    int *s = (int *)calloc(1, sizeof(int));
    return s;
}
void uacpi_kernel_free_spinlock(uacpi_handle h) { free(h); }
uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle h)
{
    (void)h;
    return 0;
}
void uacpi_kernel_unlock_spinlock(uacpi_handle h, uacpi_cpu_flags f)
{
    (void)h;
    (void)f;
}

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle)
{
    g_pci_calls++;
    if (g_allow_pci_read && address.segment == 0 && address.bus == 0 &&
        address.device == 0 && address.function == 0) {
        *out_handle = (uacpi_handle)(uintptr_t)0x1234u;
        return UACPI_STATUS_OK;
    }
    (void)out_handle;
    return UACPI_STATUS_DENIED;
}
void uacpi_kernel_pci_device_close(uacpi_handle h) { (void)h; }
uacpi_status uacpi_kernel_pci_read8(uacpi_handle h, uacpi_size o, uacpi_u8 *v)
{
    g_pci_calls++;
    if (g_allow_pci_read && h == (uacpi_handle)(uintptr_t)0x1234u && o < 4) {
        g_pci_reads++;
        *v = (uacpi_u8)(0x12348086u >> (o * 8));
        return UACPI_STATUS_OK;
    }
    (void)v;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_pci_read16(uacpi_handle h, uacpi_size o, uacpi_u16 *v)
{
    g_pci_calls++;
    if (g_allow_pci_read && h == (uacpi_handle)(uintptr_t)0x1234u && o <= 2) {
        g_pci_reads++;
        *v = (uacpi_u16)(0x12348086u >> (o * 8));
        return UACPI_STATUS_OK;
    }
    (void)v;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_pci_read32(uacpi_handle h, uacpi_size o, uacpi_u32 *v)
{
    g_pci_calls++;
    if (g_allow_pci_read && h == (uacpi_handle)(uintptr_t)0x1234u && o == 0) {
        g_pci_reads++;
        *v = 0x12348086u;
        return UACPI_STATUS_OK;
    }
    (void)v;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_pci_write8(uacpi_handle h, uacpi_size o, uacpi_u8 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_pci_calls++;
    g_pci_writes++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_pci_write16(uacpi_handle h, uacpi_size o, uacpi_u16 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_pci_calls++;
    g_pci_writes++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_pci_write32(uacpi_handle h, uacpi_size o, uacpi_u32 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_pci_calls++;
    g_pci_writes++;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle)
{
    (void)base;
    (void)len;
    (void)out_handle;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
void uacpi_kernel_io_unmap(uacpi_handle h) { (void)h; }
uacpi_status uacpi_kernel_io_read8(uacpi_handle h, uacpi_size o, uacpi_u8 *v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_io_read16(uacpi_handle h, uacpi_size o, uacpi_u16 *v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_io_read32(uacpi_handle h, uacpi_size o, uacpi_u32 *v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_io_write8(uacpi_handle h, uacpi_size o, uacpi_u8 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_io_write16(uacpi_handle h, uacpi_size o, uacpi_u16 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_io_write32(uacpi_handle h, uacpi_size o, uacpi_u32 v)
{
    (void)h;
    (void)o;
    (void)v;
    g_io_calls++;
    return UACPI_STATUS_DENIED;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle ctx, uacpi_handle *out)
{
    (void)irq;
    (void)handler;
    (void)ctx;
    (void)out;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_uninstall_interrupt_handler(
    uacpi_interrupt_handler handler, uacpi_handle h)
{
    (void)handler;
    (void)h;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_schedule_work(uacpi_work_type t, uacpi_work_handler h, uacpi_handle c)
{
    (void)t;
    (void)h;
    (void)c;
    return UACPI_STATUS_DENIED;
}
uacpi_status uacpi_kernel_wait_for_work_completion(void) { return UACPI_STATUS_OK; }
uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *req)
{
    (void)req;
    return UACPI_STATUS_DENIED;
}

static void setup_corpus(const uint8_t *aml, size_t aml_len)
{
    static uint8_t rsdp[36];
    static uint8_t xsdt[44];
    static uint8_t fadt[244];
    static uint8_t facs[64];
    static uint8_t dsdt[256];

    g_region_count = 0;
    g_mmio_calls = 0;
    g_io_calls = 0;
    g_pci_calls = 0;
    g_pci_reads = 0;
    g_pci_writes = 0;
    g_error_logs = 0;
    g_no_handler_logs = 0;
    g_allow_pci_read = 0;

    memset(rsdp, 0, sizeof(rsdp));
    memset(xsdt, 0, sizeof(xsdt));
    memset(fadt, 0, sizeof(fadt));
    memset(facs, 0, sizeof(facs));
    memset(dsdt, 0, sizeof(dsdt));

    if (36 + aml_len > sizeof(dsdt))
        abort();

    memcpy(dsdt + 36, aml, aml_len);
    finalize_sdt(dsdt, 36 + aml_len, "DSDT", 2);

    memcpy(facs, "FACS", 4);
    write_u32(facs + 4, sizeof(facs));
    facs[32] = 2;

    write_u32(fadt + 36, 0x3000); /* FIRMWARE_CTRL -> FACS */
    write_u32(fadt + 40, 0x4000); /* DSDT */
    fadt[45] = 0;
    write_u32(fadt + 112, 1u << 20); /* HW_REDUCED_ACPI off, normal FADT */
    write_u64(fadt + 132, 0x3000);
    write_u64(fadt + 140, 0x4000);
    finalize_sdt(fadt, sizeof(fadt), "FACP", 4);

    write_u64(xsdt + 36, 0x2000);
    finalize_sdt(xsdt, sizeof(xsdt), "XSDT", 1);

    memcpy(rsdp, "RSD PTR ", 8);
    rsdp[15] = 2;
    write_u32(rsdp + 20, sizeof(rsdp));
    write_u64(rsdp + 24, 0x1000);
    rsdp[8] = (uint8_t)(0 - acpi_checksum(rsdp, 20));
    rsdp[32] = (uint8_t)(0 - acpi_checksum(rsdp, sizeof(rsdp)));

    g_rsdp_phys = 0x5000;
    register_region(0x1000, rsdp, sizeof(rsdp));
    register_region(0x2000, fadt, sizeof(fadt));
    register_region(0x3000, facs, sizeof(facs));
    register_region(0x4000, dsdt, 36 + aml_len);
    register_region(0x5000, rsdp, sizeof(rsdp));
    /* Fix XSDT address registration (0x1000 is XSDT). */
    g_regions[0].data = xsdt;
    g_regions[0].len = sizeof(xsdt);
}

int main(void)
{
    /* Valid DSDT AML:
     * Scope(\_SB) {
     *   Device(PCI0) { Name(_ADR, Zero) }
     *   OperationRegion(MEM0, SystemMemory, 0xFED00000, 0x0100)
     *   Field(MEM0, DWordAcc, NoLock, Preserve) { REGA, 32 }
     *   OperationRegion(EC0_, EmbeddedControl, 0, 0x10)
     *   Field(EC0_, ByteAcc, NoLock, Preserve) { EREG, 8 }
     *   Method(MTH0, 0, Serialized) { Return (0x42) }
     * }
     */
    static const uint8_t valid_aml[] = {
        /* Scope(\_SB_) pkg_len = 81 (0x51 -> 0x41 0x05) */
        0x10, 0x41, 0x05, 0x5C, '_', 'S', 'B', '_',
        /* Device(PCI0) */
        0x5B, 0x82, 0x0B, 'P', 'C', 'I', '0',
        0x08, '_', 'A', 'D', 'R', 0x00,
        /* OperationRegion(MEM0, SystemMemory, 0xFED00000, 0x0100) */
        0x5B, 0x80, 'M', 'E', 'M', '0', 0x00,
        0x0C, 0x00, 0x00, 0xD0, 0xFE, 0x0B, 0x00, 0x01,
        /* Field(MEM0, DWordAcc, NoLock, Preserve) { REGA, 32 } */
        0x5B, 0x81, 0x0B, 'M', 'E', 'M', '0', 0x02, 'R', 'E', 'G', 'A', 0x20,
        /* OperationRegion(EC0_, EmbeddedControl, 0, 0x10) */
        0x5B, 0x80, 'E', 'C', '0', '_', 0x03, 0x00, 0x0A, 0x10,
        /* Field(EC0_, ByteAcc, NoLock, Preserve) { EREG, 8 } */
        0x5B, 0x81, 0x0B, 'E', 'C', '0', '_', 0x00, 'E', 'R', 'E', 'G', 0x08,
        /* Method(MTH0, 0, Serialized) { Return (0x42) } */
        0x14, 0x09, 'M', 'T', 'H', '0', 0x08, 0xA4, 0x0A, 0x42,
    };

    setup_corpus(valid_aml, sizeof(valid_aml));
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK) {
        fprintf(stderr, "valid corpus failed to load namespace\n");
        return 1;
    }
    if (g_error_logs != 0) {
        fprintf(stderr, "valid corpus logged %u errors\n", g_error_logs);
        return 1;
    }
    if (g_mmio_calls != 0 || g_io_calls != 0 || g_pci_calls != 0) {
        fprintf(stderr, "namespace_load performed unexpected HW access\n");
        return 1;
    }
    uacpi_namespace_node *node = NULL;
    if (uacpi_namespace_node_find(UACPI_NULL, "\\_SB.PCI0", &node) != UACPI_STATUS_OK) {
        fprintf(stderr, "missing \\_SB.PCI0 node\n");
        return 1;
    }
    if (uacpi_namespace_node_find(UACPI_NULL, "\\_SB.MTH0", &node) != UACPI_STATUS_OK) {
        fprintf(stderr, "missing \\_SB.MTH0 node\n");
        return 1;
    }
    uacpi_state_reset();

    /* Malformed / truncated AML corpus: must fail cleanly with 0 leaks / UB. */
    static const uint8_t malformed_aml[] = {
        0x14, 0x20, 'B', 'A', 'D', 'M', 0x5B, 0xFF,
    };
    setup_corpus(malformed_aml, sizeof(malformed_aml));
    (void)hues_uacpi_load_namespace(5, 64);
    if (g_error_logs == 0) {
        fprintf(stderr, "malformed corpus failed to report an AML error\n");
        return 1;
    }
    uacpi_state_reset();

    /* AP-14 Case 1: Missing _PIC allowed; _REG(SystemMemory) + _STA + _INI
     * with mediated PCI_Config read succeeds cleanly with zero errors.
     */
    static const uint8_t init_no_pic_aml[] = {
        /* Scope(\_SB_) pkg_len = 114 (0x72 -> 0x42 0x07) */
        0x10, 0x42, 0x07, 0x5C, '_', 'S', 'B', '_',
        /* Device(PCI0) pkg_len = 105 (0x69 -> 0x49 0x06) */
        0x5B, 0x82, 0x49, 0x06, 'P', 'C', 'I', '0',
        /* Name(_HID, EISAID("PNP0A03")) */
        0x08, '_', 'H', 'I', 'D', 0x0C, 0x41, 0xD0, 0x0A, 0x03,
        /* Name(_ADR, 0) */
        0x08, '_', 'A', 'D', 'R', 0x00,
        /* Name(RFLG, 0) */
        0x08, 'R', 'F', 'L', 'G', 0x00,
        /* OperationRegion(CFG0, PCI_Config, 0, 0x0100) */
        0x5B, 0x80, 'C', 'F', 'G', '0', 0x02, 0x00, 0x0B, 0x00, 0x01,
        /* Field(CFG0, DWordAcc, NoLock, Preserve) { VID0, 32 } */
        0x5B, 0x81, 0x0B, 'C', 'F', 'G', '0', 0x03, 'V', 'I', 'D', '0', 0x20,
        /* OperationRegion(MEM0, SystemMemory, 0xFED00000, 0x0100) */
        0x5B, 0x80, 'M', 'E', 'M', '0', 0x00,
        0x0C, 0x00, 0x00, 0xD0, 0xFE, 0x0B, 0x00, 0x01,
        /* Method(_REG, 2) { Store(Arg1, RFLG) } */
        0x14, 0x0C, '_', 'R', 'E', 'G', 0x02, 0x70, 0x69, 'R', 'F', 'L', 'G',
        /* Method(_STA, 0) { Return(0x0F) } */
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Method(_INI, 0) { Store(VID0, Local0) } */
        0x14, 0x0C, '_', 'I', 'N', 'I', 0x00, 0x70, 'V', 'I', 'D', '0', 0x60,
    };
    setup_corpus(init_no_pic_aml, sizeof(init_no_pic_aml));
    g_allow_pci_read = 1;
    int pic_st = -1;
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK ||
        pic_st != UACPI_STATUS_OK) {
        fprintf(stderr, "AP-14 case 1 failed\n");
        return 1;
    }
    uacpi_u64 rflg = 0;
    if (uacpi_eval_simple_integer(UACPI_NULL, "\\_SB.PCI0.RFLG", &rflg) != UACPI_STATUS_OK ||
        rflg != 1 || g_pci_reads == 0 || g_error_logs != 0) {
        fprintf(stderr, "AP-14 case 1 invariants failed (rflg=%llu reads=%u errs=%u)\n",
                (unsigned long long)rflg, g_pci_reads, g_error_logs);
        return 1;
    }
    uacpi_state_reset();

    /* AP-14 Case 2: Explicit _PIC(Arg0) receives IOAPIC (=1). */
    static const uint8_t init_pic_aml[] = {
        /* Name(PMOD, 0) */
        0x08, 'P', 'M', 'O', 'D', 0x00,
        /* Method(_PIC, 1) { Store(Arg0, PMOD) } */
        0x14, 0x0C, '_', 'P', 'I', 'C', 0x01, 0x70, 0x68, 'P', 'M', 'O', 'D',
    };
    setup_corpus(init_pic_aml, sizeof(init_pic_aml));
    pic_st = -1;
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK ||
        pic_st != UACPI_STATUS_OK) {
        fprintf(stderr, "AP-14 case 2 failed\n");
        return 1;
    }
    uacpi_u64 pmod = 0;
    if (uacpi_eval_simple_integer(UACPI_NULL, "\\PMOD", &pmod) != UACPI_STATUS_OK ||
        pmod != UACPI_INTERRUPT_MODEL_IOAPIC) {
        fprintf(stderr, "AP-14 case 2 _PIC model mismatch (%llu)\n",
                (unsigned long long)pmod);
        return 1;
    }
    uacpi_state_reset();

    /* AP-14 Case 3: Denied PCI config write inside _INI degrades cleanly. */
    static const uint8_t init_pci_write_aml[] = {
        /* Scope(\_SB_) pkg_len = 81 (0x51 -> 0x41 0x05) */
        0x10, 0x41, 0x05, 0x5C, '_', 'S', 'B', '_',
        /* Device(PCI0) pkg_len = 72 (0x48 -> 0x48 0x04) */
        0x5B, 0x82, 0x48, 0x04, 'P', 'C', 'I', '0',
        /* Name(_HID, EISAID("PNP0A03")) */
        0x08, '_', 'H', 'I', 'D', 0x0C, 0x41, 0xD0, 0x0A, 0x03,
        0x08, '_', 'A', 'D', 'R', 0x00,
        0x5B, 0x80, 'C', 'F', 'G', '0', 0x02, 0x00, 0x0B, 0x00, 0x01,
        0x5B, 0x81, 0x0B, 'C', 'F', 'G', '0', 0x03, 'V', 'I', 'D', '0', 0x20,
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Method(_INI, 0) { Store(0x42, VID0) } */
        0x14, 0x0D, '_', 'I', 'N', 'I', 0x00, 0x70, 0x0A, 0x42, 'V', 'I', 'D', '0',
    };
    setup_corpus(init_pci_write_aml, sizeof(init_pci_write_aml));
    g_allow_pci_read = 1;
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK ||
        g_pci_writes == 0 || g_error_logs == 0) {
        fprintf(stderr, "AP-14 case 3 denied PCI write check failed\n");
        return 1;
    }
    uacpi_state_reset();

    /* AP-14 Case 4: Unsupported EmbeddedControl access inside _INI degrades cleanly. */
    static const uint8_t init_ec_aml[] = {
        /* Scope(\_SB_) pkg_len = 69 (0x45 -> 0x45 0x04) */
        0x10, 0x45, 0x04, 0x5C, '_', 'S', 'B', '_',
        /* Device(EC0D) pkg_len = 60 (0x3C -> 0x4C 0x03) */
        0x5B, 0x82, 0x4C, 0x03, 'E', 'C', '0', 'D',
        0x5B, 0x80, 'E', 'C', '0', '_', 0x03, 0x00, 0x0A, 0x10,
        0x5B, 0x81, 0x0B, 'E', 'C', '0', '_', 0x00, 'E', 'R', 'E', 'G', 0x08,
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Method(_INI, 0) { Store(EREG, Local0) } */
        0x14, 0x0C, '_', 'I', 'N', 'I', 0x00, 0x70, 'E', 'R', 'E', 'G', 0x60,
    };
    setup_corpus(init_ec_aml, sizeof(init_ec_aml));
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK ||
        g_no_handler_logs == 0 || g_error_logs == 0) {
        fprintf(stderr, "AP-14 case 4 unsupported EC OpRegion check failed\n");
        return 1;
    }
    uacpi_state_reset();

    /* AP-14 Case 5: Infinite While(One) loop hits bounded loop timeout cleanly. */
    static const uint8_t init_loop_timeout_aml[] = {
        /* Scope(\_SB_) pkg_len = 41 (0x29 -> 0x29) */
        0x10, 0x29, 0x5C, '_', 'S', 'B', '_',
        /* Device(DEV0) pkg_len = 34 (0x22 -> 0x22) */
        0x5B, 0x82, 0x22, 'D', 'E', 'V', '0',
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Method(_INI, 0) { While(One) {} } */
        0x14, 0x09, '_', 'I', 'N', 'I', 0x00, 0xA2, 0x02, 0x01,
    };
    setup_corpus(init_loop_timeout_aml, sizeof(init_loop_timeout_aml));
    if (hues_uacpi_load_namespace(1, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(1, 64, &pic_st) != UACPI_STATUS_OK ||
        g_error_logs == 0) {
        fprintf(stderr, "AP-14 case 5 loop timeout check failed\n");
        return 1;
    }
    uacpi_state_reset();

    /*
     * AP-15 Case 6: PNP0A08 root without _SEG/_BBN (defaults to seg 0, bus 0),
     * _CRS with WordBusNumber(0..=3), Consumer WordIO(0xCF8..=0xCFF -> ignored),
     * Producer WordIO(0x1000..=0x1FFF), Producer DWordMemory(0x80000000..=0x8FFFFFFF),
     * and Producer Prefetchable QWordMemory(0x400000000..=0x4FFFFFFFF, _TRA=0x100000000).
     */
    static const uint8_t ap15_root_aml[] = {
        /* Scope(\_SB_) pkg_len: 5 + (2 + 4 + 10 + 10 + 6 + 3 + 2 + 128) = 170 = 0xAA -> 0x4A 0x0A */
        0x10, 0x4A, 0x0A, 0x5C, '_', 'S', 'B', '_',
        /* Device(PCI0) pkg_len: 2 + 4 + 10 + 10 + 128 = 154? wait: compute dynamically below! */
        0x5B, 0x82, 0x4A, 0x09, 'P', 'C', 'I', '0',
        /* Name(_HID, EISAID("PNP0A08")) */
        0x08, '_', 'H', 'I', 'D', 0x0C, 0x41, 0xD0, 0x0A, 0x08,
        /* Method(_STA, 0) { Return(0x0F) } */
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Name(_CRS, Buffer(118)) -> 0x08,'_','C','R','S', 0x11, 0x4C,0x07, 0x0A,118 */
        0x08, '_', 'C', 'R', 'S',
        0x11, 0x49, 0x07, 0x0A, 118,
        /* WordBusNumber(Producer, 0..=3, len=4) [16 bytes] */
        0x88, 0x0D, 0x00, 0x02, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
        /* WordIO(Consumer, 0x0CF8..=0x0CFF, len=8) [16 bytes] */
        0x88, 0x0D, 0x00, 0x01, 0x0D, 0x03,
        0x00, 0x00, 0xF8, 0x0C, 0xFF, 0x0C, 0x00, 0x00, 0x08, 0x00,
        /* WordIO(Producer, 0x1000..=0x1FFF, len=0x1000) [16 bytes] */
        0x88, 0x0D, 0x00, 0x01, 0x0C, 0x03,
        0x00, 0x00, 0x00, 0x10, 0xFF, 0x1F, 0x00, 0x00, 0x00, 0x10,
        /* DWordMemory(Producer, NonCacheable, 0x80000000..=0x8FFFFFFF, len=0x10000000) [26 bytes] */
        0x87, 0x17, 0x00, 0x00, 0x0C, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x80,
        0xFF, 0xFF, 0xFF, 0x8F,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10,
        /* QWordMemory(Producer, Prefetchable, 0x400000000..=0x4FFFFFFFF, tra=0x100000000, len=0x100000000) [46 bytes? 3+43=46] */
        /* Note: 16+16+16+26+46+2 = 122 bytes! */
        0x8A, 0x2B, 0x00, 0x00, 0x0C, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        /* EndTag [2 bytes] */
        0x79, 0x00,
    };
    uint8_t root_aml_buf[sizeof(ap15_root_aml)];
    memcpy(root_aml_buf, ap15_root_aml, sizeof(ap15_root_aml));
    /* Fix Buffer(122) length + pkg_len + Device/Scope pkg_lens cleanly */
    size_t crs_buf_len = sizeof(ap15_root_aml) - 46; /* 122 bytes */
    size_t crs_pkg = 2 + 2 + crs_buf_len;            /* 126 bytes (pkg_len + BytePrefix + len + payload) */
    size_t dev_pkg = sizeof(ap15_root_aml) - 10;     /* everything after 0x5B 0x82 */
    size_t sb_pkg = sizeof(ap15_root_aml) - 1;       /* everything after 0x10 */
    root_aml_buf[1] = (uint8_t)(0x40 | (sb_pkg & 0x0Fu));
    root_aml_buf[2] = (uint8_t)(sb_pkg >> 4);
    root_aml_buf[10] = (uint8_t)(0x40 | (dev_pkg & 0x0Fu));
    root_aml_buf[11] = (uint8_t)(dev_pkg >> 4);
    root_aml_buf[42] = (uint8_t)(0x40 | (crs_pkg & 0x0Fu));
    root_aml_buf[43] = (uint8_t)(crs_pkg >> 4);
    root_aml_buf[45] = (uint8_t)crs_buf_len;

    setup_corpus(root_aml_buf, sizeof(root_aml_buf));
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK) {
        fprintf(stderr, "AP-15 case 6 namespace init failed\n");
        return 1;
    }
    HuesPciRootsOut roots_out;
    if (hues_uacpi_collect_pci_roots(&roots_out) != UACPI_STATUS_OK ||
        roots_out.root_count != 1 || roots_out.aperture_count != 3 ||
        roots_out.roots[0].segment != 0 ||
        roots_out.roots[0].start_bus != 0 ||
        roots_out.roots[0].end_bus != 3 ||
        roots_out.apertures[0].kind != 1 ||
        roots_out.apertures[0].pci_base != 0x1000ULL ||
        roots_out.apertures[1].kind != 2 ||
        roots_out.apertures[1].pci_base != 0x80000000ULL ||
        roots_out.apertures[2].kind != 4 ||
        roots_out.apertures[2].pci_base != 0x400000000ULL ||
        roots_out.apertures[2].cpu_base != 0x500000000ULL) {
        fprintf(stderr, "AP-15 case 6 root collection mismatch (roots=%u aps=%u)\n",
                roots_out.root_count, roots_out.aperture_count);
        return 1;
    }
    uacpi_state_reset();

    /* AP-15 Case 7: Conflicting _BBN=1 vs _CRS bus 0..=3 fails closed. */
    static const uint8_t ap15_bad_bbn_aml[] = {
        /* Scope(\_SB_) */
        0x10, 0x43, 0x03, 0x5C, '_', 'S', 'B', '_',
        /* Device(PCI0) */
        0x5B, 0x82, 0x4A, 0x02, 'P', 'C', 'I', '0',
        0x08, '_', 'H', 'I', 'D', 0x0C, 0x41, 0xD0, 0x0A, 0x03,
        /* Name(_BBN, 1) */
        0x08, '_', 'B', 'B', 'N', 0x01,
        0x14, 0x09, '_', 'S', 'T', 'A', 0x00, 0xA4, 0x0A, 0x0F,
        /* Name(_CRS, Buffer(18) { WordBusNumber(0..=3), EndTag }) */
        0x08, '_', 'C', 'R', 'S', 0x11, 0x15, 0x0A, 18,
        0x88, 0x0D, 0x00, 0x02, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x79, 0x00,
    };
    uint8_t bad_bbn_buf[sizeof(ap15_bad_bbn_aml)];
    memcpy(bad_bbn_buf, ap15_bad_bbn_aml, sizeof(ap15_bad_bbn_aml));
    size_t bad_dev_pkg = sizeof(ap15_bad_bbn_aml) - 10; /* 57 -> 0x49 0x03 */
    size_t bad_sb_pkg = sizeof(ap15_bad_bbn_aml) - 1;  /* 66 -> 0x42 0x04 */
    bad_bbn_buf[1] = (uint8_t)(0x40 | (bad_sb_pkg & 0x0Fu));
    bad_bbn_buf[2] = (uint8_t)(bad_sb_pkg >> 4);
    bad_bbn_buf[10] = (uint8_t)(0x40 | (bad_dev_pkg & 0x0Fu));
    bad_bbn_buf[11] = (uint8_t)(bad_dev_pkg >> 4);

    setup_corpus(bad_bbn_buf, sizeof(bad_bbn_buf));
    if (hues_uacpi_load_namespace(5, 64) != UACPI_STATUS_OK ||
        hues_uacpi_initialize_namespace(5, 64, &pic_st) != UACPI_STATUS_OK ||
        hues_uacpi_collect_pci_roots(&roots_out) == UACPI_STATUS_OK) {
        fprintf(stderr, "AP-15 case 7 conflicting _BBN check failed\n");
        return 1;
    }
    uacpi_state_reset();

    return 0;
}
