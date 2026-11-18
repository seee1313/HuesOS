#include <uacpi/acpi.h>
#include <uacpi/context.h>
#include <uacpi/internal/context.h>
#include <uacpi/kernel_api.h>
#include <uacpi/opregion.h>
#include <uacpi/platform/libc.h>
#include <uacpi/status.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

static _Alignas(16) struct acpi_facs g_local_facs;

/*
 * Thin C bridge between uACPI's typed region/lifecycle structs and the safe
 * Rust broker/runtime boundary. Keeping struct unpacking here avoids mirroring
 * internal uACPI C layouts in Rust and keeps Rust callback code unsafe-free.
 */

extern int hues_mmio_region_read(uacpi_u64 address, uacpi_u8 width, uacpi_u64 *out_value);
extern int hues_mmio_region_write(uacpi_u64 address, uacpi_u8 width, uacpi_u64 value);

struct hues_mmio_region_ctx {
    uacpi_u64 base;
    uacpi_u64 length;
};

static void hues_free_sized(void *ptr, uacpi_size size)
{
#ifdef UACPI_SIZED_FREES
    uacpi_kernel_free(ptr, size);
#else
    (void)size;
    uacpi_kernel_free(ptr);
#endif
}

static uacpi_status hues_system_memory_region_handler(
    uacpi_region_op op,
    uacpi_handle op_data)
{
    switch (op) {
    case UACPI_REGION_OP_ATTACH: {
        uacpi_region_attach_data *data = (uacpi_region_attach_data *)op_data;
        uacpi_u64 base = data->generic_info.base;
        uacpi_u64 length = data->generic_info.length;
        struct hues_mmio_region_ctx *ctx;

        if (length == 0 || base > (UINT64_MAX - length))
            return UACPI_STATUS_INVALID_ARGUMENT;

        ctx = (struct hues_mmio_region_ctx *)uacpi_kernel_alloc(sizeof(*ctx));
        if (ctx == UACPI_NULL)
            return UACPI_STATUS_OUT_OF_MEMORY;

        ctx->base = base;
        ctx->length = length;
        data->out_region_context = ctx;
        return UACPI_STATUS_OK;
    }
    case UACPI_REGION_OP_DETACH: {
        uacpi_region_detach_data *data = (uacpi_region_detach_data *)op_data;
        if (data->region_context != UACPI_NULL)
            hues_free_sized(data->region_context, sizeof(struct hues_mmio_region_ctx));
        return UACPI_STATUS_OK;
    }
    case UACPI_REGION_OP_READ:
    case UACPI_REGION_OP_WRITE: {
        uacpi_region_rw_data *data = (uacpi_region_rw_data *)op_data;
        struct hues_mmio_region_ctx *ctx =
            (struct hues_mmio_region_ctx *)data->region_context;
        uacpi_u64 end;
        if (ctx == UACPI_NULL || data->byte_width == 0)
            return UACPI_STATUS_INVALID_ARGUMENT;
        if (data->address < ctx->base)
            return UACPI_STATUS_INVALID_ARGUMENT;
        if (data->address > UINT64_MAX - data->byte_width)
            return UACPI_STATUS_INVALID_ARGUMENT;
        end = data->address + data->byte_width;
        if (end > ctx->base + ctx->length)
            return UACPI_STATUS_INVALID_ARGUMENT;

        if (op == UACPI_REGION_OP_READ) {
            return (uacpi_status)hues_mmio_region_read(
                data->address, data->byte_width, &data->value);
        }
        return (uacpi_status)hues_mmio_region_write(
            data->address, data->byte_width, data->value);
    }
    default:
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

int hues_uacpi_load_namespace(
    uacpi_u32 loop_timeout_secs,
    uacpi_u32 max_stack_depth)
{
    uacpi_status st;

    uacpi_context_set_loop_timeout(loop_timeout_secs);
    uacpi_context_set_max_call_stack_depth(max_stack_depth);

    st = uacpi_initialize(UACPI_FLAG_NO_ACPI_MODE);
    if (st != UACPI_STATUS_OK)
        return (int)st;

    (void)uacpi_uninstall_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_SYSTEM_MEMORY);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(),
        UACPI_ADDRESS_SPACE_SYSTEM_MEMORY,
        hues_system_memory_region_handler,
        UACPI_NULL);
    if (st != UACPI_STATUS_OK)
        return (int)st;

    st = uacpi_namespace_load();
    if (st == UACPI_STATUS_OK && g_uacpi_rt_ctx.facs != UACPI_NULL) {
        /*
         * Ring-3 maps the ACPI table archive read-only and FACS may not be
         * 4-byte aligned inside the packed archive. Copy FACS into aligned
         * process-local writable memory so Global Lock cmpxchg operations
         * never fault on the immutable archive VMO or write to physical RAM.
         */
        uacpi_memcpy(&g_local_facs, g_uacpi_rt_ctx.facs, sizeof(g_local_facs));
        g_local_facs.global_lock = 0;
        g_uacpi_rt_ctx.facs = &g_local_facs;
    }
    return (int)st;
}

int hues_uacpi_initialize_namespace(
    uacpi_u32 loop_timeout_secs,
    uacpi_u32 max_stack_depth,
    int *out_pic_status)
{
    uacpi_status pic_st;
    uacpi_status reg_st;
    uacpi_status init_st;

    uacpi_context_set_loop_timeout(loop_timeout_secs);
    uacpi_context_set_max_call_stack_depth(max_stack_depth);

    /*
     * Select the IOAPIC interrupt model (_PIC(1)) when present. uACPI maps
     * missing \_PIC (UACPI_STATUS_NOT_FOUND) to UACPI_STATUS_OK per ACPI spec.
     */
    pic_st = uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);
    if (out_pic_status != UACPI_NULL)
        *out_pic_status = (int)pic_st;

    /*
     * Our mediated SystemMemory handler replaced the default handler without
     * UACPI_ADDRESS_SPACE_HANDLER_DEFAULT, so run _REG for SystemMemory
     * OpRegions explicitly before device _STA/_INI evaluation.
     */
    reg_st = uacpi_reg_all_opregions(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_SYSTEM_MEMORY);
    (void)reg_st;

    init_st = uacpi_namespace_initialize();
    return (int)init_st;
}

uacpi_i64 hues_uacpi_namespace_phase(
    uacpi_u32 phase,
    uacpi_u32 loop_timeout_secs,
    uacpi_u32 max_stack_depth)
{
    if (phase == 0) {
        int st = hues_uacpi_load_namespace(loop_timeout_secs, max_stack_depth);
        return (uacpi_i64)(uacpi_i32)st;
    }
    if (phase == 1) {
        int pic_st = 0;
        int init_st = hues_uacpi_initialize_namespace(
            loop_timeout_secs, max_stack_depth, &pic_st);
        uacpi_u64 packed =
            (((uacpi_u64)(uacpi_u32)pic_st) << 32) | (uacpi_u64)(uacpi_u32)init_st;
        return (uacpi_i64)packed;
    }
    return (uacpi_i64)(uacpi_i32)UACPI_STATUS_INVALID_ARGUMENT;
}

#ifdef HUESOS_UACPI_RUST_LOG
struct HuesLogLine {
    uacpi_u32 level;
    uacpi_u8 len;
    uacpi_u8 bytes[251];
};

extern void hues_uacpi_log(struct HuesLogLine line);

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *message)
{
    struct HuesLogLine line;
    uacpi_size idx = 0;

    line.level = (uacpi_u32)level;
    for (idx = 0; idx < sizeof(line.bytes); ++idx)
        line.bytes[idx] = 0;

    if (message != UACPI_NULL) {
        idx = 0;
        while (idx < sizeof(line.bytes) && message[idx] != '\0') {
            line.bytes[idx] = (uacpi_u8)message[idx];
            idx++;
        }
        while (idx > 0 && (line.bytes[idx - 1] == '\n' || line.bytes[idx - 1] == '\r'))
            idx--;
        line.len = (uacpi_u8)idx;
    } else {
        line.len = 0;
    }
    hues_uacpi_log(line);
}
#endif
