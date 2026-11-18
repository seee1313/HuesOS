#include <uacpi/acpi.h>
#include <uacpi/context.h>
#include <uacpi/internal/context.h>
#include <uacpi/kernel_api.h>
#include <uacpi/namespace.h>
#include <uacpi/opregion.h>
#include <uacpi/platform/libc.h>
#include <uacpi/resources.h>
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

#define HUES_MAX_PCI_ROOTS 16
#define HUES_MAX_PCI_APERTURES 64
#define HUES_APERTURE_KIND_IO 1
#define HUES_APERTURE_KIND_MMIO32 2
#define HUES_APERTURE_KIND_MMIO64 3
#define HUES_APERTURE_KIND_PREFETCH 4
#define HUES_APERTURE_FLAG_FIXED (1u << 1)

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
    HuesPciRootDesc roots[HUES_MAX_PCI_ROOTS];
    HuesPciApertureDesc apertures[HUES_MAX_PCI_APERTURES];
} HuesPciRootsOut;

struct root_crs_ctx {
    HuesPciRootsOut *out;
    uacpi_u16 root_index;
    uacpi_status error;
};

static uacpi_status push_root_address(
    struct root_crs_ctx *ctx,
    const uacpi_resource_address_common *common,
    uacpi_u64 min,
    uacpi_u64 max,
    uacpi_u64 tra,
    uacpi_u64 len,
    uacpi_bool is_addr64)
{
    HuesPciRootDesc *root = &ctx->out->roots[ctx->root_index];
    uacpi_u64 cpu_base;
    uacpi_u32 flags = 0;
    uacpi_u8 kind;

    /* Only ResourceProducer descriptors define downstream root apertures. */
    if (common->direction != UACPI_PRODUCER)
        return UACPI_STATUS_OK;

    if (len == 0)
        return UACPI_STATUS_INVALID_ARGUMENT;
    if (min > UINT64_MAX - len)
        return UACPI_STATUS_INVALID_ARGUMENT;
    if (common->fixed_min_address == UACPI_ADDRESS_FIXED &&
        common->fixed_max_address == UACPI_ADDRESS_FIXED) {
        if (max < min || (max - min) != (len - 1))
            return UACPI_STATUS_INVALID_ARGUMENT;
        flags |= HUES_APERTURE_FLAG_FIXED;
    }

    if (common->type == UACPI_RANGE_BUS) {
        if (tra != 0 || min > 0xFFu || max > 0xFFu || max < min ||
            len > 256u || (max - min) != (len - 1)) {
            return UACPI_STATUS_INVALID_ARGUMENT;
        }
        if (root->has_bus_range)
            return UACPI_STATUS_INVALID_ARGUMENT;
        if (root->has_bbn && (uacpi_u8)min != root->start_bus)
            return UACPI_STATUS_INVALID_ARGUMENT;
        root->start_bus = (uacpi_u8)min;
        root->end_bus = (uacpi_u8)max;
        root->has_bus_range = 1;
        return UACPI_STATUS_OK;
    }

    if (common->type != UACPI_RANGE_IO && common->type != UACPI_RANGE_MEMORY)
        return UACPI_STATUS_OK;

    if (min > UINT64_MAX - tra)
        return UACPI_STATUS_INVALID_ARGUMENT;
    cpu_base = min + tra;
    if (cpu_base > UINT64_MAX - len)
        return UACPI_STATUS_INVALID_ARGUMENT;

    if (common->type == UACPI_RANGE_IO) {
        kind = HUES_APERTURE_KIND_IO;
    } else if (common->attribute.memory.caching == UACPI_PREFETCHABLE) {
        kind = HUES_APERTURE_KIND_PREFETCH;
    } else if (!is_addr64 && (min + len) <= 0x100000000ULL) {
        kind = HUES_APERTURE_KIND_MMIO32;
    } else if ((min + len) <= 0x100000000ULL && (cpu_base + len) <= 0x100000000ULL) {
        kind = HUES_APERTURE_KIND_MMIO32;
    } else {
        kind = HUES_APERTURE_KIND_MMIO64;
    }

    if (ctx->out->aperture_count >= HUES_MAX_PCI_APERTURES)
        return UACPI_STATUS_OUT_OF_MEMORY;

    HuesPciApertureDesc *ap = &ctx->out->apertures[ctx->out->aperture_count++];
    ap->root_index = ctx->root_index;
    ap->kind = kind;
    ap->_pad = 0;
    ap->flags = flags;
    ap->pci_base = min;
    ap->cpu_base = cpu_base;
    ap->len = len;
    root->aperture_count++;
    return UACPI_STATUS_OK;
}

static uacpi_iteration_decision on_root_crs(void *user, uacpi_resource *res)
{
    struct root_crs_ctx *ctx = (struct root_crs_ctx *)user;
    uacpi_status st = UACPI_STATUS_OK;

    switch (res->type) {
    case UACPI_RESOURCE_TYPE_ADDRESS16:
        st = push_root_address(
            ctx,
            &res->address16.common,
            res->address16.minimum,
            res->address16.maximum,
            res->address16.translation_offset,
            res->address16.address_length,
            UACPI_FALSE);
        break;
    case UACPI_RESOURCE_TYPE_ADDRESS32:
        st = push_root_address(
            ctx,
            &res->address32.common,
            res->address32.minimum,
            res->address32.maximum,
            res->address32.translation_offset,
            res->address32.address_length,
            UACPI_FALSE);
        break;
    case UACPI_RESOURCE_TYPE_ADDRESS64:
        st = push_root_address(
            ctx,
            &res->address64.common,
            res->address64.minimum,
            res->address64.maximum,
            res->address64.translation_offset,
            res->address64.address_length,
            UACPI_TRUE);
        break;
    case UACPI_RESOURCE_TYPE_ADDRESS64_EXTENDED:
        st = push_root_address(
            ctx,
            &res->address64_extended.common,
            res->address64_extended.minimum,
            res->address64_extended.maximum,
            res->address64_extended.translation_offset,
            res->address64_extended.address_length,
            UACPI_TRUE);
        break;
    default:
        break;
    }

    if (st != UACPI_STATUS_OK) {
        ctx->error = st;
        return UACPI_ITERATION_DECISION_BREAK;
    }
    return UACPI_ITERATION_DECISION_CONTINUE;
}

struct roots_find_ctx {
    HuesPciRootsOut *out;
    uacpi_status error;
};

static uacpi_iteration_decision on_pci_root(
    void *user, uacpi_namespace_node *node, uacpi_u32 depth)
{
    struct roots_find_ctx *fctx = (struct roots_find_ctx *)user;
    (void)depth;

    if (fctx->out->root_count >= HUES_MAX_PCI_ROOTS) {
        fctx->error = UACPI_STATUS_OUT_OF_MEMORY;
        return UACPI_ITERATION_DECISION_BREAK;
    }

    uacpi_u16 root_idx = fctx->out->root_count;
    HuesPciRootDesc *root = &fctx->out->roots[root_idx];
    uacpi_memzero(root, sizeof(*root));
    root->aperture_start = fctx->out->aperture_count;

    uacpi_u64 seg = 0;
    uacpi_status st = uacpi_eval_simple_integer(node, "_SEG", &seg);
    if (st == UACPI_STATUS_NOT_FOUND) {
        seg = 0;
    } else if (st != UACPI_STATUS_OK || seg > 0xFFFFu) {
        fctx->error = (st != UACPI_STATUS_OK) ? st : UACPI_STATUS_INVALID_ARGUMENT;
        return UACPI_ITERATION_DECISION_BREAK;
    }
    root->segment = (uacpi_u16)seg;

    uacpi_u64 bbn = 0;
    st = uacpi_eval_simple_integer(node, "_BBN", &bbn);
    if (st == UACPI_STATUS_NOT_FOUND) {
        root->has_bbn = 0;
        root->start_bus = 0;
        root->end_bus = 0;
    } else if (st != UACPI_STATUS_OK || bbn > 0xFFu) {
        fctx->error = (st != UACPI_STATUS_OK) ? st : UACPI_STATUS_INVALID_ARGUMENT;
        return UACPI_ITERATION_DECISION_BREAK;
    } else {
        root->has_bbn = 1;
        root->start_bus = (uacpi_u8)bbn;
        root->end_bus = (uacpi_u8)bbn;
    }

    struct root_crs_ctx cctx = {
        .out = fctx->out,
        .root_index = root_idx,
        .error = UACPI_STATUS_OK,
    };
    st = uacpi_for_each_device_resource(node, "_CRS", on_root_crs, &cctx);
    if (st != UACPI_STATUS_OK) {
        fctx->error = st;
        return UACPI_ITERATION_DECISION_BREAK;
    }
    if (cctx.error != UACPI_STATUS_OK) {
        fctx->error = cctx.error;
        return UACPI_ITERATION_DECISION_BREAK;
    }

    fctx->out->root_count++;
    return UACPI_ITERATION_DECISION_CONTINUE;
}

int hues_uacpi_collect_pci_roots(HuesPciRootsOut *out)
{
    static const uacpi_char *const root_hids[] = {
        "PNP0A08",
        "PNP0A03",
        UACPI_NULL,
    };
    struct roots_find_ctx fctx;
    uacpi_status st;

    if (out == UACPI_NULL)
        return (int)UACPI_STATUS_INVALID_ARGUMENT;

    uacpi_memzero(out, sizeof(*out));
    fctx.out = out;
    fctx.error = UACPI_STATUS_OK;

    st = uacpi_find_devices_at(uacpi_namespace_root(), root_hids, on_pci_root, &fctx);
    if (st != UACPI_STATUS_OK)
        return (int)st;
    if (fctx.error != UACPI_STATUS_OK)
        return (int)fctx.error;
    return (int)UACPI_STATUS_OK;
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
