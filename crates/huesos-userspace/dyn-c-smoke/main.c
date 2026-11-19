#include "canvas.h"

static __thread uint64_t g_main_tls = 0xABCDEF0123456789ULL;
static int g_atexit_ran = 0;

static int c_streq(const char *a, const char *b) {
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        if (*a != *b) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == *b;
}

static void on_c_atexit(void) {
    g_atexit_ran = 1;
    canvas_debug_puts("[dyn-c-smoke] atexit OK\n");
}

struct PhdrCheckState {
    int seen_main;
    int seen_libcanvas;
    int seen_plugin;
    uint64_t adds;
};

static int phdr_cb(CanvasDlPhdrInfo *info, size_t size, void *data) {
    struct PhdrCheckState *st = (struct PhdrCheckState *)data;
    if (!info || size < sizeof(CanvasDlPhdrInfo)) {
        return 1;
    }
    if (c_streq(info->dlpi_name, "<main>")) {
        st->seen_main = 1;
    } else if (c_streq(info->dlpi_name, "libcanvas.so")) {
        st->seen_libcanvas = 1;
    } else if (c_streq(info->dlpi_name, "libsmoke_plugin.so")) {
        st->seen_plugin = 1;
    }
    st->adds = info->dlpi_adds;
    return 0;
}

static int64_t c_smoke_main(void) {
    if (canvas_abi_version() != CANVAS_ABI_VERSION) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: bad ABI version\n");
        return 1;
    }

    if (atexit(on_c_atexit) != 0) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: atexit\n");
        return 2;
    }

    g_main_tls += 1;
    if (g_main_tls != 0xABCDEF012345678AULL) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: main TLS\n");
        return 3;
    }

    uint64_t *arr = (uint64_t *)calloc(4, sizeof(uint64_t));
    if (!arr) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: calloc\n");
        return 4;
    }
    arr[3] = 99;
    arr = (uint64_t *)realloc(arr, 8 * sizeof(uint64_t));
    if (!arr || arr[3] != 99) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: realloc\n");
        return 5;
    }
    free(arr);

    /* Negative test: path traversal SONAME must be rejected with dlerror(). */
    void *bad = canvas_dlopen_soname("../escape.so", CANVAS_RTLD_LOCAL);
    if (bad != NULL || canvas_dlerror() == NULL) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: path traversal not rejected\n");
        return 6;
    }
    if (canvas_dlerror() != NULL) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dlerror not cleared\n");
        return 7;
    }

    void *plugin = canvas_dlopen_soname("libsmoke_plugin.so", CANVAS_RTLD_LOCAL);
    if (!plugin) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dlopen_soname libsmoke_plugin.so\n");
        return 8;
    }

    typedef int32_t (*add_fn_t)(int32_t, int32_t);
    typedef uint64_t (*tls_bump_fn_t)(uint64_t);
    typedef uint64_t (*heap_fn_t)(void);

    add_fn_t add_fn = (add_fn_t)canvas_dlsym(plugin, "smoke_plugin_add");
    tls_bump_fn_t tls_fn = (tls_bump_fn_t)canvas_dlsym(plugin, "smoke_plugin_tls_bump");
    heap_fn_t heap_fn = (heap_fn_t)canvas_dlsym(plugin, "smoke_plugin_heap_roundtrip");
    if (!add_fn || !tls_fn || !heap_fn) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dlsym\n");
        return 9;
    }
    if (add_fn(19, 23) != 42) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: smoke_plugin_add\n");
        return 10;
    }
    if (tls_fn(5) != 0x112233445566778DULL || tls_fn(2) != 0x112233445566778FULL) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: plugin GD TLS\n");
        return 11;
    }
    if (heap_fn() != (0xCAFEBABEDEADBEEFULL ^ 0x0123456789ABCDEFULL)) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: plugin heap\n");
        return 12;
    }

    CanvasDlInfo dlinfo;
    if (canvas_dladdr((const void *)add_fn, &dlinfo) == 0 ||
        !c_streq(dlinfo.dli_sname, "smoke_plugin_add")) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dladdr\n");
        return 13;
    }

    struct PhdrCheckState phdr_state = {0, 0, 0, 0};
    canvas_dl_iterate_phdr(phdr_cb, &phdr_state);
    if (!phdr_state.seen_main || !phdr_state.seen_libcanvas || !phdr_state.seen_plugin) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dl_iterate_phdr\n");
        return 14;
    }

    if (canvas_dlclose(plugin) != 0) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: dlclose\n");
        return 15;
    }
    if (canvas_dlsym(plugin, "smoke_plugin_add") != NULL) {
        canvas_debug_puts("[dyn-c-smoke] FAIL: stale handle after dlclose\n");
        return 16;
    }
    (void)canvas_dlerror();

    canvas_debug_puts("[dyn-c-smoke] PASS\n");
    return 0;
}

__attribute__((used)) static void c_start_impl(void) {
    int64_t code = c_smoke_main();
    canvas_exit(code);
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "and $-16, %%rsp\n"
        "call c_start_impl\n"
        :
        :
        :);
}
