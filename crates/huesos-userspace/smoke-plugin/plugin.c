#include "canvas.h"

static __thread uint64_t g_plugin_tls_counter = 0x1122334455667788ULL;

__attribute__((constructor)) static void smoke_plugin_init(void) {
    canvas_debug_puts("[smoke-plugin] ctor\n");
}

__attribute__((destructor)) static void smoke_plugin_fini(void) {
    canvas_debug_puts("[smoke-plugin] dtor\n");
}

int32_t smoke_plugin_add(int32_t a, int32_t b) {
    return a + b;
}

uint64_t smoke_plugin_tls_bump(uint64_t delta) {
    g_plugin_tls_counter += delta;
    return g_plugin_tls_counter;
}

uint64_t smoke_plugin_heap_roundtrip(void) {
    uint64_t *buf = (uint64_t *)malloc(64);
    if (!buf) {
        return 0;
    }
    buf[0] = 0xCAFEBABEDEADBEEFULL;
    buf[7] = 0x0123456789ABCDEFULL;
    uint64_t sum = buf[0] ^ buf[7];
    free(buf);
    return sum;
}
