#ifndef HUESOS_CANVAS_H
#define HUESOS_CANVAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable C ABI version exported by libcanvas.so. */
#define CANVAS_ABI_VERSION 1u

/** Well-known initial bootstrap channel handle installed in every child process. */
#define CANVAS_BOOTSTRAP_HANDLE 1u
#define CANVAS_INVALID_HANDLE 0u

/** Default handle rights bitmask (`huesos_abi::rights::SAME_RIGHTS`). */
#define CANVAS_SAME_RIGHTS 0xFFFFFFFFu

/** Wait modes (`huesos_abi::wait_mode`). */
#define CANVAS_WAIT_ANY 0u
#define CANVAS_WAIT_ALL 1u

/** Signal bits (`huesos_abi::signals`). */
#define CANVAS_SIGNAL_NONE        0u
#define CANVAS_SIGNAL_READABLE    (1u << 0)
#define CANVAS_SIGNAL_WRITABLE    (1u << 1)
#define CANVAS_SIGNAL_CANCELED    (1u << 2)
#define CANVAS_SIGNAL_PEER_CLOSED (1u << 3)
#define CANVAS_SIGNAL_SIGNALED    (1u << 4)

/** VMAR mapping/protection flags (`huesos_abi::vmar_flags`). */
#define CANVAS_VMAR_READ    (1u << 0)
#define CANVAS_VMAR_WRITE   (1u << 1)
#define CANVAS_VMAR_EXECUTE (1u << 2)
#define CANVAS_VMAR_FIXED   (1u << 3)

/** Built-in fonts (`libcanvas::framebuffer::TextFont`). */
typedef enum CanvasTextFont {
    CANVAS_FONT_COZETTE_6X13 = 0,
    CANVAS_FONT_TTY_8X16 = 1,
    CANVAS_FONT_COMPACT_8X8 = 2
} CanvasTextFont;

/** Framebuffer geometry and pixel format (`huesos_abi::FramebufferInfo`). */
typedef struct CanvasFbInfo {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint16_t bpp;
    uint8_t red_mask_size;
    uint8_t red_mask_shift;
    uint8_t green_mask_size;
    uint8_t green_mask_shift;
    uint8_t blue_mask_size;
    uint8_t blue_mask_shift;
} CanvasFbInfo;

/** Multiplexed wait item for `canvas_wait_many`. */
typedef struct CanvasWaitItem {
    uint32_t handle;
    uint32_t awaited_signals;
    uint64_t key;
    uint32_t observed_signals;
    uint32_t _reserved;
} CanvasWaitItem;

/** Hardened Scudo heap runtime statistics. */
typedef struct CanvasHeapStats {
    uint64_t allocations;
    uint64_t deallocations;
    uint64_t oom_failures;
    uint64_t corruption_failures;
    uint64_t live_bytes;
} CanvasHeapStats;

/** Opaque off-screen drawing surface backed by a VMO. */
typedef struct CanvasSurface CanvasSurface;

/** Opaque HxFS filesystem client handle. */
typedef struct CanvasFs CanvasFs;

/** Opaque HxFS open file handle. */
typedef struct CanvasFsFile CanvasFsFile;

/** Opaque intra-process thread handle. */
typedef struct CanvasThread CanvasThread;

/** Thread entry function signature for `canvas_thread_spawn`. */
typedef int64_t (*CanvasThreadFn)(void *arg);

/** `canvas_dlopen_*` flags. */
#define CANVAS_RTLD_LAZY     0x0001
#define CANVAS_RTLD_NOW      0x0002
#define CANVAS_RTLD_LOCAL    0x0000
#define CANVAS_RTLD_NOLOAD   0x0004
#define CANVAS_RTLD_GLOBAL   0x0100
#define CANVAS_RTLD_NODELETE 0x1000

/** Symbol/object info filled by `canvas_dladdr`. */
typedef struct CanvasDlInfo {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} CanvasDlInfo;

/** Loaded module info passed to `canvas_dl_iterate_phdr`. */
typedef struct CanvasDlPhdrInfo {
    uint64_t dlpi_addr;
    const char *dlpi_name;
    const void *dlpi_phdr;
    uint16_t dlpi_phnum;
    uint64_t dlpi_adds;
    uint64_t dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
} CanvasDlPhdrInfo;

/* --------------------------------------------------------------------------
 * ABI metadata & raw syscall gateway
 * -------------------------------------------------------------------------- */

uint32_t canvas_abi_version(void);
const char *canvas_error_str(int64_t err);
int64_t canvas_syscall(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);

/* --------------------------------------------------------------------------
 * Process, thread, console & system primitives
 * -------------------------------------------------------------------------- */

_Noreturn void canvas_exit(int64_t code);
void canvas_yield(void);
int64_t canvas_set_fs_base(uint64_t fs_base);
void canvas_debug_write(const uint8_t *bytes, size_t len);
void canvas_debug_puts(const char *cstr);
int64_t canvas_monotonic_ticks(uint64_t *out_ticks);
int64_t canvas_cpu_count(size_t *out_count);
int64_t canvas_current_cpu(size_t *out_cpu);
int64_t canvas_shutdown(void);
int64_t canvas_get_entropy(uint8_t *out_buf, size_t len, size_t *out_written);

/* --------------------------------------------------------------------------
 * Scudo userspace heap (auto-initialised via libcanvas.so .init_array)
 * -------------------------------------------------------------------------- */

int64_t canvas_heap_init(void);
uint8_t canvas_heap_is_initialised(void);
int64_t canvas_heap_stats(CanvasHeapStats *out_stats);
void *canvas_alloc(size_t size, size_t align);
void *canvas_malloc(size_t size);
void *canvas_calloc(size_t count, size_t size);
void *canvas_realloc(void *ptr, size_t new_size);
void canvas_free(void *ptr);
int64_t canvas_heap_commit(size_t offset, size_t len, uintptr_t *out_addr);
int64_t canvas_heap_decommit(size_t offset, size_t len);

/* --------------------------------------------------------------------------
 * Capability handles & channels
 * -------------------------------------------------------------------------- */

uint32_t canvas_bootstrap_handle(void);
int64_t canvas_handle_close(uint32_t handle);
int64_t canvas_handle_duplicate(uint32_t handle, uint32_t rights, uint32_t *out_handle);

int64_t canvas_channel_create(uint32_t *out_h0, uint32_t *out_h1);
int64_t canvas_channel_write(uint32_t ch, const uint8_t *data, size_t len);
int64_t canvas_channel_write_handles(
    uint32_t ch,
    const uint8_t *data,
    size_t len,
    const uint32_t *handles,
    size_t num_handles
);
int64_t canvas_channel_read(uint32_t ch, uint8_t *buf, size_t buf_len, size_t *out_len);
int64_t canvas_channel_read_blocking(uint32_t ch, uint8_t *buf, size_t buf_len, size_t *out_len);
int64_t canvas_channel_read_handles(
    uint32_t ch,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len,
    uint32_t *handles_out,
    size_t max_handles,
    size_t *out_num_handles
);

/* --------------------------------------------------------------------------
 * Virtual Memory Objects (VMO) & VMAR
 * -------------------------------------------------------------------------- */

int64_t canvas_vmo_create(uint64_t size, uint32_t *out_vmo);
int64_t canvas_vmo_create_ex(uint64_t size, uint32_t flags, uint32_t *out_vmo);
int64_t canvas_vmo_read(uint32_t vmo, uint64_t offset, uint8_t *buf, size_t len, size_t *out_read);
int64_t canvas_vmo_write(uint32_t vmo, uint64_t offset, const uint8_t *data, size_t len, size_t *out_written);

int64_t canvas_vmar_map(
    uint32_t vmar,
    uint64_t vaddr,
    uint32_t vmo,
    uint64_t vmo_offset,
    uint64_t len,
    uint32_t flags,
    uint64_t *out_addr
);
int64_t canvas_vmar_protect(uint32_t vmar, uint64_t vaddr, uint64_t len, uint32_t flags);
int64_t canvas_vmar_unmap(uint32_t vmar, uint64_t vaddr, uint64_t len);

/* --------------------------------------------------------------------------
 * Waitsets & signals
 * -------------------------------------------------------------------------- */

int64_t canvas_signal_create(uint32_t *out_signal);
int64_t canvas_signal_set(uint32_t signal);
int64_t canvas_signal_clear(uint32_t signal);
int64_t canvas_wait_many(CanvasWaitItem *items, size_t count, uint32_t mode, uint64_t timeout_ticks, size_t *out_satisfied);

/* --------------------------------------------------------------------------
 * Framebuffer & 2D drawing surface
 * -------------------------------------------------------------------------- */

int64_t canvas_fb_info(CanvasFbInfo *out_info);
int64_t canvas_fb_blit(
    uint32_t vmo,
    uint32_t frame_draw_cap,
    uint32_t dst_x,
    uint32_t dst_y,
    uint32_t width,
    uint32_t height,
    uint32_t src_stride_bytes
);

int64_t canvas_surface_create(uint32_t width, uint32_t height, uint32_t frame_draw_cap, CanvasSurface **out_surface);
int64_t canvas_surface_create_fullscreen(uint32_t frame_draw_cap, CanvasSurface **out_surface);
void canvas_surface_destroy(CanvasSurface *surface);
uint32_t canvas_surface_width(const CanvasSurface *surface);
uint32_t canvas_surface_height(const CanvasSurface *surface);
uint32_t canvas_surface_vmo(const CanvasSurface *surface);
int64_t canvas_surface_set_pixel(CanvasSurface *surface, uint32_t x, uint32_t y, uint8_t r, uint8_t g, uint8_t b);
int64_t canvas_surface_fill_rect(CanvasSurface *surface, uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t r, uint8_t g, uint8_t b);
int64_t canvas_surface_draw_text(
    CanvasSurface *surface,
    uint32_t x,
    uint32_t y,
    const char *utf8,
    size_t len,
    uint8_t r,
    uint8_t g,
    uint8_t b
);
int64_t canvas_surface_draw_text_font(
    CanvasSurface *surface,
    uint32_t x,
    uint32_t y,
    const char *utf8,
    size_t len,
    uint8_t r,
    uint8_t g,
    uint8_t b,
    CanvasTextFont font
);
int64_t canvas_surface_present(const CanvasSurface *surface);
int64_t canvas_surface_present_at(const CanvasSurface *surface, uint32_t dst_x, uint32_t dst_y);

/* --------------------------------------------------------------------------
 * HxFS filesystem helpers
 * -------------------------------------------------------------------------- */

int64_t canvas_fs_open(uint32_t registry_ch, CanvasFs **out_fs);
void canvas_fs_close(CanvasFs *fs);
int64_t canvas_fs_open_file(CanvasFs *fs, const char *path, size_t path_len, CanvasFsFile **out_file);
int64_t canvas_fs_file_read(CanvasFsFile *file, uint8_t *buf, size_t buf_len, size_t *out_len);
int64_t canvas_fs_file_read_at(CanvasFsFile *file, uint64_t offset, uint8_t *buf, size_t len, size_t *out_len);
void canvas_fs_file_close(CanvasFsFile *file);

/* --------------------------------------------------------------------------
 * Capability-first dynamic loading, finalisation & intra-process threading
 * -------------------------------------------------------------------------- */

void *canvas_dlopen_vmo(uint32_t vmo_handle, int32_t flags);
void *canvas_dlopen_soname(const char *soname, int32_t flags);
void *canvas_dlopen_blob(uint32_t blob_ch, int32_t flags);
void *canvas_dlsym(void *handle, const char *symbol);
int32_t canvas_dlclose(void *handle);
const char *canvas_dlerror(void);
int32_t canvas_dladdr(const void *addr, CanvasDlInfo *out_info);
int32_t canvas_dl_iterate_phdr(
    int32_t (*callback)(CanvasDlPhdrInfo *info, size_t size, void *data),
    void *data
);
int32_t canvas_dl_set_lib_dir(uint32_t hxfs_dir_ch);
int32_t canvas_dl_set_hxfs_service(uint32_t hxfs_ch);

int64_t canvas_atexit(void (*func)(void));
int32_t atexit(void (*func)(void));
int32_t __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);
void *__tls_get_addr(void *ti);

/* --------------------------------------------------------------------------
 * Process arguments, standard streams (Channel stdio) & capability mask
 * -------------------------------------------------------------------------- */

size_t canvas_args_count(void);
int64_t canvas_arg_get(size_t index, uint8_t *out_buf, size_t buf_len, size_t *out_len);
int64_t canvas_stdin_read(uint8_t *out_buf, size_t buf_len, size_t *out_read);
int64_t canvas_stdout_write(const uint8_t *data, size_t len, size_t *out_written);
int64_t canvas_stderr_write(const uint8_t *data, size_t len, size_t *out_written);
_Noreturn void canvas_exit_code(int32_t code);
uint64_t canvas_caps_mask(void);
uint32_t canvas_cap_handle(uint32_t kind);
uint32_t canvas_take_cap_handle(uint32_t kind);

int64_t canvas_thread_spawn(
    const char *name,
    CanvasThreadFn entry,
    void *arg,
    size_t stack_size,
    CanvasThread **out_thread
);
int64_t canvas_thread_join(CanvasThread *thread, int64_t *out_exit_code);
_Noreturn void canvas_thread_exit(int64_t code);

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t new_size);
void free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* HUESOS_CANVAS_H */
