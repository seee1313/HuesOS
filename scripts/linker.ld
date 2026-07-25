/* HuesOS kernel linker script - Limine higher-half ELF kernel.
 *
 * The kernel exports page-aligned start / end symbols for every
 * non-`.text` load segment. `huesos_arch::paging::apply_kernel_wx()`
 * walks those ranges after paging init and sets `NO_EXECUTE` on
 * every 4 KiB page they cover, so a write-what-where in kernel
 * data cannot be re-purposed as a code-execution gadget through
 * one of the higher-half data windows.
 *
 * `.text` deliberately has no such symbols: it is the *only*
 * higher-half range that must remain executable.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain_entry)

PHDRS
{
    limine_requests PT_LOAD;
    text            PT_LOAD;
    rodata          PT_LOAD;
    data            PT_LOAD;
}

SECTIONS
{
    /* Limine loads kernels within the topmost 2GiB of the address space. */
    . = 0xffffffff80000000;

    __huesos_limine_requests_start = .;
    .limine_requests : {
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :limine_requests
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __huesos_limine_requests_end = .;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    __huesos_rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    .note.gnu.build-id : {
        *(.note.gnu.build-id)
    } :rodata

    /* Kernel-user copy exception table. Each 24-byte entry is
     * (start_rip, end_rip, fixup_rip), emitted by the user_access_ok!
     * macro's asm! .pushsection block. `KEEP` prevents LTO / GC from
     * dropping the entries when the wrapping function is inlined.
     * 8-byte aligned so u64 reads never cross a cache-line for no
     * reason. Placed in :rodata so it inherits the read-only,
     * NO_EXECUTE flags stamped by apply_kernel_wx.
     */
    . = ALIGN(8);
    __huesos_ex_table_start = .;
    .ex_table : ALIGN(8) {
        KEEP(*(.ex_table))
        KEEP(*(.ex_table.*))
    } :rodata
    __huesos_ex_table_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __huesos_rodata_end = .;

    __huesos_data_start = .;
    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __huesos_data_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.* )
        *(.comment)
    }
}
