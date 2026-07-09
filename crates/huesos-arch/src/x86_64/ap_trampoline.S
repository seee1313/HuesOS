.code16
.globl ap_trampoline_start
ap_trampoline_start:
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # Enable A20 via fast gate (port 0x92)
    in al, 0x92
    or al, 0x02
    out 0x92, al

    # Load GDT with 32-bit base (operand-size override 0x66)
    .byte 0x66
    lgdt [ap_gdt_desc - ap_trampoline_start + 0x8000]

    # Enable protected mode (CR0.PE = 1)
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    # Far jump to 32-bit protected mode
    # 0x66 = operand-size override, 0xEA = JMP ptr16:32
    .byte 0x66, 0xEA
    .long (ap_prot_mode - ap_trampoline_start + 0x8000)
    .word 0x0008

.code32
ap_prot_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # Enable PAE (CR4.PAE = 1)
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    # Load CR3 from ApBootInfo at 0x7000
    mov eax, [0x7000]
    mov cr3, eax

    # Enable long mode (EFER.LME = 1)
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr

    # Enable paging (CR0.PG = 1)
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    # Far jump to 64-bit mode via RETF
    push 0x18
    push dword ptr (ap_long_mode - ap_trampoline_start + 0x8000)
    retf

.code64
ap_long_mode:
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # Load stack pointer from ApBootInfo at 0x7008
    mov rsp, [0x7008]

    # Jump to Rust AP entry point at ApBootInfo+0x10
    mov rax, [0x7010]
    jmp rax

.align 8
ap_gdt:
    .quad 0x0000000000000000  # null
    .quad 0x00CF9A000000FFFF  # 32-bit code
    .quad 0x00CF92000000FFFF  # 32-bit data
    .quad 0x00AF9A000000FFFF  # 64-bit code
    .quad 0x00AF92000000FFFF  # 64-bit data
ap_gdt_end:

ap_gdt_desc:
    .word (ap_gdt_end - ap_gdt - 1)
    .long (ap_gdt - ap_trampoline_start + 0x8000)

.globl ap_trampoline_end
ap_trampoline_end:
