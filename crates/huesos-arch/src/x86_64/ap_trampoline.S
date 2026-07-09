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
    # Temporary real-mode stack (must be non-zero before any push/call).
    mov sp, 0x8ff0

    # Enable A20 via fast gate (port 0x92)
    in al, 0x92
    or al, 0x02
    out 0x92, al

    # Load GDT (32-bit base; 0x66 = operand-size override)
    .byte 0x66
    .set ap_gdt_desc_addr, (ap_gdt_desc - ap_trampoline_start + 0x8000)
    lgdt [ap_gdt_desc_addr]

    # Enable protected mode (CR0.PE = 1)
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    # Far jump to 32-bit protected mode
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
    # CRITICAL: set a real stack before any push. ESP=0 made the old
    # long-mode retf path #PF at 0xfffffffc and triple-fault the AP.
    mov esp, 0x8ff0

    # Enable PAE
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    # Load CR3 from ApBootInfo at 0x7000
    mov eax, [0x7000]
    mov cr3, eax

    # EFER.LME | EFER.NXE — kernel PTEs use the NX bit
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x900
    wrmsr

    # Enable paging → compatibility mode (still 32-bit CS)
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    # Far jump to 64-bit code segment (CS=0x18), no stack dependency
    .byte 0xEA
    .long (ap_long_mode - ap_trampoline_start + 0x8000)
    .word 0x0018

.code64
ap_long_mode:
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # status = 1 (long mode OK) for BSP diagnostics
    mov qword ptr [0x7018], 1

    mov rsp, [0x7008]
    and rsp, 0xFFFFFFFFFFFFFFF0

    mov rax, [0x7010]
    jmp rax

.align 8
ap_gdt:
    .quad 0x0000000000000000  # null
    .quad 0x00CF9A000000FFFF  # 0x08: 32-bit code
    .quad 0x00CF92000000FFFF  # 0x10: 32-bit data
    .quad 0x00AF9A000000FFFF  # 0x18: 64-bit code
    .quad 0x00AF92000000FFFF  # 0x20: 64-bit data
ap_gdt_end:

ap_gdt_desc:
    .word (ap_gdt_end - ap_gdt - 1)
    .long (ap_gdt - ap_trampoline_start + 0x8000)

.globl ap_trampoline_end
ap_trampoline_end:
