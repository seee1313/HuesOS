.section .text

.global huesos_copy_from_user
.type huesos_copy_from_user, @function
huesos_copy_from_user:
    test rdx, rdx
    jz .Lcfu_done
.Lcfu_loop:
.Lcfu_read:
    mov al, BYTE PTR [rsi]
.Lcfu_read_end:
.Lcfu_write:
    mov BYTE PTR [rdi], al
.Lcfu_write_end:
    inc rsi
    inc rdi
    dec rdx
    jnz .Lcfu_loop
.Lcfu_done:
    xor eax, eax
    ret
.Lcfu_fixup:
    mov rax, -1
    ret
.size huesos_copy_from_user, .-huesos_copy_from_user

.global huesos_copy_to_user
.type huesos_copy_to_user, @function
huesos_copy_to_user:
    test rdx, rdx
    jz .Lctu_done
.Lctu_loop:
.Lctu_read:
    mov al, BYTE PTR [rsi]
.Lctu_read_end:
.Lctu_write:
    mov BYTE PTR [rdi], al
.Lctu_write_end:
    inc rsi
    inc rdi
    dec rdx
    jnz .Lctu_loop
.Lctu_done:
    xor eax, eax
    ret
.Lctu_fixup:
    mov rax, -1
    ret
.size huesos_copy_to_user, .-huesos_copy_to_user

.section .ex_table, "a"
.balign 8
.quad .Lcfu_read, .Lcfu_read_end, .Lcfu_fixup
.quad .Lcfu_write, .Lcfu_write_end, .Lcfu_fixup
.quad .Lctu_read, .Lctu_read_end, .Lctu_fixup
.quad .Lctu_write, .Lctu_write_end, .Lctu_fixup
