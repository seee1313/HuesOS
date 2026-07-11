# Fault Isolation and Kernel Panic

## Policy

HuesOS makes the privilege boundary the fault-containment boundary:

- an unhandled CPU exception originating at CPL3 terminates the complete
  userspace process;
- an exception originating at CPL0 is a fatal kernel integrity failure and
  enters the non-returning kernel panic path;
- the machine never reboots automatically after a kernel panic.

This distinction is based on the saved CS selector's RPL, not only on a
page-fault error bit. It therefore applies consistently to page faults,
general-protection faults, invalid opcodes, divide errors, and alignment
checks. A double fault is always treated as fatal to the kernel.

## Ring-3 process faults

The x86 IDT builds a `FaultInfo` record containing the exception kind, RIP,
RSP, RFLAGS, CS, architecture error code, and CR2 for page faults. The
architecture crate does not depend on process management; it invokes a
callback registered by `huesos-kernel` after initialization.

The kernel callback:

1. records a concise serial diagnostic;
2. maps the exception to a stable negative process exit code;
3. marks every thread belonging to the process finished on every CPU;
4. removes those threads from runnable fair queues;
5. sends reschedule IPIs to CPUs that may be running sibling threads;
6. wakes `ProcessWait` waiters;
7. defers stacks and address-space destruction to the reaper;
8. switches away from the faulting exception context without returning to
   userspace.

Address-space teardown checks every per-CPU scheduler first. If any CPU still
has a thread from that process as its current task, teardown is deferred. This
prevents freeing page tables while a remote CPU can still have their CR3
loaded.

### Stable exit codes

| Exception | Constant | Value |
|---|---|---:|
| Page fault | `fault_exit::PAGE_FAULT` | `-0x1001` |
| General protection | `fault_exit::GENERAL_PROTECTION` | `-0x1002` |
| Invalid opcode | `fault_exit::INVALID_OPCODE` | `-0x1003` |
| Divide error | `fault_exit::DIVIDE_ERROR` | `-0x1004` |
| Alignment check | `fault_exit::ALIGNMENT_CHECK` | `-0x1005` |

The first process exit status wins. `ProcessWait` returns the same `i64` used
for an ordinary explicit exit, so supervisors do not need a second waiting
mechanism.

## Kernel panic path

A ring-0 fault or Rust panic elects one CPU through an atomic compare/exchange.
The winner owns all diagnostics. A second CPU entering panic immediately
disables interrupts and halts rather than contending for locks or corrupting
the report.

The owner:

1. disables local interrupts;
2. stops the local LAPIC timer;
3. broadcasts a fixed panic-stop IPI to every other CPU;
4. writes a complete report through an emergency COM1 path that does not take
   the normal serial lock;
5. replaces the framebuffer with a dark-red background and white text;
6. enters an infinite `cli`/`hlt` loop.

There is intentionally no timeout and no reboot. The screen remains available
for an operator to photograph, while the serial report remains available to a
hypervisor, BMC, or attached debugger.

### Report fields

CPU-exception reports include:

- logical/initial APIC CPU identifier;
- exception name;
- exception error code;
- faulting linear address where applicable;
- RIP and RSP;
- RFLAGS and CS;
- active CR3;
- number of peer CPUs that acknowledged the panic-stop IPI;
- final `system halted; no automatic reboot` action.

Rust panic reports include the panic message, source file, line, column, CPU,
and CR3. A future assembly exception prologue may extend this with all general
registers. A bounded frame-pointer stack trace is also planned; it must never
turn a useful primary panic into a recursive fault.

## Panic framebuffer safety

The panic renderer is allocation-free. During framebuffer initialization it
stores a dedicated copy of the framebuffer geometry. Normal drawing never
locks this emergency copy, so a panic interrupting an ordinary framebuffer
operation cannot deadlock trying to acquire the normal drawing mutex.

Rendering uses only volatile pixel writes and the built-in 8x8 ASCII font. If
no framebuffer exists, serial diagnostics still work and the machine still
halts safely.

## Automated tests

### Process-fault containment

`huesos-fault-probe` is a tiny command-driven child embedded into init for boot
tests. Init launches fresh instances that deliberately generate #PF, #UD, #GP,
and #DE, then verifies each stable status through `ProcessWait`. Expected
serial flow includes:

```text
[fault-probe] triggering page
[user-fault] process=fault-probe ... reason=PAGE FAULT ... code=-4097
[fault-probe] triggering opcode
[fault-probe] triggering gpf
[fault-probe] triggering divide
[init] user fault isolation OK (#PF/#UD/#GP/#DE contained)
```

Init then launches DriverManager and the terminal. Reaching `terminal:ready`
proves the kernel and unrelated processes survived all four child faults.

### Fatal panic screen

The trusted HBI command-line token `panic_test=1` deliberately invokes a Rust
panic immediately after framebuffer and fault-policy initialization. It is a
diagnostic test hook, disabled in normal images. The QEMU test captures both:

- serial text containing `HuesOS KERNEL PANIC`, the requested message, CR3,
  and the no-reboot action;
- a PPM screendump whose majority is the red panic background and which
  contains white text pixels.

The framebuffer crate also has a host unit test for the red/white renderer.

## Current limitations and next hardening

- General registers are not yet captured by the `x86-interrupt` prologue.
- Stack unwinding is not yet enabled.
- Panic-stop IPI delivery is best-effort if LAPIC hardware itself is the
  failing component.
- Breakpoint (`INT3`) currently logs and resumes; a debugger subsystem should
  eventually own it.
- Machine-check and NMI policy require dedicated handlers.
- Process-wide termination is implemented, but broader object-registry
  lifetime work is still required to reclaim every object on final close.
