#pragma once

#include <uacpi/namespace.h>
#include <uacpi/types.h>

/*
 * The Notify callback runs in uACPI's deferred work queue.  It must not pass
 * an opaque namespace pointer to Rust and hope that a later PCI scan can make
 * sense of it.  This small, fixed mapping record is the C-side ACPI identity
 * proof: the target's _ADR (when present) is paired with its PNP0A03/08 root,
 * _SEG, _BBN, and _CRS bus range before the event crosses the language/IPC
 * boundary.
 */
#define HUES_HOTPLUG_TARGET_ROOT 1u
#define HUES_HOTPLUG_TARGET_BRIDGE 2u
#define HUES_HOTPLUG_TARGET_FUNCTION 3u

typedef struct HuesHotplugTarget {
    uacpi_u32 kind;
    uacpi_u16 segment;
    uacpi_u8 bus;
    uacpi_u8 device;
    uacpi_u8 function;
    uacpi_u8 valid;
    uacpi_u16 root_segment;
    uacpi_u8 root_start_bus;
    uacpi_u8 root_end_bus;
} HuesHotplugTarget;

int hues_uacpi_map_hotplug_node(
    uacpi_namespace_node *node, HuesHotplugTarget *out_target
);
