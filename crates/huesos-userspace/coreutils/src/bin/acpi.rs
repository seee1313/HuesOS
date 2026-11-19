#![no_std]
#![no_main]

use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    cu::run_registry_query("acpi", b"query:acpi")
}
