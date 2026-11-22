//! Print DriverManager's supervised-process list. The first column is the
//! stable kernel Process KOID, never a process-local handle-table slot.

#![no_std]
#![no_main]

use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    cu::run_registry_query("ps", b"query:ps")
}
