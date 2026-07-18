use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from("../../third_party/uacpi");
    let sources = [
        "tables.c",
        "types.c",
        "uacpi.c",
        "utilities.c",
        "interpreter.c",
        "opcodes.c",
        "namespace.c",
        "stdlib.c",
        "shareable.c",
        "opregion.c",
        "default_handlers.c",
        "io.c",
        "notify.c",
        "sleep.c",
        "registers.c",
        "resources.c",
        "event.c",
        "mutex.c",
        "osi.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(vendor.join("include"))
        .define("UACPI_BAREBONES_MODE", None)
        .define("UACPI_USE_BUILTIN_STRING", None)
        .define("UACPI_DEFAULT_LOG_LEVEL", "UACPI_LOG_INFO")
        .flag_if_supported("-ffreestanding")
        .flag_if_supported("-fno-stack-protector")
        .flag_if_supported("-fno-pic")
        .flag_if_supported("-mno-red-zone")
        .flag_if_supported("-mcmodel=large")
        .warnings(true)
        .extra_warnings(true);
    for source in sources {
        build.file(vendor.join("source").join(source));
    }
    build.compile("uacpi_barebones");

    println!("cargo:rerun-if-changed=../../third_party/uacpi/source");
    println!("cargo:rerun-if-changed=../../third_party/uacpi/include");
    println!("cargo:rerun-if-changed=../../third_party/uacpi/UPSTREAM");
}
