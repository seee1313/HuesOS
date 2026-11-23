fn main() {
    for sym in [
        "RtlLookupFunctionEntry",
        "RtlVirtualUnwind",
        "RtlCaptureContext",
        "RtlAddFunctionTable",
        "RtlDeleteFunctionTable",
        "RtlPcToFileHeader",
        "RtlCaptureStackBackTrace",
        "RtlUnwindEx",
    ] {
        println!("cargo:rustc-cdylib-link-arg=/EXPORT:{sym}=ntdll.{sym}");
    }
}
