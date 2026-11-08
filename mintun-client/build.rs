fn main() {
    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed=assets/windows.manifest");
    println!("cargo:rerun-if-changed=assets/mintun.ico");
    println!("cargo:rerun-if-env-changed=MINTUN_TRUSTED_CORE_MANIFEST");
    let trusted_output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
        .join("trusted-core.json");
    if let Some(manifest) = std::env::var_os("MINTUN_TRUSTED_CORE_MANIFEST") {
        let manifest = std::path::PathBuf::from(manifest);
        println!("cargo:rerun-if-changed={}", manifest.display());
        std::fs::copy(&manifest, &trusted_output)
            .expect("Unable to embed the supplied trusted core manifest");
    } else {
        std::fs::write(&trusted_output, b"null")
            .expect("Unable to prepare the developer-build core trust marker");
    }
    #[cfg(feature = "ui")]
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_style("fluent".into()),
    ).expect("Slint UI compilation failed");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
            let library = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".tools/w64devkit/lib/libversion.a");
            if library.is_file() {
                let imports = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("windows-imports");
                std::fs::create_dir_all(&imports).expect("Unable to prepare Windows import libraries");
                std::fs::copy(library, imports.join("libversion.a")).expect("Unable to prepare version import library");
                println!("cargo:rustc-link-search=native={}", imports.display());
            }
        }
        let mut resource = winresource::WindowsResource::new();
        resource.set("ProductName", "MinTun Client");
        resource.set("FileDescription", "MinTun Client");
        resource.set("OriginalFilename", "MinTunClient.exe");
        resource.set("FileVersion", env!("CARGO_PKG_VERSION"));
        resource.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        resource.set_manifest_file("assets/windows.manifest");
        resource.set_icon("assets/mintun.ico");
        resource.compile().expect("Windows resources compilation failed");
    }
}
