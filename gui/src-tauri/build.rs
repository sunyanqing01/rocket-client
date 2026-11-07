fn main() {
    println!("cargo:rerun-if-env-changed=ROCKET_NO_ADMIN");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=app.asinvoker.manifest");

    // ROCKET_NO_ADMIN=1 builds an asInvoker exe, used only to smoke-test the UI
    // (tray/window) from a non-elevated shell.
    let manifest = if std::env::var("ROCKET_NO_ADMIN").ok().as_deref() == Some("1") {
        include_str!("app.asinvoker.manifest")
    } else {
        include_str!("app.manifest")
    };

    let windows = tauri_build::WindowsAttributes::new().app_manifest(manifest);
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run tauri-build");
}
